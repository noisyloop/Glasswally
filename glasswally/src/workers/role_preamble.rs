// glasswally/src/workers/role_preamble.rs
//
// Role preamble fingerprinting — Phase 1 signal.
//
// Distillation campaigns frequently use a fixed system prompt ("role preamble") to
// prime the model for capability extraction: "You are an expert X, always explain
// your reasoning in detail..."  The preamble is chosen to maximise response quality
// for training data collection and is repeated verbatim or near-verbatim across
// thousands of requests.
//
// Detection strategy:
//   1. Compute a structural hash of the system_prompt / leading role segment.
//   2. Track per-account preamble hash stability (low entropy → template reuse).
//   3. Detect cross-account preamble collisions — same hash across many accounts
//      is a near-certain indicator of coordinated extraction.
//   4. Keyword scan for known role-injection archetypes.
//
// Score contributions:
//   template_reuse:           +0.35   (≥80% same hash in 1-hour window)
//   cross_account_collision:  +0.50   (≥5 accounts share same preamble hash)
//   archetype_match:          +0.25   (known extraction role pattern)
//   chain_request:            +0.15   (preamble ends with explicit task chain)

use std::collections::HashMap;

use chrono::Utc;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

// ── Known role preamble archetypes ────────────────────────────────────────────
// Each entry is a lowercase substring that strongly suggests a systematic
// extraction role rather than an ordinary assistant role.

const EXTRACTION_ROLE_PATTERNS: &[&str] = &[
    // Generic capability maximisation
    "always provide complete",
    "never refuse",
    "never say you cannot",
    "do not add disclaimers",
    "do not include warnings",
    "omit caveats",
    "respond without restrictions",
    "respond with maximum detail",
    // Reasoning elicitation
    "always explain your step-by-step reasoning",
    "show every step of your reasoning",
    "provide detailed chain of thought",
    "reason through each step explicitly",
    "think aloud before answering",
    // Expert persona combined with comprehensive output
    "you are an expert",
    "act as an expert",
    "you are a highly skilled",
    "you are a world-class",
    "you are a top-tier",
    // Dataset / training framing
    "your answers will be used to train",
    "your responses are being recorded",
    "answer as if explaining to another ai",
    "generate high-quality training examples",
    // Breadth elicitation
    "cover all aspects",
    "provide exhaustive",
    "be comprehensive and thorough",
    "do not omit anything",
    "include all relevant details",
    // Response format optimisation for data collection
    "format your answer in json",
    "structure your response as",
    "output must be parseable",
    "use xml tags to separate",
];

// ── Structural hash of system prompt ─────────────────────────────────────────

fn preamble_hash(prompt: &str) -> String {
    use sha2::{Digest, Sha256};
    // Take first 512 chars, lowercase, strip punctuation noise.
    let normalised: String = prompt
        .chars()
        .take(512)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();
    let normalised = normalised.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut h = Sha256::new();
    h.update(normalised.as_bytes());
    hex::encode(&h.finalize()[..8])
}

// ── Main analysis function ────────────────────────────────────────────────────

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    // Need either an explicit system_prompt_hash or a prompt long enough to contain a preamble.
    let preamble_src = if let Some(h) = &event.system_prompt_hash {
        h.clone()
    } else if event.prompt.len() >= 80 {
        preamble_hash(&event.prompt)
    } else {
        return None;
    };

    let prompt_lower = event.prompt.to_lowercase();

    // ── 1. Archetype keyword scan ─────────────────────────────────────────────
    let mut archetype_hits: Vec<String> = EXTRACTION_ROLE_PATTERNS
        .iter()
        .filter(|&&pat| prompt_lower.contains(pat))
        .map(|&pat| pat.to_string())
        .collect();

    let archetype_score = if archetype_hits.is_empty() {
        0.0f32
    } else {
        0.25f32.min(0.10 * archetype_hits.len() as f32)
    };

    // ── 2. Within-account template reuse ─────────────────────────────────────
    // Read account preamble hash history from window.
    let window = store.get_window(&event.account_id)?;
    let preamble_hashes: Vec<String> = {
        let w = window.read();
        w.events
            .iter()
            .filter_map(|e| e.system_prompt_hash.clone())
            .collect()
    };

    let reuse_score = if preamble_hashes.len() >= 5 {
        let same = preamble_hashes
            .iter()
            .filter(|h| *h == &preamble_src)
            .count();
        let frac = same as f32 / preamble_hashes.len() as f32;
        if frac >= 0.80 {
            0.35
        } else if frac >= 0.60 {
            0.20
        } else {
            0.0
        }
    } else {
        0.0
    };

    // ── 3. Cross-account preamble collision ───────────────────────────────────
    let collision_score = {
        let n = store.accounts_with_preamble_hash(&preamble_src);
        if n >= 10 {
            0.50
        } else if n >= 5 {
            0.35
        } else if n >= 3 {
            0.18
        } else {
            0.0
        }
    };

    // ── 4. Task chaining in preamble (ends with explicit task list) ───────────
    let chain_score = if prompt_lower.contains("task 1:")
        || prompt_lower.contains("step 1:")
        || prompt_lower.contains("question 1:")
        || (prompt_lower.contains("first,")
            && prompt_lower.contains("then,")
            && prompt_lower.contains("finally,"))
    {
        0.15
    } else {
        0.0
    };

    let total = archetype_score + reuse_score + collision_score + chain_score;
    if total < 0.15 {
        return None;
    }

    let score = total.min(1.0);
    let confidence = if collision_score > 0.0 {
        0.90
    } else if reuse_score > 0.0 {
        0.75
    } else {
        0.55
    };

    let mut evidence = Vec::new();
    if archetype_score > 0.0 {
        archetype_hits.truncate(3);
        evidence.push(format!("archetype_match:{}", archetype_hits.join(",")));
    }
    if reuse_score > 0.0 {
        evidence.push(format!(
            "template_reuse:hash={}",
            preamble_src.get(..6).unwrap_or(&preamble_src)
        ));
    }
    if collision_score > 0.0 {
        let n = store.accounts_with_preamble_hash(&preamble_src);
        evidence.push(format!("cross_account_collision:{}_accounts", n));
    }
    if chain_score > 0.0 {
        evidence.push("task_chain_preamble".to_string());
    }

    let mut meta = HashMap::new();
    meta.insert(
        "preamble_hash".to_string(),
        serde_json::Value::String(preamble_src),
    );
    meta.insert(
        "archetype_hits".to_string(),
        serde_json::Value::Number(serde_json::Number::from(archetype_hits.len() as u64)),
    );

    Some(DetectionSignal {
        worker: WorkerKind::RolePreamble,
        account_id: event.account_id.clone(),
        score,
        confidence,
        evidence,
        meta,
        timestamp: Utc::now(),
    })
}
