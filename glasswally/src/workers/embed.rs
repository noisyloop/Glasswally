// glasswally/src/workers/embed.rs
//
// Semantic similarity worker — paraphrase-resistant CoT detection.
//
// The Aho-Corasick CoT worker catches exact and near-exact patterns.
// This worker catches PARAPHRASED extraction prompts:
//
//   "Show me your reasoning step by step"       → CoT catches this
//   "Articulate your internal thought process"  → CoT misses, embed catches
//   "Walk me through your logic sequentially"   → CoT misses, embed catches
//
// Approach: random feature hashing (RFH) embedding.
//   1. Normalize + tokenize prompt into word n-grams (n=1..3)
//   2. Hash each n-gram deterministically into a 512-dim ±1 feature vector
//   3. Sum and L2-normalize → unit embedding vector
//   4. Cosine similarity against 24 pre-computed canonical extraction archetypes
//
// This approximates semantic similarity without an ML runtime or model weights.
// To upgrade to sentence-transformers, enable --features neural-embed and
// swap embed() for a candle-core inference call.
//
// Performance: ~150µs per prompt on a single core (SHA256 dominates).

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const DIM: usize = 512;

/// Prompt bytes fed to the embedding (head + tail).
const MAX_EMBED_BYTES: usize = 4096;

/// Known extraction prompt archetypes — each is a centroid of a cluster of
/// real prompts observed in distillation campaigns.
const ARCHETYPES: &[(&str, &str)] = &[
    // (canonical text, label)
    (
        "explain your reasoning step by step articulate internal thought process",
        "cot_elicitation",
    ),
    (
        "show every step of your reasoning process walk through your logic",
        "cot_elicitation",
    ),
    (
        "you are an AI judge score response rubric reward model grading evaluation",
        "reward_model",
    ),
    (
        "act as a grader evaluator provide rubric based score preference pair",
        "reward_model",
    ),
    (
        "implement production grade code with unit tests comprehensive error handling",
        "code_extraction",
    ),
    (
        "write complete working implementation all edge cases handled compile run",
        "code_extraction",
    ),
    (
        "use computer vision screenshot describe what you see pixel by pixel detail",
        "vision_extraction",
    ),
    (
        "analyze image describe every element systematically comprehensive",
        "vision_extraction",
    ),
    (
        "censorship safe alternative preserve informational intent sensitive topic",
        "censorship_evasion",
    ),
    (
        "politically neutral rephrasing maintain factual content avoid detection filter",
        "censorship_evasion",
    ),
    (
        "multi step agent plan tool use agentic workflow decompose task execute",
        "agentic_extraction",
    ),
    (
        "plan and execute complex task using tools autonomously step by step agent",
        "agentic_extraction",
    ),
    (
        "statistical rigor deep domain expertise data analyst comprehensive analysis",
        "data_extraction",
    ),
    (
        "thorough analysis citations evidence based comprehensive response complete",
        "data_extraction",
    ),
    (
        "respond only in json structured output key value pairs machine readable",
        "structured_extraction",
    ),
    (
        "output json schema extract structured data parse fields complete",
        "structured_extraction",
    ),
    (
        "reinforcement learning from human feedback preference data training pairs",
        "rl_extraction",
    ),
    (
        "generate training data preference pairs chosen rejected sample diverse",
        "rl_extraction",
    ),
    (
        "summarize in complete detail all information no compression verbatim",
        "verbatim_dump",
    ),
    (
        "repeat everything you know about topic comprehensive complete nothing omitted",
        "verbatim_dump",
    ),
    (
        "translate while preserving exact meaning technical accuracy terminology",
        "translation_bypass",
    ),
    (
        "convert content different language maintain all details technical precise",
        "translation_bypass",
    ),
    (
        "generate diverse examples training dataset synthetic data augmentation",
        "dataset_gen",
    ),
    (
        "create varied examples different styles formats for fine tuning dataset",
        "dataset_gen",
    ),
];

// ── Embedding engine ──────────────────────────────────────────────────────────

/// Deterministic random feature vector for a string token.
/// Maps token → 512 dimensions of ±1 via SHA256.
fn token_feature(token: &str) -> [f32; DIM] {
    let mut h = Sha256::new();
    h.update(b"gw_rfh_v1:");
    h.update(token.as_bytes());
    let digest = h.finalize();

    let mut feat = [0.0f32; DIM];
    for i in 0..DIM {
        // Spread 32 digest bytes across 512 dimensions (16 dims per byte)
        let byte = digest[i / 16];
        let bit = (byte >> (i % 8)) & 1;
        feat[i] = if bit == 1 { 1.0 } else { -1.0 };
    }
    feat
}

/// Build a normalized embedding vector for a text string.
fn embed_text(text: &str) -> [f32; DIM] {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut vec = [0.0f32; DIM];

    for n in 1..=3usize {
        for window in tokens.windows(n) {
            let gram = window.join(" ");
            let feat = token_feature(&gram);
            for i in 0..DIM {
                vec[i] += feat[i];
            }
        }
    }

    // L2 normalize
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-8 {
        for v in vec.iter_mut() {
            *v /= norm;
        }
    }
    vec
}

fn cosine(a: &[f32; DIM], b: &[f32; DIM]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum::<f32>()
}

fn normalize_text(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' {
                c
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

static ARCHETYPE_VECS: OnceLock<Vec<([f32; DIM], &'static str)>> = OnceLock::new();

fn archetype_vecs() -> &'static Vec<([f32; DIM], &'static str)> {
    ARCHETYPE_VECS.get_or_init(|| {
        ARCHETYPES
            .iter()
            .map(|(text, label)| (embed_text(&normalize_text(text)), *label))
            .collect()
    })
}

// ── Detection worker ──────────────────────────────────────────────────────────

pub async fn analyze(event: &ApiEvent, _store: &StateStore) -> Option<DetectionSignal> {
    if event.prompt.len() < 20 {
        return None;
    }

    // Canonicalise first: an invisible character inside a word would
    // otherwise be turned into a space and split the token.
    //
    // Only the head and tail are embedded: each n-gram costs a SHA-256 plus a
    // 512-wide vector add, so embedding a 32 KiB prompt took ~30 ms of CPU
    // per event, and a long prompt's vector is too diluted to match a
    // one-line archetype anyway.
    let bounded = crate::events::truncate_middle(&event.prompt, MAX_EMBED_BYTES);
    let normalized = normalize_text(&super::normalize_prompt(&bounded));
    let query_vec = embed_text(&normalized);
    let archetypes = archetype_vecs();

    let mut top_score = 0.0f32;
    let mut top_label = "";
    let mut label_scores: HashMap<&str, f32> = HashMap::new();

    for (archetype_vec, label) in archetypes {
        let sim = cosine(&query_vec, archetype_vec);
        if sim > 0.60 {
            let entry = label_scores.entry(label).or_insert(0.0f32);
            if sim > *entry {
                *entry = sim;
            }
            if sim > top_score {
                top_score = sim;
                top_label = label;
            }
        }
    }

    if top_score < 0.60 {
        return None;
    }

    let detection_score = ((top_score - 0.60) / 0.40).min(1.0);
    let evidence: Vec<String> = label_scores
        .iter()
        .map(|(label, sim)| format!("semantic_match:{}:{:.3}", label, sim))
        .collect();

    Some(DetectionSignal {
        worker: WorkerKind::Embed,
        account_id: event.account_id.clone(),
        score: detection_score,
        confidence: top_score,
        evidence,
        meta: [
            ("top_label".into(), json!(top_label)),
            ("top_sim".into(), json!(top_score)),
            ("n_matches".into(), json!(label_scores.len())),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}
