// glasswally/src/workers/biometric.rs
//
// Behavioral biometrics — prompt sequence entropy.
//
// A human exploring an API has HIGH sequence entropy:
//   - Asks about different topics, changes direction, adds context
//   - Highly varied prompt lengths and token counts
//   - Long pauses between unrelated requests
//
// A systematic capability sweep has LOW sequence entropy:
//   - Same structural template with different domain-specific fillers
//   - Near-uniform prompt lengths (template + variable slot)
//   - Regular inter-request timing, high RPH
//   - Prompt first-word is always the same imperative verb ("Explain", "Implement")
//
// We model this with three signals:
//   1. Shannon entropy over structural prompt hashes
//   2. Coefficient of variation of prompt lengths
//   3. Template prefix repetition ratio (same first 30 chars)
//
// This is hard to evade without either:
//   a) Wasting ~50% of queries on noise → halves extraction efficiency
//   b) Adding an LLM to generate diverse wrappers → doubles per-query cost

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::{StateStore, W_1HR};

/// Structural fingerprint of a prompt.
/// Captures: length bucket (per 100 chars) + first word category + dominant verb.
fn structural_hash(prompt: &str) -> u64 {
    let len_bucket = prompt.len() / 100;
    // Lowercase once (this used to be recomputed up to 30× per prompt).
    let lower = prompt.to_lowercase();
    let first_word = prompt
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();

    let dominant_verb = [
        "implement",
        "explain",
        "analyze",
        "generate",
        "translate",
        "summarize",
        "compare",
        "evaluate",
        "describe",
        "list",
        "write",
        "create",
        "provide",
        "show",
        "tell",
    ]
    .iter()
    .find(|&&v| lower.contains(v))
    .copied()
    .unwrap_or("other");

    let mut h = Sha256::new();
    h.update(len_bucket.to_le_bytes());
    h.update(first_word.as_bytes());
    h.update(b"|");
    h.update(dominant_verb.as_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap_or([0u8; 8]))
}

/// Shannon entropy of a frequency distribution (bits).
fn shannon_entropy(counts: &HashMap<u64, usize>) -> f64 {
    let total: f64 = counts.values().sum::<usize>() as f64;
    if total == 0.0 {
        return 0.0;
    }
    counts
        .values()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let window = store.get_window(&event.account_id)?;
    let window = window.read();
    let prompts = window.prompts_in(W_1HR);
    let n = prompts.len();

    if n < 10 {
        return None;
    } // need sufficient history for reliable signal

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // ── Structural entropy ────────────────────────────────────────────────────
    let mut struct_counts: HashMap<u64, usize> = HashMap::new();
    for p in &prompts {
        *struct_counts.entry(structural_hash(p)).or_insert(0) += 1;
    }
    let entropy = shannon_entropy(&struct_counts);
    let max_entropy = (n as f64).log2();
    let norm_entropy = if max_entropy > 0.0 {
        (entropy / max_entropy) as f32
    } else {
        0.0
    };

    if norm_entropy < 0.20 {
        score += 0.45;
        evidence.push(format!("very_low_seq_entropy:{:.3}", norm_entropy));
    } else if norm_entropy < 0.40 {
        score += 0.20;
        evidence.push(format!("low_seq_entropy:{:.3}", norm_entropy));
    }

    // ── Prompt length uniformity ──────────────────────────────────────────────
    let lengths: Vec<f64> = prompts.iter().map(|p| p.len() as f64).collect();
    let mean = lengths.iter().sum::<f64>() / lengths.len() as f64;
    let std =
        (lengths.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / lengths.len() as f64).sqrt();
    let cv = if mean > 0.0 { std / mean } else { 1.0 };

    if cv < 0.10 {
        score += 0.25;
        evidence.push(format!("uniform_length:cv={:.3}", cv));
    } else if cv < 0.20 {
        score += 0.10;
        evidence.push(format!("semi_uniform_length:cv={:.3}", cv));
    }

    // ── Template prefix repetition ────────────────────────────────────────────
    let mut prefix_counts: HashMap<String, usize> = HashMap::new();
    for p in &prompts {
        let prefix: String = p.chars().take(30).collect::<String>().to_lowercase();
        *prefix_counts.entry(prefix).or_insert(0) += 1;
    }
    let max_prefix = prefix_counts.values().max().copied().unwrap_or(0);
    let prefix_ratio = max_prefix as f32 / n as f32;

    if prefix_ratio > 0.60 {
        score += 0.30;
        evidence.push(format!(
            "template_sweep:{:.0}%_same_prefix",
            prefix_ratio * 100.0
        ));
    } else if prefix_ratio > 0.40 {
        score += 0.15;
        evidence.push(format!(
            "partial_template:{:.0}%_similar_prefix",
            prefix_ratio * 100.0
        ));
    }

    if score == 0.0 {
        return None;
    }

    let confidence = (n as f32 / 50.0).min(1.0);
    score = (score * (0.3 + 0.7 * confidence)).min(1.0);

    Some(DetectionSignal {
        worker: WorkerKind::Biometric,
        account_id: event.account_id.clone(),
        score,
        confidence,
        evidence,
        meta: [
            ("n_prompts".into(), json!(n)),
            ("norm_entropy".into(), json!(norm_entropy)),
            ("length_cv".into(), json!(cv)),
            ("n_struct_types".into(), json!(struct_counts.len())),
            ("prefix_ratio".into(), json!(prefix_ratio)),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}
