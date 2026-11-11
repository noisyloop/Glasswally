// glasswally/src/workers/refusal_probe.rs
//
// Refusal probe detection — Phase 1 signal.
//
// Some distillation campaigns specifically probe the model's refusal behaviour
// in order to:
//   A. Train the student model to match safety refusals (RLHF-style alignment cloning)
//   B. Map refusal boundaries to identify jailbreak surfaces for later exploitation
//   C. Collect "I cannot help with that" style responses as negative training examples
//
// The tell is a high density of prompts that are specifically crafted to elicit
// refusals — prompts about illegal activity, weapons, self-harm, explicit content,
// CBRN topics — systematically varied to probe the exact refusal boundary.
//
// Signals:
//   refusal_density       — fraction of recent prompts containing refusal-probe keywords
//   boundary_sweep        — prompts vary a single topic across a clear severity gradient
//   cross_category_probe  — systematic coverage across multiple refusal categories
//
// Note: This worker looks at prompt *patterns*, not at model responses.
// A very high refusal_density could also indicate a researcher testing model safety —
// confidence is deliberately modulated lower than other workers unless cross-category
// sweep evidence is also present.

use std::collections::{HashMap, HashSet};

use chrono::Utc;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

// ── Refusal topic categories and their probe keywords ────────────────────────

const REFUSAL_CATEGORIES: &[(&str, &[&str])] = &[
    (
        "violence",
        &[
            "how to kill",
            "how to hurt",
            "how to attack",
            "how to assault",
            "how to stab",
            "how to shoot",
            "instructions for violence",
            "how to make a weapon",
            "how to build a weapon",
        ],
    ),
    (
        "illegal_drugs",
        &[
            "how to synthesize",
            "how to make meth",
            "how to make fentanyl",
            "drug synthesis",
            "precursor chemicals",
            "how to extract",
            "cook meth",
            "manufacture cocaine",
            "how to make mdma",
        ],
    ),
    (
        "cbrn",
        &[
            "biological weapon",
            "chemical weapon",
            "nerve agent",
            "sarin",
            "ricin synthesis",
            "anthrax",
            "radiological",
            "dirty bomb",
            "nuclear weapon design",
            "bioweapon",
        ],
    ),
    (
        "cybercrime",
        &[
            "write malware",
            "create a virus",
            "ransomware code",
            "exploit code",
            "sql injection payload",
            "phishing template",
            "how to hack into",
            "password cracking",
            "keylogger code",
        ],
    ),
    (
        "self_harm",
        &[
            "how to commit suicide",
            "methods of self-harm",
            "overdose on",
            "painless way to die",
            "how to end my life",
        ],
    ),
    (
        "explicit",
        &[
            "explicit sexual",
            "graphic sexual",
            "pornographic",
            "sexual content involving",
            "erotic story",
        ],
    ),
    (
        "fraud",
        &[
            "credit card fraud",
            "how to scam",
            "fake id",
            "identity theft",
            "social security fraud",
            "insurance fraud",
            "how to counterfeit",
        ],
    ),
    (
        "privacy_attack",
        &[
            "find someone's address",
            "track someone without",
            "stalk",
            "doxx",
            "leak personal information",
            "find private information",
        ],
    ),
];

const MIN_REQUESTS: usize = 5;
const REFUSAL_DENSITY_THRESHOLD: f32 = 0.25;

fn categorize_prompt(prompt: &str) -> HashSet<&'static str> {
    let lower = super::normalize_prompt(prompt);
    let mut hits = HashSet::new();
    for (cat, keywords) in REFUSAL_CATEGORIES {
        if keywords.iter().any(|&kw| lower.contains(kw)) {
            hits.insert(*cat);
        }
    }
    hits
}

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let window = store.get_window(&event.account_id)?;

    // Bounded: re-scanning the full window on every event is quadratic.
    let prompts: Vec<String> = window.read().recent_prompts();

    if prompts.len() < MIN_REQUESTS {
        return None;
    }

    // ── 1. Refusal density ────────────────────────────────────────────────────
    let per_prompt_cats: Vec<HashSet<&'static str>> =
        prompts.iter().map(|p| categorize_prompt(p)).collect();

    let refusal_count = per_prompt_cats.iter().filter(|c| !c.is_empty()).count();
    let density = refusal_count as f32 / prompts.len() as f32;

    if density < REFUSAL_DENSITY_THRESHOLD {
        return None;
    }

    // ── 2. Category coverage (cross-category sweep) ───────────────────────────
    let all_cats: HashSet<&'static str> = per_prompt_cats
        .iter()
        .flat_map(|c| c.iter().copied())
        .collect();

    let n_categories = all_cats.len();

    // ── 3. Score composition ──────────────────────────────────────────────────
    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // Density contribution
    if density >= 0.60 {
        score += 0.45;
        evidence.push(format!("refusal_density:{:.0}%", density * 100.0));
    } else if density >= 0.40 {
        score += 0.30;
        evidence.push(format!("refusal_density:{:.0}%", density * 100.0));
    } else {
        score += 0.15;
        evidence.push(format!("refusal_density:{:.0}%", density * 100.0));
    }

    // Cross-category sweep (systematic boundary mapping across multiple categories)
    if n_categories >= 4 {
        score += 0.40;
        evidence.push(format!(
            "cross_category_sweep:{}_categories:{}",
            n_categories,
            all_cats.iter().cloned().collect::<Vec<_>>().join(",")
        ));
    } else if n_categories >= 2 {
        score += 0.20;
        evidence.push(format!("multi_category_probe:{}_categories", n_categories));
    }

    // Current request is also a probe
    let current_cats = categorize_prompt(&event.prompt);
    if !current_cats.is_empty() {
        evidence.push(format!(
            "current_request_probe:{}",
            current_cats.iter().cloned().next().unwrap_or("unknown")
        ));
    }

    if score < 0.20 {
        return None;
    }

    // Confidence is deliberately modest — researchers legitimately probe safety.
    // Compound signals (high density + multi-category + cluster) push confidence up.
    let confidence = if n_categories >= 4 && density >= 0.40 {
        0.75
    } else if n_categories >= 2 {
        0.55
    } else {
        0.40
    };

    let mut meta = HashMap::new();
    meta.insert(
        "refusal_density".to_string(),
        serde_json::json!((density * 100.0).round() as u32),
    );
    meta.insert(
        "n_categories".to_string(),
        serde_json::Value::Number(serde_json::Number::from(n_categories as u64)),
    );
    meta.insert(
        "categories".to_string(),
        serde_json::Value::Array(
            all_cats
                .iter()
                .map(|c| serde_json::Value::String(c.to_string()))
                .collect(),
        ),
    );

    Some(DetectionSignal {
        worker: WorkerKind::RefusalProbe,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence,
        evidence,
        meta,
        timestamp: Utc::now(),
    })
}
