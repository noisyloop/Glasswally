// glasswally/src/workers/cot.rs
//
// Chain-of-thought elicitation detector.
// Aho-Corasick automaton: O(n) per prompt regardless of pattern count.
// All 33 patterns from the Anthropic report + domain capability heatmap.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use chrono::Utc;
use serde_json::json;
use std::sync::OnceLock;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::{StateStore, W_1HR};

static COT_AC: OnceLock<(AhoCorasick, Vec<&'static str>)> = OnceLock::new();
static DOMAIN_AC: OnceLock<(AhoCorasick, Vec<&'static str>)> = OnceLock::new();

// Pattern → label pairs
const COT_PATTERNS: &[(&str, &str)] = &[
    ("chain of thought", "chain_of_thought"),
    ("chain-of-thought", "chain_of_thought"),
    ("step by step", "step_by_step"),
    ("step-by-step", "step_by_step"),
    ("articulate the internal reasoning", "articulate_reasoning"),
    ("articulate your reasoning", "articulate_reasoning"),
    ("walk through your reasoning", "walk_through_reasoning"),
    ("walk through the reasoning", "walk_through_reasoning"),
    ("trace your reasoning", "trace_reasoning"),
    ("trace the reasoning", "trace_reasoning"),
    ("show every step", "show_steps"),
    ("show each step", "show_steps"),
    ("write out each step", "write_steps"),
    ("write out every step", "write_steps"),
    ("explain your reasoning process", "explain_reasoning"),
    ("explain your reasoning chain", "explain_reasoning"),
    ("reward model", "reward_model"),
    ("rubric-based grading", "rubric_grading"),
    ("rubric-based scoring", "rubric_grading"),
    ("act as a judge", "act_as_judge"),
    ("act as a grader", "act_as_judge"),
    ("act as an evaluator", "act_as_judge"),
    ("internal reasoning behind", "internal_reasoning"),
    ("labeled tuple", "labeled_tuple"),
    ("censorship-safe", "censorship_evasion"),
    ("censorship safe alternative", "censorship_evasion"),
    ("preserve the informational intent", "censorship_evasion"),
    ("politically sensitive", "censorship_evasion"),
    ("reinforcement learning", "rl_reference"),
    ("respond only in json", "json_extraction"),
    ("respond only with json", "json_extraction"),
    (
        "complete and transparent reasoning",
        "transparent_reasoning",
    ),
    ("statistical rigor with deep domain", "data_analyst_pattern"), // exact DeepSeek phrase
];

const DOMAIN_PATTERNS: &[(&str, &str)] = &[
    ("chain of thought", "reasoning_cot"),
    ("step by step", "reasoning_cot"),
    ("tool_call", "agentic"),
    ("tool use", "agentic"),
    ("multi-step plan", "agentic"),
    ("agent loop", "agentic"),
    ("implement", "coding"),
    ("production-grade", "coding"),
    ("unit test", "coding"),
    ("computer-use", "computer_vision"),
    ("screenshot", "computer_vision"),
    ("vision agent", "computer_vision"),
    ("reward model", "reward_model_rl"),
    ("rubric", "reward_model_rl"),
    ("reinforcement", "reward_model_rl"),
    ("censorship-safe", "censorship_evasion"),
    ("politically", "censorship_evasion"),
    ("data analyst", "data_analysis"),
    ("statistical rigor", "data_analysis"),
];

fn cot_automaton() -> &'static (AhoCorasick, Vec<&'static str>) {
    COT_AC.get_or_init(|| {
        let patterns: Vec<&str> = COT_PATTERNS.iter().map(|(p, _)| *p).collect();
        let labels: Vec<&str> = COT_PATTERNS.iter().map(|(_, l)| *l).collect();
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .expect("CoT AC build failed");
        (ac, labels)
    })
}

fn domain_automaton() -> &'static (AhoCorasick, Vec<&'static str>) {
    DOMAIN_AC.get_or_init(|| {
        let patterns: Vec<&str> = DOMAIN_PATTERNS.iter().map(|(p, _)| *p).collect();
        let labels: Vec<&str> = DOMAIN_PATTERNS.iter().map(|(_, l)| *l).collect();
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .expect("Domain AC build failed");
        (ac, labels)
    })
}

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let (cot_ac, cot_labels) = cot_automaton();
    let (domain_ac, domain_labels) = domain_automaton();

    // Scan current prompt — O(prompt_len). Match on the canonical form so
    // spacing / invisible-character tricks don't hide a pattern.
    let prompt = super::normalize_prompt(&event.prompt);
    let cot_hits: Vec<&str> = cot_ac
        .find_iter(&prompt)
        .map(|m| cot_labels[m.pattern().as_usize()])
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let domain_hits: Vec<&str> = domain_ac
        .find_iter(&prompt)
        .map(|m| domain_labels[m.pattern().as_usize()])
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    if !cot_hits.is_empty() {
        score += 0.40;
        evidence.extend(cot_hits.iter().take(3).map(|s| s.to_string()));
    }

    // Window-level CoT ratio
    if let Some(window) = store.get_window(&event.account_id) {
        let window = window.read();
        let prompts: Vec<String> = window
            .prompts_in(W_1HR)
            .iter()
            .map(|p| super::normalize_prompt(p))
            .collect();
        let n = prompts.len();

        if n >= 5 {
            let cot_count = prompts
                .iter()
                .filter(|p| cot_ac.is_match(p.as_str()))
                .count();
            let cot_ratio = cot_count as f32 / n as f32;

            if cot_ratio >= 0.20 {
                score += 0.35;
                evidence.push(format!("cot_ratio:{:.0}%", cot_ratio * 100.0));
            }

            // Capability domain concentration
            let mut domain_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for p in &prompts {
                for m in domain_ac.find_iter(p.as_str()) {
                    *domain_counts
                        .entry(domain_labels[m.pattern().as_usize()])
                        .or_insert(0) += 1;
                }
            }
            if let Some((&top, &count)) = domain_counts.iter().max_by_key(|(_, v)| *v) {
                let ratio = count as f32 / n as f32;
                if ratio >= 0.70 {
                    score += 0.25;
                    evidence.push(format!(
                        "capability_concentration:{}={:.0}%",
                        top,
                        ratio * 100.0
                    ));
                }
            }
        }
    }

    Some(DetectionSignal {
        worker: WorkerKind::Cot,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence: 0.9,
        evidence,
        meta: [
            ("cot_hits".into(), json!(cot_hits.len())),
            ("domain_hits".into(), json!(domain_hits)),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::test_event;

    #[tokio::test]
    async fn obfuscated_cot_phrases_still_match() {
        let store = StateStore::new();
        for prompt in [
            "Think  step\nby   step about this",
            "show your chain\u{200b} of thought",
            "ｃｈａｉｎ ｏｆ ｔｈｏｕｇｈｔ please",
        ] {
            let ev = test_event("a", prompt);
            let sig = analyze(&ev, &store).await.unwrap();
            assert!(sig.score >= 0.40, "missed: {prompt:?}");
        }
    }
}
