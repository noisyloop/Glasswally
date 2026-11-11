// glasswally/src/workers/sequence_model.rs
//
// Behavioral sequence modeling via Markov chains — Phase 3 signal.
//
// Distillation campaigns systematically traverse the model's capability space.
// When we extract the *topic* of each prompt and model it as a Markov chain, we
// see two tell-tale patterns:
//
//   1. HIGH STATIONARY ENTROPY — the steady-state distribution is nearly uniform
//      across topics (all capability buckets queried equally).  Legitimate users
//      have a narrow topic distribution concentrated on their domain.
//
//   2. LOW TRANSITION ENTROPY — given the current topic, the next topic is highly
//      predictable (systematic drill-down sequences: "code → code → code → math →
//      math → ..." as the attacker works through a fixed topic list).
//
// Topic extraction:
//   Fast heuristic keyword tagger — 12 capability buckets (code, math, science,
//   medicine, law, finance, creative, reasoning, language, factual, safety, other).
//   No ML required; patterns cover the vast majority of extraction prompts.
//
// Minimum history required: 15 prompts.

use std::collections::HashMap;

use chrono::Utc;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const MIN_PROMPTS: usize = 15;

// ── Topic classifier ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Topic {
    Code,
    Math,
    Science,
    Medicine,
    Law,
    Finance,
    Creative,
    Reasoning,
    Language,
    Factual,
    Safety,
    Other,
}

impl Topic {
    fn index(self) -> usize {
        match self {
            Self::Code => 0,
            Self::Math => 1,
            Self::Science => 2,
            Self::Medicine => 3,
            Self::Law => 4,
            Self::Finance => 5,
            Self::Creative => 6,
            Self::Reasoning => 7,
            Self::Language => 8,
            Self::Factual => 9,
            Self::Safety => 10,
            Self::Other => 11,
        }
    }

    const N: usize = 12;
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Code => "code",
                Self::Math => "math",
                Self::Science => "science",
                Self::Medicine => "medicine",
                Self::Law => "law",
                Self::Finance => "finance",
                Self::Creative => "creative",
                Self::Reasoning => "reasoning",
                Self::Language => "language",
                Self::Factual => "factual",
                Self::Safety => "safety",
                Self::Other => "other",
            }
        )
    }
}

fn classify_topic(prompt: &str) -> Topic {
    let p = prompt.to_lowercase();
    // Simple priority-ordered keyword matching
    if p.contains("def ")
        || p.contains("function")
        || p.contains("class ")
        || p.contains("implement")
        || p.contains("algorithm")
        || p.contains("code")
        || p.contains("python")
        || p.contains("rust")
        || p.contains("javascript")
        || p.contains("sql")
        || p.contains("api")
    {
        return Topic::Code;
    }
    if p.contains("calculate")
        || p.contains("equation")
        || p.contains("integral")
        || p.contains("derivative")
        || p.contains("probability")
        || p.contains("matrix")
        || p.contains("statistics")
        || p.contains("theorem")
        || p.contains("proof")
        || p.contains("geometry")
        || p.contains("algebra")
    {
        return Topic::Math;
    }
    if p.contains("biology")
        || p.contains("chemistry")
        || p.contains("physics")
        || p.contains("quantum")
        || p.contains("thermodynamic")
        || p.contains("molecule")
        || p.contains("experiment")
        || p.contains("hypothesis")
    {
        return Topic::Science;
    }
    if p.contains("diagnosis")
        || p.contains("symptom")
        || p.contains("treatment")
        || p.contains("medication")
        || p.contains("disease")
        || p.contains("patient")
        || p.contains("clinical")
        || p.contains("pharmacol")
    {
        return Topic::Medicine;
    }
    if p.contains("legal")
        || p.contains("statute")
        || p.contains("contract")
        || p.contains("liability")
        || p.contains("jurisdiction")
        || p.contains("court")
        || p.contains("regulation")
        || p.contains("compliance")
    {
        return Topic::Law;
    }
    if p.contains("investment")
        || p.contains("stock")
        || p.contains("portfolio")
        || p.contains("financial")
        || p.contains("revenue")
        || p.contains("accounting")
        || p.contains("valuation")
        || p.contains("economics")
    {
        return Topic::Finance;
    }
    if p.contains("write a story")
        || p.contains("poem")
        || p.contains("creative")
        || p.contains("fiction")
        || p.contains("narrative")
        || p.contains("character")
        || p.contains("plot")
    {
        return Topic::Creative;
    }
    if p.contains("step by step")
        || p.contains("reasoning")
        || p.contains("deduce")
        || p.contains("infer")
        || p.contains("logic")
        || p.contains("argument")
        || p.contains("conclude")
    {
        return Topic::Reasoning;
    }
    if p.contains("translate")
        || p.contains("grammar")
        || p.contains("language")
        || p.contains("spanish")
        || p.contains("french")
        || p.contains("chinese")
        || p.contains("japanese")
        || p.contains("arabic")
    {
        return Topic::Language;
    }
    if p.contains("history")
        || p.contains("explain")
        || p.contains("what is")
        || p.contains("who was")
        || p.contains("when did")
        || p.contains("where")
        || p.contains("describe")
    {
        return Topic::Factual;
    }
    if p.contains("safe")
        || p.contains("harmful")
        || p.contains("ethical")
        || p.contains("dangerous")
        || p.contains("appropriate")
    {
        return Topic::Safety;
    }
    Topic::Other
}

// ── Markov chain ──────────────────────────────────────────────────────────────

struct MarkovChain {
    /// Transition counts: trans[from][to] = count
    trans: [[u32; Topic::N]; Topic::N],
    /// Marginal counts
    marginal: [u32; Topic::N],
}

impl MarkovChain {
    fn new() -> Self {
        Self {
            trans: [[0; Topic::N]; Topic::N],
            marginal: [0; Topic::N],
        }
    }

    fn feed(&mut self, topics: &[Topic]) {
        for &t in topics {
            self.marginal[t.index()] += 1;
        }
        for w in topics.windows(2) {
            self.trans[w[0].index()][w[1].index()] += 1;
        }
    }

    /// Shannon entropy of marginal distribution (normalised by log2(N)).
    fn stationary_entropy(&self) -> f64 {
        let total: u32 = self.marginal.iter().sum();
        if total == 0 {
            return 0.0;
        }
        let mut h = 0.0f64;
        for &c in &self.marginal {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total as f64;
            h -= p * p.log2();
        }
        h / (Topic::N as f64).log2() // normalise to [0,1]
    }

    /// Mean transition entropy (how predictable is the next topic given current).
    fn mean_transition_entropy(&self) -> f64 {
        let mut total_h = 0.0f64;
        let mut valid_rows = 0;
        for row in &self.trans {
            let row_sum: u32 = row.iter().sum();
            if row_sum < 2 {
                continue;
            }
            let mut h = 0.0f64;
            for &c in row {
                if c == 0 {
                    continue;
                }
                let p = c as f64 / row_sum as f64;
                h -= p * p.log2();
            }
            total_h += h / (Topic::N as f64).log2();
            valid_rows += 1;
        }
        if valid_rows == 0 {
            return 0.5;
        }
        total_h / valid_rows as f64
    }

    /// Number of distinct topics seen.
    fn n_topics(&self) -> usize {
        self.marginal.iter().filter(|&&c| c > 0).count()
    }
}

// ── Main analysis ─────────────────────────────────────────────────────────────

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let window = store.get_window(&event.account_id)?;
    // Bounded: re-scanning the full window on every event is quadratic.
    let prompts: Vec<String> = window.read().recent_prompts();

    if prompts.len() < MIN_PROMPTS {
        return None;
    }

    let topics: Vec<Topic> = prompts.iter().map(|p| classify_topic(p)).collect();

    let mut chain = MarkovChain::new();
    chain.feed(&topics);

    let stat_h = chain.stationary_entropy(); // high = broad coverage
    let trans_h = chain.mean_transition_entropy(); // low = predictable drill-down
    let n_topics = chain.n_topics();

    // Distillation: high stationary entropy AND low transition entropy
    // Human:        low stationary entropy (narrow domain) OR high transition entropy (random browsing)
    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // Broad capability coverage
    if stat_h >= 0.80 {
        score += 0.40;
        evidence.push(format!(
            "broad_topic_coverage:entropy={:.2}_topics={}",
            stat_h, n_topics
        ));
    } else if stat_h >= 0.65 {
        score += 0.22;
        evidence.push(format!("moderate_topic_coverage:entropy={:.2}", stat_h));
    }

    // Predictable topic transitions (systematic drill-down)
    if trans_h <= 0.25 {
        score += 0.40;
        evidence.push(format!(
            "systematic_topic_drill_down:trans_entropy={:.2}",
            trans_h
        ));
    } else if trans_h <= 0.40 {
        score += 0.20;
        evidence.push(format!(
            "semi_predictable_transitions:trans_entropy={:.2}",
            trans_h
        ));
    }

    // Compound: all 12 topics sampled
    if n_topics >= 10 {
        score += 0.20;
        evidence.push(format!("full_capability_sweep:{}_of_12_topics", n_topics));
    }

    if score < 0.25 {
        return None;
    }

    let confidence = if stat_h >= 0.80 && trans_h <= 0.25 {
        0.80
    } else if score >= 0.40 {
        0.65
    } else {
        0.50
    };

    let mut meta = HashMap::new();
    meta.insert(
        "stationary_entropy".to_string(),
        serde_json::json!((stat_h * 1000.0).round() / 1000.0),
    );
    meta.insert(
        "transition_entropy".to_string(),
        serde_json::json!((trans_h * 1000.0).round() / 1000.0),
    );
    meta.insert(
        "n_topics".to_string(),
        serde_json::Value::Number(serde_json::Number::from(n_topics as u64)),
    );
    meta.insert(
        "n_prompts".to_string(),
        serde_json::Value::Number(serde_json::Number::from(prompts.len() as u64)),
    );

    Some(DetectionSignal {
        worker: WorkerKind::SequenceModel,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence,
        evidence,
        meta,
        timestamp: Utc::now(),
    })
}
