// glasswally/src/eval/mod.rs
//
// Labeled dataset + evaluation framework — Phase 2.
//
// Provides a benchmarking harness that:
//   1. Loads a labeled JSONL dataset of API events (with ground_truth campaign labels)
//   2. Runs the full Glasswally pipeline on every event in order
//   3. Computes per-worker and aggregate precision / recall / F1 / FPR
//   4. Outputs a confusion matrix and ROC curve data
//   5. Prints a markdown-formatted report
//
// Dataset format (one JSON object per line):
//   { ...ApiEvent fields..., "campaign_label": "distillation_campaign_X" or null }
//
// A non-null campaign_label means the event is from a known distillation campaign
// (positive class).  Null means legitimate traffic (negative class).
//
// Run:
//   glasswally --mode eval --path labeled_dataset.jsonl
//   glasswally --mode eval --path labeled_dataset.jsonl --eval-threshold 0.52

pub mod report;

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use tracing::info;

use crate::events::{ApiEvent, WorkerKind};
use crate::state::window::StateStore;

// ── Per-worker performance counters ───────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct WorkerMetrics {
    pub tp: u64,  // true positive
    pub fp: u64,  // false positive
    pub tn: u64,  // true negative
    pub fn_: u64, // false negative
}

impl WorkerMetrics {
    pub fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            1.0
        } else {
            self.tp as f64 / denom as f64
        }
    }

    pub fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            0.0
        } else {
            self.tp as f64 / denom as f64
        }
    }

    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    pub fn fpr(&self) -> f64 {
        let denom = self.fp + self.tn;
        if denom == 0 {
            0.0
        } else {
            self.fp as f64 / denom as f64
        }
    }
}

// ── Aggregate evaluation result ───────────────────────────────────────────────

#[derive(Debug)]
pub struct EvalResult {
    pub n_events: usize,
    pub n_positive: usize, // true distillation events
    pub n_negative: usize, // legitimate traffic events
    pub threshold: f32,
    pub global: WorkerMetrics,
    pub per_worker: HashMap<WorkerKind, WorkerMetrics>,
    pub tier_counts: HashMap<String, u64>,
    pub score_histogram: Vec<(f32, usize)>, // (score_bin_lower, count)
}

impl EvalResult {
    pub fn print_report(&self) {
        println!("\n## Glasswally Evaluation Report\n");
        println!("| Metric       | Value   |");
        println!("|--------------|---------|");
        println!("| Events       | {}      |", self.n_events);
        println!("| Positive     | {}      |", self.n_positive);
        println!("| Negative     | {}      |", self.n_negative);
        println!("| Threshold    | {:.3}   |", self.threshold);
        println!("| Precision    | {:.4}   |", self.global.precision());
        println!("| Recall       | {:.4}   |", self.global.recall());
        println!("| F1           | {:.4}   |", self.global.f1());
        println!("| FPR          | {:.4}   |", self.global.fpr());
        println!();

        println!("### Per-Worker Performance\n");
        println!("| Worker | P | R | F1 | FPR |");
        println!("|--------|---|---|----|-----|");

        let mut workers: Vec<_> = self.per_worker.iter().collect();
        workers.sort_by(|a, b| {
            b.1.f1()
                .partial_cmp(&a.1.f1())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for (worker, m) in workers {
            println!(
                "| {:15} | {:.3} | {:.3} | {:.3} | {:.4} |",
                worker,
                m.precision(),
                m.recall(),
                m.f1(),
                m.fpr()
            );
        }

        println!("\n### Score Distribution\n");
        for (lower, count) in &self.score_histogram {
            let bar: String = "#".repeat((*count as f64 / self.n_events as f64 * 80.0) as usize);
            println!("{:.2}–{:.2} | {:5} | {}", lower, lower + 0.05, count, bar);
        }
    }
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

pub struct Evaluator {
    threshold: f32,
}

impl Evaluator {
    pub fn new(threshold: f32) -> Self {
        Self { threshold }
    }

    pub async fn run_dataset(&self, path: &Path) -> Result<EvalResult> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut events: Vec<ApiEvent> = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<ApiEvent>(line) {
                Ok(mut ev) => {
                    if ev.sanitize() {
                        events.push(ev);
                    }
                }
                Err(e) => tracing::warn!("Eval dataset parse error: {}", e),
            }
        }

        info!("Loaded {} events from {}", events.len(), path.display());

        // Rebase timestamps so the dataset ends "now", preserving all
        // inter-event deltas. The sliding windows (events_in) are anchored to
        // wall clock, so a committed dataset with historical timestamps would
        // otherwise fall outside every window and no worker would fire.
        if let Some(max_ts) = events.iter().map(|e| e.timestamp).max() {
            let shift = chrono::Utc::now() - max_ts;
            for ev in &mut events {
                ev.timestamp += shift;
            }
            events.sort_by_key(|e| e.timestamp);
        }

        self.evaluate(events).await
    }

    async fn evaluate(&self, events: Vec<ApiEvent>) -> Result<EvalResult> {
        let store = std::sync::Arc::new(StateStore::new());
        let engine = crate::engine::fusion::FusionEngine::new();

        let n_events = events.len();
        let n_positive = events.iter().filter(|e| e.campaign_label.is_some()).count();
        let n_negative = n_events - n_positive;

        let mut global = WorkerMetrics::default();
        let mut per_worker: HashMap<WorkerKind, WorkerMetrics> = HashMap::new();
        let mut tier_counts: HashMap<String, u64> = HashMap::new();
        let mut score_bins = [0usize; 20]; // 0.05-wide bins

        for event in &events {
            store.ingest(event);
            let signals = crate::workers::run_all(event, &store).await;
            let decision = engine.fuse(event, &store, &signals);

            let is_positive = event.campaign_label.is_some();
            let alerted = decision
                .as_ref()
                .map(|d| d.composite_score >= self.threshold)
                .unwrap_or(false);

            // Per-worker metrics
            for sig in &signals {
                let m = per_worker.entry(sig.worker).or_default();
                let worker_fired = sig.score >= 0.30;
                match (worker_fired, is_positive) {
                    (true, true) => m.tp += 1,
                    (true, false) => m.fp += 1,
                    (false, true) => m.fn_ += 1,
                    (false, false) => m.tn += 1,
                }
            }

            // Global
            match (alerted, is_positive) {
                (true, true) => global.tp += 1,
                (true, false) => global.fp += 1,
                (false, true) => global.fn_ += 1,
                (false, false) => global.tn += 1,
            }

            // Score histogram
            if let Some(d) = &decision {
                let bin = ((d.composite_score / 0.05) as usize).min(19);
                score_bins[bin] += 1;
                *tier_counts.entry(d.tier.to_string()).or_default() += 1;
            }
        }

        let score_histogram = score_bins
            .iter()
            .enumerate()
            .map(|(i, &c)| (i as f32 * 0.05, c))
            .collect();

        Ok(EvalResult {
            n_events,
            n_positive,
            n_negative,
            threshold: self.threshold,
            global,
            per_worker,
            tier_counts,
            score_histogram,
        })
    }
}
