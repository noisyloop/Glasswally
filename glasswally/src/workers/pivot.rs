// glasswally/src/workers/pivot.rs
//
// Model pivot worker — detects the MiniMax coordinated model version switch.
// A single account switching models is organic. 20+ accounts in the same
// cluster all switching to the same new model within 6 hours is not.

use chrono::{Duration, Utc};
use serde_json::json;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const PIVOT_WINDOW_HOURS: i64 = 6;
const MIN_PIVOT_ACCOUNTS: usize = 5;

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let switches = store.model_switches(&event.account_id);

    if switches.is_empty() {
        return None; // no pivot — skip signal entirely
    }

    let (ts, old_model, new_model) = switches.last().unwrap();
    let age = Utc::now() - *ts;

    if age > Duration::hours(24) {
        return None; // stale
    }

    let mut score = 0.20f32; // single-account pivot = mild
    let mut evidence = vec![format!(
        "model_pivot:{}→{}",
        tail_chars(old_model, 10),
        tail_chars(new_model, 10)
    )];

    // Check for cluster-wide coordinated pivot
    if let Some(cluster_id) = store.get_cluster(&event.account_id) {
        let members = store.cluster_members(cluster_id);
        let pivot_window = Duration::hours(PIVOT_WINDOW_HOURS);
        let mut coordinated = 0usize;

        for member_id in &members {
            let member_switches = store.model_switches(member_id);
            let pivoted_same = member_switches.iter().any(|(switch_ts, _, switch_new)| {
                switch_new == new_model && (*switch_ts - *ts).abs() < pivot_window
            });
            if pivoted_same {
                coordinated += 1;
            }
        }

        if coordinated >= MIN_PIVOT_ACCOUNTS {
            score = (0.20 + (coordinated as f32 / 30.0) * 0.80).min(1.0);
            evidence.push(format!(
                "coordinated_pivot:cluster_{}:{}_accounts",
                cluster_id, coordinated
            ));
        }
    }

    Some(DetectionSignal {
        worker: WorkerKind::Pivot,
        account_id: event.account_id.clone(),
        score,
        confidence: 0.85,
        evidence,
        meta: [
            ("old_model".into(), json!(old_model)),
            ("new_model".into(), json!(new_model)),
            ("n_switches".into(), json!(switches.len())),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}

/// Last `n` characters of `s`. Model names are client-controlled, so byte
/// slicing could split a multi-byte char and panic the worker.
fn tail_chars(s: &str, n: usize) -> &str {
    let start = s
        .char_indices()
        .rev()
        .nth(n.saturating_sub(1))
        .map_or(0, |(i, _)| i);
    &s[start..]
}
