// glasswally/src/engine/fusion.rs
//
// Weighted signal fusion with geo uplift + cluster floor raise.
//
// Weight distribution across 16 workers (sum = 1.00):
//   Fingerprint   0.14  — JA3 + JA3S + header entropy (highest precision)
//   Velocity      0.10  — RPH / timing (complemented by TimingCluster)
//   Cot           0.09  — Aho-Corasick patterns (complemented by Embed)
//   Embed         0.08  — semantic similarity (catches CoT paraphrases)
//   Hydra         0.08  — cluster graph scoring
//   TimingCluster 0.07  — cross-account synchronized bursts
//   H2Grpc        0.06  — HTTP/2 SETTINGS + gRPC fingerprinting
//   Pivot         0.05  — coordinated model switch
//   Biometric     0.05  — prompt sequence entropy
//   Watermark     0.04  — watermark probe / ZW character detection
//   AsnClassifier 0.07  — datacenter/hosting provider IP classification (Phase 1)
//   RolePreamble  0.06  — role injection preamble fingerprinting (Phase 1)
//   SessionGap    0.04  — inter-session timing regularity / cron detection (Phase 1)
//   TokenBudget   0.03  — max_tokens sweep / greedy budget probing (Phase 1)
//   RefusalProbe  0.02  — safety refusal probe pattern detection (Phase 1)
//   SequenceModel 0.02  — Markov chain over prompt topic transitions (Phase 3)
//
// Weights sum: 0.14+0.10+0.09+0.08+0.08+0.07+0.06+0.05+0.05+0.04+0.07+0.06+0.04+0.03+0.02+0.02 = 1.00

use chrono::Utc;
use dashmap::DashMap;
use std::collections::HashMap;

use crate::events::{ActionKind, ApiEvent, DetectionSignal, RiskDecision, RiskTier, WorkerKind};
use crate::state::window::StateStore;

// Signal weights — must sum to 1.0
const WEIGHTS: &[(WorkerKind, f32)] = &[
    (WorkerKind::Fingerprint, 0.14),
    (WorkerKind::Velocity, 0.10),
    (WorkerKind::Cot, 0.09),
    (WorkerKind::Embed, 0.08),
    (WorkerKind::Hydra, 0.08),
    (WorkerKind::TimingCluster, 0.07),
    (WorkerKind::H2Grpc, 0.06),
    (WorkerKind::Pivot, 0.05),
    (WorkerKind::Biometric, 0.05),
    (WorkerKind::Watermark, 0.04),
    (WorkerKind::AsnClassifier, 0.07),
    (WorkerKind::RolePreamble, 0.06),
    (WorkerKind::SessionGap, 0.04),
    (WorkerKind::TokenBudget, 0.03),
    (WorkerKind::RefusalProbe, 0.02),
    (WorkerKind::SequenceModel, 0.02),
];

const CRITICAL: f32 = 0.72;
const HIGH: f32 = 0.55;
const MEDIUM: f32 = 0.35;
const COOLDOWN: i64 = 600; // seconds before re-alerting same account

pub struct FusionEngine {
    /// account → (time, tier) of the most recent alert.
    last_alert: DashMap<String, (chrono::DateTime<Utc>, RiskTier)>,
    suspended: DashMap<String, bool>,
}

impl FusionEngine {
    pub fn new() -> Self {
        Self {
            last_alert: DashMap::new(),
            suspended: DashMap::new(),
        }
    }

    pub fn fuse(
        &self,
        event: &ApiEvent,
        store: &StateStore,
        signals: &[DetectionSignal],
    ) -> Option<RiskDecision> {
        if signals.is_empty() {
            return None;
        }

        let sig_map: HashMap<WorkerKind, &DetectionSignal> =
            signals.iter().map(|s| (s.worker, s)).collect();

        let mut composite = 0.0f32;
        let mut sig_scores: HashMap<String, f32> = HashMap::new();

        for (worker, weight) in WEIGHTS {
            if let Some(s) = sig_map.get(worker) {
                let effective = s.score * (0.4 + 0.6 * s.confidence);
                composite += effective * weight;
                sig_scores.insert(worker.to_string(), s.score);
            }
        }

        // Geo uplift — CN access raises composite 30%
        if event.country_code == "CN" {
            composite = (composite * 1.30).min(1.0);
        }

        // Cluster floor — being in a large cluster adds 8 points
        if let Some(cid) = store.get_cluster(&event.account_id) {
            if store.cluster_members(cid).len() >= 5 {
                composite = (composite + 0.08).min(1.0);
            }
        }

        composite = (composite * 10000.0).round() / 10000.0;
        if composite < MEDIUM {
            return None;
        }

        let (tier, action) = if composite >= CRITICAL {
            (RiskTier::Critical, ActionKind::SuspendAccount)
        } else if composite >= HIGH {
            // High tier: inject canary + flag for review
            (RiskTier::High, ActionKind::InjectCanary)
        } else {
            (RiskTier::Medium, ActionKind::RateLimit)
        };

        let top_evidence: Vec<String> = signals
            .iter()
            .flat_map(|s| s.evidence.iter().cloned())
            .filter(|e| {
                ![
                    "cached",
                    "no_cluster",
                    "insufficient_data",
                    "small_cluster",
                    "account_watermarked",
                ]
                .contains(&e.as_str())
            })
            .take(10)
            .collect();

        let window = store.get_window(&event.account_id);
        let n_reqs = window.as_ref().map(|w| w.read().events.len()).unwrap_or(0);
        let countries = window
            .map(|w| w.read().country_codes.iter().cloned().collect())
            .unwrap_or_default();

        Some(RiskDecision {
            account_id: event.account_id.clone(),
            composite_score: composite,
            tier,
            signal_scores: sig_scores,
            top_evidence,
            country_codes: countries,
            cluster_id: store.get_cluster(&event.account_id),
            n_requests_seen: n_reqs,
            action,
            timestamp: Utc::now(),
            ground_truth: event.campaign_label.clone(),
        })
    }

    pub fn should_alert(&self, account_id: &str) -> bool {
        if self.is_suspended(account_id) {
            return false;
        }
        self.last_alert
            .get(account_id)
            .map(|t| (Utc::now() - t.0).num_seconds() >= COOLDOWN)
            .unwrap_or(true)
    }

    /// Atomically decide whether to alert on `account_id` at `tier`, and if
    /// so record the alert. Returns true when the caller should dispatch.
    ///
    /// Two properties the separate `should_alert` / `record_alert` pair did
    /// not have:
    ///   - check-and-set is one operation, so concurrent events for the same
    ///     account cannot both pass the cooldown and double-dispatch;
    ///   - the cooldown only suppresses alerts at the same or a lower tier.
    ///     Previously any alert started a 10-minute window in which nothing
    ///     else fired, so tripping a cheap MEDIUM (rate-limit) alert bought
    ///     an account ten minutes of immunity from suspension.
    pub fn try_claim_alert(&self, account_id: &str, tier: RiskTier) -> bool {
        use dashmap::mapref::entry::Entry;
        if self.is_suspended(account_id) {
            return false;
        }
        let now = Utc::now();
        match self.last_alert.entry(account_id.to_string()) {
            Entry::Vacant(v) => {
                v.insert((now, tier));
                true
            }
            Entry::Occupied(mut o) => {
                let (at, last_tier) = *o.get();
                if (now - at).num_seconds() >= COOLDOWN || tier > last_tier {
                    o.insert((now, tier));
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Undo a claim whose dispatch failed, so the next event can retry.
    pub fn release_claim(&self, account_id: &str) {
        self.last_alert.remove(account_id);
    }

    pub fn mark_suspended(&self, account_id: &str) {
        self.suspended.insert(account_id.to_string(), true);
    }

    pub fn record_alert(&self, account_id: &str, suspend: bool) {
        self.last_alert
            .insert(account_id.to_string(), (Utc::now(), RiskTier::Low));
        if suspend {
            self.mark_suspended(account_id);
        }
    }

    /// Forget cooldown entries that have expired (bounds `last_alert`).
    pub fn prune(&self) {
        let now = Utc::now();
        self.last_alert
            .retain(|_, (at, _)| (now - *at).num_seconds() < COOLDOWN);
    }

    /// Returns true if the account is currently suspended (used by gRPC query API).
    pub fn is_suspended(&self, account_id: &str) -> bool {
        self.suspended.get(account_id).map(|s| *s).unwrap_or(false)
    }
}

impl Default for FusionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// Float const arithmetic is not stable; enforce the sum invariant via test.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_is_exclusive_but_escalation_passes_cooldown() {
        let e = FusionEngine::new();
        assert!(e.try_claim_alert("a", RiskTier::Medium));
        assert!(!e.try_claim_alert("a", RiskTier::Medium));
        // A cheap MEDIUM alert must not shield the account from CRITICAL.
        assert!(e.try_claim_alert("a", RiskTier::Critical));
        assert!(!e.try_claim_alert("a", RiskTier::High));
        e.mark_suspended("a");
        assert!(!e.try_claim_alert("a", RiskTier::Critical));
        e.release_claim("b");
        assert!(e.try_claim_alert("b", RiskTier::High));
    }

    #[test]
    fn weights_sum_to_one() {
        let sum: f32 = WEIGHTS.iter().map(|(_, w)| w).sum();
        assert!(
            (sum - 1.0).abs() < 0.001,
            "WEIGHTS must sum to 1.0, got {sum}"
        );
    }
}
