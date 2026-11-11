// glasswally/src/engine/dispatcher.rs
//
// Writes enforcement actions to output JSONL files.
// On CLUSTER_TAKEDOWN: suspends all cluster members + writes IOC bundle.
// On INJECT_CANARY: generates a per-request canary token for response
//                   watermarking and registers it in StateStore.
// Wire these files to your enforcement API / Kafka topics in production.

use anyhow::Result;
use chrono::Utc;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::events::{
    ActionKind, CanaryToken, EnforcementAction, IocBundle, RiskDecision, RiskTier,
};
use crate::state::window::{subnet_key, StateStore};

/// Cap on the weakly-linked accounts listed in one review entry.
const MAX_REVIEW_ACCOUNTS: usize = 512;

pub struct Dispatcher {
    out: PathBuf,
}

impl Dispatcher {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        let out: PathBuf = output_dir.into();
        std::fs::create_dir_all(&out).expect("Failed to create output directory");
        // Enforcement / IOC / audit logs contain account IDs, evidence and
        // IP IOCs. Restrict the directory to the owner so other local users
        // can't read them or plant symlinks for the append-only writers to
        // follow (CWE-377 / CWE-59).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)) {
                tracing::warn!("Could not tighten output dir permissions: {e}");
            }
        }
        Self { out }
    }

    pub async fn dispatch(
        &self,
        decision: &RiskDecision,
        store: &StateStore,
    ) -> Result<EnforcementAction> {
        let mut action_type = decision.action;
        let mut affected = vec![decision.account_id.clone()];
        let mut canary = None::<CanaryToken>;

        // ── INJECT_CANARY (High tier) ─────────────────────────────────────────
        // Generate a unique canary token and mark the account for response
        // watermarking. The token is registered in StateStore so that if it
        // appears in a future inbound request (scraped dataset replay), we can
        // attribute the distillation campaign.
        if action_type == ActionKind::InjectCanary {
            let token = CanaryToken::generate(&decision.account_id, "dispatch");
            store.mark_watermarked(&decision.account_id);
            store.register_canary(token.clone());
            canary = Some(token);
            info!(
                "INJECT_CANARY account={} score={:.4}",
                decision.account_id, decision.composite_score
            );
        }

        // ── CLUSTER TAKEDOWN (Critical tier) ─────────────────────────────────
        // Group enforcement is limited to accounts *strongly* linked to the
        // triggering account (shared payment instrument / org id).
        //
        // Cluster membership alone is not enough: clusters also form on a
        // shared /24 or JA3 hash, which anyone can acquire. Suspending the
        // whole cluster let an attacker enrol bystanders (same HTTP library,
        // same NAT / cloud egress range) and then deliberately trip a
        // CRITICAL score to have them all suspended — and published in a
        // cross-provider IOC bundle. Weakly linked members are sent to the
        // analyst queue instead.
        let mut review: Vec<String> = Vec::new();
        if decision.tier == RiskTier::Critical {
            if let Some(cid) = decision.cluster_id {
                let cluster = store.cluster_members(cid);
                let strong = store.strongly_linked(&decision.account_id);
                let mut members: Vec<String> = strong.iter().cloned().collect();
                members.sort();
                review = cluster.difference(&strong).cloned().collect();
                review.sort();
                review.truncate(MAX_REVIEW_ACCOUNTS);

                if members.len() >= 3 {
                    action_type = ActionKind::ClusterTakedown;
                    affected = members.clone();

                    // Build IOC bundle from the enforced members' data only
                    let mut ips = std::collections::HashSet::new();
                    let mut payments = std::collections::HashSet::new();
                    let mut ja3s = std::collections::HashSet::new();
                    let mut ja3s_set = std::collections::HashSet::new();
                    let mut hdrs = std::collections::HashSet::new();
                    let mut h2fps = std::collections::HashSet::new();

                    for acc in &members {
                        if let Some(w) = store.get_window(acc) {
                            let w = w.read();
                            ips.extend(w.ip_addresses.iter().cloned());
                            payments.extend(w.payment_hashes.iter().cloned());
                            ja3s.extend(w.ja3_hashes.iter().cloned());
                            ja3s_set.extend(w.ja3s_hashes.iter().cloned());
                            hdrs.extend(w.header_hashes.iter().cloned());
                            h2fps.extend(w.h2_fingerprints.iter().cloned());
                        }
                    }

                    let subnets: std::collections::HashSet<String> =
                        ips.iter().filter_map(|ip| subnet_key(ip)).collect();

                    // Collect any triggered canaries for this cluster
                    let triggered_canaries: Vec<String> = store
                        .triggered_canaries_for_cluster(cid)
                        .into_iter()
                        .collect();

                    let ioc = IocBundle {
                        cluster_id: cid,
                        ip_addresses: ips.into_iter().collect(),
                        ip_subnets: subnets.into_iter().collect(),
                        payment_hashes: payments.into_iter().collect(),
                        ja3_hashes: ja3s.into_iter().collect(),
                        ja3s_hashes: ja3s_set.into_iter().collect(),
                        header_order_hashes: hdrs.into_iter().collect(),
                        h2_fingerprints: h2fps.into_iter().collect(),
                        watermark_tokens: triggered_canaries,
                        account_ids: members,
                        country_codes: decision.country_codes.clone(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        total_requests: decision.n_requests_seen as u64,
                        targeted_capabilities: decision.top_evidence.clone(),
                        confidence: decision.composite_score,
                        timestamp: Utc::now(),
                    };

                    self.write("ioc_bundles.jsonl", &(serde_json::to_string(&ioc)? + "\n"))
                        .await?;
                    info!(
                        "CLUSTER_TAKEDOWN cluster={} accounts={} review={}",
                        cid,
                        affected.len(),
                        review.len()
                    );
                }
            }
        }

        let action = EnforcementAction {
            action_type,
            account_id: Some(decision.account_id.clone()),
            cluster_id: decision.cluster_id,
            affected_accounts: affected,
            reason: format!(
                "score={:.4} tier={}",
                decision.composite_score, decision.tier
            ),
            evidence: decision.top_evidence.clone(),
            composite_score: decision.composite_score,
            canary_token: canary,
            timestamp: Utc::now(),
        };

        let line = action.to_jsonl() + "\n";
        match action_type {
            ActionKind::SuspendAccount | ActionKind::ClusterTakedown => {
                self.write("enforcement_actions.jsonl", &line).await?
            }
            ActionKind::RateLimit => self.write("rate_limit_commands.jsonl", &line).await?,
            ActionKind::FlagForReview | ActionKind::InjectCanary => {
                self.write("analyst_queue.jsonl", &line).await?
            }
            _ => {}
        }
        self.write("audit_log.jsonl", &line).await?;

        // Weakly linked cluster members: human review, never auto-enforced.
        if !review.is_empty() {
            let flag = EnforcementAction {
                action_type: ActionKind::FlagForReview,
                account_id: None,
                cluster_id: decision.cluster_id,
                affected_accounts: review,
                reason: format!(
                    "share only weak infrastructure (subnet/JA3) with critical account {}; \
                     not auto-suspended",
                    decision.account_id
                ),
                evidence: decision.top_evidence.clone(),
                composite_score: decision.composite_score,
                canary_token: None,
                timestamp: Utc::now(),
            };
            let line = flag.to_jsonl() + "\n";
            self.write("analyst_queue.jsonl", &line).await?;
            self.write("audit_log.jsonl", &line).await?;
        }

        Ok(action)
    }

    async fn write(&self, file: &str, content: &str) -> Result<()> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        // Owner-only: these files hold account ids, IPs and evidence. The
        // directory is 0700 when we create it, but an operator-supplied
        // existing directory may not be.
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(self.out.join(file)).await?;
        f.write_all(content.as_bytes()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::test_event;
    use std::collections::HashMap;

    fn critical(account: &str, store: &StateStore) -> RiskDecision {
        RiskDecision {
            account_id: account.into(),
            composite_score: 0.9,
            tier: RiskTier::Critical,
            signal_scores: HashMap::new(),
            top_evidence: vec![],
            country_codes: vec![],
            cluster_id: store.get_cluster(account),
            n_requests_seen: 1,
            action: ActionKind::SuspendAccount,
            timestamp: Utc::now(),
            ground_truth: None,
        }
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gw-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// An attacker shares a JA3 (same HTTP library) with bystanders, then
    /// trips CRITICAL. Bystanders must not be suspended or exported as IOCs.
    #[tokio::test]
    async fn takedown_spares_weakly_linked_bystanders() {
        let store = StateStore::new();
        for acct in ["atk1", "atk2", "atk3"] {
            let mut e = test_event(acct, "hi");
            e.payment_method_hash = Some("ring-card".into());
            e.ja3_hash = Some("common-ja3".into());
            store.ingest(&e);
        }
        for (i, acct) in ["victim1", "victim2", "victim3"].iter().enumerate() {
            let mut e = test_event(acct, "hi");
            e.ip_address = format!("198.51.{}.7", i).parse().unwrap();
            e.payment_method_hash = Some(format!("own-card-{i}"));
            e.ja3_hash = Some("common-ja3".into());
            store.ingest(&e);
        }
        let dir = tmp_dir("takedown");
        let d = Dispatcher::new(&dir);
        let action = d.dispatch(&critical("atk1", &store), &store).await.unwrap();

        assert_eq!(action.action_type, ActionKind::ClusterTakedown);
        assert_eq!(action.affected_accounts, ["atk1", "atk2", "atk3"]);
        let ioc = std::fs::read_to_string(dir.join("ioc_bundles.jsonl")).unwrap();
        assert!(!ioc.contains("victim") && !ioc.contains("198.51."));
        let queue = std::fs::read_to_string(dir.join("analyst_queue.jsonl")).unwrap();
        assert!(queue.contains("victim1") && queue.contains("FlagForReview"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A lone attacker in a JA3-only cluster gets a single-account suspension.
    #[tokio::test]
    async fn weak_only_cluster_is_not_taken_down() {
        let store = StateStore::new();
        for acct in ["atk", "v1", "v2", "v3"] {
            let mut e = test_event(acct, "hi");
            e.payment_method_hash = Some(format!("card-{acct}"));
            store.ingest(&e); // all share 10.0.0.0/24
        }
        let dir = tmp_dir("weak");
        let d = Dispatcher::new(&dir);
        let action = d.dispatch(&critical("atk", &store), &store).await.unwrap();
        assert_eq!(action.action_type, ActionKind::SuspendAccount);
        assert_eq!(action.affected_accounts, ["atk"]);
        assert!(!dir.join("ioc_bundles.jsonl").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("audit_log.jsonl"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "output files must be owner-only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
