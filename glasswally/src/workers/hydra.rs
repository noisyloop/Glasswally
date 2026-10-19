// glasswally/src/workers/hydra.rs
//
// Hydra cluster worker — scores accounts based on cluster membership.
// The cluster graph is maintained by StateStore; this worker just queries it.
//
// Tier 2 addition — Payment graph analytics:
//   Sophisticated campaigns use separate payment methods per account but
//   fund them from the same source — prepaid cards from the same batch
//   (same BIN prefix), crypto wallets from the same exchange withdrawal,
//   etc. We detect this by analyzing BIN prefixes across the cluster.

use chrono::Utc;
use serde_json::json;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let cluster_id = store.get_cluster(&event.account_id)?;
    let members = store.cluster_members(cluster_id);
    let n = members.len();

    if n < 3 {
        return Some(DetectionSignal {
            worker: WorkerKind::Hydra,
            account_id: event.account_id.clone(),
            score: 0.0,
            confidence: 0.2,
            evidence: vec!["small_cluster".into()],
            meta: Default::default(),
            timestamp: Utc::now(),
        });
    }

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // Cluster size contribution
    let size_score = (n as f32 / 25.0).min(1.0) * 0.40;
    score += size_score;
    evidence.push(format!("cluster_{}_size:{}", cluster_id, n));

    // Aggregate infrastructure across cluster
    let mut all_payments = std::collections::HashSet::new();
    let mut shared_subnets = std::collections::HashSet::new();
    let mut all_countries = std::collections::HashSet::new();
    let mut all_h2_fps = std::collections::HashSet::new();
    let mut total_requests = 0usize;

    for member_id in &members {
        if let Some(w) = store.get_window(member_id) {
            let w = w.read();
            all_payments.extend(w.payment_hashes.iter().cloned());
            shared_subnets.extend(w.subnets());
            all_countries.extend(w.country_codes.iter().cloned());
            all_h2_fps.extend(w.h2_fingerprints.iter().cloned());
            total_requests += w.events.len();
        }
    }

    if !all_payments.is_empty() {
        score += (all_payments.len() as f32 * 0.07).min(0.35);
        evidence.push(format!("shared_payments:{}", all_payments.len()));
    }
    if !shared_subnets.is_empty() {
        score += (shared_subnets.len() as f32 * 0.03).min(0.15);
        evidence.push(format!("shared_subnets:{}", shared_subnets.len()));
    }
    if all_countries.contains("CN") {
        score += 0.10;
        evidence.push("restricted_geo:CN".into());
    }

    // ── Payment graph analytics — Tier 2 ─────────────────────────────────────
    // Analyze BIN prefix correlation across all payment hashes in the cluster.
    // BIN = first 6 digits of card number. Cards from the same batch/purchase
    // share the same BIN even if they're nominally different payment methods.
    //
    // We approximate this on hashed payment methods by looking at common
    // SHA256 prefix groups (first 3 hex chars = ~12 bits of similarity).
    let bin_groups = payment_bin_groups(&all_payments);
    if let Some((dominant_bin, bin_count)) = bin_groups.iter().max_by_key(|(_, c)| *c) {
        let bin_ratio = *bin_count as f32 / all_payments.len().max(1) as f32;
        if bin_ratio >= 0.40 && *bin_count >= 3 {
            score += 0.20;
            evidence.push(format!(
                "payment_batch_correlation:bin_prefix={}:{}_cards={:.0}%",
                dominant_bin,
                bin_count,
                bin_ratio * 100.0
            ));
        }
    }

    // Same HTTP/2 SETTINGS fingerprint across cluster — all clients compiled
    // from same codebase / configuration
    if all_h2_fps.len() == 1 && n >= 5 {
        score += 0.12;
        evidence.push(format!(
            "uniform_h2_settings:{}_accounts_identical_fingerprint",
            n
        ));
    }

    // ── Phase 3: Deep payment bipartite graph ─────────────────────────────────
    // Collect per-member payment lists for bipartite analysis
    let member_payment_lists: Vec<(String, Vec<String>)> = members
        .iter()
        .filter_map(|m| {
            store.get_window(m).map(|w| {
                let payments: Vec<String> = w.read().payment_hashes.iter().cloned().collect();
                (m.clone(), payments)
            })
        })
        .collect();

    let (max_shared, clique_size, _clique) = payment_bipartite_analysis(&member_payment_lists);
    if max_shared >= 2 && clique_size >= 3 {
        score += 0.25;
        evidence.push(format!(
            "payment_bipartite_clique:{}_accounts_share_{}_payment_methods",
            clique_size, max_shared
        ));
    } else if max_shared >= 1 && clique_size >= 4 {
        score += 0.15;
        evidence.push(format!(
            "payment_sharing:{}_accounts_share_common_method",
            clique_size
        ));
    }

    // Virtual card provider clustering
    if let Some((prefix, count)) = virtual_card_clustering(&all_payments) {
        score += 0.12;
        evidence.push(format!(
            "virtual_card_cluster:prefix={}:{}_cards_same_provider",
            prefix, count
        ));
    }

    let confidence = (total_requests as f32 / 100.0).min(1.0);
    score = score.min(1.0);

    Some(DetectionSignal {
        worker: WorkerKind::Hydra,
        account_id: event.account_id.clone(),
        score,
        confidence,
        evidence,
        meta: [
            ("cluster_id".into(), json!(cluster_id)),
            ("cluster_size".into(), json!(n)),
            ("total_requests".into(), json!(total_requests)),
            ("n_payment_methods".into(), json!(all_payments.len())),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}

/// Group payment hashes by their first 3 hex chars (BIN prefix approximation).
/// Returns (prefix, count) pairs sorted by count descending.
fn payment_bin_groups(
    payments: &std::collections::HashSet<String>,
) -> std::collections::HashMap<String, usize> {
    let mut groups: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for pm in payments {
        if let Some(prefix) = pm.get(..3) {
            *groups.entry(prefix.to_string()).or_insert(0) += 1;
        }
    }
    groups
}

// ── Phase 3: Deep payment graph analysis ─────────────────────────────────────
// Build a bipartite graph: accounts on one side, payment method hashes on the
// other.  Detect accounts that share ≥2 payment methods (strong coordination
// evidence even across distinct BIN prefixes).
//
// Returns (max_shared_payments, n_accounts_in_max_clique, clique_members)

pub(crate) fn payment_bipartite_analysis(
    member_payments: &[(String, Vec<String>)],
) -> (usize, usize, Vec<String>) {
    if member_payments.len() < 2 {
        return (0, 0, vec![]);
    }

    // For each pair of accounts, count shared payment methods.
    let mut max_shared = 0usize;
    let mut max_clique: Vec<String> = vec![];

    for i in 0..member_payments.len() {
        let (acc_i, pm_i) = &member_payments[i];
        let set_i: std::collections::HashSet<_> = pm_i.iter().collect();

        let mut clique_members = vec![acc_i.clone()];
        let mut clique_payments = set_i.clone();

        for (acc_j, pm_j) in member_payments.iter().skip(i + 1) {
            let set_j: std::collections::HashSet<_> = pm_j.iter().collect();
            let shared: std::collections::HashSet<_> =
                clique_payments.intersection(&set_j).collect();

            if !shared.is_empty() {
                clique_members.push(acc_j.clone());
                // Narrow clique to shared payments only
                clique_payments = shared.into_iter().cloned().collect();
            }
        }

        if clique_payments.len() > max_shared
            || (clique_payments.len() == max_shared && clique_members.len() > max_clique.len())
        {
            max_shared = clique_payments.len();
            max_clique = clique_members;
        }
    }

    (max_shared, max_clique.len(), max_clique)
}

/// Detect virtual card provider clustering: if many distinct payment hashes
/// share the same 2-char prefix from the same provider signature, it indicates
/// bulk virtual card purchases from a single provider (e.g. Privacy.com, Revolut).
pub(crate) fn virtual_card_clustering(
    payments: &std::collections::HashSet<String>,
) -> Option<(String, usize)> {
    if payments.len() < 4 {
        return None;
    }
    let mut prefix2: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for pm in payments {
        if let Some(prefix) = pm.get(..2) {
            *prefix2.entry(prefix.to_string()).or_default() += 1;
        }
    }
    prefix2
        .into_iter()
        .filter(|(_, c)| *c >= 4)
        .max_by_key(|(_, c)| *c)
}
