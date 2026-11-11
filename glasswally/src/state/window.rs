// glasswally/src/state/window.rs
//
// Lock-free sliding window state store.
// DashMap = sharded concurrent HashMap — safe across tokio tasks with no mutex.
//
// Design:
//   - Per-account event ring buffer (VecDeque, auto-expiring)
//   - Infrastructure reverse indexes: payment → accounts, subnet → accounts
//   - Relationship graph: accounts as nodes, shared infra as edges
//   - Cluster membership: connected components with 3+ accounts
//   - Timing buckets: second-resolution global burst detection
//   - Canary registry: per-account watermark + canary token tracking
//
// This is the in-memory equivalent of:
//   Redis     → per-account state
//   Neo4j     → relationship graph
//   ClickHouse → analytics aggregates

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::events::{truncate_middle, ApiEvent, CanaryToken};

// ── Window durations ──────────────────────────────────────────────────────────

pub const W_5MIN: i64 = 5 * 60;
pub const W_1HR: i64 = 60 * 60;
pub const W_24HR: i64 = 24 * 60 * 60;

/// Maximum number of related accounts processed in a single incremental
/// cluster update. Without this, an attacker who makes many accounts share
/// one cheap, self-controlled attribute (a /24 subnet, a JA3 hash) forces
/// O(cluster size) work on *every* subsequent ingest — an
/// algorithmic-complexity DoS — and can also rope unrelated accounts into a
/// takedown cluster. Past this fan-out we stop re-expanding the cluster.
pub const MAX_CLUSTER_FANOUT: usize = 512;

/// Per-account cap on retained events / model observations. Time-based
/// expiry alone does not bound memory: a single high-rate account (or one
/// sending future-dated timestamps, which never expire) could otherwise
/// grow its window without limit.
pub const MAX_EVENTS_PER_ACCOUNT: usize = 10_000;

/// Per-account cap on recorded model switches (only recent ones matter).
pub const MAX_MODEL_SWITCHES: usize = 256;

/// Bytes of each prompt retained in the sliding window. The live event is
/// analysed at full (bounded) length; history only needs enough to recognise
/// templates and phrase patterns. Without this cap one account could pin
/// MAX_EVENTS_PER_ACCOUNT × multi-megabyte prompts in memory.
pub const MAX_STORED_PROMPT_BYTES: usize = 2048;

/// Cap on each per-account attribute set (IPs, user agents, fingerprints ...).
/// These sets are never expired, so a client that rotates a free-form value
/// (e.g. a unique User-Agent per request) would otherwise grow them forever.
pub const MAX_SET_ENTRIES: usize = 256;

/// Most-recent prompts a worker re-scans per event. History scans are
/// O(history) on *every* event, so an account with a full window would make
/// each of its own requests cost thousands of prompt scans (quadratic CPU).
pub const HISTORY_SCAN_LIMIT: usize = 512;

/// Upper bound on the accounts returned by a strong-link traversal.
pub const MAX_STRONG_LINKS: usize = 512;

/// How long cross-account timing buckets are kept.
pub const TIMING_BUCKET_RETENTION_SECS: i64 = 600;

// ── Per-account window ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountWindow {
    pub account_id: String,
    pub events: VecDeque<ApiEvent>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ip_addresses: HashSet<String>,
    pub payment_hashes: HashSet<String>,
    pub user_agents: HashSet<String>,
    pub country_codes: HashSet<String>,
    pub org_ids: HashSet<String>,
    pub models_seen: Vec<(DateTime<Utc>, String)>,
    pub header_hashes: HashSet<String>,   // header order hashes
    pub ja3_hashes: HashSet<String>,      // TLS ClientHello fingerprints
    pub ja3s_hashes: HashSet<String>,     // TLS ServerHello fingerprints (Tier 1)
    pub h2_fingerprints: HashSet<String>, // HTTP/2 SETTINGS fingerprints (Tier 2)
    pub suspended: bool,
    pub last_alerted: Option<DateTime<Utc>>,
    pub watermarked_at: Option<DateTime<Utc>>, // when account was first watermarked
}

impl AccountWindow {
    pub fn new(account_id: &str, now: DateTime<Utc>) -> Self {
        Self {
            account_id: account_id.to_string(),
            events: VecDeque::new(),
            first_seen: now,
            last_seen: now,
            ip_addresses: HashSet::new(),
            payment_hashes: HashSet::new(),
            user_agents: HashSet::new(),
            country_codes: HashSet::new(),
            org_ids: HashSet::new(),
            models_seen: Vec::new(),
            header_hashes: HashSet::new(),
            ja3_hashes: HashSet::new(),
            ja3s_hashes: HashSet::new(),
            h2_fingerprints: HashSet::new(),
            suspended: false,
            last_alerted: None,
            watermarked_at: None,
        }
    }

    pub fn ingest(&mut self, event: &ApiEvent) {
        self.last_seen = event.timestamp;
        bounded_insert(&mut self.ip_addresses, event.ip_address.to_string());
        bounded_insert(&mut self.user_agents, event.user_agent.clone());
        bounded_insert(&mut self.country_codes, event.country_code.clone());
        if let Some(ref pm) = event.payment_method_hash {
            bounded_insert(&mut self.payment_hashes, pm.clone());
        }
        if let Some(ref org) = event.org_id {
            bounded_insert(&mut self.org_ids, org.clone());
        }
        if let Some(ref ja3) = event.ja3_hash {
            bounded_insert(&mut self.ja3_hashes, ja3.clone());
        }
        if let Some(ref ja3s) = event.ja3s_hash {
            bounded_insert(&mut self.ja3s_hashes, ja3s.clone());
        }
        if let Some(ref h2) = event.h2_settings {
            if !h2.fingerprint.is_empty() {
                bounded_insert(&mut self.h2_fingerprints, h2.fingerprint.clone());
            }
        }
        // Header order hash
        if !event.header_order.is_empty() {
            use sha2::{Digest, Sha256};
            let joined = event.header_order.join("|");
            let mut h = Sha256::new();
            h.update(joined.as_bytes());
            bounded_insert(&mut self.header_hashes, hex::encode(&h.finalize()[..16]));
        }
        self.models_seen
            .push((event.timestamp, event.model.clone()));
        if self.models_seen.len() > MAX_EVENTS_PER_ACCOUNT {
            let excess = self.models_seen.len() - MAX_EVENTS_PER_ACCOUNT;
            self.models_seen.drain(..excess);
        }
        // Keep a compact copy: history only needs the head/tail of the prompt.
        let mut stored = event.clone();
        if let std::borrow::Cow::Owned(p) = truncate_middle(&stored.prompt, MAX_STORED_PROMPT_BYTES)
        {
            stored.prompt = p;
        }
        self.events.push_back(stored);
        while self.events.len() > MAX_EVENTS_PER_ACCOUNT {
            self.events.pop_front();
        }
    }

    pub fn events_in(&self, seconds: i64) -> Vec<&ApiEvent> {
        let cutoff = Utc::now() - Duration::seconds(seconds);
        self.events
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .collect()
    }

    /// The most recent (at most HISTORY_SCAN_LIMIT) prompts seen in the last
    /// `seconds`, oldest first.
    pub fn prompts_in(&self, seconds: i64) -> Vec<String> {
        let evs = self.events_in(seconds);
        let skip = evs.len().saturating_sub(HISTORY_SCAN_LIMIT);
        evs.into_iter()
            .skip(skip)
            .map(|e| e.prompt.clone())
            .collect()
    }

    /// The most recent (at most HISTORY_SCAN_LIMIT) retained prompts,
    /// regardless of age, oldest first.
    pub fn recent_prompts(&self) -> Vec<String> {
        let skip = self.events.len().saturating_sub(HISTORY_SCAN_LIMIT);
        self.events
            .iter()
            .skip(skip)
            .map(|e| e.prompt.clone())
            .collect()
    }

    pub fn rate_per_hour(&self, seconds: i64) -> f64 {
        let evs = self.events_in(seconds);
        if evs.len() < 2 {
            return 0.0;
        }
        let span = (evs.last().unwrap().timestamp - evs.first().unwrap().timestamp)
            .num_seconds()
            .max(1) as f64;
        (evs.len() as f64 / span) * 3600.0
    }

    pub fn interarrivals(&self, seconds: i64) -> Vec<f64> {
        let evs = self.events_in(seconds);
        if evs.len() < 2 {
            return vec![];
        }
        evs.windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).num_milliseconds() as f64 / 1000.0)
            .filter(|&d| d > 0.0)
            .collect()
    }

    pub fn subnets(&self) -> HashSet<String> {
        self.ip_addresses
            .iter()
            .filter_map(|ip| subnet_key(ip))
            .collect()
    }

    pub fn expire_old(&mut self) {
        let cutoff = Utc::now() - Duration::seconds(W_24HR);
        while self
            .events
            .front()
            .map(|e| e.timestamp < cutoff)
            .unwrap_or(false)
        {
            self.events.pop_front();
        }
        self.models_seen.retain(|(ts, _)| *ts >= cutoff);
    }
}

/// Insert into a per-account attribute set unless it is already at capacity.
fn bounded_insert(set: &mut HashSet<String>, value: String) {
    if set.len() < MAX_SET_ENTRIES || set.contains(&value) {
        set.insert(value);
    }
}

/// Network prefix used for infrastructure clustering: the /24 of an IPv4
/// address, or the /48 of an IPv6 address. IPv4-mapped IPv6 addresses are
/// folded to IPv4 first. (Previously only dotted-quad strings produced a
/// key, so any IPv6 client was invisible to subnet clustering.)
pub fn subnet_key(ip: &str) -> Option<String> {
    match ip.parse::<std::net::IpAddr>().ok()?.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}", o[0], o[1], o[2]))
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]))
        }
    }
}

// ── Global state store ────────────────────────────────────────────────────────

pub struct StateStore {
    // Account windows — the primary per-account state
    pub accounts: DashMap<String, Arc<RwLock<AccountWindow>>>,

    // Infrastructure reverse indexes — fast cluster detection
    payment_idx: DashMap<String, HashSet<String>>, // payment_hash → account_ids
    subnet_idx: DashMap<String, HashSet<String>>,  // subnet → account_ids
    org_idx: DashMap<String, HashSet<String>>,     // org_id → account_ids
    ja3_idx: DashMap<String, HashSet<String>>,     // ja3_hash → account_ids
    ja3s_idx: DashMap<String, HashSet<String>>,    // ja3s_hash → account_ids
    hdr_idx: DashMap<String, HashSet<String>>,     // header_hash → account_ids

    // Cluster assignments (updated incrementally on each new edge)
    pub account_cluster: DashMap<String, u32>,
    pub clusters: DashMap<u32, HashSet<String>>,
    next_cluster: parking_lot::Mutex<u32>,

    // Model pivot tracking
    model_switches: DashMap<String, Vec<(DateTime<Utc>, String, String)>>,

    // Cross-account timing buckets (Tier 1 — synchronized burst detection)
    // Key = Unix timestamp in seconds, Value = set of account_ids that fired in that second
    timing_buckets: DashMap<u64, HashSet<String>>,

    // Role preamble index (Phase 1 — cross-account preamble collision detection)
    // Key = preamble hash (SHA256[:8] of normalized role preamble), Value = account_ids
    preamble_idx: DashMap<String, HashSet<String>>,

    // Canary token registry (Tier 2 — response attribution)
    canary_registry: DashMap<String, CanaryToken>, // token → metadata

    // Watermark tracking — accounts under active watermark surveillance
    watermarked: DashMap<String, DateTime<Utc>>, // account_id → watermark start time

    // Global counters
    pub total_events: std::sync::atomic::AtomicU64,
    pub total_accounts: std::sync::atomic::AtomicU64,
}

impl StateStore {
    pub fn new() -> Self {
        Self {
            accounts: DashMap::new(),
            payment_idx: DashMap::new(),
            subnet_idx: DashMap::new(),
            org_idx: DashMap::new(),
            ja3_idx: DashMap::new(),
            ja3s_idx: DashMap::new(),
            hdr_idx: DashMap::new(),
            account_cluster: DashMap::new(),
            clusters: DashMap::new(),
            next_cluster: parking_lot::Mutex::new(0),
            model_switches: DashMap::new(),
            timing_buckets: DashMap::new(),
            preamble_idx: DashMap::new(),
            canary_registry: DashMap::new(),
            watermarked: DashMap::new(),
            total_events: std::sync::atomic::AtomicU64::new(0),
            total_accounts: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Ingest one event. Updates all indexes and triggers cluster detection.
    pub fn ingest(&self, event: &ApiEvent) {
        self.total_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let is_new = !self.accounts.contains_key(&event.account_id);
        let window = self
            .accounts
            .entry(event.account_id.clone())
            .or_insert_with(|| {
                Arc::new(RwLock::new(AccountWindow::new(
                    &event.account_id,
                    event.timestamp,
                )))
            })
            .clone();

        if is_new {
            self.total_accounts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Detect model pivot before ingesting
        {
            let r = window.read();
            if let Some(last) = r.events.back() {
                if !last.model.is_empty() && last.model != event.model {
                    let mut switches = self
                        .model_switches
                        .entry(event.account_id.clone())
                        .or_default();
                    switches.push((event.timestamp, last.model.clone(), event.model.clone()));
                    if switches.len() > MAX_MODEL_SWITCHES {
                        let excess = switches.len() - MAX_MODEL_SWITCHES;
                        switches.drain(..excess);
                    }
                }
            }
        }

        window.write().ingest(event);

        // Update all indexes
        if let Some(ref pm) = event.payment_method_hash {
            self.payment_idx
                .entry(pm.clone())
                .or_default()
                .insert(event.account_id.clone());
        }
        if let Some(ref org) = event.org_id {
            self.org_idx
                .entry(org.clone())
                .or_default()
                .insert(event.account_id.clone());
        }
        if let Some(ref ja3) = event.ja3_hash {
            self.ja3_idx
                .entry(ja3.clone())
                .or_default()
                .insert(event.account_id.clone());
        }
        if let Some(ref ja3s) = event.ja3s_hash {
            self.ja3s_idx
                .entry(ja3s.clone())
                .or_default()
                .insert(event.account_id.clone());
        }
        for subnet in window.read().subnets() {
            self.subnet_idx
                .entry(subnet)
                .or_default()
                .insert(event.account_id.clone());
        }

        // Record global timing bucket (for cross-account burst detection)
        let bucket = event.timestamp.timestamp() as u64;
        self.timing_buckets
            .entry(bucket)
            .or_default()
            .insert(event.account_id.clone());

        // Record preamble hash (Phase 1 — role preamble collision detection)
        if let Some(ref ph) = event.system_prompt_hash {
            self.preamble_idx
                .entry(ph.clone())
                .or_default()
                .insert(event.account_id.clone());
        }

        // Trigger incremental cluster update
        self.update_clusters(&event.account_id);
    }

    fn update_clusters(&self, account_id: &str) {
        // Find all accounts related to this one via shared infrastructure
        let mut related: HashSet<String> = HashSet::new();

        let window = match self.accounts.get(account_id) {
            Some(w) => w.read().clone_meta(),
            None => return,
        };

        // Shared payment (weight 4 — strongest signal)
        for pm in &window.payment_hashes {
            if let Some(accts) = self.payment_idx.get(pm) {
                related.extend(accts.iter().cloned());
            }
        }
        // Shared org (weight 3)
        for org in &window.org_ids {
            if let Some(accts) = self.org_idx.get(org) {
                related.extend(accts.iter().cloned());
            }
        }
        // Shared subnet (weight 2)
        for subnet in &window.subnets() {
            if let Some(accts) = self.subnet_idx.get(subnet) {
                related.extend(accts.iter().cloned());
            }
        }
        // Shared JA3 (weight 2 — script clients sharing same library version)
        for ja3 in &window.ja3_hashes {
            if let Some(accts) = self.ja3_idx.get(ja3) {
                related.extend(accts.iter().cloned());
            }
        }

        related.remove(account_id);
        if related.len() < 2 {
            return;
        }

        // Cap fan-out: beyond this, the cluster is already established and
        // re-expanding it every event is pure attacker-controllable cost.
        if related.len() > MAX_CLUSTER_FANOUT {
            if self.account_cluster.get(account_id).is_none() {
                if let Some(any_rel) = related.iter().next() {
                    if let Some(cid) = self.account_cluster.get(any_rel).map(|c| *c) {
                        self.account_cluster.insert(account_id.to_string(), cid);
                        self.clusters
                            .entry(cid)
                            .or_default()
                            .insert(account_id.to_string());
                    }
                }
            }
            return;
        }

        // Find existing cluster IDs for this account and its neighbors
        let mut cluster_ids: HashSet<u32> = HashSet::new();
        if let Some(cid) = self.account_cluster.get(account_id) {
            cluster_ids.insert(*cid);
        }
        for rel in &related {
            if let Some(cid) = self.account_cluster.get(rel) {
                cluster_ids.insert(*cid);
            }
        }

        // Merge clusters (or create new)
        let cluster_id = if cluster_ids.is_empty() {
            let mut next = self.next_cluster.lock();
            let id = *next;
            *next += 1;
            id
        } else {
            // Use the lowest existing ID (merge others into it)
            *cluster_ids.iter().min().unwrap()
        };

        // Assign all members
        let mut members = related;
        members.insert(account_id.to_string());

        for member in &members {
            self.account_cluster.insert(member.clone(), cluster_id);
        }
        self.clusters.entry(cluster_id).or_default().extend(members);

        debug!(
            "Cluster {} now has {} members",
            cluster_id,
            self.clusters.get(&cluster_id).map(|c| c.len()).unwrap_or(0)
        );
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn get_window(&self, account_id: &str) -> Option<Arc<RwLock<AccountWindow>>> {
        self.accounts.get(account_id).map(|w| w.clone())
    }

    pub fn get_cluster(&self, account_id: &str) -> Option<u32> {
        self.account_cluster.get(account_id).map(|c| *c)
    }

    pub fn cluster_members(&self, cluster_id: u32) -> HashSet<String> {
        self.clusters
            .get(&cluster_id)
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// Accounts connected to `account_id` through *strong* shared
    /// infrastructure — the same payment instrument or the same org id —
    /// following links transitively. Always contains `account_id` itself.
    ///
    /// Unlike a /24 or a JA3 hash, these attributes cannot be acquired by a
    /// third party: an attacker can sit in a victim's subnet or use the same
    /// HTTP library, but cannot pay with the victim's card. Enforcement that
    /// acts on a whole group must use this set, not raw cluster membership.
    pub fn strongly_linked(&self, account_id: &str) -> HashSet<String> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        seen.insert(account_id.to_string());
        queue.push_back(account_id.to_string());

        while let Some(acc) = queue.pop_front() {
            let Some(meta) = self.accounts.get(&acc).map(|w| w.read().clone_meta()) else {
                continue;
            };
            let payments = meta.payment_hashes.iter().map(|k| self.payment_idx.get(k));
            let orgs = meta.org_ids.iter().map(|k| self.org_idx.get(k));
            for linked in payments.chain(orgs).flatten() {
                for other in linked.iter() {
                    if seen.len() >= MAX_STRONG_LINKS {
                        return seen;
                    }
                    if seen.insert(other.clone()) {
                        queue.push_back(other.clone());
                    }
                }
            }
        }
        seen
    }

    pub fn model_switches(&self, account_id: &str) -> Vec<(DateTime<Utc>, String, String)> {
        self.model_switches
            .get(account_id)
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn accounts_with_ja3(&self, ja3: &str) -> HashSet<String> {
        self.ja3_idx.get(ja3).map(|a| a.clone()).unwrap_or_default()
    }

    pub fn accounts_with_ja3s(&self, ja3s: &str) -> HashSet<String> {
        self.ja3s_idx
            .get(ja3s)
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    pub fn accounts_with_header_hash(&self, hash: &str) -> HashSet<String> {
        self.hdr_idx
            .get(hash)
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Number of distinct accounts that share the given preamble hash (Phase 1).
    pub fn accounts_with_preamble_hash(&self, hash: &str) -> usize {
        self.preamble_idx.get(hash).map(|a| a.len()).unwrap_or(0)
    }

    pub fn n_accounts(&self) -> usize {
        self.accounts.len()
    }
    pub fn n_clusters(&self) -> usize {
        self.clusters.len()
    }

    // ── Timing bucket queries (Tier 1 — cross-account burst detection) ────────

    /// Record that account fired at the given Unix-second bucket.
    pub fn record_timing(&self, account_id: &str, bucket: u64) {
        self.timing_buckets
            .entry(bucket)
            .or_default()
            .insert(account_id.to_string());
    }

    /// Count how many distinct accounts fired in a given 1-second bucket.
    pub fn accounts_in_bucket(&self, bucket: u64) -> usize {
        self.timing_buckets
            .get(&bucket)
            .map(|b| b.len())
            .unwrap_or(0)
    }

    // ── Watermark management (Tier 1) ─────────────────────────────────────────

    pub fn is_watermarked(&self, account_id: &str) -> bool {
        self.watermarked.contains_key(account_id)
    }

    pub fn mark_watermarked(&self, account_id: &str) {
        self.watermarked.insert(account_id.to_string(), Utc::now());
        if let Some(w) = self.accounts.get(account_id) {
            w.write().watermarked_at = Some(Utc::now());
        }
    }

    // ── Canary token registry (Tier 2) ────────────────────────────────────────

    pub fn register_canary(&self, token: CanaryToken) {
        self.canary_registry.insert(token.token.clone(), token);
    }

    pub fn lookup_canary(&self, token: &str) -> Option<CanaryToken> {
        self.canary_registry.get(token).map(|t| t.clone())
    }

    pub fn trigger_canary(&self, token: &str) {
        if let Some(mut entry) = self.canary_registry.get_mut(token) {
            entry.triggered = true;
            entry.trigger_ts = Some(Utc::now());
        }
    }

    pub fn triggered_canaries_for_cluster(&self, cluster_id: u32) -> Vec<String> {
        let members = self.cluster_members(cluster_id);
        self.canary_registry
            .iter()
            .filter(|e| e.triggered && members.contains(&e.account_id))
            .map(|e| e.token.clone())
            .collect()
    }

    // ── Housekeeping ──────────────────────────────────────────────────────────

    pub async fn housekeeping_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            let evicted = self.housekeeping_pass(Utc::now());
            if evicted > 0 {
                debug!("Housekeeping evicted {} idle accounts", evicted);
            }
        }
    }

    /// One housekeeping sweep. Returns the number of idle accounts evicted.
    pub fn housekeeping_pass(&self, now: DateTime<Utc>) -> usize {
        for entry in self.accounts.iter() {
            entry.value().write().expire_old();
        }
        // Expire old model switches (pivot ignores anything > 24h old).
        let switch_cutoff = now - chrono::Duration::seconds(W_24HR);
        self.model_switches.retain(|_, s| {
            s.retain(|(ts, _, _)| *ts >= switch_cutoff);
            !s.is_empty()
        });
        // Keep only the last 10 minutes of timing buckets. Buckets in the
        // future (bogus timestamps) are dropped too — they would never age
        // past the lower bound.
        let bucket_min = (now.timestamp() - TIMING_BUCKET_RETENTION_SECS).max(0) as u64;
        let bucket_max = (now.timestamp() + TIMING_BUCKET_RETENTION_SECS).max(0) as u64;
        self.timing_buckets
            .retain(|&bucket, _| bucket >= bucket_min && bucket <= bucket_max);

        self.evict_idle(now)
    }

    /// Drop accounts with no events left in the 24h window, together with
    /// every index entry that points at them.
    ///
    /// Without this the account map and the reverse indexes only ever grow:
    /// each distinct account id ever seen stays resident forever. In eBPF
    /// mode an account id is derived from whatever credential a client
    /// *presents*, so the set of ids is attacker-controlled.
    fn evict_idle(&self, now: DateTime<Utc>) -> usize {
        let cutoff = now - Duration::seconds(W_24HR);
        let idle: HashSet<String> = self
            .accounts
            .iter()
            .filter(|e| {
                let w = e.value().read();
                w.events.is_empty() && w.last_seen < cutoff
            })
            .map(|e| e.key().clone())
            .collect();
        if idle.is_empty() {
            return 0;
        }

        let mut evicted: HashSet<String> = HashSet::with_capacity(idle.len());
        for id in idle {
            // Re-check under the map lock: the account may have just woken up.
            if self
                .accounts
                .remove_if(&id, |_, w| w.read().events.is_empty())
                .is_some()
            {
                evicted.insert(id);
            }
        }

        let prune = |idx: &DashMap<String, HashSet<String>>| {
            idx.retain(|_, accts| {
                accts.retain(|a| !evicted.contains(a));
                !accts.is_empty()
            });
        };
        prune(&self.payment_idx);
        prune(&self.subnet_idx);
        prune(&self.org_idx);
        prune(&self.ja3_idx);
        prune(&self.ja3s_idx);
        prune(&self.hdr_idx);
        prune(&self.preamble_idx);

        for id in &evicted {
            self.model_switches.remove(id);
            self.account_cluster.remove(id);
        }
        self.clusters.retain(|_, members| {
            members.retain(|a| !evicted.contains(a));
            !members.is_empty()
        });

        evicted.len()
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

// Helper: clone just metadata fields for cluster analysis (avoids cloning all events)
struct WindowMeta {
    payment_hashes: HashSet<String>,
    org_ids: HashSet<String>,
    ja3_hashes: HashSet<String>,
    ip_addresses: HashSet<String>,
}

impl WindowMeta {
    fn subnets(&self) -> HashSet<String> {
        self.ip_addresses
            .iter()
            .filter_map(|ip| subnet_key(ip))
            .collect()
    }
}

impl AccountWindow {
    fn clone_meta(&self) -> WindowMeta {
        WindowMeta {
            payment_hashes: self.payment_hashes.clone(),
            org_ids: self.org_ids.clone(),
            ja3_hashes: self.ja3_hashes.clone(),
            ip_addresses: self.ip_addresses.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::test_event;

    #[test]
    fn subnet_key_covers_ipv6_and_mapped_addresses() {
        assert_eq!(subnet_key("203.0.113.9").as_deref(), Some("203.0.113"));
        assert_eq!(
            subnet_key("::ffff:203.0.113.9").as_deref(),
            Some("203.0.113")
        );
        assert_eq!(
            subnet_key("2001:db8:aa:1::5"),
            subnet_key("2001:db8:aa:ffff::9")
        );
        assert_ne!(subnet_key("2001:db8:aa::1"), subnet_key("2001:db8:ab::1"));
        assert_eq!(subnet_key("not-an-ip"), None);
    }

    #[test]
    fn ipv6_accounts_cluster_by_prefix() {
        let store = StateStore::new();
        for (i, acct) in ["a", "b", "c"].iter().enumerate() {
            let mut e = test_event(acct, "hi");
            e.ip_address = format!("2001:db8:aa:{}::1", i).parse().unwrap();
            store.ingest(&e);
        }
        assert!(store.get_cluster("c").is_some());
    }

    #[test]
    fn stored_prompt_and_attribute_sets_are_bounded() {
        let store = StateStore::new();
        for i in 0..(MAX_SET_ENTRIES + 50) {
            let mut e = test_event("acct", &"p".repeat(100_000));
            e.user_agent = format!("ua-{i}");
            store.ingest(&e);
        }
        let w = store.get_window("acct").unwrap();
        let w = w.read();
        assert_eq!(w.user_agents.len(), MAX_SET_ENTRIES);
        assert!(w
            .events
            .iter()
            .all(|e| e.prompt.len() <= MAX_STORED_PROMPT_BYTES + 1));
        assert!(w.recent_prompts().len() <= HISTORY_SCAN_LIMIT);
    }

    #[test]
    fn strong_links_follow_payment_not_ja3() {
        let store = StateStore::new();
        // Attacker ring: shared card.
        for acct in ["atk1", "atk2", "atk3"] {
            let mut e = test_event(acct, "hi");
            e.payment_method_hash = Some("card-ring".into());
            e.ja3_hash = Some("common-library-ja3".into());
            store.ingest(&e);
        }
        // Bystanders: same HTTP library, own cards.
        for acct in ["victim1", "victim2"] {
            let mut e = test_event(acct, "hi");
            e.ip_address = "198.51.100.7".parse().unwrap();
            e.payment_method_hash = Some(format!("card-{acct}"));
            e.ja3_hash = Some("common-library-ja3".into());
            store.ingest(&e);
        }
        // Everyone lands in one cluster through the shared JA3 ...
        let cid = store.get_cluster("atk1").unwrap();
        assert!(store.cluster_members(cid).contains("victim1"));
        // ... but only the ring is strongly linked.
        let strong = store.strongly_linked("atk1");
        assert_eq!(strong.len(), 3);
        assert!(!strong.contains("victim1"));
        assert_eq!(store.strongly_linked("victim1").len(), 1);
    }

    #[test]
    fn idle_accounts_and_their_index_entries_are_evicted() {
        let store = StateStore::new();
        let old = Utc::now() - Duration::hours(30);
        for acct in ["old1", "old2", "old3"] {
            let mut e = test_event(acct, "hi");
            e.timestamp = old;
            e.payment_method_hash = Some("shared".into());
            e.system_prompt_hash = Some("pre".into());
            store.ingest(&e);
        }
        let mut live = test_event("live", "hi");
        live.ip_address = "192.0.2.1".parse().unwrap();
        store.ingest(&live);
        assert!(store.get_cluster("old1").is_some());

        assert_eq!(store.housekeeping_pass(Utc::now()), 3);
        assert_eq!(store.n_accounts(), 1);
        assert!(store.get_window("live").is_some());
        assert_eq!(store.n_clusters(), 0);
        assert!(store.get_cluster("old1").is_none());
        assert!(store.payment_idx.is_empty());
        assert_eq!(store.accounts_with_preamble_hash("pre"), 0);
    }
}
