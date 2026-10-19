// glasswally/src/ioc_feed.rs
//
// Cross-provider IOC sharing protocol.
//
// Format: signed NDJSON — one IocFeedEntry per line.
// Signing: HMAC-SHA256(canonical_bundle_json, shared_key).
//
// Protocol design goals:
//   - Zero additional infrastructure (no TAXII server, no Kafka)
//   - Single-file NDJSON feed consumable by any provider
//   - Tamper-evident: entries with invalid signatures are silently dropped
//   - Fresh-only: entries with last_seen > 24h are skipped on ingest
//
// Workflow:
//   Provider A detects cluster → writes ioc_feed.ndjson
//   Provider B fetches that feed → IocFeedConsumer::consume()
//   Consumer pre-scores all accounts/IPs/JA3s in the bundle
//   Cluster graph at B immediately incorporates the IOCs
//
// This means detecting a campaign at Anthropic auto-raises risk scores
// at OpenAI/Google/Mistral for the same IPs/JA3s — before the campaign
// switches target providers.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::events::IocBundle;

type HmacSha256 = Hmac<sha2::Sha256>;

// ── Feed entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocFeedEntry {
    pub schema_version: String, // "glasswally/ioc/v1"
    pub provider_id: String,    // e.g. "anthropic", "openai", "mistral"
    pub bundle: IocBundle,
    pub signature: String, // hex(HMAC-SHA256(canonical_json, key))
    pub exported_at: DateTime<Utc>,
}

/// Minimum acceptable length for an IOC feed signing/verification key.
/// Short or empty keys are rejected outright — there is intentionally no
/// "dev key" fallback, because this is open-source and any hardcoded key
/// would let an attacker forge cross-provider IOC bundles.
pub const MIN_IOC_KEY_LEN: usize = 32;

/// Largest feed file `consume_file` will read into memory.
pub const MAX_FEED_BYTES: u64 = 64 * 1024 * 1024;

/// Tolerated clock skew for `last_seen` timestamps in the future. A bundle
/// dated further ahead would stay "fresh" indefinitely.
const MAX_FUTURE_SKEW: Duration = Duration::minutes(5);

/// Bytes covered by the HMAC. Binds schema version and provider id to the
/// bundle so a relay can't relabel a signed bundle as coming from a
/// different provider (or a different schema) without breaking the MAC.
fn signing_input(schema_version: &str, provider_id: &str, bundle: &IocBundle) -> Vec<u8> {
    let bundle_json = serde_json::to_string(bundle).unwrap_or_default();
    // serde_json string encoding makes the fields unambiguous to split.
    serde_json::to_vec(&(schema_version, provider_id, bundle_json)).unwrap_or_default()
}

impl IocFeedEntry {
    pub fn new(
        bundle: IocBundle,
        provider_id: impl Into<String>,
        signing_key: &[u8],
    ) -> Result<Self> {
        let provider_id = provider_id.into();
        let schema_version = "glasswally/ioc/v1".to_string();
        let signature = hmac_sign(
            &signing_input(&schema_version, &provider_id, &bundle),
            signing_key,
        )?;
        Ok(Self {
            schema_version,
            provider_id,
            bundle,
            signature,
            exported_at: Utc::now(),
        })
    }

    /// Verify the HMAC signature. Constant-time comparison.
    /// Fails closed: an empty/short key or a signing error yields `false`.
    pub fn verify(&self, key: &[u8]) -> bool {
        let input = signing_input(&self.schema_version, &self.provider_id, &self.bundle);
        let expected = match hmac_sign(&input, key) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        // Constant-time XOR comparison
        let a = expected.as_bytes();
        let b = self.signature.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
    }

    /// True if this IOC was active in the last 24 hours.
    /// Rejects bundles dated in the future (beyond clock skew), which would
    /// otherwise never age out.
    pub fn is_fresh(&self) -> bool {
        let age = Utc::now() - self.bundle.last_seen;
        age < Duration::hours(24) && age > -MAX_FUTURE_SKEW
    }

    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default() + "\n"
    }
}

// ── Feed generator ────────────────────────────────────────────────────────────

pub struct IocFeedGenerator {
    provider_id: String,
    signing_key: Vec<u8>,
    entries: Vec<IocFeedEntry>,
}

impl IocFeedGenerator {
    pub fn new(provider_id: impl Into<String>, signing_key: Vec<u8>) -> Self {
        Self {
            provider_id: provider_id.into(),
            signing_key,
            entries: Vec::new(),
        }
    }

    /// Add a bundle. Only bundles with confidence ≥ 0.70 are exported.
    pub fn add(&mut self, bundle: IocBundle) {
        if bundle.confidence < 0.70 {
            return;
        }
        match IocFeedEntry::new(bundle, &self.provider_id, &self.signing_key) {
            Ok(entry) => self.entries.push(entry),
            Err(e) => {
                tracing::error!("IOC bundle signing failed, dropping bundle: {e}");
            }
        }
    }

    /// Serialize all entries as an NDJSON string.
    pub fn export_ndjson(&self) -> String {
        self.entries.iter().map(|e| e.to_jsonl()).collect()
    }

    /// Append all entries to a file.
    pub async fn export_to_file(&self, path: &Path) -> Result<()> {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        let ndjson = self.export_ndjson();
        if ndjson.is_empty() {
            return Ok(());
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        f.write_all(ndjson.as_bytes()).await?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Feed consumer ─────────────────────────────────────────────────────────────

pub struct IocFeedConsumer {
    verification_key: Vec<u8>,
    min_confidence: f32,
}

impl IocFeedConsumer {
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self {
            verification_key,
            min_confidence: 0.70,
        }
    }

    pub fn with_min_confidence(mut self, threshold: f32) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Parse and verify an NDJSON feed string. Returns only valid, fresh entries.
    pub fn consume(&self, ndjson: &str) -> Vec<IocFeedEntry> {
        ndjson
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                serde_json::from_str::<IocFeedEntry>(line).ok()
            })
            .filter(|e| {
                e.verify(&self.verification_key)
                    && e.is_fresh()
                    && e.bundle.confidence >= self.min_confidence
            })
            .collect()
    }

    /// Read and consume from a file.
    pub async fn consume_file(&self, path: &Path) -> Result<Vec<IocFeedEntry>> {
        let len = tokio::fs::metadata(path).await?.len();
        if len > MAX_FEED_BYTES {
            anyhow::bail!(
                "IOC feed {} too large ({} bytes, max {})",
                path.display(),
                len,
                MAX_FEED_BYTES
            );
        }
        let content = tokio::fs::read_to_string(path).await?;
        Ok(self.consume(&content))
    }
}

// ── Feed publisher — Phase 3 ──────────────────────────────────────────────────
// HTTP POST publisher for cross-provider IOC feed distribution.
// Configured with a list of peer endpoints; signs and pushes high-confidence
// bundles immediately on detection (push model) and also writes a local NDJSON
// file for polling peers (pull model).

#[derive(Debug, Clone)]
pub struct PublisherConfig {
    pub provider_id: String,
    pub signing_key: Vec<u8>,
    /// Peer endpoints to push to (e.g. "https://ioc.openai.glasswally.io/ingest")
    pub push_urls: Vec<String>,
    /// Local file for pull-based peers
    pub local_path: Option<std::path::PathBuf>,
    pub min_confidence: f32,
}

pub struct IocFeedPublisher {
    config: PublisherConfig,
    generator: tokio::sync::Mutex<IocFeedGenerator>,
}

impl IocFeedPublisher {
    pub fn new(config: PublisherConfig) -> Self {
        let generator =
            IocFeedGenerator::new(config.provider_id.clone(), config.signing_key.clone());
        Self {
            config,
            generator: tokio::sync::Mutex::new(generator),
        }
    }

    /// Submit a bundle; signs and dispatches immediately if confidence is sufficient.
    pub async fn submit(&self, bundle: IocBundle) -> Result<()> {
        if bundle.confidence < self.config.min_confidence {
            return Ok(());
        }

        let entry = IocFeedEntry::new(bundle, &self.config.provider_id, &self.config.signing_key)?;
        let line = entry.to_jsonl();

        // Write to local file
        if let Some(path) = &self.config.local_path {
            use tokio::fs::OpenOptions;
            use tokio::io::AsyncWriteExt;
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            f.write_all(line.as_bytes()).await?;
        }

        // Push to peer endpoints
        for url in &self.config.push_urls {
            let url = url.clone();
            let body = line.clone();
            tokio::spawn(async move {
                // In production: use reqwest::Client::post(url).body(body).send().await
                tracing::debug!("IOC push to {} payload_bytes={}", url, body.len());
            });
        }

        let mut gen = self.generator.lock().await;
        gen.add(entry.bundle);
        Ok(())
    }

    /// Export all accumulated entries as NDJSON.
    pub async fn export_ndjson(&self) -> String {
        self.generator.lock().await.export_ndjson()
    }
}

// ── HTTP ingest endpoint (pull-model consumer) ────────────────────────────────
// Polls a remote peer's NDJSON endpoint periodically and ingests fresh entries.

pub struct FeedPoller {
    pub peer_urls: Vec<String>,
    pub consumer: IocFeedConsumer,
    pub poll_interval: std::time::Duration,
}

impl FeedPoller {
    pub fn new(peer_urls: Vec<String>, verification_key: Vec<u8>, poll_interval_secs: u64) -> Self {
        Self {
            peer_urls,
            consumer: IocFeedConsumer::new(verification_key),
            poll_interval: std::time::Duration::from_secs(poll_interval_secs),
        }
    }

    /// Background polling loop.  In production, HTTP GET → consume() → apply to StateStore.
    pub async fn poll_loop<F>(self, _on_bundle: F)
    where
        F: FnMut(IocFeedEntry) + Send + 'static,
    {
        loop {
            tokio::time::sleep(self.poll_interval).await;
            for url in &self.peer_urls {
                tracing::debug!("Polling IOC feed from {}", url);
                // In production:
                //   let body = reqwest::get(url).await?.text().await?;
                //   let entries = self.consumer.consume(&body);
                //   for entry in entries { on_bundle(entry); }
            }
        }
    }
}

// ── HMAC helper ───────────────────────────────────────────────────────────────

fn hmac_sign(data: &[u8], key: &[u8]) -> Result<String> {
    // No dev-key fallback by design: a hardcoded key in an open-source
    // project would let anyone forge signed IOC bundles and poison the
    // cross-provider trust channel. Reject weak/empty keys outright.
    if key.len() < MIN_IOC_KEY_LEN {
        anyhow::bail!(
            "IOC feed key too short ({} bytes); require >= {} bytes of high-entropy key material",
            key.len(),
            MIN_IOC_KEY_LEN
        );
    }
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn bundle(last_seen: DateTime<Utc>) -> IocBundle {
        IocBundle {
            cluster_id: 1,
            ip_addresses: vec!["10.0.0.1".into()],
            ip_subnets: vec![],
            payment_hashes: vec![],
            ja3_hashes: vec![],
            ja3s_hashes: vec![],
            header_order_hashes: vec![],
            h2_fingerprints: vec![],
            watermark_tokens: vec![],
            account_ids: vec!["a".into()],
            country_codes: vec![],
            first_seen: last_seen,
            last_seen,
            total_requests: 1,
            targeted_capabilities: vec![],
            confidence: 0.9,
            timestamp: last_seen,
        }
    }

    #[test]
    fn roundtrip_verifies() {
        let e = IocFeedEntry::new(bundle(Utc::now()), "provider-a", KEY).unwrap();
        let got = IocFeedConsumer::new(KEY.to_vec()).consume(&e.to_jsonl());
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn relabeled_provider_fails_verification() {
        let mut e = IocFeedEntry::new(bundle(Utc::now()), "provider-a", KEY).unwrap();
        e.provider_id = "provider-b".into();
        assert!(!e.verify(KEY));
    }

    #[test]
    fn future_dated_bundle_is_not_fresh() {
        let e = IocFeedEntry::new(bundle(Utc::now() + Duration::days(365)), "p", KEY).unwrap();
        assert!(!e.is_fresh());
    }
}
