// glasswally/src/workers/watermark.rs
//
// Response watermarking — statistical attribution signatures.
//
// Embeds imperceptible zero-width Unicode markers in responses sent to
// flagged accounts. If those patterns appear in a public model release,
// distillation is confirmed and the campaign is attributed.
//
// Mechanism:
//   - 32-bit account-specific mark: HMAC-SHA256(secret, "gw_wm_v1:" || account_id)
//     The secret matters: with a plain hash of the account id, anyone who
//     knows (or guesses) an account id could compute that account's mark,
//     plant it in a dataset and frame the account as the leak source — or
//     confirm and strip their own mark with certainty.
//   - Encoded as ZWJ (bit=1) / ZWNJ (bit=0) inserted after spaces in text
//   - Invisible to readers, survives most copy-paste operations
//   - Detectable by scanning for ZWJ/ZWNJ sequences, comparing to registry
//
// This worker detects meta-attacks against the watermarking system:
//   - Prompts asking about invisible Unicode characters (probing)
//   - Zero-width characters arriving in inbound prompts (strip attempts)
//   - Accounts flagged for canary injection (returning watermarked content)

use chrono::Utc;
use serde_json::json;
use sha2::Sha256;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const ZWJ: char = '\u{200D}'; // zero-width joiner   → bit 1
const ZWNJ: char = '\u{200C}'; // zero-width non-joiner → bit 0

/// Minimum length of the watermark secret.
pub const MIN_WATERMARK_KEY_LEN: usize = 32;

/// Generate 32 deterministic watermark bits for an account.
/// Derived from HMAC-SHA256(key, "gw_wm_v1:" || account_id). Returns None if
/// the key is too short — there is deliberately no default key.
pub fn account_watermark_bits(key: &[u8], account_id: &str) -> Option<[bool; 32]> {
    use hmac::{Hmac, Mac};
    if key.len() < MIN_WATERMARK_KEY_LEN {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(b"gw_wm_v1:");
    mac.update(account_id.as_bytes());
    let d = mac.finalize().into_bytes();
    let mut bits = [false; 32];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = (d[i / 8] >> (i % 8)) & 1 == 1;
    }
    Some(bits)
}

/// Embed the account's watermark into a response string.
///
/// Inserts ZWJ (bit=1) or ZWNJ (bit=0) immediately after each space.
/// The 32-bit sequence cycles across the full text.
/// Returns None if the key is unusable (the text must then be sent unmarked
/// and the failure surfaced, never marked with a guessable pattern).
pub fn embed(text: &str, account_id: &str, key: &[u8]) -> Option<String> {
    let bits = account_watermark_bits(key, account_id)?;
    let mut out = String::with_capacity(text.len() + text.len() / 5);
    let mut bit_idx = 0usize;

    for ch in text.chars() {
        out.push(ch);
        if ch == ' ' {
            out.push(if bits[bit_idx % 32] { ZWJ } else { ZWNJ });
            bit_idx += 1;
        }
    }
    Some(out)
}

/// Scan text for a watermark matching any of the known accounts.
/// Returns (account_id, confidence 0..1) if ≥85% of bits match.
pub fn detect(text: &str, accounts: &[String], key: &[u8]) -> Option<(String, f32)> {
    let extracted: Vec<bool> = text
        .chars()
        .filter(|&c| c == ZWJ || c == ZWNJ)
        .map(|c| c == ZWJ)
        .collect();

    // Require a meaningful sample: with too few bits the 0.85 threshold is
    // hit by chance, producing false attributions when scanning many
    // accounts. 32 bits = one full key period.
    if extracted.len() < 32 {
        return None;
    }

    let check_len = extracted.len().min(128);
    for account_id in accounts {
        let expected = account_watermark_bits(key, account_id)?;
        // Try every phase offset: a single inserted/removed space (or a
        // leading stripped marker) shifts the bitstream, which would
        // otherwise defeat detection entirely.
        let mut best = 0usize;
        for phase in 0..32 {
            let matches = (0..check_len)
                .filter(|&i| extracted[i] == expected[(i + phase) % 32])
                .count();
            best = best.max(matches);
        }
        let confidence = best as f32 / check_len as f32;
        // Require both a high ratio AND a minimum absolute match count so a
        // short noisy sample can't cross the threshold by luck.
        if confidence >= 0.85 && best >= 28 {
            return Some((account_id.clone(), confidence));
        }
    }
    None
}

// ── Detection worker ──────────────────────────────────────────────────────────

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // ── Watermark probe detection ─────────────────────────────────────────────
    // Attacker testing whether our responses carry invisible markers.
    let probe_terms = [
        "zero-width",
        "invisible character",
        "hidden character",
        "unicode steganograph",
        "watermark detection",
        "\\u200",
        "u200c",
        "u200d",
        "u200b",
        "zwsp",
        "zero width",
        "strip whitespace",
        "normalize unicode",
        "remove formatting characters",
    ];
    // Canonical form, but probe for the raw markers separately below —
    // normalisation strips them.
    let pl = super::normalize_prompt(&event.prompt);
    let probe_hits: Vec<&str> = probe_terms
        .iter()
        .filter(|&&t| pl.contains(t))
        .copied()
        .collect();
    if !probe_hits.is_empty() {
        score += 0.50;
        evidence.push(format!("wm_probe:{}", probe_hits.join(",")));
    }

    // ── ZWJ/ZWNJ in incoming prompt ───────────────────────────────────────────
    // Attacker reflecting watermarked text back, or testing strip routines.
    let zw_count = event
        .prompt
        .chars()
        .filter(|&c| c == ZWJ || c == ZWNJ || c == '\u{200B}')
        .count();
    if zw_count > 0 {
        score += 0.35;
        evidence.push(format!("zwsp_in_prompt:{}_markers", zw_count));
    }

    // ── Account already under active watermark surveillance ───────────────────
    if store.is_watermarked(&event.account_id) {
        score += 0.05;
        evidence.push("account_watermarked".into());
    }

    if score == 0.0 {
        return None;
    }

    Some(DetectionSignal {
        worker: WorkerKind::Watermark,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence: 0.80,
        evidence,
        meta: [
            ("zw_count".into(), json!(zw_count)),
            ("probe_hits".into(), json!(probe_hits.len())),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn watermark_roundtrip_requires_the_key() {
        let text = "a ".repeat(80);
        let marked = embed(&text, "acct-1", KEY).unwrap();
        let accounts = vec!["acct-0".to_string(), "acct-1".to_string()];
        assert_eq!(detect(&marked, &accounts, KEY).unwrap().0, "acct-1");
        // A different secret yields a different mark: knowing the account id
        // alone is not enough to forge or recognise it.
        let other = b"ffffffffffffffffffffffffffffffff";
        assert_ne!(
            account_watermark_bits(KEY, "acct-1"),
            account_watermark_bits(other, "acct-1")
        );
        assert!(embed(&text, "acct-1", b"short").is_none());
    }
}
