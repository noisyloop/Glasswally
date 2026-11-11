// Phase 1 (original)
pub mod biometric;
pub mod cot;
pub mod embed;
pub mod fingerprint;
pub mod h2_grpc;
pub mod hydra;
pub mod pivot;
pub mod timing_cluster;
pub mod velocity;
pub mod watermark;
// Phase 1 (new signals)
pub mod asn_classifier;
pub mod refusal_probe;
pub mod role_preamble;
pub mod session_gap;
pub mod token_budget;
// Phase 3
pub mod sequence_model;

use crate::events::{ApiEvent, DetectionSignal};
use crate::state::window::StateStore;

/// Canonical form of a prompt for phrase matching: lowercase, runs of any
/// whitespace collapsed to one space, invisible/format characters removed,
/// and full-width ASCII folded to ASCII.
///
/// Matching the raw prompt made every phrase detector trivially evadable
/// without changing what the model reads: "step  by step" (two spaces),
/// "step\nby step", "st\u{200b}ep by step" or "ｓｔｅｐ ｂｙ ｓｔｅｐ" all
/// slipped past the Aho-Corasick and substring patterns.
///
/// Not handled: cross-script homoglyphs (Cyrillic "е" for Latin "e") and
/// paraphrase — see lab.md.
pub fn normalize_prompt(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for c in text.chars() {
        let c = match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        };
        if matches!(c,
            '\u{00AD}' | '\u{034F}' | '\u{180E}' | '\u{FEFF}'
            | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}')
        {
            continue;
        }
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// Run all 16 detection workers concurrently and collect their signals.
/// Workers returning None (insufficient data / no signal) are silently dropped.
pub async fn run_all(event: &ApiEvent, store: &StateStore) -> Vec<DetectionSignal> {
    let (fp, vel, cot_s, hyd, piv, wm, em, tc, h2, bio, asn, role, gap, tok, ref_p, seq) = tokio::join!(
        fingerprint::analyze(event, store),
        velocity::analyze(event, store),
        cot::analyze(event, store),
        hydra::analyze(event, store),
        pivot::analyze(event, store),
        watermark::analyze(event, store),
        embed::analyze(event, store),
        timing_cluster::analyze(event, store),
        h2_grpc::analyze(event, store),
        biometric::analyze(event, store),
        asn_classifier::analyze(event, store),
        role_preamble::analyze(event, store),
        session_gap::analyze(event, store),
        token_budget::analyze(event, store),
        refusal_probe::analyze(event, store),
        sequence_model::analyze(event, store),
    );

    [
        fp, vel, cot_s, hyd, piv, wm, em, tc, h2, bio, asn, role, gap, tok, ref_p, seq,
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::normalize_prompt;

    #[test]
    fn normalization_defeats_spacing_and_invisible_char_evasion() {
        for evasive in [
            "Explain  STEP\tby\nstep",
            "explain st\u{200b}ep by st\u{200d}ep",
            "ｅｘｐｌａｉｎ　ｓｔｅｐ ｂｙ ｓｔｅｐ",
            "  explain step\u{00a0}by step  ",
        ] {
            assert_eq!(normalize_prompt(evasive), "explain step by step");
        }
    }
}
