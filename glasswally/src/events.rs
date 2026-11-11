// glasswally/src/events.rs
//
// Shared event types and all domain types flowing through Glasswally.
// These mirror the BPF structs in glasswally-ebpf/src/main.rs
// and must be kept in sync (same repr(C) layout).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub const MAX_BUF: usize = 4096;

// ── Ingest-boundary limits ────────────────────────────────────────────────────
// Every field of an ApiEvent is ultimately client- or gateway-supplied. These
// caps are applied once, in `ApiEvent::sanitize`, before the event reaches the
// state store or any worker, so no later stage has to reason about unbounded
// or control-character-laden input.

/// Events whose account id is empty or longer than this are dropped.
pub const MAX_ACCOUNT_ID_BYTES: usize = 256;
/// Prompt bytes the workers will analyse. Longer prompts keep their head and
/// tail (extraction instructions sit at one end or the other).
pub const MAX_ANALYZED_PROMPT_BYTES: usize = 32 * 1024;
/// Cap for short metadata strings (user agent, model, hashes, ASN org ...).
pub const MAX_FIELD_BYTES: usize = 512;
/// Cap on the number of header names kept for fingerprinting.
pub const MAX_HEADERS: usize = 64;
/// Cap on a single header name.
pub const MAX_HEADER_NAME_BYTES: usize = 64;
/// Timestamps further in the future than this are replaced with "now": a
/// future-dated event never ages out of the sliding windows.
pub const MAX_FUTURE_SKEW_SECS: i64 = 300;

/// Largest index `<= max` that is a char boundary of `s`.
fn floor_boundary(s: &str, max: usize) -> usize {
    let mut i = max.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Smallest index `>= min` that is a char boundary of `s`.
fn ceil_boundary(s: &str, min: usize) -> usize {
    let mut i = min.min(s.len());
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Shorten `s` to at most `max` bytes, keeping the first three quarters and
/// the last quarter. Never splits a multi-byte character.
pub fn truncate_middle(s: &str, max: usize) -> std::borrow::Cow<'_, str> {
    if s.len() <= max {
        return std::borrow::Cow::Borrowed(s);
    }
    let head = floor_boundary(s, max - max / 4);
    let tail = ceil_boundary(s, s.len() - max / 4);
    let mut out = String::with_capacity(head + (s.len() - tail) + 1);
    out.push_str(&s[..head]);
    out.push('\n');
    out.push_str(&s[tail..]);
    std::borrow::Cow::Owned(out)
}

/// Remove control characters (ESC, CR, NUL ...) so a client-chosen string
/// cannot inject terminal escape sequences or forge log lines when it is
/// later echoed in an alert.
pub fn strip_control(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().any(char::is_control) {
        std::borrow::Cow::Owned(s.chars().filter(|c| !c.is_control()).collect())
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// In-place: strip control characters and cap at `max` bytes.
fn clean_field(s: &mut String, max: usize) {
    if let std::borrow::Cow::Owned(clean) = strip_control(s) {
        *s = clean;
    }
    if s.len() > max {
        s.truncate(floor_boundary(s, max));
    }
}

fn clean_opt(s: &mut Option<String>, max: usize) {
    if let Some(v) = s {
        clean_field(v, max);
    }
}

// ── Raw events from BPF ───────────────────────────────────────────────────────

/// Raw SSL event from kernel — plaintext captured at ssl_write/ssl_read.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RawSslEvent {
    pub pid: u32,
    pub tid: u32,
    pub fd: i32,
    pub direction: u8, // 0=write, 1=read
    pub buf_len: u32,
    pub buf: [u8; MAX_BUF],
}

/// Direction of SSL data capture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslDirection {
    Write, // outbound — API request (prompt)
    Read,  // inbound  — API response
}

impl From<u8> for SslDirection {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Read,
            _ => Self::Write,
        }
    }
}

/// Raw TCP connection event from kernel.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RawConnEvent {
    pub pid: u32,
    pub fd: i32,
    pub src_ip: u32, // network byte order
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub kind: u8, // 0=connect, 1=close
}

// ── Parsed / enriched events ──────────────────────────────────────────────────

/// Parsed SSL event — text extracted, pid correlated to account.
#[derive(Debug, Clone)]
pub struct SslCapture {
    pub pid: u32,
    pub fd: i32,
    pub direction: SslDirection,
    pub text: String, // UTF-8 decoded (lossy)
    pub timestamp: DateTime<Utc>,
    pub account_id: Option<String>, // correlated from pid→account map
    pub conn_key: Option<ConnKey>,
}

/// TCP connection 5-tuple — used to correlate SSL events with accounts.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl std::fmt::Display for ConnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} → {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

/// HTTP request reconstructed from SSL captures.
/// Multiple SSL events may be needed to reconstruct one HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub conn_key: Option<ConnKey>,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>, // in arrival order (for header fingerprint)
    pub body: String,
    pub timestamp: DateTime<Utc>,
    pub account_id: Option<String>,
    pub model: Option<String>,  // extracted from path or body
    pub prompt: Option<String>, // extracted from JSON body
    pub token_count: Option<u32>,
    /// Hash of the system prompt / role preamble, when the body carries one.
    #[serde(default)]
    pub system_prompt_hash: Option<String>,
    /// Further account ids derived from *other* credentials presented on the
    /// same request (see `http_reconstruct`). Empty for a normal request.
    #[serde(default)]
    pub alt_account_ids: Vec<String>,
}

impl HttpRequest {
    /// Extract headers in arrival order (for header entropy analysis).
    pub fn header_names_in_order(&self) -> Vec<String> {
        self.headers.iter().map(|(k, _)| k.to_lowercase()).collect()
    }

    /// Find a specific header value (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

// ── HTTP/2 SETTINGS frame fingerprint ────────────────────────────────────────
// Every HTTP/2 client sends a SETTINGS frame with fixed defaults per library.
// python-httpx, Go net/http2, curl, Chrome all ship with distinct values.

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct H2Settings {
    pub header_table_size: u32,
    pub enable_push: u8,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
    /// SHA256[:8] over all SETTINGS values — canonical fingerprint string.
    pub fingerprint: String,
}

impl H2Settings {
    pub fn compute_fingerprint(&mut self) {
        use sha2::{Digest, Sha256};
        let canonical = format!(
            "{},{},{:?},{},{},{:?}",
            self.header_table_size,
            self.enable_push,
            self.max_concurrent_streams,
            self.initial_window_size,
            self.max_frame_size,
            self.max_header_list_size,
        );
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        self.fingerprint = hex::encode(&h.finalize()[..16]);
    }
}

// ── TLS library identification ────────────────────────────────────────────────

/// Which TLS library is the client using — detected from uprobe symbol path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TlsLibrary {
    #[default]
    Unknown,
    OpenSsl,   // libssl.so — most Python/Ruby/Node clients
    BoringSSL, // Chrome, some Go programs, android
    Nss,       // Firefox, curl on some distros
    GoTls,     // Go crypto/tls — pure-Go, no libssl
}

impl std::fmt::Display for TlsLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::OpenSsl => write!(f, "openssl"),
            Self::BoringSSL => write!(f, "boringssl"),
            Self::Nss => write!(f, "nss"),
            Self::GoTls => write!(f, "go_tls"),
        }
    }
}

// ── Canary token ───────────────────────────────────────────────────────────────
// Unique tokens embedded in responses to high-risk accounts.
// If a token appears in a scraped dataset / future training request →
// distillation confirmed and the source campaign is attributed.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    pub token: String, // unique 32-char hex string
    pub account_id: String,
    pub request_id: String,
    pub inserted_at: DateTime<Utc>,
    pub triggered: bool, // true once token seen in inbound request
    pub trigger_ts: Option<DateTime<Utc>>,
}

impl CanaryToken {
    pub fn generate(account_id: &str, request_id: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"gw_canary:");
        h.update(account_id.as_bytes());
        h.update(b":");
        h.update(request_id.as_bytes());
        h.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        let token = hex::encode(&h.finalize()[..16]);
        Self {
            token,
            account_id: account_id.to_string(),
            request_id: request_id.to_string(),
            inserted_at: Utc::now(),
            triggered: false,
            trigger_ts: None,
        }
    }
}

// ── Parsed API event ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    pub request_id: String,
    pub account_id: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub model: String,
    pub prompt: String,
    pub token_count: u32,
    pub payment_method_hash: Option<String>,
    pub org_id: Option<String>,
    pub country_code: String,
    pub header_order: Vec<String>, // from eBPF HTTP reconstruction
    pub ja3_hash: Option<String>,  // TLS ClientHello fingerprint
    pub ja3s_hash: Option<String>, // TLS ServerHello fingerprint (Tier 1)
    pub h2_settings: Option<H2Settings>, // HTTP/2 SETTINGS frame (Tier 2)
    pub tls_library: Option<TlsLibrary>, // detected TLS implementation
    pub asn_number: Option<u32>,   // BGP ASN of source IP (Phase 1)
    pub asn_org: Option<String>,   // ASN org name (e.g. "AMAZON-AES", "AS-CHOOPA")
    pub max_tokens: Option<u32>,   // requested max_tokens from API body
    pub system_prompt_hash: Option<String>, // SHA256[:8] of system prompt / role preamble
    pub campaign_label: Option<String>,
}

impl ApiEvent {
    /// Bound and clean every client-influenced field. Must be called before
    /// the event is ingested. Returns `false` when the event cannot be
    /// attributed safely (unusable account id) and should be dropped.
    pub fn sanitize(&mut self) -> bool {
        // The account id is a map key everywhere; never rewrite it (that
        // could merge two accounts) — reject instead.
        if self.account_id.is_empty()
            || self.account_id.len() > MAX_ACCOUNT_ID_BYTES
            || self.account_id.chars().any(char::is_control)
        {
            return false;
        }
        let latest = Utc::now() + chrono::Duration::seconds(MAX_FUTURE_SKEW_SECS);
        if self.timestamp > latest {
            self.timestamp = Utc::now();
        }
        if let std::borrow::Cow::Owned(p) = truncate_middle(&self.prompt, MAX_ANALYZED_PROMPT_BYTES)
        {
            self.prompt = p;
        }
        clean_field(&mut self.request_id, MAX_FIELD_BYTES);
        clean_field(&mut self.user_agent, MAX_FIELD_BYTES);
        clean_field(&mut self.model, MAX_FIELD_BYTES);
        clean_field(&mut self.country_code, 8);
        clean_opt(&mut self.payment_method_hash, MAX_FIELD_BYTES);
        clean_opt(&mut self.org_id, MAX_FIELD_BYTES);
        clean_opt(&mut self.ja3_hash, MAX_FIELD_BYTES);
        clean_opt(&mut self.ja3s_hash, MAX_FIELD_BYTES);
        clean_opt(&mut self.asn_org, MAX_FIELD_BYTES);
        clean_opt(&mut self.system_prompt_hash, MAX_FIELD_BYTES);
        clean_opt(&mut self.campaign_label, MAX_FIELD_BYTES);
        if let Some(h2) = &mut self.h2_settings {
            clean_field(&mut h2.fingerprint, MAX_FIELD_BYTES);
        }
        self.header_order.truncate(MAX_HEADERS);
        for h in &mut self.header_order {
            clean_field(h, MAX_HEADER_NAME_BYTES);
        }
        true
    }

    /// Map a reconstructed HTTP request (eBPF capture path) onto the shared
    /// pipeline event type. Fields the kernel capture cannot know yet
    /// (JA3, ASN, geo, payment) are left unset; workers that need them
    /// simply see no signal. Returns None when no account could be derived.
    /// One event per credential presented on the request (see
    /// `HttpRequest::alt_account_ids`). A normal request yields one event.
    pub fn all_from_http_request(req: &HttpRequest) -> Vec<ApiEvent> {
        let Some(primary) = Self::from_http_request(req) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(1 + req.alt_account_ids.len());
        for alt in &req.alt_account_ids {
            let mut ev = primary.clone();
            ev.request_id = format!(
                "{}-{}",
                alt,
                req.timestamp.timestamp_nanos_opt().unwrap_or(0)
            );
            ev.account_id = alt.clone();
            out.push(ev);
        }
        out.insert(0, primary);
        out
    }

    pub fn from_http_request(req: &HttpRequest) -> Option<ApiEvent> {
        let account_id = req.account_id.clone()?;
        Some(ApiEvent {
            request_id: format!(
                "{}-{}",
                account_id,
                req.timestamp.timestamp_nanos_opt().unwrap_or(0)
            ),
            account_id,
            timestamp: req.timestamp,
            ip_address: req
                .conn_key
                .as_ref()
                .map(|k| k.src_ip)
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            user_agent: req.header("user-agent").unwrap_or("").to_string(),
            model: req.model.clone().unwrap_or_default(),
            prompt: req.prompt.clone().unwrap_or_default(),
            token_count: req.token_count.unwrap_or(0),
            payment_method_hash: None,
            org_id: None,
            country_code: String::new(),
            header_order: req.header_names_in_order(),
            ja3_hash: None,
            ja3s_hash: None,
            h2_settings: None,
            tls_library: None,
            asn_number: None,
            asn_org: None,
            max_tokens: req.token_count,
            system_prompt_hash: req.system_prompt_hash.clone(),
            campaign_label: None,
        })
    }
}

// ── Detection types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WorkerKind {
    // Core detectors
    Fingerprint, // JA3 mismatch + HTTP header entropy
    Velocity,    // RPH / timing regularity
    Cot,         // Aho-Corasick CoT elicitation patterns
    Semantic,    // legacy; use Embed
    Hydra,       // cluster graph scoring
    Pivot,       // coordinated model switch
    // Tier 1 (original)
    Watermark,     // response watermark probe detection
    Embed,         // semantic similarity — paraphrase-resistant CoT
    TimingCluster, // cross-account synchronized burst detection
    // Tier 2 (original)
    H2Grpc,    // HTTP/2 SETTINGS + gRPC fingerprinting
    Biometric, // behavioral sequence entropy
    // Phase 1 — new signals
    AsnClassifier, // datacenter/hosting provider IP classification
    RolePreamble,  // role injection preamble fingerprinting
    SessionGap,    // inter-session timing regularity (cron detection)
    TokenBudget,   // max_tokens sweep / greedy budget probing
    RefusalProbe,  // safety refusal probe pattern detection
    // Phase 3
    SequenceModel, // Markov chain over prompt topic transitions
}

impl std::fmt::Display for WorkerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::Velocity => write!(f, "velocity"),
            Self::Cot => write!(f, "cot"),
            Self::Semantic => write!(f, "semantic"),
            Self::Hydra => write!(f, "hydra"),
            Self::Pivot => write!(f, "pivot"),
            Self::Watermark => write!(f, "watermark"),
            Self::Embed => write!(f, "embed"),
            Self::TimingCluster => write!(f, "timing_cluster"),
            Self::H2Grpc => write!(f, "h2_grpc"),
            Self::Biometric => write!(f, "biometric"),
            Self::AsnClassifier => write!(f, "asn_classifier"),
            Self::RolePreamble => write!(f, "role_preamble"),
            Self::SessionGap => write!(f, "session_gap"),
            Self::TokenBudget => write!(f, "token_budget"),
            Self::RefusalProbe => write!(f, "refusal_probe"),
            Self::SequenceModel => write!(f, "sequence_model"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub worker: WorkerKind,
    pub account_id: String,
    pub score: f32,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub meta: HashMap<String, serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionKind {
    Monitor,
    RateLimit,
    FlagForReview,
    SuspendAccount,
    ClusterTakedown,
    IntelShare,
    InjectCanary, // mark account for response watermarking + canary injection
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "MONITOR"),
            Self::RateLimit => write!(f, "RATE_LIMIT"),
            Self::FlagForReview => write!(f, "FLAG_FOR_REVIEW"),
            Self::SuspendAccount => write!(f, "SUSPEND_ACCOUNT"),
            Self::ClusterTakedown => write!(f, "CLUSTER_TAKEDOWN"),
            Self::IntelShare => write!(f, "INTEL_SHARE"),
            Self::InjectCanary => write!(f, "INJECT_CANARY"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDecision {
    pub account_id: String,
    pub composite_score: f32,
    pub tier: RiskTier,
    pub signal_scores: HashMap<String, f32>,
    pub top_evidence: Vec<String>,
    pub country_codes: Vec<String>,
    pub cluster_id: Option<u32>,
    pub n_requests_seen: usize,
    pub action: ActionKind,
    pub timestamp: DateTime<Utc>,
    pub ground_truth: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementAction {
    pub action_type: ActionKind,
    pub account_id: Option<String>,
    pub cluster_id: Option<u32>,
    pub affected_accounts: Vec<String>,
    pub reason: String,
    pub evidence: Vec<String>,
    pub composite_score: f32,
    pub canary_token: Option<CanaryToken>, // set when action_type == InjectCanary
    pub timestamp: DateTime<Utc>,
}

impl EnforcementAction {
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocBundle {
    pub cluster_id: u32,
    pub ip_addresses: Vec<String>,
    pub ip_subnets: Vec<String>,
    pub payment_hashes: Vec<String>,
    pub ja3_hashes: Vec<String>,
    pub ja3s_hashes: Vec<String>, // Tier 1: server-hello fingerprints
    pub header_order_hashes: Vec<String>,
    pub h2_fingerprints: Vec<String>, // Tier 2: HTTP/2 SETTINGS fingerprints
    pub watermark_tokens: Vec<String>, // triggered canary tokens
    pub account_ids: Vec<String>,
    pub country_codes: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_requests: u64,
    pub targeted_capabilities: Vec<String>,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}

/// Minimal benign event for unit tests across the crate.
#[cfg(test)]
pub(crate) fn test_event(account: &str, prompt: &str) -> ApiEvent {
    ApiEvent {
        request_id: "r".into(),
        account_id: account.into(),
        timestamp: Utc::now(),
        ip_address: "10.0.0.1".parse().unwrap(),
        user_agent: "ua".into(),
        model: "m".into(),
        prompt: prompt.into(),
        token_count: 1,
        payment_method_hash: None,
        org_id: None,
        country_code: "US".into(),
        header_order: vec![],
        ja3_hash: None,
        ja3s_hash: None,
        h2_settings: None,
        tls_library: None,
        asn_number: None,
        asn_org: None,
        max_tokens: None,
        system_prompt_hash: None,
        campaign_label: None,
    }
}

#[cfg(test)]
mod tests {
    use super::test_event as event;
    use super::*;

    #[test]
    fn truncate_middle_respects_char_boundaries() {
        let s = "é".repeat(5000); // 2 bytes each
        let t = truncate_middle(&s, 1001);
        assert!(t.len() <= 1001 + 1);
        assert!(t.starts_with('é') && t.ends_with('é'));
        assert_eq!(truncate_middle("short", 100), "short");
    }

    #[test]
    fn sanitize_bounds_and_cleans_fields() {
        let mut e = event("acct", &"x".repeat(MAX_ANALYZED_PROMPT_BYTES * 4));
        e.model = "claude\x1b[2J\x1b[31mFAKE ALERT".into();
        e.user_agent = "u".repeat(10_000);
        e.header_order = vec!["h".repeat(1000); 500];
        e.timestamp = Utc::now() + chrono::Duration::days(365);
        assert!(e.sanitize());
        assert!(e.prompt.len() <= MAX_ANALYZED_PROMPT_BYTES + 1);
        assert!(!e.model.contains('\x1b'));
        assert_eq!(e.user_agent.len(), MAX_FIELD_BYTES);
        assert_eq!(e.header_order.len(), MAX_HEADERS);
        assert!(e
            .header_order
            .iter()
            .all(|h| h.len() <= MAX_HEADER_NAME_BYTES));
        assert!(e.timestamp <= Utc::now());
    }

    #[test]
    fn sanitize_rejects_unusable_account_ids() {
        assert!(!event("", "p").sanitize());
        assert!(!event(&"a".repeat(MAX_ACCOUNT_ID_BYTES + 1), "p").sanitize());
        assert!(!event("acct\x1b[0m", "p").sanitize());
        assert!(event("sk-normal", "p").sanitize());
    }
}
