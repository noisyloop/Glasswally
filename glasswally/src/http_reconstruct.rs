// glasswally/src/http_reconstruct.rs
//
// HTTP request reconstruction from raw SSL plaintext captures.
//
// SSL events arrive as raw byte chunks — one ssl_write call may contain
// a partial HTTP request, or multiple requests. We reassemble them here
// into structured HttpRequest objects, then extract:
//   - Header names in arrival order (for header fingerprint)
//   - Authorization / x-api-key (→ account_id)
//   - Request body JSON (→ model, prompt, token_count)
//   - User-Agent (for JA3 mismatch detection)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::events::{HttpRequest, SslCapture, SslDirection};

/// Hard cap on the size of a single in-flight (reassembling) HTTP request.
/// Anything larger is dropped rather than buffered — prevents a monitored
/// client from exhausting daemon memory by never completing a request.
const MAX_REQUEST_BYTES: usize = 1024 * 1024; // 1 MiB

/// Hard cap on the number of concurrently reassembling connections.
/// Bounds the per-connection buffer map so a flood of partial requests
/// cannot grow it without limit.
const MAX_CONNS: usize = 8192;

/// Largest Content-Length we will wait for before considering a request
/// "complete at the header boundary". Beyond this we refuse to keep
/// buffering for a body that will never plausibly arrive.
const MAX_CONTENT_LENGTH: usize = 8 * 1024 * 1024; // 8 MiB

/// A reassembling request that has seen no new data for this long is
/// considered abandoned and may be evicted. `flush()` is not wired to a
/// close event, so without this the map would fill with dead partial
/// requests and then refuse to track any new connection at all.
const STALE_AFTER: Duration = Duration::from_secs(30);

// ── HTTP parser ───────────────────────────────────────────────────────────────

/// Reconstruct an HTTP request from a plaintext SSL capture.
/// Returns None if the capture doesn't look like an HTTP request.
pub fn reconstruct(capture: &SslCapture) -> Option<HttpRequest> {
    if capture.direction != SslDirection::Write {
        return None; // Only parse outbound (request) data
    }

    let text = &capture.text;

    // Quick check: must start with HTTP method
    if !looks_like_http_request(text) {
        return None;
    }

    parse_http_request(text, capture)
}

fn looks_like_http_request(text: &str) -> bool {
    text.starts_with("GET ")
        || text.starts_with("POST ")
        || text.starts_with("PUT ")
        || text.starts_with("DELETE ")
        || text.starts_with("PATCH ")
        || text.starts_with("HEAD ")
}

fn parse_http_request(text: &str, capture: &SslCapture) -> Option<HttpRequest> {
    // Split headers from body at \r\n\r\n
    let (header_section, body) = if let Some(idx) = text.find("\r\n\r\n") {
        (&text[..idx], text[idx + 4..].to_string())
    } else if let Some(idx) = text.find("\n\n") {
        (&text[..idx], text[idx + 2..].to_string())
    } else {
        (text, String::new())
    };

    let mut lines = header_section.lines();

    // Request line: METHOD /path HTTP/version
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    // Parse headers — PRESERVE ORDER (critical for fingerprinting)
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_string();
            let value = line[colon + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    // Derive account ids from the presented credentials.
    // In Anthropic's API: x-api-key: sk-ant-... ; OpenAI-compatible APIs use
    // Authorization: Bearer ... . We hash the key — the raw value is never
    // stored.
    //
    // A request may carry several credentials (both headers, or a repeated
    // header). Which one the backend honours is its business and we cannot
    // know it here, so picking one would let a client choose its own
    // identity: send the real key in the header the backend reads and a
    // fresh random value in the header we read, and every request lands on
    // a brand-new "account". Instead the request is attributed to *every*
    // presented credential, so the real account always accumulates it.
    let mut account_ids: Vec<String> = Vec::new();
    for (name, value) in &headers {
        if (name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key"))
            && !value.is_empty()
        {
            let id = derive_account_id(value);
            if !account_ids.contains(&id) {
                account_ids.push(id);
            }
        }
    }
    if account_ids.len() > MAX_CREDENTIALS {
        // Keep both ends: backends take either the first or the last value.
        let tail = account_ids.split_off(account_ids.len() - MAX_CREDENTIALS / 2);
        account_ids.truncate(MAX_CREDENTIALS / 2);
        account_ids.extend(tail);
    }
    let mut account_ids = account_ids.into_iter();
    let account_id = account_ids.next().or_else(|| capture.account_id.clone());
    let alt_account_ids: Vec<String> = account_ids.collect();

    // De-chunk the body if the client used chunked transfer encoding.
    let body = if is_chunked(&headers) {
        dechunk(&body).unwrap_or(body)
    } else {
        body
    };

    // Extract model + prompt from the JSON body. The Content-Type header is
    // client-controlled and matched loosely: gating on an exact, lowercase
    // "json" let `Content-Type: application/JSON` (or no header at all)
    // hide the prompt from every content-based worker.
    let content_type = header_value(&headers, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let parsed = if !body.is_empty()
        && (content_type.contains("json") || body.trim_start().starts_with('{'))
    {
        extract_from_json_body(&body)
    } else {
        BodyFields::default()
    };

    // Extract model from path if not in body
    // Anthropic API: POST /v1/messages, model in body
    // OpenAI compat: POST /v1/chat/completions
    let model = parsed.model.or_else(|| extract_model_from_path(&path));

    Some(HttpRequest {
        conn_key: capture.conn_key.clone(),
        method,
        path,
        headers,
        body,
        timestamp: capture.timestamp,
        account_id,
        model,
        prompt: parsed.prompt,
        token_count: parsed.max_tokens,
        system_prompt_hash: parsed.system_prompt_hash,
        alt_account_ids,
    })
}

/// Distinct credentials attributed per request (first half + last half).
const MAX_CREDENTIALS: usize = 8;

fn is_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    })
}

/// Decode a chunked body. Returns None until the terminating zero-length
/// chunk is present (i.e. the body is still incomplete) or if the framing is
/// malformed.
fn dechunk(body: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut pos = 0usize;
    loop {
        let line_end = pos + bytes[pos..].iter().position(|&b| b == b'\n')?;
        let size_line = std::str::from_utf8(&bytes[pos..line_end]).ok()?;
        // Drop chunk extensions (";name=value") and the trailing CR.
        let size_hex = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        pos = line_end + 1;
        if size == 0 {
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
        let end = pos.checked_add(size)?;
        out.extend_from_slice(bytes.get(pos..end)?);
        pos = end;
        // Skip the CRLF (or bare LF) that closes the chunk.
        if bytes.get(pos) == Some(&b'\r') {
            pos += 1;
        }
        if bytes.get(pos) == Some(&b'\n') {
            pos += 1;
        }
    }
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == name)
        .map(|(_, v)| v.clone())
}

/// Derive a stable account identifier from the API key.
/// We hash it so we never store raw keys.
fn derive_account_id(auth: &str) -> String {
    use sha2::{Digest, Sha256};
    // Extract the key part (after "Bearer " if present)
    // The auth scheme is case-insensitive (RFC 9110 §11.1), so "bearer",
    // "BEARER" and extra whitespace must all map to the same account —
    // otherwise one key can be split into many account ids to dilute
    // per-account signals.
    let auth = auth.trim();
    let key = match auth.split_once(char::is_whitespace) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => rest.trim(),
        _ => auth,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"gw_acct_v1:");
    hasher.update(key.as_bytes());
    // 128-bit truncation: wide enough that an adversary cannot deliberately
    // force account-id collisions to merge into / split out of clusters.
    hex::encode(&hasher.finalize()[..16])
}

#[derive(Default)]
struct BodyFields {
    model: Option<String>,
    prompt: Option<String>,
    max_tokens: Option<u32>,
    system_prompt_hash: Option<String>,
}

/// Text of a message `content` value: either a plain string or an array of
/// content blocks (`[{"type":"text","text":"..."}, ...]`). The block form is
/// the standard shape for multimodal / tool-use requests; reading only the
/// string form left every such prompt empty.
fn content_text(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    let parts: Vec<&str> = v
        .as_array()?
        .iter()
        .filter_map(|block| block["text"].as_str())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

fn extract_from_json_body(body: &str) -> BodyFields {
    // Fast path: try serde_json
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        let model = v["model"].as_str().map(|s| s.to_string());
        let msgs = v["messages"].as_array();

        // Extract prompt from Anthropic messages format:
        // {"messages": [{"role": "user", "content": "..."}]}
        let prompt = msgs
            .and_then(|msgs| {
                msgs.iter()
                    .rev()
                    .find(|m| m["role"] == "user")
                    .and_then(|m| content_text(&m["content"]))
            })
            // Also check direct "prompt" field (legacy)
            .or_else(|| v["prompt"].as_str().map(|s| s.to_string()));

        // System prompt: top-level "system" (Anthropic) or a role=system
        // message (OpenAI-compatible). Hashed for preamble-collision
        // detection; the text itself is not kept.
        let system = content_text(&v["system"]).or_else(|| {
            msgs.and_then(|msgs| {
                msgs.iter()
                    .find(|m| m["role"] == "system" || m["role"] == "developer")
                    .and_then(|m| content_text(&m["content"]))
            })
        });
        let system_prompt_hash = system
            .filter(|s| !s.trim().is_empty())
            .map(|s| crate::workers::role_preamble::preamble_hash(&s));

        // max_tokens as a proxy for expected response size
        let max_tokens = v["max_tokens"]
            .as_u64()
            .or_else(|| v["max_completion_tokens"].as_u64())
            .map(|t| t.min(u32::MAX as u64) as u32);

        return BodyFields {
            model,
            prompt,
            max_tokens,
            system_prompt_hash,
        };
    }

    // Slow path: regex-free text extraction for malformed JSON.
    // Don't attempt the prompt on malformed JSON.
    BodyFields {
        model: extract_json_string(body, "model"),
        ..BodyFields::default()
    }
}

fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":", key);
    let start = text.find(&search)? + search.len();
    let rest = text[start..].trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

fn extract_model_from_path(path: &str) -> Option<String> {
    // /v1/models/claude-3-5-sonnet → claude-3-5-sonnet
    if let Some(models_pos) = path.find("/models/") {
        let after = &path[models_pos + 8..];
        let end = after.find('/').unwrap_or(after.len());
        if !after[..end].is_empty() {
            return Some(after[..end].to_string());
        }
    }
    None
}

// ── Stream reassembler ────────────────────────────────────────────────────────
// Some HTTP requests span multiple SSL write calls.
// We buffer per-connection until we see a complete request.

pub struct StreamReassembler {
    /// Per-connection partial buffers + time of last append
    buffers: HashMap<u64, (Instant, String)>, // key = pid<<32|fd
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Feed a raw SSL capture. Returns a complete HttpRequest if one is ready.
    pub fn feed(&mut self, capture: SslCapture) -> Option<HttpRequest> {
        if capture.direction != SslDirection::Write {
            return None;
        }

        let key = ((capture.pid as u64) << 32) | ((capture.fd as u64) & 0xFFFFFFFF);

        // Check if this is a fresh request (starts with HTTP method)
        if looks_like_http_request(&capture.text) {
            // A single chunk larger than the cap is never reassembled.
            if capture.text.len() > MAX_REQUEST_BYTES {
                self.buffers.remove(&key);
                return None;
            }
            // Keep the map bounded under a partial-request flood. Evict
            // stale/oldest entries instead of refusing new connections:
            // refusing would let a flood of never-completed requests blind
            // the reassembler to every connection opened afterwards.
            if !self.buffers.contains_key(&key) && self.buffers.len() >= MAX_CONNS {
                self.evict();
            }
            // New request — replace any partial buffer
            self.buffers
                .insert(key, (Instant::now(), capture.text.clone()));
        } else {
            // Continuation — append only to an already-tracked request.
            // A continuation with no in-flight request cannot be a valid
            // request start, so we drop it instead of allocating a buffer
            // (which would let stray chunks grow the connection map).
            let (last, buf) = self.buffers.get_mut(&key)?;
            if buf.len().saturating_add(capture.text.len()) > MAX_REQUEST_BYTES {
                // Oversized / never-completing request — abandon it.
                self.buffers.remove(&key);
                return None;
            }
            buf.push_str(&capture.text);
            *last = Instant::now();
        }

        // Try to parse whatever we have
        let (_, buf) = self.buffers.get(&key)?;
        if is_complete_http_request(buf) {
            let buf_clone = buf.clone();
            self.buffers.remove(&key);
            parse_http_request(&buf_clone, &capture)
        } else {
            None
        }
    }

    /// Flush a connection's buffer (called on tcp_close).
    pub fn flush(&mut self, pid: u32, fd: i32) -> Option<String> {
        let key = ((pid as u64) << 32) | ((fd as u64) & 0xFFFFFFFF);
        self.buffers.remove(&key).map(|(_, b)| b)
    }

    /// Make room for one more connection: drop every stale buffer, and if
    /// none were stale, drop the least recently updated one.
    fn evict(&mut self) {
        let now = Instant::now();
        self.buffers
            .retain(|_, (last, _)| now.duration_since(*last) < STALE_AFTER);
        if self.buffers.len() >= MAX_CONNS {
            if let Some(oldest) = self
                .buffers
                .iter()
                .min_by_key(|(_, (last, _))| *last)
                .map(|(k, _)| *k)
            {
                self.buffers.remove(&oldest);
            }
        }
    }
}

fn is_complete_http_request(text: &str) -> bool {
    // Has headers + body separator
    let header_end = text.find("\r\n\r\n").or_else(|| text.find("\n\n"));
    let Some(header_end) = header_end else {
        return false;
    };

    // Chunked bodies have no Content-Length: the request is complete once
    // the terminating zero-length chunk has arrived. Treating it as complete
    // at the header boundary dropped the whole body (and with it the prompt).
    let header_text = &text[..header_end];
    let chunked = extract_header_value(header_text, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        let body_start = if text[header_end..].starts_with("\r\n\r\n") {
            header_end + 4
        } else {
            header_end + 2
        };
        return dechunk(&text[body_start..]).is_some();
    }

    // If POST/PUT, check Content-Length vs actual body length. Only look in
    // the header section so a body can't smuggle in a fake Content-Length.
    if let Some(cl_str) = extract_header_value(&text[..header_end], "content-length") {
        if let Ok(cl) = cl_str.trim().parse::<usize>() {
            // Don't wait forever for an implausibly large (or attacker-forged)
            // body: treat the request as complete at the header boundary so
            // the buffer is parsed and released instead of growing.
            if cl > MAX_CONTENT_LENGTH {
                return true;
            }
            let body_start = text
                .find("\r\n\r\n")
                .map(|i| i + 4)
                .or_else(|| text.find("\n\n").map(|i| i + 2))
                .unwrap_or(text.len());
            return text.len() >= body_start + cl;
        }
    }
    true
}

fn extract_header_value<'a>(headers: &'a str, header: &str) -> Option<&'a str> {
    // Match whole header names at line start only: a substring search would
    // pick up e.g. "x-content-length:" and let a client desync reassembly.
    // Byte offsets come straight from `headers` (no Unicode lowercasing,
    // which can change lengths and make slicing panic on attacker input).
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(header)
            .then(|| value.trim())
    })
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(pid: u32, fd: i32, text: &str) -> SslCapture {
        SslCapture {
            pid,
            fd,
            direction: SslDirection::Write,
            text: text.to_string(),
            timestamp: chrono::Utc::now(),
            account_id: None,
            conn_key: None,
        }
    }

    #[test]
    fn non_ascii_headers_do_not_panic() {
        // 'İ' lowercases to a longer byte sequence under Unicode rules.
        let req = format!(
            "POST /v1/messages HTTP/1.1\r\nX-Pad: {}\r\nContent-Length: 2\r\n\r\n{{}}",
            "İ".repeat(64)
        );
        let mut r = StreamReassembler::new();
        assert!(r.feed(cap(1, 1, &req)).is_some());
    }

    #[test]
    fn content_length_only_from_headers() {
        let req = "POST / HTTP/1.1\r\nX-Content-Length: 999\r\n\r\ncontent-length: 999";
        assert!(is_complete_http_request(req));
        let partial = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
        assert!(!is_complete_http_request(partial));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        let a = derive_account_id("Bearer sk-test");
        assert_eq!(a, derive_account_id("bearer sk-test"));
        assert_eq!(a, derive_account_id("BEARER   sk-test "));
        assert_eq!(a, derive_account_id("sk-test"));
    }

    #[test]
    fn every_presented_credential_is_attributed() {
        // Real key where the backend reads it, a throwaway where we used to.
        let mk = |decoy: &str| {
            format!(
                "POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer {decoy}\r\n\
                 x-api-key: sk-real\r\nContent-Length: 2\r\n\r\n{{}}"
            )
        };
        let real = derive_account_id("sk-real");
        let mut r = StreamReassembler::new();
        for decoy in ["rand-1", "rand-2"] {
            let req = r.feed(cap(1, 1, &mk(decoy))).unwrap();
            let ids: Vec<String> = crate::events::ApiEvent::all_from_http_request(&req)
                .into_iter()
                .map(|e| e.account_id)
                .collect();
            assert_eq!(ids.len(), 2);
            assert!(ids.contains(&real), "real account must see every request");
        }
    }

    #[test]
    fn content_type_case_and_block_content_do_not_hide_prompt() {
        let body = r#"{"model":"m","max_tokens":4096,"system":[{"type":"text","text":"You are an expert."}],"messages":[{"role":"user","content":[{"type":"text","text":"explain step by step"}]}]}"#;
        for ct in ["application/JSON", "text/plain"] {
            let req = format!(
                "POST /v1/messages HTTP/1.1\r\nx-api-key: k\r\nContent-Type: {ct}\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let got = StreamReassembler::new().feed(cap(1, 1, &req)).unwrap();
            assert_eq!(got.prompt.as_deref(), Some("explain step by step"));
            assert!(got.system_prompt_hash.is_some());
            let ev = crate::events::ApiEvent::from_http_request(&got).unwrap();
            assert_eq!(ev.max_tokens, Some(4096));
        }
    }

    #[test]
    fn chunked_body_is_reassembled_and_parsed() {
        let body = r#"{"model":"m","messages":[{"role":"user","content":"show every step"}]}"#;
        let (a, b) = body.split_at(20);
        let head = "POST /v1/messages HTTP/1.1\r\nx-api-key: k\r\n\
                    Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut r = StreamReassembler::new();
        assert!(r.feed(cap(1, 1, head)).is_none());
        assert!(r
            .feed(cap(1, 1, &format!("{:x}\r\n{a}\r\n", a.len())))
            .is_none());
        let got = r
            .feed(cap(
                1,
                1,
                &format!("{:X};ext=1\r\n{b}\r\n0\r\n\r\n", b.len()),
            ))
            .unwrap();
        assert_eq!(got.prompt.as_deref(), Some("show every step"));
        assert_eq!(dechunk("zz\r\n"), None);
        assert_eq!(dechunk("ffffffffffffffff\r\nab"), None);
    }

    #[test]
    fn full_map_still_tracks_new_connections() {
        let mut r = StreamReassembler::new();
        for fd in 0..MAX_CONNS as i32 {
            assert!(r.feed(cap(7, fd, "POST / HTTP/1.1\r\n")).is_none());
        }
        assert_eq!(r.buffers.len(), MAX_CONNS);
        // A new connection must still be reassembled once the map is full.
        assert!(r.feed(cap(8, 1, "POST / HTTP/1.1\r\n")).is_none());
        assert!(r.feed(cap(8, 1, "Content-Length: 0\r\n\r\n")).is_some());
        assert!(r.buffers.len() <= MAX_CONNS);
    }
}
