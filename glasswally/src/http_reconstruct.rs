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

    // Extract specific headers
    let _user_agent = header_value(&headers, "user-agent").unwrap_or_default();
    let auth = header_value(&headers, "authorization")
        .or_else(|| header_value(&headers, "x-api-key"))
        .unwrap_or_default();
    let content_type = header_value(&headers, "content-type").unwrap_or_default();

    // Derive account_id from auth header
    // In Anthropic's API: Authorization: Bearer sk-ant-...
    // We hash it for privacy — we don't need the raw key
    let account_id = if !auth.is_empty() {
        Some(derive_account_id(&auth))
    } else {
        capture.account_id.clone()
    };

    // Extract model + prompt from JSON body
    let (model, prompt, token_count) = if content_type.contains("json") && !body.is_empty() {
        extract_from_json_body(&body)
    } else {
        (None, None, None)
    };

    // Extract model from path if not in body
    // Anthropic API: POST /v1/messages, model in body
    // OpenAI compat: POST /v1/chat/completions
    let model = model.or_else(|| extract_model_from_path(&path));

    Some(HttpRequest {
        conn_key: capture.conn_key.clone(),
        method,
        path,
        headers,
        body,
        timestamp: capture.timestamp,
        account_id,
        model,
        prompt,
        token_count,
    })
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

fn extract_from_json_body(body: &str) -> (Option<String>, Option<String>, Option<u32>) {
    // Fast path: try serde_json
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        let model = v["model"].as_str().map(|s| s.to_string());

        // Extract prompt from Anthropic messages format:
        // {"messages": [{"role": "user", "content": "..."}]}
        let prompt = v["messages"]
            .as_array()
            .and_then(|msgs| {
                msgs.iter()
                    .rev()
                    .find(|m| m["role"] == "user")
                    .and_then(|m| m["content"].as_str())
                    .map(|s| s.to_string())
            })
            // Also check direct "prompt" field (legacy)
            .or_else(|| v["prompt"].as_str().map(|s| s.to_string()));

        // max_tokens as a proxy for expected response size
        let token_count = v["max_tokens"].as_u64().map(|t| t as u32);

        return (model, prompt, token_count);
    }

    // Slow path: regex-free text extraction for malformed JSON
    let model = extract_json_string(body, "model");
    let prompt = None; // Don't attempt on malformed JSON

    (model, prompt, None)
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
