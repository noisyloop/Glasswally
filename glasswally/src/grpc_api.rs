// glasswally/src/grpc_api.rs
//
// gRPC query API — Phase 2.
//
// Exposes a gRPC endpoint that API gateways (nginx, Envoy, Kong) can call
// synchronously before forwarding a request to the LLM backend:
//
//   rpc CheckAccount(AccountRequest) -> AccountStatus
//
// Returns: suspended, rate_limited, watch, or ok — plus the composite score
// and the triggering evidence strings for gateway logging.
//
// Protocol buffer schema is defined inline via tonic's build-time codegen.
// For this implementation we use tonic's reflection-compatible hand-rolled
// codec approach to keep the build dependency simple (no protoc required).
//
// Bind address defaults to 127.0.0.1:50051.  In production, add mTLS certs
// via tonic::transport::ServerTlsConfig.
//
// Example gateway integration (Envoy ext_proc filter):
//   The gateway calls CheckAccount with the API key → if the response is
//   "suspended", it returns 429 before the request reaches the LLM.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{info, warn};

/// Max concurrent client connections — bounds the per-connection task and
/// socket fan-out so the API can't be connection-exhausted.
const MAX_CONNS: usize = 256;

/// Idle/read timeout for a client connection.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Constant-time byte-string equality (avoids token-comparison timing leaks).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

use crate::engine::fusion::FusionEngine;
use crate::events::ActionKind;
use crate::state::window::StateStore;

// ── Wire protocol (length-prefixed JSON over TCP) ─────────────────────────────
// We use a simple framing protocol rather than full gRPC to avoid the protoc
// build dependency.  A real deployment should switch to tonic + proto3.
//
// Frame format:
//   [4 bytes little-endian length] [JSON payload]

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountRequest {
    pub account_id: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    /// Shared-secret bearer token. Required when the server is configured
    /// with an `auth_token`; ignored otherwise.
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountStatus {
    pub account_id: String,
    pub status: AccountStatusKind,
    pub composite_score: f32,
    pub evidence: Vec<String>,
    pub rate_limit_rpm: Option<u32>, // requests per minute cap if rate_limited
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatusKind {
    Ok,
    Watch,
    RateLimited,
    Suspended,
}

impl From<ActionKind> for AccountStatusKind {
    fn from(a: ActionKind) -> Self {
        match a {
            ActionKind::SuspendAccount | ActionKind::ClusterTakedown => Self::Suspended,
            ActionKind::RateLimit => Self::RateLimited,
            ActionKind::FlagForReview | ActionKind::InjectCanary => Self::Watch,
            _ => Self::Ok,
        }
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

pub struct QueryServer {
    store: Arc<StateStore>,
    engine: Arc<FusionEngine>,
    addr: SocketAddr,
    /// Optional shared secret. When set, every request must present a
    /// matching `auth_token` or it is rejected.
    auth_token: Option<String>,
    conn_limit: Arc<Semaphore>,
}

impl QueryServer {
    pub fn new(store: Arc<StateStore>, engine: Arc<FusionEngine>, addr: SocketAddr) -> Self {
        Self {
            store,
            engine,
            addr,
            auth_token: None,
            conn_limit: Arc::new(Semaphore::new(MAX_CONNS)),
        }
    }

    /// Configure a required shared-secret token for all requests.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        if !token.is_empty() {
            self.auth_token = Some(token);
        }
        self
    }

    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("gRPC query API listening on {}", self.addr);
        if self.auth_token.is_none() {
            warn!(
                "Query API on {} has NO auth token configured — bind it to \
                 localhost / a trusted network only.",
                self.addr
            );
        }

        loop {
            let (stream, peer) = listener.accept().await?;
            // Reject (by dropping) connections beyond the concurrency cap
            // instead of spawning unbounded tasks.
            let Ok(permit) = Arc::clone(&self.conn_limit).try_acquire_owned() else {
                warn!("Query API connection limit reached — dropping {}", peer);
                continue;
            };
            let srv = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = srv.handle_connection(stream).await {
                    warn!("Query API connection error from {}: {}", peer, e);
                }
            });
        }
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        loop {
            // Read 4-byte length prefix (with an idle timeout)
            let mut len_buf = [0u8; 4];
            match timeout(IO_TIMEOUT, stream.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => anyhow::bail!("client read timed out"),
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 1_048_576 {
                anyhow::bail!("frame too large: {} bytes", len);
            }

            let mut body = vec![0u8; len];
            timeout(IO_TIMEOUT, stream.read_exact(&mut body))
                .await
                .map_err(|_| anyhow::anyhow!("client body read timed out"))??;

            let req: AccountRequest = serde_json::from_slice(&body)?;

            // Enforce shared-secret auth (constant-time) when configured.
            if let Some(expected) = &self.auth_token {
                let presented = req.auth_token.as_deref().unwrap_or("");
                if !ct_eq(presented.as_bytes(), expected.as_bytes()) {
                    anyhow::bail!("unauthorized: missing or invalid auth token");
                }
            }

            let resp = self.check_account(&req.account_id);
            let resp_bytes = serde_json::to_vec(&resp)?;

            let resp_len = resp_bytes.len() as u32;
            let mut frame = Vec::with_capacity(4 + resp_bytes.len());
            frame.extend_from_slice(&resp_len.to_le_bytes());
            frame.extend_from_slice(&resp_bytes);
            // Bound the write too: a client that never reads would otherwise
            // block here forever, pinning one of the MAX_CONNS permits; enough
            // of them lock every gateway out of the API.
            timeout(IO_TIMEOUT, stream.write_all(&frame))
                .await
                .map_err(|_| anyhow::anyhow!("client write timed out"))??;
        }
        Ok(())
    }

    fn check_account(&self, account_id: &str) -> AccountStatus {
        // Look up the most recent decision cached in the fusion engine.
        // The engine's `last_alert` and `suspended` maps hold the state.
        let (status, score, evidence) = self
            .store
            .get_window(account_id)
            .map(|w| {
                let _w = w.read();
                let score = 0.0f32; // placeholder; real impl reads decision cache
                let ev: Vec<String> = Vec::new();
                (AccountStatusKind::Ok, score, ev)
            })
            .unwrap_or((AccountStatusKind::Ok, 0.0, vec![]));

        // Override with suspension state from engine.
        let final_status = if self.engine.is_suspended(account_id) {
            AccountStatusKind::Suspended
        } else {
            status
        };

        AccountStatus {
            account_id: account_id.to_string(),
            status: final_status,
            composite_score: score,
            evidence,
            rate_limit_rpm: if final_status == AccountStatusKind::RateLimited {
                Some(10)
            } else {
                None
            },
            timestamp: chrono::Utc::now(),
        }
    }
}
