// glasswally/src/main.rs
//
// Glasswally — Real-time LLM distillation attack detection via eBPF
//
// Infrastructure modules (grpc_api, kafka_output, redis_state, load_shedder,
// otel, eval, loader) are wired in during deployment; suppress dead_code for
// the entire crate while development is in progress.
#![allow(dead_code)]
//
// Three operational modes:
//   ebpf    — live kernel uprobes on ssl_write/ssl_read (Linux 5.8+, production)
//   tail    — tail a JSONL API gateway log file (any platform, staging)
//   replay  — replay a captured log at scaled speed (testing/research)
//   eval    — run the labeled-dataset evaluation harness and exit
//
// Usage:
//   sudo glasswally --mode ebpf                            # live eBPF
//   glasswally --mode tail --path /var/log/api/access.jsonl
//   glasswally --mode replay --path captured.jsonl --speed 10.0
//   glasswally --mode eval --path datasets/labeled_5k.jsonl

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod engine;
mod eval;
mod events;
mod grpc_api;
mod http_reconstruct;
mod ioc_feed;
mod kafka_output;
mod load_shedder;
mod loader;
mod otel;
mod redis_state;
mod redteam;
mod state;
mod workers;

/// Drop pathologically long JSONL lines instead of parsing them — bounds
/// memory/CPU if the feed file is attacker-influenced.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Max events processed concurrently. The source channel is bounded, but
/// spawning a task per event without a cap would move the backlog into an
/// unbounded set of tasks under a flood; with the cap, back-pressure reaches
/// the source instead.
const MAX_IN_FLIGHT: usize = 4096;

use engine::{dispatcher::Dispatcher, fusion::FusionEngine};
use events::{ActionKind, ApiEvent, RiskTier};
use state::window::StateStore;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "glasswally",
    about   = "Real-time LLM distillation attack detection via eBPF",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    #[arg(long, value_enum, default_value = "tail")]
    mode: Mode,

    #[arg(
        long,
        default_value = "./glasswally_feed.jsonl",
        help = "JSONL log path (tail/replay modes)"
    )]
    path: PathBuf,

    #[arg(long, default_value = "1.0", help = "Replay speed multiplier")]
    speed: f64,

    #[arg(
        long,
        default_value = "./glasswally_output",
        help = "Enforcement output directory"
    )]
    output: PathBuf,

    #[arg(long, default_value = "443", help = "TLS port for eBPF mode")]
    port: u16,

    #[arg(
        long,
        default_value = "0.35",
        help = "Composite score alert threshold (eval mode)"
    )]
    eval_threshold: f32,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    Ebpf,   // live kernel uprobes (Linux 5.8+, requires CAP_BPF or root)
    Tail,   // tail a live JSONL log file
    Replay, // replay a static JSONL file at scaled speed
    Eval,   // run the labeled-dataset evaluation harness and exit
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

struct Pipeline {
    store: Arc<StateStore>,
    engine: Arc<FusionEngine>,
    dispatcher: Arc<Dispatcher>,
}

impl Pipeline {
    fn new(output: PathBuf) -> Self {
        Self {
            store: Arc::new(StateStore::new()),
            engine: Arc::new(FusionEngine::new()),
            dispatcher: Arc::new(Dispatcher::new(output)),
        }
    }

    async fn process(&self, event: ApiEvent) {
        // Ingest into sliding windows + indexes
        self.store.ingest(&event);

        // Run all workers concurrently
        let signals = workers::run_all(&event, &self.store).await;

        // Fuse signals
        let decision = match self.engine.fuse(&event, &self.store, &signals) {
            Some(d) => d,
            None => return,
        };

        if !self.engine.should_alert(&event.account_id) {
            return;
        }

        // Dispatch enforcement action
        match self.dispatcher.dispatch(&decision, &self.store).await {
            Ok(action) => {
                self.engine
                    .record_alert(&event.account_id, decision.tier == RiskTier::Critical);
                print_alert(&decision, &action.action_type);
            }
            Err(e) => error!("Dispatch failed: {}", e),
        }
    }
}

// ── Terminal output ───────────────────────────────────────────────────────────

fn print_banner() {
    println!("\x1b[1m");
    println!("  ██████╗ ██╗      █████╗ ███████╗███████╗██╗    ██╗ █████╗ ██╗     ██╗  ██╗   ██╗");
    println!(" ██╔════╝ ██║     ██╔══██╗██╔════╝██╔════╝██║    ██║██╔══██╗██║     ██║  ╚██╗ ██╔╝");
    println!(" ██║  ███╗██║     ███████║███████╗███████╗██║ █╗ ██║███████║██║     ██║   ╚████╔╝ ");
    println!(" ██║   ██║██║     ██╔══██║╚════██║╚════██║██║███╗██║██╔══██║██║     ██║    ╚██╔╝  ");
    println!(" ╚██████╔╝███████╗██║  ██║███████║███████║╚███╔███╔╝██║  ██║███████╗███████╗██║   ");
    println!("  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ");
    println!("\x1b[0m");
    println!("  \x1b[90mReal-time LLM distillation attack detection | eBPF + Rust\x1b[0m");
    println!("  \x1b[90mgithub.com/noisyloop/Glasswally\x1b[0m\n");
}

fn print_alert(decision: &events::RiskDecision, action: &ActionKind) {
    let (color, icon) = match decision.tier {
        RiskTier::Critical => ("\x1b[91;1m", "🔴"),
        RiskTier::High => ("\x1b[93;1m", "🟡"),
        RiskTier::Medium => ("\x1b[96m", "🔵"),
        RiskTier::Low => ("\x1b[92m", "🟢"),
    };
    let reset = "\x1b[0m";
    let ev = decision
        .top_evidence
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    let gt = decision
        .ground_truth
        .as_deref()
        .map(|g| format!(" \x1b[90m[{}]{}", g, reset))
        .unwrap_or_default();

    println!(
        "\n{}{} {} → {}{}",
        color, icon, decision.tier, action, reset
    );
    println!("  Account : {}{}{}", color, decision.account_id, reset);
    println!(
        "  Score   : {}{:.4}{}",
        color, decision.composite_score, reset
    );
    println!("  Cluster : {:?}", decision.cluster_id);
    println!("  Evidence: {}{}", ev, gt);
}

async fn print_stats_loop(store: Arc<StateStore>, start: Instant) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let elapsed = start.elapsed().as_secs_f64();
        let events = store
            .total_events
            .load(std::sync::atomic::Ordering::Relaxed);
        println!(
            "\n\x1b[1m── stats  uptime={:.0}s  events={}  eps={:.1}  accounts={}  clusters={} ──\x1b[0m",
            elapsed, events, events as f64 / elapsed,
            store.n_accounts(), store.n_clusters()
        );
    }
}

// ── Event sources ─────────────────────────────────────────────────────────────

async fn tail_jsonl(path: PathBuf, tx: mpsc::Sender<ApiEvent>, seek_end: bool) -> Result<()> {
    let mut file = tokio::fs::File::open(&path).await?;
    if seek_end {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::End(0)).await?;
    }
    let mut reader = BufReader::new(file);

    info!("Tailing {}", path.display());
    // Bytes of the current, not yet newline-terminated line. Reading raw
    // bytes (instead of `lines()`) matters for a feed that may be
    // attacker-influenced:
    //   - a line is capped at MAX_LINE_BYTES *while* reading, not after the
    //     whole thing has been buffered;
    //   - invalid UTF-8 skips one line instead of returning an error that
    //     ends the tail task and silently stops all detection;
    //   - a line still being written at EOF is kept until its newline
    //     arrives instead of being parsed (and lost) as two fragments.
    let mut line: Vec<u8> = Vec::new();
    let mut oversized = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            continue;
        }
        let (consumed, complete) = match chunk.iter().position(|&b| b == b'\n') {
            Some(nl) => (nl + 1, true),
            None => (chunk.len(), false),
        };
        if !oversized {
            let take = if complete { consumed - 1 } else { consumed };
            if line.len() + take > MAX_LINE_BYTES {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&chunk[..take]);
            }
        }
        reader.consume(consumed);
        if !complete {
            continue;
        }

        if oversized {
            warn!("Dropping oversized feed line (> {} bytes)", MAX_LINE_BYTES);
            oversized = false;
            continue;
        }
        let raw = std::mem::take(&mut line);
        let Ok(text) = std::str::from_utf8(&raw) else {
            warn!("Dropping feed line with invalid UTF-8");
            continue;
        };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        match serde_json::from_str::<ApiEvent>(text) {
            Ok(ev) => {
                if tx.send(ev).await.is_err() {
                    break;
                }
            }
            Err(e) => warn!("Parse error: {}", e),
        }
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("glasswally=info".parse()?))
        .compact()
        .init();

    let cli = Cli::parse();

    // Eval mode: run the labeled-dataset harness, print the report, exit.
    if matches!(cli.mode, Mode::Eval) {
        let result = eval::Evaluator::new(cli.eval_threshold)
            .run_dataset(&cli.path)
            .await?;
        result.print_report();
        return Ok(());
    }

    let pipeline = Arc::new(Pipeline::new(cli.output.clone()));
    let start = Instant::now();
    let (tx, mut rx) = mpsc::channel::<ApiEvent>(16384);

    print_banner();

    // Stats printer
    let store_stats = Arc::clone(&pipeline.store);
    tokio::spawn(print_stats_loop(store_stats, start));

    // Housekeeping
    let store_hk = Arc::clone(&pipeline.store);
    tokio::spawn(store_hk.housekeeping_loop());

    // Event source
    let tx2 = tx.clone();
    match cli.mode {
        Mode::Ebpf => {
            // Hard-fail rather than silently degrade: an operator running
            // `--mode ebpf` must not be left believing kernel monitoring is
            // active when it is not. Silently tailing a file would be a
            // detection-control failure (false sense of security).
            #[cfg(not(feature = "live-ebpf"))]
            {
                let _ = tx2;
                eprintln!(
                    "error: eBPF mode requires the `live-ebpf` build feature and Linux 5.8+."
                );
                eprintln!(
                    "Build with: cargo xtask build-ebpf && \
                     cargo run --features live-ebpf -- --mode ebpf"
                );
                eprintln!(
                    "Refusing to fall back to tail mode — that would silently \
                     disable kernel monitoring."
                );
                std::process::exit(2);
            }

            #[cfg(feature = "live-ebpf")]
            {
                println!("  Mode: \x1b[91;1meBPF\x1b[0m  |  Attaching kernel uprobes...");
                println!("  \x1b[90mRequires: Linux 5.8+, CAP_BPF or root\x1b[0m\n");
                let loader = loader::GlasswallLoader::load()?;
                let (mut rx_ssl, _report) = loader.attach_and_stream().await?;
                tokio::spawn(async move {
                    let mut reassembler = http_reconstruct::StreamReassembler::new();
                    while let Some(capture) = rx_ssl.recv().await {
                        // Reconstructed requests feed the same channel as
                        // tail/replay — one pipeline, no second code path.
                        if let Some(req) = reassembler.feed(capture) {
                            if let Some(ev) = ApiEvent::from_http_request(&req) {
                                if tx2.send(ev).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }

        Mode::Tail => {
            println!("  Mode: \x1b[96mTAIL\x1b[0m  |  {}", cli.path.display());
            println!("  Output: \x1b[90m{}\x1b[0m\n", cli.output.display());
            let path = cli.path.clone();
            tokio::spawn(async move {
                // Surface the failure: a dead tail task means no detection.
                if let Err(e) = tail_jsonl(path, tx2, true).await {
                    error!("Tail source stopped — detection is no longer running: {e}");
                }
            });
        }

        Mode::Eval => unreachable!("handled before pipeline setup"),

        Mode::Replay => {
            println!(
                "  Mode: \x1b[93mREPLAY\x1b[0m  |  {}  speed={:.1}x",
                cli.path.display(),
                cli.speed
            );
            println!("  Output: \x1b[90m{}\x1b[0m\n", cli.output.display());
            let path = cli.path.clone();
            let speed = cli.speed;
            tokio::spawn(async move {
                replay_jsonl(path, tx2, speed).await.ok();
            });
        }
    }

    println!("  Press Ctrl+C to stop.\n");

    // Drop the local sender: once every source task has finished (replay
    // reaching EOF), the channel closes and the consumer loop below exits.
    // Long-running sources (tail, ebpf) hold their own clone, so they keep
    // the process alive.
    drop(tx);

    // Main consumer — one task per event for parallelism, bounded.
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    while let Some(event) = rx.recv().await {
        let permit = Arc::clone(&in_flight)
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let p = Arc::clone(&pipeline);
        tokio::spawn(async move {
            let _permit = permit;
            p.process(event).await;
        });
    }

    // Wait for in-flight per-event tasks to finish before exit.
    let _ = in_flight.acquire_many(MAX_IN_FLIGHT as u32).await;
    let events = pipeline
        .store
        .total_events
        .load(std::sync::atomic::Ordering::Relaxed);
    println!(
        "\n\x1b[1mReplay complete — {} events, {} accounts, {} clusters. \
         Enforcement output in {}\x1b[0m",
        events,
        pipeline.store.n_accounts(),
        pipeline.store.n_clusters(),
        cli.output.display()
    );

    Ok(())
}

async fn replay_jsonl(path: PathBuf, tx: mpsc::Sender<ApiEvent>, speed: f64) -> Result<()> {
    let content = tokio::fs::read_to_string(&path).await?;
    let mut events: Vec<(f64, ApiEvent)> = Vec::new();

    for line in content.lines() {
        if line.len() > MAX_LINE_BYTES {
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<ApiEvent>(line) {
            let ts = ev.timestamp.timestamp_millis() as f64;
            events.push((ts, ev));
        }
    }

    if events.is_empty() {
        return Ok(());
    }
    events.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    let base_ts = events[0].0;
    let base_wall = std::time::Instant::now();

    for (ts, mut event) in events {
        let offset = (ts - base_ts) / speed / 1000.0;
        let target = base_wall + std::time::Duration::from_secs_f64(offset);
        let now = std::time::Instant::now();
        if target > now {
            tokio::time::sleep(target - now).await;
        }
        event.timestamp = Utc::now();
        if tx.send(event).await.is_err() {
            break;
        }
    }
    Ok(())
}
