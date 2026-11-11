// glasswally/src/loader.rs
//
// aya BPF loader — loads compiled BPF bytecode and attaches probes.
//
// Tier 1 additions:
//   BoringSSL: fully covered — path discovery + SSL_write (capital-S) symbols
//   NSS:       PR_Write / PR_Read — covers Firefox, some curl, Java NSS
//
// Tier 1 addition:
//   Go crypto/tls: uprobe attachment via ELF symbol table scanning
//                  (offset changes per compile — resolved at load time)
//
// Tier 3 addition:
//   DoH: kprobe on udp_sendmsg — identifies accounts using DNS-over-HTTPS

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
#[cfg(feature = "live-ebpf")]
use aya::include_bytes_aligned;
use aya::{
    maps::{AsyncPerfEventArray, MapData},
    programs::{KProbe, UProbe},
    util::online_cpus,
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::events::{RawSslEvent, SslCapture, SslDirection, MAX_BUF};

// ── TLS library paths ─────────────────────────────────────────────────────────

const OPENSSL_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
    "/usr/local/lib/libssl.so.3",
    "/usr/local/ssl/lib/libssl.so",
];

const BORINGSSL_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libboringssl.so",
    "/opt/google/chrome/libssl.so",
    "/snap/chromium/current/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
];

/// NSS — Firefox, curl --with-nss, some Java runtimes.
const NSS_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libnss3.so",
    "/usr/lib64/libnss3.so",
    "/usr/lib/firefox/libnss3.so",
    "/opt/firefox/libnss3.so",
    "/usr/lib/firefox-esr/libnss3.so",
];

// ── Symbol names ──────────────────────────────────────────────────────────────

const SSL_WRITE_SYMS: &[&str] = &["ssl_write", "SSL_write"];
const SSL_READ_SYMS: &[&str] = &["ssl_read", "SSL_read"];
const NSS_WRITE_SYMS: &[&str] = &["PR_Write", "PR_Send"];
const NSS_READ_SYMS: &[&str] = &["PR_Read", "PR_Recv"];
const GO_TLS_WRITE_SYMS: &[&str] = &["crypto/tls.(*Conn).Write"];
const GO_TLS_READ_SYMS: &[&str] = &["crypto/tls.(*Conn).Read"];

// ── GlasswallLoader ───────────────────────────────────────────────────────────

pub struct GlasswallLoader {
    bpf: Ebpf,
}

#[derive(Debug, Default)]
pub struct AttachReport {
    pub openssl: Option<PathBuf>,
    pub boringssl: Option<PathBuf>,
    pub nss: Option<PathBuf>,
    pub go_bins: Vec<PathBuf>,
}

impl GlasswallLoader {
    pub fn load() -> Result<Self> {
        #[cfg(feature = "live-ebpf")]
        let bpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/glasswally-ebpf"));
        #[cfg(not(feature = "live-ebpf"))]
        let bpf_bytes: &[u8] = &[];

        if bpf_bytes.is_empty() {
            return Err(anyhow!(
                "BPF bytecode not embedded. Run: cargo xtask build-ebpf\n\
                 Then rebuild with: cargo build --features live-ebpf"
            ));
        }

        let mut bpf = EbpfLoader::new()
            .load(bpf_bytes)
            .context("Failed to load BPF object")?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            warn!("BPF logger init failed (non-fatal): {}", e);
        }
        Ok(Self { bpf })
    }

    pub async fn attach_and_stream(mut self) -> Result<(mpsc::Receiver<SslCapture>, AttachReport)> {
        let (tx, rx) = mpsc::channel(65536);
        let mut report = AttachReport::default();

        // OpenSSL
        if let Some(p) = find_library(OPENSSL_PATHS, "libssl") {
            info!("Attaching OpenSSL: {}", p.display());
            // Only report the library as covered if the probes really
            // attached; a swallowed error here meant "active" was printed
            // while nothing was being captured.
            match self.attach_ssl_pair(&p, SSL_WRITE_SYMS, SSL_READ_SYMS) {
                Ok(()) => report.openssl = Some(p),
                Err(e) => warn!("OpenSSL attach failed {}: {}", p.display(), e),
            }
        }

        // BoringSSL (Chrome, some Go) — uses SSL_write with capital S
        if let Some(p) = find_library(BORINGSSL_PATHS, "boringssl") {
            info!("Attaching BoringSSL: {}", p.display());
            // Only report the library as covered if the probes really
            // attached; a swallowed error here meant "active" was printed
            // while nothing was being captured.
            match self.attach_ssl_pair(&p, SSL_WRITE_SYMS, SSL_READ_SYMS) {
                Ok(()) => report.boringssl = Some(p),
                Err(e) => warn!("BoringSSL attach failed {}: {}", p.display(), e),
            }
        }

        // NSS (Firefox, some curl builds) — uses PR_Write / PR_Read
        if let Some(p) = find_library(NSS_PATHS, "nss") {
            info!("Attaching NSS: {}", p.display());
            // Only report the library as covered if the probes really
            // attached; a swallowed error here meant "active" was printed
            // while nothing was being captured.
            match self.attach_ssl_pair(&p, NSS_WRITE_SYMS, NSS_READ_SYMS) {
                Ok(()) => report.nss = Some(p),
                Err(e) => warn!("NSS attach failed {}: {}", p.display(), e),
            }
        }

        // Go crypto/tls — scan running processes for Go binaries with TLS
        for bin in find_go_tls_binaries() {
            info!("Attaching Go TLS: {}", bin.display());
            match self.attach_go_tls(&bin) {
                Ok(()) => report.go_bins.push(bin),
                Err(e) => warn!("Go TLS attach failed {}: {}", bin.display(), e),
            }
        }

        if report.openssl.is_none()
            && report.boringssl.is_none()
            && report.nss.is_none()
            && report.go_bins.is_empty()
        {
            return Err(anyhow!("No TLS library found to attach to"));
        }

        // tcp_connect kprobe
        if let Ok(prog) = self
            .bpf
            .program_mut("tcp_connect_entry")
            .context("no tcp_connect_entry")
        {
            let kp = TryInto::<&mut KProbe>::try_into(prog)?;
            kp.load()?;
            kp.attach("tcp_connect", 0).ok();
            info!("Attached kprobe: tcp_connect");
        }

        // DoH kprobe (Tier 3)
        if let Some(prog) = self.bpf.program_mut("udp_sendmsg_entry") {
            if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
                if kp.load().and_then(|_| kp.attach("udp_sendmsg", 0)).is_ok() {
                    info!("Attached kprobe: udp_sendmsg (DoH detection)");
                }
            }
        }

        // Perf ring buffer
        let mut ssl_map: AsyncPerfEventArray<MapData> = self
            .bpf
            .take_map("SSL_EVENTS")
            .context("SSL_EVENTS not found")?
            .try_into()?;

        for cpu_id in online_cpus().unwrap_or_else(|_| vec![0]) {
            let tx2 = tx.clone();
            let mut buf = ssl_map.open(cpu_id, None)?;
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(MAX_BUF + 64))
                    .collect::<Vec<_>>();
                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(e) => e,
                        Err(e) => {
                            error!("Perf CPU{}: {}", cpu_id, e);
                            break;
                        }
                    };
                    for bd in buffers.iter().take(events.read) {
                        let Some(raw) = parse_ssl_event(bd) else {
                            continue;
                        };
                        let text = String::from_utf8_lossy(
                            &raw.buf[..raw.buf_len.min(MAX_BUF as u32) as usize],
                        )
                        .into_owned();
                        let cap = SslCapture {
                            pid: raw.pid,
                            fd: raw.fd,
                            direction: SslDirection::from(raw.direction),
                            text,
                            timestamp: Utc::now(),
                            account_id: None,
                            conn_key: None,
                        };
                        if tx2.send(cap).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }

        info!("Glasswally eBPF probes active.");
        Ok((rx, report))
    }

    fn attach_ssl_pair(
        &mut self,
        lib: &PathBuf,
        write_syms: &[&str],
        read_syms: &[&str],
    ) -> Result<()> {
        self.attach_uprobe_any("ssl_write_enter", lib, write_syms, false)?;
        self.attach_uprobe_any("ssl_write_exit", lib, write_syms, true)?;
        self.attach_uprobe_any("ssl_read_enter", lib, read_syms, false)?;
        self.attach_uprobe_any("ssl_read_exit", lib, read_syms, true)?;
        Ok(())
    }

    fn attach_uprobe_any(
        &mut self,
        prog: &str,
        lib: &PathBuf,
        syms: &[&str],
        _is_ret: bool,
    ) -> Result<()> {
        let p = self
            .bpf
            .program_mut(prog)
            .with_context(|| format!("{prog} not found in BPF object"))?;
        let up: &mut UProbe = p.try_into()?;
        up.load()?;
        for &sym in syms {
            if up.attach(Some(sym), 0, lib, None).is_ok() {
                info!("Attached {prog}: {}:{sym}", lib.display());
                return Ok(());
            }
        }
        Err(anyhow!("No symbol matched for {prog} in {}", lib.display()))
    }

    fn attach_go_tls(&mut self, bin: &PathBuf) -> Result<()> {
        let w_off = find_go_symbol_offset(bin, GO_TLS_WRITE_SYMS)
            .context("crypto/tls.(*Conn).Write not found")?;
        let r_off = find_go_symbol_offset(bin, GO_TLS_READ_SYMS)
            .context("crypto/tls.(*Conn).Read not found")?;

        let wp = self
            .bpf
            .program_mut("ssl_write_enter")
            .context("ssl_write_enter missing")?;
        let wu: &mut UProbe = wp.try_into()?;
        wu.load()?;
        wu.attach(None, w_off, bin, None)?;

        let rp = self
            .bpf
            .program_mut("ssl_read_enter")
            .context("ssl_read_enter missing")?;
        let ru: &mut UProbe = rp.try_into()?;
        ru.load()?;
        ru.attach(None, r_off, bin, None)?;

        info!("Go TLS: write@{w_off:#x} read@{r_off:#x}");
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_library(paths: &[&str], label: &str) -> Option<PathBuf> {
    for p in paths {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    // Scan /proc for loaded instances
    for proc_dir in std::fs::read_dir("/proc").ok()?.flatten() {
        if let Ok(maps) = std::fs::read_to_string(proc_dir.path().join("maps")) {
            for line in maps.lines() {
                if line.to_lowercase().contains(label) {
                    if let Some(p) = line.split_whitespace().last() {
                        let pb = PathBuf::from(p);
                        if pb.exists() {
                            return Some(pb);
                        }
                    }
                }
            }
        }
    }
    None
}

fn find_go_tls_binaries() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in procs.flatten() {
        if let Ok(bin) = std::fs::read_link(entry.path().join("exe")) {
            if bin.exists() && !found.contains(&bin) && is_go_tls_binary(&bin) {
                found.push(bin);
            }
        }
    }
    found
}

/// Largest executable the loader will read into memory while looking for Go
/// TLS symbols. The paths come from /proc/*/exe, i.e. from any local user's
/// processes, and this daemon runs privileged: the size must be checked
/// *before* reading, or a multi-gigabyte (sparse) binary exhausts memory.
const MAX_SCAN_BINARY_BYTES: u64 = 256 * 1024 * 1024;

fn read_bounded(path: &PathBuf) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SCAN_BINARY_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn is_go_tls_binary(path: &PathBuf) -> bool {
    read_bounded(path).is_some_and(|data| memfind(&data, b"crypto/tls"))
}

fn find_go_symbol_offset(path: &PathBuf, syms: &[&str]) -> Option<u64> {
    let data = read_bounded(path)?;
    for sym in syms {
        let needle = sym.as_bytes();
        let mut pos = 0usize;
        while pos + needle.len() <= data.len() {
            if let Some(idx) = data[pos..]
                .windows(needle.len())
                .position(|w| w == needle)
                .map(|p| p + pos)
            {
                if idx >= 16 {
                    let vb: [u8; 8] = data[idx - 16..idx - 8].try_into().ok()?;
                    let addr = u64::from_le_bytes(vb);
                    if addr > 0x1000 {
                        return Some(addr);
                    }
                }
                pos = idx + 1;
            } else {
                break;
            }
        }
    }
    None
}

fn memfind(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn parse_ssl_event(buf: &BytesMut) -> Option<RawSslEvent> {
    if buf.len() < std::mem::size_of::<RawSslEvent>() {
        return None;
    }
    // The perf-ring backing buffer is not guaranteed to be aligned for
    // `RawSslEvent`, so a plain `&*(ptr as *const RawSslEvent)` reference
    // would be undefined behavior. Read the bytes unaligned instead.
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const RawSslEvent) })
}
