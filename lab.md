# Glasswally security lab report

| | |
|---|---|
| **Date** | 2026-11-11 |
| **Baseline** | `a37ef79` (main, after the two earlier security passes in PR #6 and PR #9) |
| **Scope** | Whole repository: userspace daemon (`glasswally/`), eBPF programs (`glasswally-ebpf/`), build tooling, Docker/compose, CI, dependencies |
| **Result** | 27 findings. 17 fixed in this change (3 high, 6 medium, 8 low). 10 left open with recommendations (2 high, 4 medium, 4 low/info) — the two open highs are in the eBPF kernel programs, which could not be compiled in this environment. |

## 1. What matters most

1. **Cluster takedown could be turned against bystanders (GW-01, fixed).** Clusters form on a shared /24 or JA3 hash, and a CRITICAL score on one member suspended the whole cluster and exported everyone's IPs in an IOC bundle. An attacker only had to use the same HTTP library as their targets. Group enforcement is now limited to accounts linked by payment instrument or org id; the rest go to the analyst queue.
2. **One account could stall the detector (GW-02, fixed).** Prompts were stored whole and re-scanned in full on every event. 1,500 requests of 100 KB from a single account did not finish in 10 minutes before the fix; they take about 31 s now.
3. **eBPF mode let the client pick its own account id (GW-03, fixed)** and hid the prompt behind ordinary request shapes (GW-04, fixed).
4. **eBPF mode still has structural gaps (GW-18, GW-19, open).** Every connection in a process shares one reassembly buffer, and HTTP/2, writes over 4 KB, `SSL_write_ex` and server-side reads are not captured. Until those are fixed, treat eBPF mode as experimental and rely on tail mode.

## 2. Method

- Manual read of all Rust sources (about 7,000 lines), the BPF programs, Dockerfile, compose file, CI workflow, Falco rules and docs.
- `cargo audit` on both lockfiles, `cargo clippy -D warnings`, `cargo fmt --check`, `cargo test`.
- Each fixed finding has a regression test. The five most important were also reproduced against the baseline commit in a throwaway worktree (section 6).
- Before/after runs of the labeled evaluation set and of a single-account flood.

Not done: no live eBPF run (no nightly toolchain or BPF linker here, so `glasswally-ebpf` was reviewed by reading only), no fuzzing, no review of third-party crate internals.

Severity reflects impact on a deployment that uses the affected mode. Several modules (`grpc_api`, `ioc_feed`, `kafka_output`, `redis_state`, `otel`, `load_shedder`) are not wired into `main.rs` yet; issues there are rated for when they are.

## 3. Findings at a glance

| ID | Sev | Area | Finding | Status |
|---|---|---|---|---|
| GW-01 | High | Enforcement | Cluster takedown suspends and exports weakly linked bystanders | Fixed |
| GW-02 | High | Availability | Memory/CPU exhaustion from stored prompts, unbounded sets, full-history rescans | Fixed |
| GW-03 | High | eBPF parsing | Client chooses its account id by sending two credentials | Fixed |
| GW-04 | Medium | eBPF parsing | Prompt hidden by `Content-Type` case, content blocks, chunked bodies | Fixed |
| GW-05 | Medium | Detection | Phrase detectors evaded by extra spaces, newlines, zero-width or full-width characters | Fixed (partly, see GW-26) |
| GW-06 | Medium | Enforcement | Cooldown blocked escalation; check-then-record race; takedown members not marked suspended | Fixed |
| GW-07 | Medium | Availability | Accounts and reverse indexes never evicted | Fixed |
| GW-08 | Medium | Tail mode | Detection stops silently after log rotation or truncation | Fixed |
| GW-09 | Medium | Watermark | Watermark derivable from the account id alone (forgery, framing) | Fixed |
| GW-10 | Low | Detection | IPv6 clients invisible to subnet clustering | Fixed |
| GW-11 | Low | Output | Terminal escape injection through client-chosen strings | Fixed |
| GW-12 | Low | State | Future-dated events and timing buckets never expire | Fixed |
| GW-13 | Low | Loader | Privileged loader reads arbitrary-size binaries; reports coverage after failed attach | Fixed |
| GW-14 | Low | Output | Enforcement files created world-readable in a pre-existing directory | Fixed |
| GW-15 | Low | CLI | `--speed 0` panics; failed replay reported as success | Fixed |
| GW-16 | Low | Dependencies | tokio 1.49.0 affected by RUSTSEC-2026-0386 (CI audit job fails) | Fixed |
| GW-17 | Low | CI / repo | Default workflow token permissions, unlocked builds, `output/` not ignored | Fixed |
| GW-18 | High | eBPF kernel | `fd` is always 0: all connections of a process share one reassembly buffer | Open |
| GW-19 | High | eBPF kernel | Capture gaps: HTTP/2, writes over 4 KB, `SSL_write_ex`, server-side reads | Open |
| GW-20 | Medium | eBPF kernel | Captures TLS plaintext of every process on the host; `--port` is unused | Open |
| GW-21 | Medium | eBPF kernel | Argument-map entries leak on failed calls until capture stops | Open |
| GW-22 | Medium | IOC feed | Shared HMAC key lets any peer forge any provider; consumer trusts peer-supplied account ids | Open |
| GW-23 | Medium | Detection | Weak-link clusters still raise bystanders' scores | Open |
| GW-24 | Low | Query API | Placeholder verdicts, token in plaintext, fails open | Open |
| GW-25 | Low | State | Suspensions and canaries are memory-only; canary token is unkeyed | Open |
| GW-26 | Info | Detection | Remaining content evasions and residual per-event cost | Open |
| GW-27 | Info | Supply chain | Actions and base images pinned by tag; YARA check cannot fail | Open |

## 4. Fixed findings

### GW-01 · Cluster takedown hits bystanders — High

`StateStore::update_clusters` joins accounts that share a payment hash, org id, /24 subnet **or JA3 hash**. On a CRITICAL decision the dispatcher suspended every member of the cluster and wrote all their IPs, payment hashes and account ids to `ioc_bundles.jsonl`.

A subnet and a JA3 hash are free to acquire: use the same HTTP library as the targets, or sit behind the same NAT or cloud egress range. An attacker could enrol victims this way, then trip a CRITICAL score on purpose. In the labeled dataset every benign account already sits in a cluster (Hydra false-positive rate 1.0), so the precondition is the normal state.

**Fix.** `StateStore::strongly_linked` walks payment and org links only. `ClusterTakedown` and the IOC bundle cover that set (three or more accounts); with fewer, the trigger account alone is suspended. Remaining cluster members are written to `analyst_queue.jsonl` as `FlagForReview`.

**Behaviour change to be aware of:** a campaign that uses a distinct card per account and is linked only by subnet or JA3 is no longer auto-suspended as a group; it is queued for review.

Files: `state/window.rs`, `engine/dispatcher.rs`. Tests: `takedown_spares_weakly_linked_bystanders`, `weak_only_cluster_is_not_taken_down`, `strong_links_follow_payment_not_ja3`.

### GW-02 · Resource exhaustion from one account — High

- Each account kept up to 10,000 events with the full prompt (lines up to 4 MiB).
- `refusal_probe` and `sequence_model` cloned and re-scanned the whole window on every event; `cot` and `biometric` did the same for the last hour. Cost per event grew with the account's own history.
- `user_agents`, `ip_addresses` and the other per-account sets had no cap and no expiry.
- `embed` hashed every 1–3-gram of the whole prompt.

| Single account, 1,500 events × 100 KB prompt (eval mode) | Wall time | Peak RSS |
|---|---|---|
| Baseline | did not finish in 600 s | 584 MB |
| After | 31 s | 243 MB (189 MB of that is the input file) |

**Fix.** `ApiEvent::sanitize` runs before ingest and caps every field (prompt analysed: 32 KiB head + tail; metadata: 512 bytes; header list: 64). The window stores 2 KiB of each prompt, history scans cover the latest 512 prompts, attribute sets hold 256 entries, and `embed` reads 4 KiB.

Files: `events.rs`, `state/window.rs`, `workers/*`, `main.rs`, `eval/mod.rs`. Tests: `sanitize_bounds_and_cleans_fields`, `stored_prompt_and_attribute_sets_are_bounded`.

### GW-03 · Client-chosen account id in eBPF mode — High

`http_reconstruct` derived the account from `Authorization`, falling back to `x-api-key`. A client that sends its real key in `x-api-key` and a random value in `Authorization` gets a new account id on every request, so no per-account signal ever accumulates.

**Fix.** Every credential on the request (both headers, repeats included, up to eight) yields an account id, and the request is attributed to each. The real account therefore sees all of its traffic. The throwaway ids are evicted after 24 hours (GW-07).

Files: `http_reconstruct.rs`, `events.rs`, `main.rs`. Test: `every_presented_credential_is_attributed`.

### GW-04 · Prompt hidden from content workers in eBPF mode — Medium

Three ordinary request shapes left `prompt` empty, which silences seven workers:

- `Content-Type: application/JSON` — the check was a case-sensitive `contains("json")`.
- `content` as an array of blocks, the standard shape for multimodal and tool-use requests.
- `Transfer-Encoding: chunked` — the request was treated as complete at the header boundary and the body discarded.

Also, `system_prompt_hash` and `max_tokens` were never set on eBPF events, so RolePreamble collision detection and TokenBudget could not fire.

**Fix.** JSON is parsed when the content type says so in any case or the body starts with `{`; text blocks are joined; chunked bodies are reassembled and de-chunked; the system prompt hash and `max_tokens` are populated.

Tests: `content_type_case_and_block_content_do_not_hide_prompt`, `chunked_body_is_reassembled_and_parsed`.

### GW-05 · Phrase detectors evaded by formatting — Medium

CoT, RolePreamble, RefusalProbe and the watermark-probe check matched the raw prompt. `step  by step` (two spaces), `step\nby step`, a zero-width space inside a word, or full-width letters all scored zero while reading identically to the model.

**Fix.** `workers::normalize_prompt` lowercases, collapses whitespace, drops invisible format characters and folds full-width ASCII. The phrase workers and `embed` match on that form. Cross-script homoglyphs and paraphrase are not covered (GW-26).

Tests: `normalization_defeats_spacing_and_invisible_char_evasion`, `obfuscated_cot_phrases_still_match`.

### GW-06 · Alert cooldown weaknesses — Medium

- Any alert started a 10-minute cooldown for the account, at every tier. Tripping a MEDIUM (rate limit) alert gave ten minutes in which a CRITICAL score did nothing.
- `should_alert` and `record_alert` were separate calls with an `await` between them, so concurrent events for one account could each dispatch.
- After a cluster takedown only the triggering account was marked suspended.

**Fix.** `FusionEngine::try_claim_alert` is one atomic check-and-record, lets a higher tier through the cooldown, and is released if dispatch fails. All enforced accounts are marked suspended. Expired cooldown entries are pruned.

Test: `claim_is_exclusive_but_escalation_passes_cooldown`.

### GW-07 · State never evicted — Medium

Events expired after 24 hours, but the account entry, its attribute sets, the reverse indexes and cluster membership stayed forever. With GW-03 the set of account ids is attacker-controlled in eBPF mode.

**Fix.** Housekeeping evicts accounts with no events in the window and removes them from every index and cluster. Test: `idle_accounts_and_their_index_entries_are_evicted`.

### GW-08 · Tail mode goes blind after log rotation — Medium

`tail_jsonl` held the original file handle. After `logrotate` (rename and create, or truncate) it waited on the old file forever with no error. **Fix:** at EOF, once a second, compare device/inode and length with the path; reopen from the start on rotation or truncation and log a warning.

### GW-09 · Watermark derivable from the account id — Medium

Watermark bits were `SHA256("gw_wm_v1:" ‖ account_id)`. Anyone who knows an account id could compute that account's mark, plant it in a dataset to frame the account, or confirm and strip their own. **Fix:** bits are `HMAC-SHA256(secret, …)`, a secret of at least 32 bytes is required, and there is no default. `embed`/`detect` are not called from the pipeline yet; whoever wires them supplies the key. Test: `watermark_roundtrip_requires_the_key`.

### GW-10 to GW-17 — Low

| ID | Issue | Fix |
|---|---|---|
| GW-10 | Subnet keys were built by splitting on `.`, so IPv6 addresses never clustered | `subnet_key`: /24 for IPv4, /48 for IPv6, IPv4-mapped addresses folded |
| GW-11 | Model names and account ids are echoed to the terminal; a model named with ANSI escapes could clear the screen or fake an alert | Control characters stripped at ingest and again at print |
| GW-12 | Events and timing buckets with future timestamps never aged out | Timestamps more than 5 minutes ahead are reset to now; out-of-range buckets dropped |
| GW-13 | The loader read each `/proc/*/exe` fully before checking its size, and listed a TLS library as attached even when attach failed | Size checked first; library reported only on success |
| GW-14 | Output files were created with the default umask; only a directory the daemon created itself was 0700 | Files created 0600 |
| GW-15 | `--speed 0` or a negative value panicked in `Duration::from_secs_f64`; a missing replay file printed "Replay complete" | Speed validated; replay errors logged |
| GW-16 | tokio 1.49.0, RUSTSEC-2026-0386 (unsound `AsyncFd` constructors). The CI job runs `cargo audit --deny warnings`, so it was failing | tokio 1.51.6. Not 1.54: that needs Rust 1.85 and the Dockerfile builds on 1.82 |
| GW-17 | Workflow had default token permissions and built without `--locked`; compose writes `./output` (account ids, IPs) which was not ignored | `permissions: contents: read`, `--locked`, `/output/` in `.gitignore` |

Also corrected: `THREAT_MODEL.md` said detection works "without reading plaintext prompts". Seven workers read prompt text and eBPF mode captures TLS plaintext.

## 5. Open findings

### GW-18 · One reassembly buffer per process — High (eBPF mode)

The BPF programs set `event.fd = 0`. Userspace keys reassembly on `pid << 32 | fd`, so every TLS connection in a process shares one buffer. Concurrent requests corrupt each other, and a continuation chunk from one connection is appended to another connection's request — a body can end up attributed to someone else's credential.

**Recommendation.** Save the `SSL*` pointer (argument 0) at probe entry and emit it as the connection id; key reassembly on `(pid, ssl_ptr)`. Storing its low 32 bits in the existing `fd` field avoids a struct layout change.

### GW-19 · Capture gaps that amount to full evasion — High (eBPF mode)

- **HTTP/2.** Frames are binary and never match the `POST ` prefix check. Any HTTP/2 client is invisible.
- **Large writes.** Only the first 4,096 bytes of each `SSL_write` are copied. A larger body never satisfies `Content-Length`, so the request sits in the buffer until the next one replaces it.
- **`SSL_write_ex` / `SSL_read_ex`.** Not hooked; clients using the OpenSSL 1.1.1+ `_ex` calls are missed.
- **Direction.** Only `SSL_write` data is parsed as requests. On a TLS-terminating gateway, requests arrive through `SSL_read`, which is captured and then discarded.

**Recommendation.** Parse requests from the read direction on server deployments, loop the copy to cover large writes, hook the `_ex` symbols, and add an HTTP/2 frame and HPACK decoder (or document eBPF mode as HTTP/1.1-only). Until then, tail mode fed by the gateway is the dependable source.

### GW-20 · Host-wide plaintext capture — Medium (eBPF mode)

The uprobes attach to the shared library, so plaintext from **every** process using it reaches the daemon: package managers, database clients, other services, with their credentials. The `--port` flag is parsed and never used. **Recommendation:** filter in the BPF program by pid, cgroup or destination port, and do not copy the read direction unless it is used.

### GW-21 · Probe argument maps fill up — Medium (eBPF mode)

`SSL_WRITE_ARGS` / `SSL_READ_ARGS` entries are removed only on the success path. A call that returns ≤ 0 (routine with non-blocking sockets) leaves its entry behind when the thread exits. The maps hold 2,048 entries; once full, inserts fail and capture stops for new threads, silently. **Recommendation:** remove the entry before every return, or use an LRU hash map.

### GW-22 · IOC feed trust model — Medium (not wired; transport is stubbed)

- All providers share one HMAC key, so any participant can sign a bundle as any other. Binding `provider_id` into the MAC does not help when every signer holds the same key.
- The consumer accepts peer-supplied `account_ids` and IPs. A malicious or compromised peer can direct enforcement at another provider's customers.
- No replay or duplicate tracking; `IocFeedGenerator.entries` grows without bound.

**Recommendation.** Per-provider Ed25519 keys with a pinned key per `provider_id`; treat peer bundles as score hints, never as direct enforcement; ignore peer account ids; deduplicate on a bundle hash.

### GW-23 · Weak-link clusters still inflate scores — Medium

GW-01 removed the enforcement path, but cluster membership still adds to scores: Hydra scores on cluster size, and fusion adds 0.08 for clusters of five or more. An attacker sharing a JA3 or subnet with a victim can push a borderline benign account over the MEDIUM (rate limit) threshold. The evaluation shows the cost: Hydra and TokenBudget false-positive rate 1.0, TimingCluster 0.98. **Recommendation:** weight edges by type, exclude high-cardinality JA3 values from clustering, and require a strong edge for the cluster bonus.

### GW-24 · Query API — Low (not wired)

`check_account` returns `ok` for anything not suspended and never `rate_limited` (the score is a placeholder). The shared token travels inside the JSON body over plaintext TCP. A gateway that cannot reach the API gets no verdict, so integrations fail open unless written otherwise. The metrics endpoint is unauthenticated. **Recommendation:** finish the decision cache, add TLS (mTLS preferred), and state the fail-open or fail-closed contract.

### GW-25 · Volatile enforcement state — Low

Suspensions, cooldowns, watermark flags and the canary registry live in memory only; a restart forgets every suspension. Canary tokens are a hash of account id, a constant and the clock — not secret, and the registry never shrinks. **Recommendation:** persist suspensions and canaries (the Redis module is a stub today) and generate canaries from a CSPRNG or keyed HMAC.

### GW-26 · Residual evasion and cost — Info

- Cross-script homoglyphs, paraphrase and non-English prompts still bypass the phrase lists.
- Only the last user turn is analysed; instructions placed in an earlier turn or an assistant prefill are not seen.
- eBPF mode drops requests over 1 MiB instead of analysing a prefix.
- Prompts over 32 KiB are analysed head and tail only.
- A heavy account still costs about 20 ms of CPU per event, because the last 512 prompts are re-scanned each time. It is bounded now; incremental per-account counters would remove it.
- Evaluation results vary slightly between runs (recall 0.906–0.911 on the same data), because windows are anchored to wall-clock time. A deterministic clock would make regressions easier to spot.

### GW-27 · Supply chain and CI hygiene — Info

- GitHub Actions are pinned by tag (`@v4`, `@stable`), base images by tag. Pin by commit SHA and digest.
- The YARA step ends in `|| true`, so it can never fail.
- The runtime image installs `curl`, which nothing uses.
- The compose `ebpf` profile cannot work as written: the image is built without `live-ebpf`, and added capabilities do not apply to the non-root user.
- The compose stack runs Kafka and Redis without authentication. Ports are bound to loopback, so this is acceptable for local development only.

## 6. Verification

Run from the repository root.

| Check | Command | Result |
|---|---|---|
| Unit tests | `cargo test -p glasswally --locked` | 25 passed (8 at baseline; 17 added) |
| Lint | `cargo clippy -p glasswally --locked --all-targets -- -D warnings` | clean |
| Format | `cargo fmt -p glasswally -- --check` | clean |
| Advisories | `cargo audit` (workspace and `glasswally-ebpf/`) | no advisories (baseline: 1 warning) |
| Build tooling | `cargo check -p xtask --locked` | builds |
| Detection quality | `glasswally --mode eval --path datasets/labeled_5k.jsonl` | precision 1.000, false-positive rate 0.000, recall 0.906–0.911; baseline 1.000 / 0.000 / 0.907–0.908 (within run-to-run variation) |
| Replay smoke test | `glasswally --mode replay --path examples/sample_events.jsonl --speed 100000` | 3,000 events processed; output files mode 0600 |

Reproduced on the baseline commit before fixing:

| Finding | Baseline behaviour observed |
|---|---|
| GW-01 | Takedown triggered by `atk1` listed `victim1`–`victim3` as affected and exported their IPs in the IOC bundle |
| GW-02 | Flood run did not complete in 600 s |
| GW-03 | Same `x-api-key`, two different `Authorization` values → two different account ids, neither the real one |
| GW-04 | `application/JSON` → prompt `None`; block content → prompt `None`; chunked → emitted at header boundary with prompt `None` |
| GW-05 | `Think step by step` scored 0.4; `Think  step\nby   step` and `chain\u{200b} of thought` scored 0 |

Not verified: anything requiring a live kernel attach. The `loader.rs` changes compile and are small, but were not exercised against real probes. The BPF source was not modified.

## 7. Suggested order of work

1. GW-18 and GW-19 before relying on eBPF mode for anything.
2. GW-20 and GW-21 in the same BPF change.
3. GW-23, so cluster membership stops raising scores for bystanders.
4. GW-22 and GW-24 before wiring the IOC feed or the query API.
5. GW-25 when the Redis module becomes real.
