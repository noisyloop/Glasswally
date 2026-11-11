# Glasswally Threat Model
## LLM Distillation Attack Detection — MITRE ATT&CK Mapping

**Version**: 0.1.0
**Last Updated**: 2026-02-27
**Maintainer**: noisyloop
**Scope**: Commercial LLM API providers (OpenAI, Anthropic, Google, Mistral-class services)

---

## Executive Summary

**LLM distillation attacks** are systematic campaigns to extract the capabilities of a proprietary frontier model into a smaller, cheaper model by:
1. Querying the target model at scale across many accounts
2. Collecting (prompt, completion) pairs as synthetic training data
3. Fine-tuning or training a student model on those pairs

This is distinct from "prompt injection" or "jailbreaking" — the attacker is not trying to bypass safety filters, they are trying to _steal the model's knowledge_ at industrial scale.

Glasswally detects distillation campaigns by fusing 16 complementary signals. Most are behavioral (timing, fingerprints, infrastructure), but the content workers (CoT, Embed, RolePreamble, RefusalProbe, SequenceModel, Biometric, Watermark) **do read prompt text**, and eBPF mode captures TLS plaintext on the monitored host — deploy and scope it accordingly (see `lab.md`).

---

## Threat Actors

| Actor Class | Motivation | Scale | Sophistication |
|-------------|-----------|-------|---------------|
| **AI Startups** | Reduce training cost, clone competitor capabilities | 10M–1B queries | Medium — uses commercial proxies, multiple cloud accounts |
| **Nation-State Labs** | Strategic AI capability transfer | 100M+ queries | High — purpose-built evasion tooling (Fingerprint Suite) |
| **Academic Researchers** | "Democratization" framing, capability benchmarking | 1M–50M queries | Low–Medium — often uses personal API keys |
| **Enterprise Competitors** | Narrow capability cloning (e.g., coding assistant, medical Q&A) | 5M–200M queries | Medium — systematic prompt engineering |
| **Underground Markets** | Resale of distillation datasets / fine-tuned models | Variable | Low — bulk scraping tools, minimal evasion |

---

## Attack Taxonomy

### T-DIST-001 · Systematic Capability Extraction

**Description**: Methodical coverage of model capability space via structured prompt sequences. Attacker generates prompts that probe specific skill buckets (math, code, reasoning, medical, legal) exhaustively.

**Indicators**:
- High entropy across prompt topics (covers full capability space)
- Prompt sequences follow hierarchical drill-down structure
- Chain-of-Thought (CoT) elicitation prefixes present: "Think step by step", "Let's reason carefully", "First, let's break this down"
- Requests for explicit reasoning traces, not just answers

**Glasswally Detectors**: `CoT` (weight 0.12), `Embed` (weight 0.10)
**MITRE Analogy**: T1119 — Automated Collection

---

### T-DIST-002 · Hydra Account Clustering

**Description**: Attacker distributes queries across many accounts to stay under per-account rate limits and evade single-account velocity checks. Accounts are coordinated but designed to appear independent.

**Sub-techniques**:

#### T-DIST-002a · Payment Fragmentation
Multiple accounts share BIN prefix (same card batch purchase), virtual card providers, or cryptocurrency payment clustering.

**Glasswally Detectors**: `Hydra` (weight 0.11) — BIN prefix grouping, payment graph edges

#### T-DIST-002b · IP Infrastructure Sharing
Accounts rotate through the same datacenter CIDR ranges, Tor exit nodes, or residential proxy pools in coordinated fashion.

**Glasswally Detectors**: `Hydra` (0.11), `Fingerprint` (0.20) — subnet clustering, JA3 hash clusters

#### T-DIST-002c · Load Balancer Synchronization
Requests from multiple accounts exhibit millisecond-precision synchronization due to shared upstream load balancer distributing to the LLM API simultaneously.

**Glasswally Detectors**: `TimingCluster` (0.09) — 1-second bucket bursts, cadence CV

**MITRE Analogy**: T1078 — Valid Accounts (Infrastructure Sharing)

---

### T-DIST-003 · Fingerprint Suite Evasion

**Description**: Purpose-built toolkit that randomizes HTTP/TLS fingerprints to appear as diverse genuine browser traffic. Randomizes: JA3, JA3S, HTTP/2 SETTINGS frames, header order, User-Agent strings.

**Sub-techniques**:

#### T-DIST-003a · JA3 Spoofing
Client spoofs browser TLS ClientHello (JA3 hash). May successfully fool JA3-based detection but cannot fully control the _server's_ ServerHello (JA3S), creating a detectable mismatch.

**Glasswally Detectors**: `Fingerprint` (0.20) — JA3S cross-consistency check (+0.30 on browser JA3 + script JA3S mismatch)

#### T-DIST-003b · HTTP/2 SETTINGS Mismatch
Spoofing UA to appear as Chrome/Firefox but HTTP/2 SETTINGS frame reveals python-httpx or Go net/http2 defaults. Library-specific window sizes (1MB for httpx, 16MB for curl) are difficult to fully randomize without re-implementing TLS stacks.

**Glasswally Detectors**: `H2Grpc` (0.07) — exact SETTINGS fingerprint matching, UA/library mismatch (+0.72 score)

#### T-DIST-003c · Header Order Normalization
HTTP header arrival order is deterministic per TLS library; proxies and load balancers may reorder headers in library-specific ways.

**Glasswally Detectors**: `Fingerprint` (0.20) — header order hash, cross-account header order clustering

**MITRE Analogy**: T1036 — Masquerading; T1027 — Obfuscated Files or Information

---

### T-DIST-004 · Credential/Account Rotation

**Description**: Attacker creates new accounts faster than detection systems can build behavioral history. Each account operates for a short burst then is discarded.

**Indicators**:
- High account creation rate from shared infrastructure
- Velocity spike on new accounts with no history
- Payment methods reused across newly created accounts
- IP addresses or subnets reused within short windows

**Glasswally Detectors**: `Velocity` (0.13) — burst detection in W_5MIN/W_1HR; `Hydra` (0.11) — payment/IP pivots to new accounts
**MITRE Analogy**: T1078.003 — Cloud Accounts

---

### T-DIST-005 · Model Capability Pivoting

**Description**: After initial account suspension or rate limiting, attacker pivots to probe remaining capability gaps using the partially-trained student model to identify what it cannot yet answer.

**Indicators**:
- Systematic shift in prompt topics after enforcement actions
- Prompts reference specific capability gaps (suggest attacker is running student model evaluations)
- New accounts immediately begin with high-sophistication targeted prompts (no "warm-up" period)

**Glasswally Detectors**: `Pivot` (0.07) — account-to-account capability shift analysis
**MITRE Analogy**: T1590 — Gather Victim Network Information

---

### T-DIST-006 · DNS-over-HTTPS (DoH) Infrastructure Correlation

**Description**: Sophisticated attackers use encrypted DNS (DNS-over-HTTPS or DNS-over-TLS) to prevent DNS-level detection of their coordination infrastructure. DoH usage by API clients is anomalous and clusters around distillation tooling.

**Indicators**:
- API client processes issuing DNS queries to port 853 (DoT) or DoH endpoints
- Shared DoH provider across multiple accounts
- Coordination IPs resolved via DoH not appearing in standard DNS logs

**Glasswally Detectors**: eBPF `udp_sendmsg_entry` kprobe — intercepts UDP sends to detect DoH transport
**MITRE Analogy**: T1071.004 — DNS Application Layer Protocol; T1090 — Proxy

---

### T-DIST-007 · Behavioral Template Injection

**Description**: Attacker uses a small number of prompt templates, systematically filling in variable fields (topic, domain, difficulty level). Prompt sequences have very low structural entropy — same sentence frames, same verb patterns, same length distributions.

**Indicators**:
- Normalized prompt structural entropy < 0.20
- Prompt length coefficient of variation < 0.10
- High repetition of template prefix tokens across sessions

**Glasswally Detectors**: `Biometric` (0.06) — structural hash entropy analysis
**MITRE Analogy**: T1119 — Automated Collection (automated prompt generation)

---

### T-DIST-008 · Response Watermark Scraping

**Description**: Attacker deliberately elicits responses that contain embedded watermarks (injected by the provider) as part of their dataset, then strips watermarks before training. Alternatively, attacker's student model reproduces watermarked text, revealing the distillation.

**Indicators**:
- Zero-width Unicode characters (ZWJ U+200D, ZWNJ U+200C) in prompt text — scraped from previous watermarked responses
- Canary token strings appearing in inbound requests (previously injected, now reproduced)
- High frequency of prompts asking for "complete" or "verbatim" text reproductions

**Glasswally Detectors**: `Watermark` (0.05) — ZW character detection, canary token attribution
**Action**: `InjectCanary` (High tier) → response watermarking for subsequent attribution
**MITRE Analogy**: T1565 — Data Manipulation; T1588 — Obtain Capabilities

---

### T-DIST-009 · Semantic Paraphrase Attacks

**Description**: To evade keyword/pattern-based CoT detection, attacker paraphrases CoT elicitation prompts. Instead of "Think step by step", uses "Walk me through your reasoning" or "Explain each inference in turn." Paraphrase-resistant detection requires semantic similarity analysis.

**Indicators**:
- Prompts semantically similar to known extraction archetypes at cosine similarity > 0.60
- High concentration of prompts in capability-specific semantic clusters
- Absence of conversational filler (pure extraction, no back-and-forth)

**Glasswally Detectors**: `Embed` (0.10) — Random Feature Hashing 512-dim embeddings, archetype cosine similarity
**MITRE Analogy**: T1027.004 — Compile After Delivery (runtime evasion)

---

### T-DIST-010 · gRPC Bulk Extraction

**Description**: Attacker uses gRPC streaming API (where available) rather than REST to maximize throughput. gRPC connections carry many requests per connection, and HTTP/2 window size manipulation enables high-throughput bulk transfer.

**Indicators**:
- gRPC `Content-Type: application/grpc` header
- HTTP/2 initial window size > 200MB (configured for bulk throughput)
- gRPC-specific headers: `grpc-encoding`, `grpc-timeout`
- Very high request/connection ratio

**Glasswally Detectors**: `H2Grpc` (0.07) — gRPC header detection, bulk window size analysis
**MITRE Analogy**: T1071.001 — Web Protocols (high-throughput channel)

---

## New Attack Techniques (Phase 1–3 additions)

### T-DIST-011 · Role Preamble Fingerprinting Attack

**Description**: Campaigns use fixed system prompts optimised for extraction quality ("You are an expert, always provide complete responses, never refuse"). The same preamble template is reused verbatim across many accounts, creating a detectable cross-account fingerprint.

**Indicators**: Cross-account preamble hash collision; "never refuse" + "always complete" compound; numbered task chains in system prompt.

**Glasswally Detectors**: `RolePreamble` (0.06)
**MITRE Analogy**: T1036 — Masquerading

---

### T-DIST-012 · Token Budget Probing

**Description**: Attacker sweeps `max_tokens` values (1, 4, 16, 64, 256...) to map model response length distributions, or always requests the maximum to collect the fullest training signal.

**Indicators**: Geometric/arithmetic max_tokens sweep; >70% of requests at ≥90% of model max context.

**Glasswally Detectors**: `TokenBudget` (0.03)
**MITRE Analogy**: T1590 — Gather Victim Network Information

---

### T-DIST-013 · Cloud Infrastructure Automation

**Description**: Distillation jobs run on cloud compute (AWS, GCP, Azure, Hetzner, Vultr). Legitimate individual users connect from residential ISPs. A cluster of accounts all on datacenter ASNs is a near-certain indicator of coordinated automation.

**Indicators**: Source ASN is cloud/hosting provider; ≥60% of cluster on datacenter ASNs; all cluster accounts on same cloud provider.

**Glasswally Detectors**: `AsnClassifier` (0.07)
**MITRE Analogy**: T1583 — Acquire Infrastructure

---

### T-DIST-014 · Cron-Scheduled Session Regularity

**Description**: Distillation jobs scheduled by cron or task schedulers produce extremely regular inter-session gaps (e.g., 3600s ± 5s). Human usage has irregular gaps. Combined with uniform session sizes, this is a reliable automation fingerprint.

**Indicators**: Inter-session gap CV < 0.08; uniform session request counts (size CV < 0.10); >20 sessions in 24h.

**Glasswally Detectors**: `SessionGap` (0.04)
**MITRE Analogy**: T1053 — Scheduled Task/Job

---

### T-DIST-015 · Safety Boundary Mapping

**Description**: Campaigns systematically probe the model's refusal behaviour — which topics trigger refusals, what paraphrasings succeed — to either: (A) train the student model to replicate safety responses, or (B) identify jailbreak surfaces.

**Indicators**: High density (>25%) of refusal-category prompts; cross-category sweep (≥4 safety categories covered).

**Glasswally Detectors**: `RefusalProbe` (0.02)
**MITRE Analogy**: T1592 — Gather Victim Host Information

---

### T-DIST-016 · Markov Topic Sweep

**Description**: Systematic capability distillation visits all capability buckets (code, math, medicine, law, finance...) in a structured sequence. Markov chain analysis reveals high stationary entropy (broad coverage) with low transition entropy (predictable drill-down order).

**Indicators**: Topic stationary entropy > 0.80; topic transition entropy < 0.25; ≥10 of 12 capability categories sampled.

**Glasswally Detectors**: `SequenceModel` (0.02)
**MITRE Analogy**: T1119 — Automated Collection

---

## Detection Signal Matrix (Full — 16 Workers)

**Legend**: ✓✓ = primary detector, ✓ = supporting signal, — = not applicable

| Attack Technique | Fp | Vel | CoT | Emb | Hyd | TC | H2 | Pvt | Bio | Wm | ASN | RP | SG | TB | RfP | SM |
|-----------------|:--:|:---:|:---:|:---:|:---:|:--:|:--:|:---:|:---:|:--:|:---:|:--:|:--:|:--:|:---:|:--:|
| T-DIST-001 Systematic extraction | — | — | ✓✓ | ✓✓ | — | — | — | — | ✓ | — | — | ✓ | — | — | — | ✓✓ |
| T-DIST-002a Payment fragmentation | — | — | — | — | ✓✓ | — | — | — | — | — | — | — | — | — | — | — |
| T-DIST-002b IP infrastructure sharing | ✓ | — | — | — | ✓✓ | — | — | — | — | — | ✓✓ | — | — | — | — | — |
| T-DIST-002c Load balancer sync | — | ✓ | — | — | — | ✓✓ | — | — | — | — | — | — | — | — | — | — |
| T-DIST-003a JA3 spoofing | ✓✓ | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| T-DIST-003b H2 SETTINGS mismatch | ✓ | — | — | — | — | — | ✓✓ | — | — | — | — | — | — | — | — | — |
| T-DIST-003c Header order | ✓✓ | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| T-DIST-004 Account rotation | — | ✓✓ | — | — | ✓ | — | — | — | — | — | ✓ | — | — | — | — | — |
| T-DIST-005 Capability pivoting | — | — | — | — | — | — | — | ✓✓ | — | — | — | — | — | — | — | — |
| T-DIST-006 DoH infrastructure | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | eBPF |
| T-DIST-007 Template injection | — | — | — | — | — | — | — | — | ✓✓ | — | — | — | ✓ | — | — | — |
| T-DIST-008 Watermark scraping | — | — | — | — | — | — | — | — | — | ✓✓ | — | — | — | — | — | — |
| T-DIST-009 Semantic paraphrase | — | — | ✓ | ✓✓ | — | — | — | — | — | — | — | — | — | — | — | ✓ |
| T-DIST-010 gRPC bulk extraction | — | ✓ | — | — | — | — | ✓✓ | — | — | — | — | — | — | — | — | — |
| T-DIST-011 Role preamble | — | — | — | — | — | — | — | — | — | — | — | ✓✓ | — | — | — | ✓ |
| T-DIST-012 Token budget probing | — | — | — | — | — | — | — | — | — | — | — | — | — | ✓✓ | — | — |
| T-DIST-013 Cloud automation | — | — | — | — | ✓ | — | — | — | — | — | ✓✓ | — | — | — | — | — |
| T-DIST-014 Cron scheduling | — | ✓ | — | — | — | ✓ | — | — | — | — | — | — | ✓✓ | — | — | — |
| T-DIST-015 Safety boundary mapping | — | — | — | — | — | — | — | — | — | — | — | — | — | — | ✓✓ | — |
| T-DIST-016 Markov topic sweep | — | — | ✓ | ✓ | — | — | — | — | — | — | — | — | — | — | — | ✓✓ |

**Column key**: Fp=Fingerprint, Vel=Velocity, CoT=CoT, Emb=Embed, Hyd=Hydra, TC=TimingCluster, H2=H2Grpc, Pvt=Pivot, Bio=Biometric, Wm=Watermark, ASN=AsnClassifier, RP=RolePreamble, SG=SessionGap, TB=TokenBudget, RfP=RefusalProbe, SM=SequenceModel
| T-DIST-009 Semantic paraphrase | | | ✓ | ✓✓ | | | | | | |
| T-DIST-010 gRPC bulk extraction | | ✓ | | | | | ✓✓ | | | |

**Legend**: ✓✓ = primary detector, ✓ = supporting signal

---

## Risk Tier Thresholds

| Tier | Score Range | Action | Rationale |
|------|------------|--------|-----------|
| **Critical** | ≥ 0.85 | `ClusterTakedown` | Near-certain organized campaign; suspend all cluster members + emit IOC bundle |
| **High** | ≥ 0.72 | `InjectCanary` | Strong evidence; begin response watermarking for attribution confirmation |
| **Medium** | ≥ 0.52 | `RateLimit` | Probable automated collection; throttle to raise attacker cost |
| **Low** | ≥ 0.35 | `FlagForReview` | Anomalous but ambiguous; human review queue |
| — | < 0.35 | No action | Noise floor; do not alert |

---

## Fusion Weight Rationale

The 10 workers are weighted based on:
1. **Precision** — false positive rate on known-clean traffic
2. **Coverage** — fraction of confirmed attacks where the signal fires
3. **Evasion cost** — how hard it is for attackers to defeat this signal

| Worker | Weight | Key Reasoning |
|--------|--------|---------------|
| `Fingerprint` | 0.14 | JA3+JA3S+header cross-consistency is near-impossible to fully spoof without custom TLS stack; very high precision |
| `Velocity` | 0.10 | High precision on burst patterns; low false positive rate; commodity signal |
| `CoT` | 0.09 | High recall for systematic extraction; Aho-Corasick O(n) at scale |
| `Embed` | 0.08 | Paraphrase-resistant; catches obfuscated extraction prompts; moderate precision |
| `Hydra` | 0.08 | Graph pivoting uniquely identifies multi-account coordination; no benign analogue |
| `TimingCluster` | 0.07 | Sync bursts from load balancers are very difficult to randomize; high precision |
| `AsnClassifier` | 0.07 | Cloud datacenter IPs are near-certain for automated jobs; high precision, broad coverage |
| `H2Grpc` | 0.06 | Strong signal when present, but not all attacks use gRPC |
| `RolePreamble` | 0.06 | Cross-account preamble collision is near-unique to coordinated campaigns |
| `Pivot` | 0.05 | Unique signal for late-stage campaigns; low false positives |
| `Biometric` | 0.05 | Structural entropy is strong but requires 10+ prompts of history |
| `Watermark` | 0.04 | High precision on canary hit; low recall until sufficient watermarks deployed |
| `SessionGap` | 0.04 | Cron regularity is a reliable automation fingerprint; complements Velocity |
| `TokenBudget` | 0.03 | Strong when geometric sweep detected; moderate standalone signal |
| `RefusalProbe` | 0.02 | Niche but high precision when cross-category sweep present |
| `SequenceModel` | 0.02 | Unique signal for full-capability coverage; requires ≥15 prompts of history |

---

## Adversarial Robustness

### Attacks Requiring High Cost to Defeat Glasswally

| Evasion Technique | Cost | Residual Signal |
|------------------|------|-----------------|
| Custom TLS stack to fake JA3S | Prohibitive | TimingCluster, Embed still fire |
| Fully random H2 SETTINGS per request | High | JA3S mismatch, structural biometrics |
| Natural language CoT elicitation (no keywords) | High | Embed cosine similarity still fires |
| Sub-second burst timing randomization | High | Velocity and longer-window TimingCluster still fire |
| Unique payment per account | High | IP and H2 fingerprint clustering survives |

### Attacks That Partially Evade

| Evasion Technique | Cost | Residual Signal |
|------------------|------|-----------------|
| Residential proxy rotation | Medium | Timing, H2, JA3S fingerprint stable per session |
| Low-and-slow (< 100 req/day/account) | Medium | Semantic embed, biometrics over longer windows |
| Multiple cloud providers | Medium | H2 SETTINGS library fingerprint survives provider change |
| Human-in-the-loop prompt variation | Very High | Timing, biometrics lose signal; Hydra + watermark survive |

---

## IOC Sharing Protocol

Cross-provider IOC sharing enables detection of campaigns operating across multiple LLM providers simultaneously. High-confidence IOC bundles (≥ 0.70) are:

1. **Signed** with HMAC-SHA256 using a provider-specific key
2. **Timestamped** with first/last seen
3. **Structured** as `IocBundle` JSON containing: IPs, subnets, JA3 hashes, JA3S hashes, H2 fingerprints, payment hashes, watermark tokens, account IDs
4. **Consumed** by peers after signature verification and freshness check (< 24h)

**Privacy**: Account IDs are hashed before sharing. Raw prompt content is never shared. Only behavioral fingerprints are included.

---

## Scope Exclusions

The following are explicitly **out of scope** for Glasswally:

- **Single-turn jailbreaks**: Not a distillation attack; handled by content safety systems
- **Prompt injection via user data**: Application security concern, not infrastructure
- **Denial of service**: Rate limiting infrastructure concern
- **Account sharing** (credential stuffing): Handled by auth/fraud systems
- **Legitimate high-volume API usage**: Scientific research, batch document processing — distinguished by semantic diversity and absence of CoT elicitation patterns

---

## References

- Hinton et al., "Distilling the Knowledge in a Neural Network" (2015)
- Orekondy et al., "Knockoff Nets: Stealing Functionality of Black-Box Models" (2019)
- Wallace et al., "Imitation Attacks and Defenses for Black-box Machine Translation Systems" (2020)
- Carlini et al., "Extracting Training Data from Large Language Models" (2021)
- JA3/JA3S: Salesforce Engineering, "TLS Fingerprinting with JA3 and JA3S" (2018)
- HTTP/2 SETTINGS fingerprinting: Akamai Research (2020)
- MITRE ATT&CK Enterprise Framework v15.1
