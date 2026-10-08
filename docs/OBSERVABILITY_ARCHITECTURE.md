# OBSERVABILITY_ARCHITECTURE.md — Privacy-Preserving Diagnostics & Telemetry

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVEX OBSERVABILITY**  
> This document specifies the privacy-preserving observability architecture of PRIVEX, detailing local-only diagnostic logging, crash sanitization, Differential Privacy telemetry, and Oblivious HTTP relays.

---

## 1. THE PRIVACY-PRESERVING OBSERVABILITY CONSTITUTION

> **OBSERVABILITY CONSTITUTIONAL INVARIANT**: Observability must **NEVER** become a backdoor for exfiltrating sensitive user payloads. All diagnostics are **LOCAL-FIRST**, and any outbound telemetry is **STRICTLY OPT-IN**, mathematically noise-injected, and decoupled from client IP addresses.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ LOCAL DEVICE BOUNDARY (USER-ACCESSIBLE AUDIT LOGS)                                                    │
│                                                                                                        │
│   ┌───────────────────────────────┐     ┌──────────────────────────────┐     ┌──────────────────────┐  │
│   │ Local Execution Metrics       │     │ Local Crash Dumps            │     │ Local Audit History  │  │
│   │ • Subsystem latency p50/p95   │     │ • Scrubbed stack traces      │     │ • Truncated hashes   │  │
│   │ • RSS Memory watermark (MB)   │     │ • Zero memory payload dumps  │     │ • Threat categories  │  │
│   └───────────────────────────────┘     └──────────────────────────────┘     └──────────────────────┘  │
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │
                                                    ▼ User Opt-In Gate (Default: OFF)
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ANONYMOUS TELEMETRY PIPELINE (MATHEMATICAL PRIVACY ENFORCEMENT)                                        │
│                                                                                                        │
│   1. PII Stripping: Strip all URLs, IPs, user IDs, timestamps, device IDs                              │
│   2. k-Anonymity Truncation: Hash prefix truncated to 16 bits (Ensures k >= 1,000 domains match)       │
│   3. Differential Privacy: Laplace Noise injection (epsilon = 1.0, sensitivity = 1)                    │
│   4. Oblivious HTTP (OHTTP RFC 9458) Relay: IP address stripped at edge relay                          │
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │
                                                    ▼ Blind Encrypted Payload
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ CENTRAL AGGREGATOR (Sees payload, NEVER sees IP • Cannot identify or track individual users)           │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. LOCAL DIAGNOSTIC METRICS & HEALTH MONITORING

Local diagnostic counters are maintained in volatile RAM and written periodically to the encrypted local SQLite database:

### 2.1 Metrics Captured Locally
1. **Latency Distributions**:
   - `perf.scan.url.p50_ms`: Median time for URL evaluation.
   - `perf.scan.url.p95_ms`: 95th percentile latency (SLA: $< 1.0\text{ ms}$).
   - `perf.scan.message.p95_ms`: 95th percentile for message parsing (SLA: $< 5.0\text{ ms}$).
   - `perf.ai.synthesis.p95_ms`: Explanation generation latency (SLA: $< 25.0\text{ ms}$).
2. **Resource Watermarks**:
   - `system.memory.rss_mb`: Peak resident set size of process.
   - `system.storage.db_size_kb`: Total encrypted database file size on disk.
3. **Detector Trigger Frequencies**:
   - Aggregated counters for rule activations (e.g. `rules.hit.ip_host: 42`, `rules.hit.brand_spoof: 12`).

---

## 3. LOCAL CRASH REPORTING & SCRUBBED STACK TRACES

When an unhandled exception or process panic occurs:
1. **Memory Scrubbing**:
   - Minidump generation on desktop/mobile explicitly disables memory heap dumps (`MiniDumpNormal` on Windows; zero memory buffers captured).
   - Only CPU register state, thread execution addresses, and module load addresses are captured.
2. **Stack Trace Sanitization**:
   - Path strings are sanitized to strip local user directories (`C:\Users\<username>\...` replaced with `[REDACTED_USER_PATH]`).
   - Function arguments containing string values are completely replaced with `[REDACTED_ARG]`.
3. **Storage & Transmission**:
   - Crash reports are stored locally in `.crash_logs/`.
   - **Never automatically uploaded**. The user must explicitly inspect the scrubbed text and approve any transmission.

---

## 4. MATHEMATICAL PRIVACY IN TELEMETRY

For users who explicitly opt into anonymous threat intelligence sharing:

### 4.1 $k$-Anonymity Domain Hash Truncation
When reporting a detected malicious domain:
- The client computes $\text{SHA-256}(\text{canonical\_domain})$.
- The hash is truncated to the first **16 bits** ($2\text{ bytes}$), leaving $240\text{ bits}$ discarded.
- In a universe of $350,000,000$ active registered domains, a 16-bit prefix matches approximately $5,340$ distinct domains:
  $$k \approx \frac{350,000,000}{2^{16}} \approx 5,340 \gg 1,000$$
- It is mathematically impossible for the receiver to determine which of the $5,340$ domains the user visited.

### 4.2 Laplace Differential Privacy ($\varepsilon = 1.0$)
When reporting event category counters:
- True count $c$ is randomized by adding noise drawn from the Laplace distribution:
  $$c_{\text{reported}} = c + \text{Laplace}\left(0, \frac{\Delta f}{\varepsilon}\right)$$
  Where sensitivity $\Delta f = 1$ (one user can contribute at most one event) and privacy budget $\varepsilon = 1.0$.
- This guarantees $\varepsilon$-differential privacy, preventing linkage attacks even if an attacker possesses external side-channel data.

---

## 5. USER PRIVACY CONTROLS & DASHBOARD

1. **Transparency Viewer**:
   - In Settings $\rightarrow$ Privacy & Diagnostics, users can view every metric counter and audit record stored on their device.
2. **One-Click Crypto-Shred**:
   - A prominent button allows immediate, irreversible cryptographic deletion of all audit logs and local counters.
3. **Granular Consent Toggles**:
   - `Anonymous Threat Telemetry: [OFF | ON]` (Default: OFF).
   - `Automated Crash Submissions: [OFF | ON]` (Default: OFF).
   - `Threat Feed Updates: [OFF | ON]` (Default: ON).
