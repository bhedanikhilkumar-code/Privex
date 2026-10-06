# memory.md — Long-Term Project & Architectural Memory for Private Protection

> **DOCUMENT STATUS:** CANONICAL LONG-TERM PROJECT MEMORY  
> **LAST UPDATED:** 2026-10-05  
> **PURPOSE:** Persistent state, architectural ground truth, verified repository inventory, key design decisions, and rejected approaches across agent sessions.

---

## 1. Product Goal

Transform **Private Protection Windows Desktop** (`apps/desktop/`) from a basic on-device file/URL security scanner into a **real, strong, local-first, offline-first Windows Antivirus & Endpoint Protection product** while preserving 100% compatibility and shared core architecture (`@private-protection/core`, `@private-protection/ml`) across the Web App (`apps/web/`), Android App (`apps/mobile/`), and Browser Extension (`apps/extension/`).

---

## 2. Current Verified Codebase Architecture (Ground Truth vs. Legacy Docs)

> **CRITICAL MEMORY NOTE:** While early pre-coding documents in `docs/` (`docs/DESKTOP_TECHNICAL_ARCHITECTURE.md`) mentioned Tauri 2.x + Rust + Solid.js, the **actual implemented and tested repository** uses the following production stack:

- **Monorepo Tooling:** `pnpm` workspaces + TypeScript + `esbuild` + `Vitest` (39 test files across monorepo).
- **Shared Core Detection Engine (`packages/core/` — `@private-protection/core`):**
  - `URLAnalyzer` (`url-analyzer.ts`), `TextAnalyzer` (`text-analyzer.ts`), `CoreFileAnalyzer` (`file-analyzer.ts`).
  - `RuleEngine` (`rule-engine.ts`), `RiskScorer` (`risk-scorer.ts`), `DetectionPipeline` (`detection-pipeline.ts`).
  - `BloomFilter` (`bloom-filter.ts` — Kirsch-Mitzenmacher FNV-1a binary `PPBF` format) + `ThreatIntel` (`threat-intel.ts`) + `ThreatIntelUpdater` (`threat-intel-updater.ts` — Ed25519 verification).
- **Shared On-Device AI / ML Boundary (`packages/ml/` — `@private-protection/ml`):**
  - `PromptSanitizer`, `PromptBoundary`, `SchemaValidator`, `ResponsePolicy.enforceAuthority()`, and `TemplateFallback`.
- **Windows Desktop Application (`apps/desktop/`):**
  - **Runtime:** Electron `^44.5.1` (`src/main/electron-main.ts`, `src/preload/electron-preload.ts`) + React 18 (`src/renderer/`) + C# self-extracting installer (`scripts/installer-src/Installer.cs`).
  - **IPC Layer:** `src/ipc/ipc-channels.ts`, `src/ipc/ipc-validator.ts`, `src/ipc/ipc-handler.ts`.
  - **Desktop Services (`src/services/`):** `scanner.service.ts`, `quick-scan.service.ts`, `quarantine.service.ts`, `realtime-monitor.service.ts`, `process-auditor.service.ts`, `persistence-auditor.service.ts`, `network-monitor.service.ts`, `removable-media.service.ts`, `secure-storage.service.ts`, `update-verifier.service.ts`.

---

## 3. Core Security Principles

1. **LOCAL-FIRST:** All threat detection, static/structural parsing, behavioral correlation, ransomware containment, quarantine encryption, and AI explanation synthesis run 100% on-device.
2. **OFFLINE-FIRST:** 100% core detection parity when operating completely air-gapped without internet access.
3. **PRIVACY-FIRST & DATA-MINIMIZATION:** Zero Tier-1 user payloads (files, filenames, document text, URLs, process arguments) are ever uploaded to the cloud or persisted in plaintext logs.
4. **LOW-LATENCY & LOW-RESOURCE:** Sub-millisecond `CleanFileCache` fast path ($<0.08\text{ ms}$), header-first slicing, streaming 64 KB encryption ($<16\text{ MB}$ heap delta), $<1\%$ idle CPU, and $<200\text{ MB}$ peak scan RSS.
5. **FAIL-CLOSED DEFAULTS:** Malformed headers, tampered configurations (`storage.enc`), or invalid update signatures fail closed to `WARN`/`SUSPICIOUS` or Maximum Protection Defaults—never to silent `ALLOW`.
6. **PROTECTED SYSTEM FILE SAFETY (`RULE-09`):** Canonical Windows OS binaries (`C:\Windows\System32`, etc.) are never quarantined or deleted; if a system LOLBin (`powershell.exe`, `cmd.exe`, `vssadmin.exe`) is abused, only the offending process instance is terminated and the untrusted script/dropper quarantined.

---

## 4. Constitutional AI Boundary (`CORE -> VERDICT -> AI EXPLANATION`)

- **Unidirectional Flow:** The deterministic Core Engine computes the `riskScore` ($0\text{–}100$) and `verdict` (`ALLOW`, `INFORM`, `WARN`, `BLOCK`, `QUARANTINE`, `CONTAIN_PROCESS`). The AI Assistant (`@private-protection/ml`) receives **only** sanitized `Evidence` tokens after the verdict is finalized.
- **Zero Authority:** The AI Assistant cannot make verdicts, alter scores, override rules, disable shields, quarantine/restore files, or modify exclusions.
- **Strict Validation:** Untrusted strings are wrapped in `<UNTRUSTED_EVIDENCE_DATA>`, output is validated against a rigid JSON schema and Flesch-Kincaid Grade $\le 8.0$ readability check, and any failure falls back to deterministic templates in $<1\text{ ms}$.

---

## 5. Verified Current Capabilities vs. Identified Gaps

| Capability Area | Current Status | Verified Evidence & Key Gaps to Remediate |
|---|---|---|
| **Web / Phishing / Scam Text Detection** | `EXISTS + VERIFIED` | `url-analyzer.ts`, `text-analyzer.ts`, `rule-engine.ts` verified across Core, Extension, Web, Mobile, and Desktop. |
| **AI Explanation Boundary** | `EXISTS + VERIFIED` | `prompt-boundary.ts`, `response-policy.ts` verified against prompt injection and authority escalation. |
| **Automatic Quarantine Trigger** | `EXISTS + VERIFIED` | `realtime-monitor.service.ts:159-174` auto-isolates `BLOCK` verdicts. |
| **File & Malware Detection Engine** | `EXISTS + WEAK` / `PARTIAL` | Checks 64KB magic header, global entropy, and double extensions only. **Gaps:** Ignores computed SHA-256 (`lookupHash` never called; 0 file hashes in seed DB), 0 byte/YARA signatures (`Mimikatz`/`vssadmin`/EICAR not matched by content), no PE section/IAT/Authenticode parser, no ZIP/archive inspection, no Office macro/script de-obfuscation, and flags benign high-entropy `.exe` files as `WARN`. |
| **Quarantine Vault (`QuarantineService`)** | `EXISTS + VERIFIED` | Hardened `PPVAULT2` streaming 64 KB AES-256-GCM encryption with per-chunk AAD binding (`uuid || chunkIdx || isFinal`), DPAPI key sealing, atomic encrypted `manifest.json.enc` with `.bak` crash recovery, TOCTOU file descriptor pinning (`O_NOFOLLOW`), NTFS `:Zone.Identifier` ADS preservation, and "Restore & Trust SHA-256" workflow. 100 MB large-file peak V8 heap delta `4.111 MB` (SLA: $<16\text{ MB}$). |
| **Real-Time File & Download Shield (`RealtimeMonitorService`)** | `EXISTS + VERIFIED (PHASE E)` | Recursive multi-root watching across 6 security-relevant locations (`Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, `Startup`), download lifecycle state tracking (`.crdownload`, `.part`), bounded priority queue (`maxQueueSize = 10,000`), backpressure handling with bounded RSS ($< 200\text{ MB}$), file stability verification, canonical pipeline routing (`FileAnalyzer` -> `RiskScorer` -> `EngineVerdict`), automatic quarantine of `BLOCK` threats to `PPVAULT2`, System Tray icon with background continuity on window close, and rate-limited OS toast notifications ($\le 3$ per 10s). Ingress latency $p95 < 50\text{ ms}$ ($p95 = 31.94\text{ ms}$ e2e / $2.46\text{ ms}$ engine). |
| **Process & Behavior Monitoring** | `EXISTS + WEAK` | Runs `tasklist /FO CSV` checking 4 dummy names; lacks full executable path, PPID parent-child tree, LOLBin command-line analysis, and process containment. |
| **Ransomware Protection** | `MISSING` | Needs Protected Folders (`Documents`/`Pictures`/`Desktop`), Trusted App access control, Canary Trap files, Sliding-Window Velocity/Entropy detector, and Copy-on-Write `ShadowVault` rollback. |
| **Startup / Persistence Protection** | `EXISTS + WEAK` | Checks per-user Startup folder filenames only; needs All-Users Startup, `.lnk` target parser, Registry `Run`/`RunOnce`, and Scheduled Tasks. |
| **USB / Removable Media Protection** | `EXISTS + WEAK` | Checks `D:\`–`Z:\` existence only; needs `DriveType=2` detection, capacity reporting, `autorun.inf`/`.lnk` worm scanning, and UI wiring. |
| **Scheduled Scanning** | `MISSING` | Needs `ScanSchedulerService` with Daily Quick, Weekly Full, Startup Catch-Up, and battery/load guards. |
| **Notifications & Storm Rate-Limiter** | `PARTIAL` | In-app banner exists; needs native Windows OS Toast notifications, System Tray icon, and $\le 3$ toasts/10s storm coalescer. |
| **Updates & Threat Intelligence** | `PARTIAL` | Ed25519 verifier exists, but version `1` is hardcoded in `App.tsx`; needs canonical tuple signing, offline `.ppdb` bundle import, and LKG rollback. |
| **Self-Health, Watchdog & Audit Log** | `PARTIAL` | Needs 4-State Health Model (`HEALTHY`/`WARNING`/`DEGRADED`/`CRITICAL`), `WatchdogService` auto-recovery + shield snooze timer, and HMAC-chained `AuditLoggerService`. |
| **Desktop UX Command Center** | `EXISTS + WEAK` | 11 views exist; expanding to the full 20-Screen Antivirus UX architecture (`design.md`). |

---

## 6. Target Capabilities Summary

1. **10-Layer Malware Detection Engine (`4-Stage Sieve`):**
   - `Layer 1`: `CleanFileCache` + SHA-256 `BloomFilter` & Exact Malware Table + Signed Vendor Allowlist.
   - `Layer 2`: Flattened `Int32Array` Aho-Corasick multi-pattern byte/string automaton + YARA-lite boolean rules.
   - `Layer 3`: Magic Header vs. Extension, Double/Triple Extension, Whitespace Padding, Unicode RTLO (`\u202E`), and NTFS `:Zone.Identifier` MOTW URL inspection.
   - `Layer 4`: Section & 4 KB Sliding-Window Shannon Entropy (`ENTROPY_LUT`), `W+X` permissions, Packer section names, IAT injection/credential API clusters, and Base64/charcode script de-obfuscation.
   - `Layer 5`: Zero-Allocation `DataView` PE32/PE32+ Parser, Bounded ZIP Central Directory Inspector (with zip-bomb ratio $>100:1$ guard), Office OLE2/OOXML Macro Parser, and `.eml` MIME/attachment scanner.
   - `Layer 6`: Process Lineage Tree, LOLBin CLI analyzer, Ransomware Velocity detector, and Canary Trap triggers.
   - `Layer 7`: Local Path Zone & Timestomping reputation.
   - `Layer 8`: Cross-Layer Synergy Correlation Matrix.
   - `Layer 9`: Bounded Non-Linear Log-Odds `RiskScorer` with clean-installer dampening.
   - `Layer 10`: 6-Tier Verdict (`ALLOW`, `INFORM`, `WARN`, `BLOCK`, `QUARANTINE`, `CONTAIN_PROCESS`) & 5-Tier Automatic Response Ladder.
2. **Ransomware Shield & Copy-on-Write `ShadowVault`:** Protected folders, Smart/Strict app access control, decoy canary traps, $<500\text{ ms}$ velocity arrest, and 1-click file restoration independent of Windows VSS.
3. **Hardened `PPVAULT2` Quarantine:** 64 KB chunked streaming AES-256-GCM, DPAPI key sealing, atomic encrypted manifest with `.bak` recovery, and "Restore & Trust SHA-256".
4. **20-Screen Antivirus Command Center UX:** Complete desktop experience with 3-tier posture hero, 4-Pillar plain-language alerts, System Tray persistence, native rate-limited OS toasts, HMAC-chained forensic history, and Watchdog self-healing.

---

## 7. Important Architectural Decisions

1. **`DECISION-01` (Preserve & Harden Electron + TypeScript Monorepo):** Keep the working Electron 44 + TypeScript + React 18 architecture in `apps/desktop/` and `@private-protection/core` rather than rewriting from scratch in Tauri/Rust, ensuring zero regressions while adding deep byte-level `DataView` parsers and Windows OS integrations.
2. **`DECISION-02` (4-Stage Short-Circuit Sieve for CPU Efficiency):** Gate expensive full-file SHA-256 hashing and deep PE/heuristic parsing behind Stage 0 (`CleanFileCache`, $<0.08\text{ ms}$) and Stage 1 (4 KB/64 KB header & magic triage, $<0.50\text{ ms}$).
3. **`DECISION-03` (VSS-Independent Copy-on-Write `ShadowVault`):** Because ransomware routinely executes `vssadmin delete shadows /all /quiet`, Private Protection maintains its own encrypted Copy-on-Write backup cache (`~/.private-protection/shadow-vault/`) alongside blocking `vssadmin` command lines.
4. **`DECISION-04` (SHA-256 Hash-Bound Trust & Exclusions):** Bind false-positive quarantine restorations and Trusted Applications to exact **SHA-256 file hashes** by default so if an excluded/trusted binary is later modified or replaced by malware, trust is automatically revoked.
5. **`DECISION-05` (`RULE-29` — Atomic Git Commit & Push on Every Step & Prompt):** Every step, architectural document, and implementation phase across every prompt must be committed atomically with an informative commit message and immediately pushed to `origin/main`.

---

## 8. Explicitly Rejected Approaches

1. **`REJECTED-01` (Custom Kernel Minifilter `FltMgr.sys` / `ELAM` Driver in Core Release):** Rejected due to mandatory EV Hardware HSM + Microsoft WHQL kernel attestation signing requirements, BSOD system stability risk, and Windows Security Center Defender deactivation liability.
2. **`REJECTED-02` (Local TLS MITM Proxy for HTTPS/Email Scanning):** Rejected because installing a local root CA and intercepting TLS traffic breaks application certificate pinning, weakens browser TLS cipher validation, and introduces severe local attack surface. Web and email protection instead use the Browser Extension, NTFS `:Zone.Identifier` MOTW inspection, and local `.eml`/attachment scanning.
3. **`REJECTED-03` (Custom NDIS/WFP Packet-Filtering Firewall Driver):** Rejected in favor of user-mode active TCP socket-to-PID auditing (`netstat -ano` + `ThreatIntel` C2 IP matching) and native Windows Defender Firewall integration.
4. **`REJECTED-04` (Cloud Sandbox File Upload / `CyberCapture`):** Rejected as a direct violation of `AGENTS.md` Tier-1 Privacy Mandate (`RULE-01`, `RULE-03`, `RULE-05`).
5. **`REJECTED-05` (Giving the AI Assistant Verdict or Remediation Authority):** Rejected under Constitutional Invariant 2 (`RULE-04`).

---

## 9. Current Phase & Next Phase

- **Previously Completed:**
  - **`PHASE A — Antivirus Baseline + Security Core Hardening`** (`docs/PHASE_A_COMPLETION.md`, `docs/PHASE_A_PERFORMANCE_BASELINE.md`).
  - **`PHASE B — Core Detection Engine Expansion`** (`docs/PHASE_B_COMPLETION.md`, `docs/PHASE_B_FINAL_INDEPENDENT_AUDIT.md`).
  - **`PHASE C — File Protection & 10-Layer Static Malware Engine`** (`docs/PHASE_C_COMPLETION.md`, `docs/PHASE_C_PERFORMANCE_BASELINE.md`, `docs/PHASE_C_FINAL_INDEPENDENT_AUDIT.md`).
- **Phase Completed & Audit Verified:** **`PHASE D — Quarantine Hardening (PPVAULT2)`** (GO / COMPLETE).
  - **Audit Reports:** `docs/PHASE_D_COMPLETION.md`, `docs/PHASE_D_PERFORMANCE_BASELINE.md`, `docs/PHASE_D_REMEDIATION.md`, `docs/PHASE_D_FINAL_INDEPENDENT_AUDIT.md`.
  - **Phase D Verified Capabilities (`apps/desktop` & `@private-protection/core`):**
    - **`PPVAULT2` Streaming 64 KB AES-256-GCM Engine:** Chunked streaming encryption and decryption with per-chunk AAD binding (`containerUuid || chunkIndex || isFinalChunk`) and dual-magic backward compatibility for legacy `PPVAULT1` containers.
    - **DPAPI Key Sealing:** Sealed `.vault.key` via Windows DPAPI `safeStorage` / `CryptProtectData` with machine-local `0o600` key fallback.
    - **Encrypted Manifest & Crash Recovery:** Authenticated AES-256-GCM encrypted `manifest.json.enc` with atomic unique `.tmp` swap, automatic `.bak` backup recovery, and boot-time orphaned `.blob` reconciler.
    - **TOCTOU & Symlink Defense:** Pinned `O_RDONLY | O_NOFOLLOW` file descriptors rejecting symlinks, directory junctions, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
    - **NTFS :Zone.Identifier ADS:** Captures and preserves Mark-of-the-Web metadata on Windows systems.
    - **Restore & Trust SHA-256 Grant:** Restoring falsely detected files with `trustSha256: true` dynamically adds their SHA-256 digest to `ThreatIntel.getSharedInstance()` and `CleanFileCache`, preventing `RealtimeMonitorService` re-quarantine loops.
    - **Remediated Hardening (SEC-D-01 to SEC-D-04):** Upper-bound check on declared chunk ciphertext length against memory exhaustion, in-memory concurrency lock on active quarantine IDs, boot-time sweep of stale `.tmp` files, and pre-unlink manifest staging with atomic rollback.
  - **Empirical Performance Benchmarks:**
    - 100 MB large-file peak V8 heap delta: **`4.166 MB`** (SLA: $< 16.0\text{ MB}$, **PASS**)
    - 100 MB streaming throughput: **`16.06 MB/s`** (encrypt), **`26.13 MB/s`** (decrypt)
    - 1 MB streaming latency: **`124.52 ms`** (encrypt $p50$), **`147.38 ms`** (decrypt $p50$)
    - Restore & Trust lookup latency: **`0.001 ms`** ($p50$) (SLA: $< 0.050\text{ ms}$)
  - **Monorepo Regression Test Rate:**
    - **658/658 PASS (100%)** across 110 test files in all 6 monorepo workspaces (0 failures, 0 errors, 0 skips).
    - **49 dedicated quarantine tests** all passing.
- **Phase Implemented & Verified:** **`PHASE E — Real-Time Protection Engine & Background Continuity`** (COMPLETE).
  - **Reports & Architecture:** `docs/PHASE_E_ARCHITECTURE.md`, `docs/PHASE_E_COMPLETION.md`.
  - **Phase E Verified Capabilities (`apps/desktop`):**
    - Recursive multi-directory watching of 6 Windows user roots (`Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, `Startup`).
    - Download lifecycle tracking (`.crdownload`, `.part`, `.download`, `.tmp`) ensuring partial downloads never raise false alerts, triggering immediately upon rename to finalized target.
    - Two-tier bounded priority queue (`maxQueueSize = 10,000`), debounce, event deduplication, and backpressure eviction under load (Peak RSS: `120.68 MB` < `200 MB`).
    - Symlink and reparse point rejection (`lstat.isSymbolicLink()`).
    - File stability probe verifying non-exclusive read handle release before scanning.
    - Single canonical verdict authority: `FileAnalyzer` -> `RiskScorer` -> `EngineVerdict`.
    - Automatic quarantine into `PPVAULT2` for critical `BLOCK` threats.
    - System Tray integration with 16x16 RGBA shield icon, background continuity on window close, and rate-limited OS toast notifications ($\le 3$ per 10s).
  - **Empirical Performance Benchmarks:**
    - Ingress detection & auto-quarantine latency: $p95 = 31.94\text{ ms}$ (end-to-end) / $2.46\text{ ms}$ (internal queue processing) (SLA: $< 50.0\text{ ms}$, **PASS**).
    - Category 13 Burst Test: 1,000 rapid file events processed with 0 dropped threats and bounded memory (`120.68 MB` RSS).
  - **Monorepo Regression Test Rate:**
    - **672/672 PASS (100%)** across 113 test files in all 6 monorepo workspaces (0 failures, 0 errors, 0 skips).
    - **29/29 desktop test files PASS (149/149 tests)**.
- **Next Phase:**
  - **`PHASE F: Process, Behavioral & LOLBin Monitoring`** (from `phase.md`). Awaiting user master implementation prompt / audit before commencing Phase F.


