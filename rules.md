# rules.md — Permanent Engineering & Security Rulebook for Privex Windows Antivirus

> **DOCUMENT STATUS:** CANONICAL ENGINEERING & SECURITY GOVERNANCE RULEBOOK  
> **APPLICABILITY:** All Engineers, Autonomous AI Agents, Subagents, CI/CD Pipelines, and Code Reviewers working on Privex (`apps/desktop`, `packages/core`, `packages/ml`, and native Windows service helpers).  
> **SUPREMACY:** This rulebook complements and enforces `AGENTS.md` specifically for the transformation of Privex Windows Desktop into a real, local-first, offline-first Windows Antivirus & Endpoint Protection product. Violation of any rule in this document blocks phase completion and PR merge.

---

## Rule Index (The 42 Mandatory Engineering & Security Rules)

| Rule ID | Rule Name | Enforcement Layer | Primary Verification Gate |
|---|---|---|---|
| **RULE-01** | Local-First Rule | Architecture & Network Sandbox | `network-isolation.test.ts` |
| **RULE-02** | Offline-First Rule | Core Engine & Desktop Services | `offline-parity.test.ts` |
| **RULE-03** | Privacy & Data Minimization Rule | Storage, Memory & Telemetry | Tier-1 Zero-Persistence Audit |
| **RULE-04** | AI Boundary Rule | Detection Pipeline & AI Adapter | `assistant-prompt-injection.test.ts` |
| **RULE-05** | No Silent Cloud Dependency Rule | Dependency Graph & CSP/Socket Guard | Outbound Socket Interceptor |
| **RULE-06** | No Live Malware in Tests Rule | Repository & CI Security | Safe Fixture Policy Scanner |
| **RULE-07** | Evidence Before Claims Rule | Engineering Process & PR Review | Code & Test Citation Verification |
| **RULE-08** | Fail-Safe Defaults Rule | Parsers, Services & Configuration | Fault-Injection & Corrupt-Input Suite |
| **RULE-09** | Protected System File Rule | Quarantine, Remediation & Exclusions | `false-positive-corpus.test.ts` |
| **RULE-10** | Quarantine Safety Rule | `QuarantineService` & Vault Format | `quarantine-streaming.test.ts` |
| **RULE-11** | Signed Update Rule | `UpdateVerifierService` & Threat DB | `update-verifier.test.ts` |
| **RULE-12** | IPC Validation Rule | `IpcValidator`, `IpcHandler` & Named Pipes | `ipc-security.test.ts` |
| **RULE-13** | Least Privilege Rule | Windows Service, Worker Threads & UI | Process Token & DACL Audit |
| **RULE-14** | Resource Budget Rule | Worker Pool, Cache & Memory Streams | `performance-benchmark.test.ts` |
| **RULE-15** | Notification Rate Limit Rule | `NotificationService` & UI Banner | `notification-rate-limiter.test.ts` |
| **RULE-16** | Rollback Safety Rule | Ransomware Vault & Update Manager | `ransomware-shield.test.ts` & `update-verifier.test.ts` |
| **RULE-17** | False Positive Protection Rule | Allowlist, Heuristics & Restore Flow | `false-positive-corpus.test.ts` |
| **RULE-18** | Log Privacy Rule | `AuditLogger` & Crash Reporter | PII & Tier-1 Scrubbing Verification |
| **RULE-19** | Configuration Integrity Rule | `SecureStorageService` & Friction Gate | Config Tamper & DPAPI Suite |
| **RULE-20** | Testing Before Completion Rule | CI Pipeline & Definition of Done | 100% Test Pass + $\ge 90\%$ Coverage |
| **RULE-21** | Performance Verification Rule | Benchmark Suite & Low-End Profiles | p50/p95 Latency & RSS Gates |
| **RULE-22** | Security Review Before Merge Rule | STRIDE Threat Model Sign-Off | Pre-Merge Security Checklist |
| **RULE-23** | Documentation Sync Rule | Root Docs (`PRD`, `Architecture`, `phase`, `memory`) | Doc-to-Code Traceability Check |
| **RULE-24** | No Stub / Fake Protection Rule | Source Code & Runtime Audit | Zero-Stub / Zero-Mock Production Gate |
| **RULE-25** | Explicit Status Reporting Rule | Agent & Engineering Reporting | 6-State Status Classification |
| **RULE-26** | Architectural Honesty Rule | Windows OS Integration & UI Claims | User-Mode vs Kernel Capability Audit |
| **RULE-27** | Clean Code & Modularity Rule | Monorepo Boundaries & Type Safety | `tsc --noEmit` & Linter Gate |
| **RULE-28** | Regression Prevention Rule | Automated Regression Corpus | Continuous CI Golden Suite |
| **RULE-29** | Atomic Git Commit & Push Every Step Rule | Git Workflow & Release Governance | `git status` Clean + `git push` Verified |

---

## Detailed Rule Specifications

### RULE-01: Local-First Rule
- **Mandate:** All primary antivirus detection, static PE/header inspection, signature matching, behavioral process analysis, ransomware containment, URL/Mark-of-the-Web (MOTW) evaluation, risk scoring, verdict mapping, quarantine encryption, and plain-language AI explanation synthesis **MUST** execute 100% locally on the user's Windows endpoint.
- **Prohibition:** Never offload file scanning, process command-line evaluation, or verdict calculation to a remote server or cloud API.
- **Verification:** `apps/desktop/src/__tests__/privacy/network-isolation.test.ts` verifies that scanning files, processes, and URLs triggers zero outbound network sockets.

### RULE-02: Offline-First Rule
- **Mandate:** The Windows Desktop Antivirus **MUST** maintain 100% core detection, behavioral monitoring, ransomware protection, quarantine, and explanation parity when completely air-gapped (disconnected from the internet).
- **Staleness Handling:** When offline for extended periods, the system uses the embedded factory-seeded or last-verified threat intelligence database, transitions the Health State from `HEALTHY` to `WARNING` after 7 days of definition staleness (and `DEGRADED` after 30 days), and slightly increases heuristic sensitivity weight as specified in `docs/OFFLINE_ARCHITECTURE.md`—never failing open.
- **Verification:** `apps/desktop/src/__tests__/offline/offline-parity.test.ts` blocks all `net`, `tls`, `http`, `https`, and `dns` calls and asserts identical verdicts between online and air-gapped execution.

### RULE-03: Privacy & Data Minimization Rule
- **Mandate:** User files, document contents, raw process command lines containing user secrets, visited URLs, and personal directory structures are classified as **Tier 1 (Highly Sensitive)**.
  1. Tier 1 raw contents are **NEVER** transmitted off-device under any circumstance.
  2. During scanning, file chunks are processed in bounded volatile RAM buffers (`64 KB`) and dereferenced/zeroed immediately upon scan completion.
  3. Only minimum necessary metadata (e.g., SHA-256 hash, threat category, rule ID, sanitized path in encrypted local storage) is retained locally when a threat is quarantined or logged.
- **Verification:** Memory buffer lifecycle checks and zero Tier-1 plaintext disk persistence assertions.

### RULE-04: AI Boundary Rule
- **Mandate:** The execution pipeline is strictly unidirectional:
  $$\text{CORE ENGINE} \longrightarrow \text{DETERMINISTIC VERDICT \& RISK SCORE} \longrightarrow \text{READ-ONLY AI EXPLANATION}$$
  1. **Zero Decision Authority:** The AI Assistant (`ExplanationEngine` / local SLM) **MUST NEVER** make security verdicts, alter `riskScore`, downgrade `severity`, override `RuleEngine` or `RiskScorer`, disable protection shields, quarantine/restore files, or modify exclusions.
  2. **Data vs. Instructions:** Raw file strings, filenames, process command lines, and URLs are untrusted data and **MUST NEVER** be concatenated into executable LLM system prompts. The AI layer receives only structured, sanitized `Evidence` objects (`ruleId`, `category`, `weight`, `description`).
  3. **Schema & Deterministic Fallback:** AI output must validate against a rigid JSON schema and Flesch-Kincaid Grade $\le 8$ readability check; any validation failure or timeout immediately falls back to deterministic explanation templates in $< 1\text{ ms}$.
- **Verification:** `apps/desktop/src/__tests__/ai/assistant-prompt-injection.test.ts` injects 500+ adversarial prompt strings into filenames and binary payloads and verifies 0% change in `verdict` or `riskScore`.

### RULE-05: No Silent Cloud Dependency Rule
- **Mandate:** No feature, third-party npm package, native helper, or UI component may introduce silent outbound network requests, remote telemetry pings, CDN font/script fetches, or cloud reputation lookups by default.
- **Update & Optional Network Policy:** The only permitted outbound network activity is:
  1. Checking/downloading Ed25519-signed threat definition and engine updates (which can be disabled or air-gapped).
  2. Strictly opt-in, OHTTP-relayed, $\varepsilon$-differentially private telemetry (`telemetryOptIn: false` by default).
- **Verification:** Electron Content Security Policy (`default-src 'self'; connect-src 'none'` in renderer UI) and main-process socket guards.

### RULE-06: No Live Malware in Tests Rule
- **Mandate:** Real, live, weaponized, or self-replicating malware binaries, live ransomware executables, or active exploit payloads **MUST NEVER** be committed to the repository, fetched in CI, or executed during testing.
- **Permitted Test Artifacts:**
  1. Standard 68-byte **EICAR** test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`).
  2. **Synthetic PE/MZ Structural Fixtures:** Constructed byte buffers with valid `MZ`/`PE\0\0` headers, high-entropy random sections, and benign test indicator strings (e.g., `"PP_TEST_INDICATOR_CREATEREMOTETHREAD"`).
  3. **Sandboxed Ransomware Simulator:** A deterministic test harness that verifies target paths begin with `os.tmpdir()/pp-ransom-sandbox-<uuid>` before performing rapid high-entropy writes or renames on dummy files.
- **Verification:** CI pre-commit check ensuring test fixtures contain only EICAR or synthetic headers.

### RULE-07: Evidence Before Claims Rule
- **Mandate:** Neither human engineers nor AI agents may claim a feature works, a bug is fixed, a competitor behaves in a certain way, or a performance SLA is met without concrete, verifiable evidence.
  1. Repository claims require exact file paths and line numbers.
  2. Competitor and OS mechanism claims require official vendor/Microsoft documentation URLs (`SOURCE-DERIVED FACT`) clearly separated from `MODEL/ENGINEERING INFERENCE` and `PROJECT DECISION`.
  3. Implementation claims require passing automated test output and benchmark numbers.
- **Verification:** Enforced during PR review and phase exit gates.

### RULE-08: Fail-Safe Defaults Rule
- **Mandate:** Every parser, analyzer, IPC validator, configuration loader, and update verifier must **fail closed** (or fail to a safe `CAUTION` / `WARN` / `Maximum Protection` state), never to silent `ALLOW` or weakened security:
  1. If a file header or PE structure is malformed or truncated so it crashes a parser $\rightarrow$ return `SUSPICIOUS` (`WARN`), never `SAFE`.
  2. If `settings.enc` fails AES-GCM/HMAC authentication $\rightarrow$ enforce **Maximum Protection Defaults** (`realtimeShieldEnabled: true`, `autoQuarantineCritical: true`, `excludedPaths: []`) and emit `SECURITY_CONFIG_TAMPERED`.
  3. If an update signature, hash, or monotonic sequence check fails $\rightarrow$ abort staging, retain the existing verified database, and log `UPDATE_VERIFICATION_FAILED`.
- **Verification:** Fault-injection unit tests across all services.

### RULE-09: Protected System File Rule
- **Mandate:** The antivirus **MUST NEVER** quarantine, move, modify, or delete critical Windows operating system binaries or boot files, as doing so can brick the user's PC (weaponized false-positive DoS).
  1. Paths resolved via canonical `fs.realpathSync.native()` inside protected OS roots (`C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Windows\WinSxS`, `C:\Program Files\Windows Defender`, boot sectors) with valid Microsoft Authenticode signatures are **exempt from automatic file quarantine/deletion**.
  2. If a legitimate system binary (LOLBin such as `powershell.exe`, `cmd.exe`, `rundll32.exe`, `mshta.exe`, `vssadmin.exe`) exhibits malicious command-line arguments or behavior, the engine **terminates/suspends the offending process instance**, blocks the child payload, and quarantines the untrusted script/dropper—**NEVER** quarantining `powershell.exe` or `cmd.exe` itself.
- **Verification:** `apps/desktop/src/__tests__/regression/false-positive-corpus.test.ts` and `quarantine.test.ts`.

### RULE-10: Quarantine Safety Rule
- **Mandate:** Every quarantined file must be completely inert, non-executable, encrypted at rest, and restorable without corruption or path traversal:
  1. **Streaming Encryption:** Use chunked (`64 KB`) streaming `AES-256-GCM` (`PPVAULT2` / `PPVAULT1` compatible) so large files never cause V8 heap OOM.
  2. **Hardware/OS Key Wrapping:** Wrap the vault master key (`K_vault`) using Windows DPAPI (`CryptProtectData` / Electron `safeStorage`) rather than relying solely on POSIX `0o600` file modes on NTFS.
  3. **Race-Free Isolation:** Acquire an exclusive file handle (`FILE_SHARE_NONE` / `O_NOFOLLOW`), reject symlinks and NTFS directory junctions (`FILE_ATTRIBUTE_REPARSE_POINT`), strip/record Alternate Data Streams (`:Zone.Identifier`), and write `manifest.json.enc` atomically via `.tmp` + rename swap.
  4. **Safe Restore:** Verify AES-GCM authentication tags and original SHA-256 hash before writing bytes; block restoration to system directories or Startup folders unless explicitly overridden via Friction Gate; resolve filename collisions safely (`_restored_<timestamp>`).
- **Verification:** `apps/desktop/src/__tests__/services/quarantine-streaming.test.ts` and `gap24-quarantine-path-safety.test.ts`.

### RULE-11: Signed Update Rule
- **Mandate:** No threat intelligence database, heuristic ruleset, Bloom filter, or binary update may be loaded unless it passes cryptographic verification:
  1. **Ed25519 Signature:** Verify signature against a pinned production Root Public Key over the canonical tuple `(version || versionSequence || publishedAt || sha256)`.
  2. **Monotonic Anti-Downgrade:** Reject any manifest where `versionSequence <= currentVersionSequence` persisted in DPAPI-protected storage.
  3. **Atomic Staging & Self-Test:** Write updates to an isolated staging directory, verify SHA-256 and header integrity, run a smoke test against the EICAR fixture, and perform an atomic pointer/file swap. If the self-test fails, automatically roll back to the previous known-good version.
- **Verification:** `apps/desktop/src/__tests__/services/update-verifier.test.ts`.

### RULE-12: IPC Validation Rule
- **Mandate:** Every IPC boundary (`Renderer <-> Electron Main` and `Electron Main <-> Background Windows Service`) is a Zero-Trust boundary:
  1. Validate sender origin (`event.senderFrame === event.sender.mainFrame` and strict packaged `file://`/`app://` origin in production).
  2. Validate every payload against strict schema validators (`IpcValidator`) rejecting null bytes, shell metacharacters, UNC paths (`\\server\share`), DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), and path traversal (`..`).
  3. Enforce per-channel Token Bucket rate limiting and require cryptographic Friction Gate tokens for destructive or protection-weakening actions.
- **Verification:** `apps/desktop/src/__tests__/ipc/ipc-security.test.ts`.

### RULE-13: Least Privilege Rule
- **Mandate:** Components must run with the minimum OS privileges required for their task:
  1. **Electron Renderer UI:** Runs inside a strict Chromium sandbox (`sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`) with zero direct filesystem or OS access.
  2. **Scanner Worker Threads / Parser Processes:** Perform complex PE, archive, and heuristic parsing using read-only file handles and bounded memory.
  3. **Privileged Remediation / Service Operations:** When restoring files into a user directory from a privileged service context, impersonate the logged-on user token (`ImpersonateLoggedOnUser`) rather than writing as `SYSTEM` to prevent symlink/junction elevation-of-privilege attacks.
- **Verification:** Security architecture audit and symlink/junction privilege escalation tests.

### RULE-14: Resource Budget Rule
- **Mandate:** The antivirus must protect the PC without making it slow, even on low-end Windows laptops (4 GB RAM, dual-core CPU):
  1. **Idle CPU:** $< 1.0\%$ average CPU usage when no scan is active.
  2. **Idle RAM:** $< 50\text{ MB}$ RSS for background protection daemon; $< 120\text{ MB}$ with UI open.
  3. **Peak Scan RAM:** $< 200\text{ MB}$ RSS during Full System Scan or large-file quarantine (enforced via `64 KB` streaming reads and bounded worker queues).
  4. **Real-Time Fast Path Latency:** $< 2.0\text{ ms}$ ($p50$) / $< 10.0\text{ ms}$ ($p95$) for CleanFileCache + header triage; $< 50.0\text{ ms}$ ($p95$) for deep PE/heuristic inspection.
  5. **Battery / Game / Full-Screen Awareness:** Automatically throttle background scheduled scan worker concurrency to `1` thread (or pause scheduled scans) when running on battery power (`< 20%`) or when high system CPU load (`> 80%`) is detected.
- **Verification:** `apps/desktop/src/__tests__/benchmarks/performance-benchmark.test.ts`.

### RULE-15: Notification Rate Limit Rule
- **Mandate:** Malware outbreaks or archive extractions containing hundreds of infected files **MUST NEVER** flood the Windows Notification Center or freeze the UI with modal storms:
  1. Enforce a strict token-bucket rate limit of **at most 3 native OS toast notifications per 10-second window**.
  2. When $\ge 3$ threats are detected within a 5-second burst, automatically coalesce subsequent alerts into a single **Batch Threat Summary Notification** (e.g., *"Privex blocked 47 threats in Downloads. Click to review summary"*).
  3. Suppress non-critical (`LOW` / `MEDIUM`) background notifications when the user is in a full-screen application, while still executing automatic `CRITICAL` / `RANSOMWARE_BEHAVIOR` containment silently and logging the event.
- **Verification:** `apps/desktop/src/__tests__/services/notification-rate-limiter.test.ts`.

### RULE-16: Rollback Safety Rule
- **Mandate:** Every automated state mutation must have a tested, deterministic rollback mechanism:
  1. **Ransomware Shadow Vault Rollback:** Maintain a local Copy-on-Write / pre-modification backup cache (`ShadowVault`) for protected user folders (`Documents`, `Pictures`, `Desktop`) within a bounded user-configurable disk quota (default `2 GB`), enabling 1-click restoration of files modified by a contained process before termination.
  2. **Quarantine Rollback:** Every quarantined file retains its encrypted original path, permissions, and SHA-256 hash for 1-click restoration.
  3. **Update Rollback:** Keep the previous verified threat database (`N-1`) on disk so a corrupted or faulty `N` update rolls back atomically in $< 200\text{ ms}$.
- **Verification:** Category 10 Rollback Test Suite.

### RULE-17: False Positive Protection Rule
- **Mandate:** High detection sensitivity must be paired with strong false-positive safeguards so legitimate user and developer workflows are not disrupted:
  1. Never quarantine a file based solely on high Shannon entropy ($\ge 7.2$) without corroborating executable/packing anomalies or malicious indicators (since compressed `.zip`, `.png`, `.mp4`, and `.pdf` files naturally have high entropy).
  2. Support granular exclusions by **SHA-256 hash** (preferred), **canonical file path**, **folder path**, or **process trust rule**, guarded by a Friction Gate.
  3. Provide a 1-click **"Restore & Trust this file version (SHA-256)"** action in the Quarantine UI.
- **Verification:** 0.00% false-block rate across the 500-fixture clean binary/media/developer build corpus (`false-positive-corpus.test.ts`).

### RULE-18: Log Privacy Rule
- **Mandate:** Local forensic and audit logs (`AuditLogger`) must provide complete security visibility while protecting user privacy:
  1. Log records are stored locally in an encrypted, append-only **HMAC-SHA256 hash-chained** database (`audit.log.enc`) to detect any post-incident log tampering or deletion.
  2. **Data Minimization in Logs:** Never log raw document text, clipboard contents, passwords, or URL query parameters/fragments (`?token=...`). Strip URLs to `scheme + hostname + path-hash` or sanitized indicator metadata.
  3. Support user-configurable retention (default 90 days) and instant cryptographic erasure via the Privacy Shredder.
- **Verification:** Audit log schema and PII-scrubbing unit tests.

### RULE-19: Configuration Integrity Rule
- **Mandate:** Security configuration (`DesktopSettings`, exclusions, protected folders, trusted apps) must be protected against unauthorized local modification:
  1. Encrypt configuration at rest using DPAPI-backed AES-256-GCM and bind a monotonic `configSequence` and `hmacSha256`.
  2. Require an interactive **Friction Gate** (challenge token + hold timer / OS user confirmation) before disabling real-time shields, disabling ransomware protection, or adding path exclusions.
  3. Require an automatic **Re-Enable Timer** (`15m`, `30m`, `1h`, or `Until Reboot`) whenever real-time protection is paused so protection is never accidentally left off permanently.
- **Verification:** Configuration tamper & auto-resume tests.

### RULE-20: Testing Before Completion Rule
- **Mandate:** No phase, service, or feature may be marked complete until:
  1. Unit tests, integration tests, and adversarial security tests for that capability are written and committed.
  2. `pnpm test` passes 100% with zero skipped or flaky tests.
  3. Statement, line, and branch coverage is $\ge 90\%$ across modified modules.
- **Verification:** Automated CI test & coverage gate.

### RULE-21: Performance Verification Rule
- **Mandate:** Every change to the detection pipeline, file watcher, process monitor, or quarantine service must be benchmarked against the latency and memory SLAs defined in `RULE-14` before phase sign-off.
- **Prohibition:** Never call synchronous full-file `fs.readFileSync` on unbounded files on the main Electron/UI thread.
- **Verification:** `apps/desktop/src/__tests__/benchmarks/performance-benchmark.test.ts`.

### RULE-22: Security Review Before Merge Rule
- **Mandate:** Every phase implementation must undergo a structured STRIDE security review verifying:
  - Input byte bounds and timeout enforcement
  - Reparse point (symlink/junction) and TOCTOU file-handle pinning
  - IPC origin and schema validation
  - Fail-closed error handling
  - Zero Tier-1 data leakage
- **Verification:** Documented security sign-off in phase verification report.

### RULE-23: Documentation Sync Rule
- **Mandate:** The root governance and architecture documents (`PRD.md`, `Architecture.md`, `rules.md`, `phase.md`, `design.md`, `memory.md`) are living contracts. Whenever a phase is completed or an architectural decision is refined, `phase.md` and `memory.md` must be updated in the same commit/session so documentation never drifts from the actual codebase.
- **Verification:** Pre-completion documentation sync check.

### RULE-24: No Stub / Fake Protection Rule
- **Mandate:** Production code **MUST NEVER** contain fake security toggles, hardcoded `"0 threats found"` counters, `setTimeout` simulated scan progress bars, `TODO` placeholders, or UI switches that do not actually configure an active underlying service. Every UI control on every screen must be wired end-to-end through `IpcHandler` to a real, tested backend service.
- **Verification:** Static AST/grep check for stubs/TODOs + E2E runtime verification (`desktop-runtime-e2e.test.ts`).

### RULE-25: Explicit Status Reporting Rule
- **Mandate:** In all audits, status reports, and phase reviews, every capability must be classified using the strict 6-state taxonomy:
  - `EXISTS + VERIFIED` (implemented in production code AND verified by passing automated tests)
  - `EXISTS + WEAK` (implemented, but has functional, performance, or security limitations)
  - `PARTIAL` (partially implemented or not wired end-to-end)
  - `MISSING` (not yet implemented in code)
  - `ARCHITECTURALLY BLOCKED` (requires an OS/privilege dependency not yet present)
  - `NOT RECOMMENDED` (intentionally excluded for security, stability, or scope reasons)
- **Verification:** Independent Reviewer (`SUBAGENT 14`) audit.

### RULE-26: Architectural Honesty Rule
- **Mandate:** Never claim kernel-mode capabilities (`FltMgr` pre-execution kernel blocking, `ELAM` boot driver, `PsSetCreateProcessNotifyRoutineEx` kernel callbacks, or `PPL` anti-termination) unless a Microsoft WHQL EV-signed kernel driver is actually compiled and loaded.
- **Honest User-Mode Engineering:** Clearly document and engineer our high-speed user-mode architecture (`ReadDirectoryChangesW` + NTFS USN Journal + Canary Oplocks + ETW/WMI process tracking + `NtSuspendProcess`/Job Object arrest + Copy-on-Write Shadow Vault rollback) as a rapid near-real-time detection, containment, and rollback architecture that avoids BSOD risk and coexists safely with Windows Defender.
- **Verification:** Architecture & UI copy review.

### RULE-27: Clean Code & Modularity Rule
- **Mandate:** Maintain strict separation of concerns across the monorepo:
  1. Platform-independent detection logic, byte parsers, YARA/signature matchers, entropy calculators, and risk scoring belong in `@private-protection/core`.
  2. Windows-specific OS adapters (file watchers, USN journal, ADS parsers, DPAPI, process/registry auditors, quarantine vault, IPC) belong in `apps/desktop/src/services/` and `apps/desktop/src/core/`.
  3. React UI components in `apps/desktop/src/renderer/` must be pure presentation/state consumers communicating exclusively via `window.privateProtection` typed IPC contracts.
  4. Zero `any` types in security-critical paths; strict TypeScript compilation (`tsc --noEmit`) must pass with 0 errors.
- **Verification:** `pnpm typecheck` and `pnpm lint`.

### RULE-28: Regression Prevention Rule
- **Mandate:** Every bug discovered, security gap remediated, or false positive fixed must immediately be codified as a permanent regression test in `apps/desktop/src/__tests__/regression/` or `services/`. No previously passing capability or test in Web, Android, Browser Extension, Core, or Desktop may be broken during the Windows Antivirus transformation.
- **Verification:** Monorepo-wide test suite execution before every phase sign-off.

### RULE-29: Atomic Git Commit & Push Every Step Rule
- **Mandate:** Every completed step, phase, architectural artifact, and prompt turn **MUST** be committed to git using clear, informative, conventional commit messages (`docs(...)`, `feat(...)`, `fix(...)`, `test(...)`, `sec(...)`) and immediately pushed to the remote repository (`git push origin main`).
- **Verification:** `git status -s` must be clean and `git log -n 5` / `git push` must confirm synchronization with `origin/main` at the conclusion of every step and every prompt.



---

# MOBILE SECURITY EXTENSION — ANDROID PROTECTION CONSTITUTION

> Scope: These rules extend the existing Windows security constitution to the Android/mobile product surface. They do not weaken any existing desktop rule.
> Architectural honesty: Privex MUST reproduce the security goals of a modern mobile security product, but MUST NOT claim privileged Android capabilities that a normal third-party application cannot actually obtain.

## Rule Index Extension

| Rule ID | Rule Name | Enforcement Layer | Primary Verification Gate |
|---|---|---|---|
| RULE-30 | Mobile Local-First Rule | Android Core / Network Guard | Offline Mobile Parity |
| RULE-31 | Install-Time App Safety Rule | Package Lifecycle / APK Analyzer | Physical-Device Install Matrix |
| RULE-32 | Download & File Shield Rule | Download/Media Observation / File Analyzer | Multi-Type Download Corpus |
| RULE-33 | Full Device Scan Rule | Storage Traversal / SAF | Full-Device Physical Scan |
| RULE-34 | Pre-Threat Warning Rule | URL Analyzer / Web Shield / Notification | Malicious-URL Warning Matrix |
| RULE-35 | Password Generator Rule | Cryptographic RNG / UI | Entropy & RNG Audit |
| RULE-36 | Mobile Capability Honesty Rule | Android OS Boundary | API/Permission Capability Audit |
| RULE-37 | Mobile Privacy & Permission Rule | Storage / Permissions / Telemetry | Permission & Privacy Audit |
| RULE-38 | Mobile Resource & Battery Rule | Scheduler / Scanner Workers | Low-Battery/Low-RAM Test |
| RULE-39 | Archive & Content Bomb Safety Rule | ZIP/Office/PDF/Image Parsers | Bomb/Parser Fuzz Suite |
| RULE-40 | Mobile Threat-DB Integrity Rule | Signed DB / LKG | Update/Rollback Audit |
| RULE-41 | Physical Device Acceptance Rule | Android Build / Device Lab | Real-Phone Acceptance Gate |
| RULE-42 | Safe Remediation & User Control Rule | Quarantine / Uninstall Guidance | Destructive-Action Audit |

## RULE-30: Mobile Local-First Rule
All core Android malware, APK, downloaded-file, URL, phishing, archive, document, image metadata, risk-scoring, and password-generation decisions MUST execute locally by default. Network access is optional and explicitly governed. No raw files, document contents, screenshots, credentials, or URL query secrets may be uploaded for scanning.

## RULE-31: Install-Time App Safety Rule
Privex MUST observe Android package installation lifecycle events available to a normal app and perform the strongest technically permitted safety check:
1. When an APK is available before installation, scan it before the user launches/installs it whenever the OS/install flow exposes the APK to Privex.
2. For installations that Privex cannot technically interpose before package commit, perform an immediate post-install package scan and warn/block use according to the supported Android control surface.
3. Analyze package name, signing certificate, version, requested permissions, exported components, native libraries, DEX structure, manifest anomalies, embedded URLs, suspicious strings, dangerous capabilities, known hashes, and local heuristic indicators.
4. Never claim to be the Android system installer, Google Play Protect, or a privileged device-owner service unless the product is actually provisioned with that role.
5. If the OS prevents pre-install interception, surface a clear limitation instead of pretending the app was checked before installation.

## RULE-32: Download & File Shield Rule
Every observable downloaded or newly created user file MUST be eligible for automatic scanning, regardless of extension. The content pipeline MUST recognize at minimum APK, ZIP, RAR/7z where supported, PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, JPG/JPEG, PNG, GIF, WEBP, MP4, TXT, CSV, HTML, JS, and generic binary files. File type MUST be determined from content/magic bytes and parser evidence rather than trusting the filename extension. Archive recursion, bomb detection, decompression limits, and nested-file scanning are mandatory.

## RULE-33: Full Device Scan Rule
A user-triggered Full Device Scan MUST traverse every storage location that Android legally exposes to the application, including shared storage and user-selected SAF trees. The scan MUST show scope, progress, files examined, threats found, skipped/protected locations, and a truthful completion status. The scanner MUST never report "100% scanned" when Android denied access to a location.

## RULE-34: Pre-Threat Warning Rule
When a URL, download, APK, or file presents a high-confidence threat before execution/opening, Privex MUST warn the user as early as technically possible. URL protection MUST use local reputation, normalized URL analysis, IDN/punycode/homograph detection, suspicious redirects, credential-form indicators, deceptive domains, dangerous schemes, and signed local threat intelligence. HTTPS content MUST NOT be decrypted or MITM'd merely to claim web protection; use privacy-preserving metadata and browser integration where technically available.

## RULE-35: Password Generator Rule
The Password Generator MUST use a platform CSPRNG (Android SecureRandom / OS secure random source), never Math.random or predictable seeds. It MUST support configurable length and character sets, generate high-entropy passwords locally, avoid accidental clipboard persistence where possible, provide copy-with-timeout behavior, and never transmit generated passwords. "Stronger than Google Password Manager" MUST NOT be claimed as an absolute fact; the product may offer configurable higher entropy and length and show the measured entropy.

## RULE-36: Mobile Capability Honesty Rule
A feature is COMPLETE only when its Android API/permission behavior has been demonstrated on a real supported device. Emulator-only success is insufficient for security-critical mobile claims. If Android sandbox, scoped storage, background execution, browser, package-install, or permission restrictions prevent a requested behavior, documentation MUST state the limitation and implement the strongest safe alternative.

## RULE-37: Mobile Privacy & Permission Rule
Request the minimum Android permissions necessary. Never request Accessibility, VPN, notification access, broad storage, device-admin/device-owner, or other sensitive privileges merely because they are convenient. Every sensitive permission MUST have a visible user-facing purpose, graceful denial behavior, and a test proving no data leaves the device unexpectedly.

## RULE-38: Mobile Resource & Battery Rule
Background scanning MUST be adaptive. On low battery, thermal throttling, low RAM, metered connections, or foreground-heavy usage, scanning MUST reduce concurrency, defer non-urgent work, or pause safely. Critical threat detection remains active. The app MUST target low background CPU, bounded memory, and no persistent wakelock unless strictly required.

## RULE-39: Archive & Content Bomb Safety Rule
All decompression and content parsing MUST be bounded by maximum compressed bytes, expanded bytes, recursion depth, entry count, parser time, and memory. ZIP bombs, nested archive bombs, malformed PDFs, Office parser abuse, oversized images, decompression bombs, and parser fuzz inputs MUST terminate safely without OOM or ANR.

## RULE-40: Mobile Threat-DB Integrity Rule
Mobile threat intelligence MUST use the same signed-update doctrine as the desktop product: pinned Ed25519 root, SHA-256 payload verification, monotonic version sequence, staged validation, self-test, atomic activation, and LKG rollback:
1. **Cryptographic Signature Verification:** Ed25519 signature over canonical tuple `${targetSequence}:${formatVersion}:${manifestSha256}`.
2. **Unconfigured Key Fail-Closed:** A placeholder zero-key (`0000...`) or unconfigured trust anchor MUST fail closed (`UNCONFIGURED_TRUST_KEY`). Test keys MUST be strictly rejected in production builds (`TEST_KEY_REJECTED`).
3. **Monotonic Anti-Downgrade:** Any manifest where `targetSequence <= currentSequence` MUST be rejected (`DOWNGRADE_REJECTED`).
4. **Staging & Self-Test:** Transactional SQLite staging with schema validation, capacity bounds ($\le 20,000$ records), and `PRAGMA quick_check` integrity test before activation.
5. **Deterministic Cache Invalidation:** Successful activation or rollback MUST trigger immediate cache invalidation via `DatabaseChangeListener` across `WebShieldService`, `UniversalFileShieldService`, and `PackageAuditService`. A failed update MUST never replace a known-good database or mutate cached verdicts.

## RULE-41: Physical Device Acceptance Rule
The Android release gate MUST include at least one supported physical Android phone. Security-critical claims MUST be verified on-device for installation events, downloads, storage access, notifications, battery behavior, web protection, APK scanning, full scan, remediation, and password generation. A green CI build alone is not release evidence.

## RULE-42: Safe Remediation & User Control Rule
Privex MUST prefer reversible actions. Quarantine must be isolated and recoverable; uninstall/block/open actions must be explicit; automatic deletion is forbidden for uncertain findings. Every destructive or security-lowering action requires clear explanation and confirmation unless it is a narrowly defined emergency containment action already authorized by the user.
