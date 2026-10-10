# Architecture.md — Complete System & Security Architecture for Privex Windows Antivirus

> **DOCUMENT STATUS:** CANONICAL SYSTEM & SECURITY ARCHITECTURE SPECIFICATION — PHASE S FULLY VERIFIED & RELEASE APPROVED  
> **PROJECT:** Privex — Windows Desktop Strong Antivirus Transformation  
> **MILESTONE:** Phase S Complete & Approved (GO Release Gate)  
> **ARCHITECTURAL DOCTRINE:** Local-First • Offline-First • Zero-Knowledge • Fail-Closed • Architectural Honesty (`RULE-26`)

---

## 1. Architectural Philosophy & Windows OS Integration Strategy

### 1.1 Architectural Honesty: High-Speed User-Mode Service vs. Kernel Driver (`RULE-26`)
- **`[SOURCE-DERIVED FACT]`** (`https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-`): Deploying a Windows Kernel File System Minifilter Driver (`FltMgr.sys`), Early Launch Antimalware (`ELAM`) boot driver, or Protected Process Light (`PPL`) kernel callback driver requires a hardware-backed Extended Validation (EV) Code Signing Certificate, Microsoft Partner Center Hardware Dashboard WHQL attestation signing, and carries catastrophic Blue Screen of Death (`BSOD`) liability if any pointer fault occurs in Ring 0.
- **`[PROJECT DECISION]`:** Privex Windows Desktop is engineered as a **Hardened User-Mode Antivirus Architecture** (`Electron 44 + TypeScript/Node.js Worker Pool + Native Windows OS APIs / Background Service`) that achieves **near-real-time detection, sub-50ms ingress containment, process tree arrest, and 100% file recovery** without kernel-driver BSOD risk or disabling Microsoft Defender:
  1. **Recursive `ReadDirectoryChangesW` + NTFS USN Journal (`FSCTL_READ_USN_JOURNAL`):** Captures every file creation, write completion, and rename across watched directories in $<5\text{ ms}$, with USN journal catch-up across boots and sleep cycles.
  2. **Canary Honeypot Files + Sliding-Window Entropy/Velocity Detection:** Detects ransomware encryption bursts within $<500\text{ ms}$ (before $>3$ user files are touched).
  3. **User-Mode Process Arrest (`NtSuspendProcess` / `TerminateProcess` / Job Objects) + Copy-on-Write `ShadowVault`:** Immediately freezes/terminates offending user-space process trees and restores any modified personal document from an encrypted, ACL-protected local Shadow Vault (`~/.private-protection/shadow-vault/`).
  4. **Windows DPAPI (`CryptProtectData` / `safeStorage`) + NTFS DACL Hardening:** Seals all local vault and configuration keys to the machine/user credential store and strips execute permissions from quarantined blobs.

---

## 2. Target 9-Layer Windows Antivirus Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: DESKTOP UI (Electron Sandboxed React 18 Renderer + System Tray Agent)           │
│  • 20-Screen Command Center • 3-Tier Posture Hero • 4-Pillar Alerts • Friction Gate UI   │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             │ Zero-Trust Typed IPC Bridge (Preload + Nonce)
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: DESKTOP SECURITY CONTROLLER (IpcHandler + IpcValidator + RateLimiter)           │
│  • Origin Verification • Schema Validation • Canonical Path Guard • Token-Bucket Limiter │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             │ Validated Command / Event Dispatch
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: SECURITY ORCHESTRATOR (DesktopSecurityOrchestrator + WorkerPoolSupervisor)      │
│  • Event Routing • Priority Scan Queue • Battery/CPU Throttling • Watchdog Coordination  │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             │
        ┌────────────────────────────────────┼────────────────────────────────────┐
        ▼                                    ▼                                    ▼
┌────────────────────────────┐ ┌───────────────────────────┐ ┌─────────────────────────────┐
│ LAYER 4: ACTIVE SHIELDS    │ │ LAYER 4: AUDIT & SCANNERS │ │ LAYER 4: VAULT & PLATFORM   │
│ • Real-Time File Shield    │ │ • Quick / Full / Custom   │ │ • Quarantine Manager        │
│ • Download & MOTW Shield   │ │ • Scan Scheduler (Cron)   │ │ • Shadow Vault (CoW Backup) │
│ • Process & Behavior Mon.  │ │ • Startup/Persistence Aud │ │ • Update Manager (Ed25519)  │
│ • Ransomware Shield        │ │ • Network Socket Auditor  │ │ • Audit Logger (HMAC Chain) │
│ • USB / Removable Shield   │ │ • Web / URL / EML Scanner │ │ • Health & Watchdog Service │
└──────────────┬─────────────┘ └─────────────┬─────────────┘ └──────────────┬──────────────┘
               └─────────────────────────────┼──────────────────────────────┘
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 5: DETECTION ENGINE (@private-protection/core + Desktop Native File/OS Adapters)   │
│  • 4-Stage Short-Circuit Sieve • CleanFileCache • Streaming Hash & Header Readers        │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 6: 10-LAYER SIGNAL & ANALYSIS PIPELINE                                             │
│  L1: Known-Good/Bad Hashes & CleanFileCache   L5: Zero-Alloc PE32/PE32+, ZIP & Office    │
│  L2: Flattened Aho-Corasick / YARA Signatures L6: Process Lineage, LOLBin & Canary Sigs  │
│  L3: Magic vs Ext, Double-Ext, RTLO, MOTW     L7: Local Origin, Path Zone & File Age     │
│  L4: Section/Window Entropy, W+X, IAT Combos  L8: Cross-Layer Synergy Correlation Matrix │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 7: VERDICT ENGINE (Layer 9 RiskScorer + Layer 10 Verdict Policy)                   │
│  • Bounded Non-Linear Log-Odds Math: R = 100 * (1 - Π(1 - x_i/100)) + Critical Overrides │
│  • Deterministic Verdict: ALLOW | INFORM | WARN | BLOCK | QUARANTINE | CONTAIN_PROCESS   │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 8: RESPONSE POLICY ENGINE (5-Tier Automatic Response Ladder + Tier-A OS Guard)     │
│  • Tier 1 LOW -> Log Only                    • Tier 4 CRITICAL -> Auto-Quarantine Blob   │
│  • Tier 2 MEDIUM -> Warn Toast & Prompt      • Tier 5 RANSOMWARE -> Kill PID + Lock +    │
│  • Tier 3 HIGH -> Hold & Quarantine/Prompt     Shadow Vault Rollback Prompt              │
└────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 9: DETERMINISTIC ACTIONS & READ-ONLY AI EXPLANATION SYNTHESIS                      │
│  • PPVAULT2 Quarantine Isolation • Process Tree Termination • Native Windows Toast Alert │
│  • CORE -> VERDICT -> AI EXPLANATION (Strict JSON Schema, Grade <= 8, Zero Authority)    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Specifications for All 16 Core Architecture Components

### Component 01: `File Monitor` (`RealtimeMonitorService` + `ScannerWorkerPool`)
- **Responsibility:** Continuously monitor high-risk and user-configured directories (`Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, Startup folders) for file creation, modification, and rename events, plus execute on-demand Quick, Full, and Custom directory traversals.
- **Inputs:** OS filesystem events (`ReadDirectoryChangesW` via recursive `fs.watch` + NTFS USN Journal catch-up checkpoints), user scan requests (`targetPaths`, `ScanOptions`), and `CleanFileCache` state.
- **Outputs:** Normalized `FileScanTask` dispatches to the Detection Engine and `RealtimeThreatEvent` / `ScanProgress` telemetry.
- **Trust Boundary:** **Tier 1 Untrusted OS Boundary.** All filenames, paths, reparse points, and file contents are treated as hostile exploit payloads.
- **Failure Behavior:** If a directory watcher handle errors or detaches, emits `WATCHER_HANDLE_LOST` to `Watchdog`, automatically re-binds the watcher within $<500\text{ ms}$, and triggers a catch-up directory walk. If a file is locked by another process (`EBUSY` / `EPERM`), queues up to 3 exponential-backoff retries (`100ms`, `250ms`, `500ms`) and marks as `SKIPPED_LOCKED` rather than crashing.
- **Security Requirements:**
  1. Open files with `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT` and track `(dev, ino)` sets to prevent symlink/NTFS junction infinite loops and TOCTOU swaps.
  2. Never execute or load inspected binaries into the process address space.
- **Performance Requirements:**
  1. Debounce rapid write chunks on the same path (`250 ms` coalescing window) and ignore in-flight browser partial files (`.crdownload`, `.part`, `.download`) until final rename.
  2. Bounded priority queue (`maxQueueSize = 10,000`) with backpressure coalescing during burst events (`npm install`, `git checkout`, archive extraction).
- **Offline Behavior:** **100% Offline.** Uses native local OS filesystem APIs with zero network calls.

---

### Component 02: `Process Monitor` (`ProcessAuditorService`)
- **Responsibility:** Enumerate running processes and monitor newly spawned processes on Windows, capturing full executable paths, command-line arguments, parent-child PID relationships (`ProcessLineageGraph`), and on-disk binary risk assessments.
- **Inputs:** WMI/CIM `Win32_Process` queries (`ProcessId`, `ParentProcessId`, `Name`, `ExecutablePath`, `CommandLine`, `CreationDate`) with `tasklist /FO CSV /NH` graceful fallback, plus `FileAnalyzer` binary verdicts.
- **Outputs:** `ProcessSecurityEntry[]` records, live parent-child lineage trees, and behavioral anomaly triggers fed to `Behavior Engine`.
- **Trust Boundary:** **Tier 1/2 OS Process Boundary.** Process command lines may contain obfuscated shellcode or user secrets (which must be scrubbed before logging).
- **Failure Behavior:** If WMI/CIM query fails or times out ($>3,000\text{ ms}$), falls back to `tasklist` + `/proc`/handle inspection and sets a `WARNING` diagnostic flag without crashing the audit pipeline.
- **Security Requirements:**
  1. Never execute command strings via an unescaped shell (`execFile` with fixed argument arrays only).
  2. Enforce `RULE-09` (Protected System File Rule): verify canonical path via `realpathSync.native()` before classifying system processes (`svchost.exe`, `lsass.exe`, `csrss.exe`, `explorer.exe`).
- **Performance Requirements:** Full process table snapshot and lineage correlation completes in $<500\text{ ms}$ off the UI thread; binary scans of running processes use `CleanFileCache` so known system binaries take $<0.05\text{ ms}$ each.
- **Offline Behavior:** **100% Offline.** Queries local Windows process tables only.

---

### Component 03: `Behavior Engine` (`BehaviorEngineService`)
- **Responsibility:** Correlate multi-signal runtime behaviors across process creation, parent-child lineage anomalies, LOLBin command-line arguments, persistence registration, and rapid file modification velocity into a deterministic behavioral danger score ($0\text{–}100$).
- **Inputs:** `ProcessSecurityEntry` events from `Process Monitor`, filesystem velocity events from `File Monitor`, persistence events from `PersistenceAuditorService`, and canary events from `Ransomware Shield`.
- **Outputs:** Behavioral `Evidence[]` tokens (`behav-office-spawns-shell`, `behav-browser-spawns-lolbin`, `behav-system-path-masquerade`, `behav-ps1-hidden-download-cradle`, `behav-ransomware-shadow-delete`) and `CONTAIN_PROCESS` containment directives.
- **Trust Boundary:** **Tier 2 Core Analytical Boundary.** Operates on structured process and file telemetry within a fixed-size in-memory ring buffer (`MAX_TRACKED_PIDS = 1024`, `64` events/PID).
- **Failure Behavior:** Fails closed to `WARN`/`SUSPICIOUS` if behavioral state ring buffer overflows; never drops `isCriticalOverride` signals (such as shadow-copy deletion or canary modification).
- **Security Requirements:**
  1. Signed Microsoft LOLBins (`powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `certutil.exe`, `regsvr32.exe`, `wscript.exe`, `cscript.exe`, `vssadmin.exe`) are **never** exempted from behavioral command-line or parent-child inspection even though their static binary on disk is signed by Microsoft.
  2. When `CONTAIN_PROCESS` is triggered on a LOLBin, terminate the specific malicious process `PID` and child tree—never quarantine the system binary in `C:\Windows\System32`.
- **Performance Requirements:** $O(1)$ ring-buffer state insertion and $<0.20\text{ ms}$ evaluation per process/file event; $<4\text{ MB}$ total RAM footprint.
- **Offline Behavior:** **100% Offline.** All behavioral rules and state machines are local and deterministic.

---

### Component 04: `URL Engine` (`UrlAnalyzer` + `MotwAnalyzer`)
- **Responsibility:** Detect phishing links, Punycode/IDN homograph attacks, brand typosquatting, high-entropy DGA domains, IP-literal hosts, and malicious download origin URLs extracted from NTFS `:Zone.Identifier` Mark-of-the-Web (MOTW) Alternate Data Streams.
- **Inputs:** Raw URL strings ($\le 2,048\text{ bytes}$), text messages containing embedded URLs, and NTFS `${filePath}:Zone.Identifier` stream contents (`ZoneId`, `HostUrl`, `ReferrerUrl`).
- **Outputs:** Normalized URL components, `Evidence[]` tokens, origin risk boost ($+35$ to $+85$) for downloaded files, and `ScanResult` verdicts.
- **Trust Boundary:** **Tier 1 Untrusted Input Boundary.** Treats every URL and ADS stream as potential parser-exploit or homograph-spoofing input.
- **Failure Behavior:** Any URL exceeding $2,048\text{ bytes}$ or failing URI parsing fails closed to `Verdict.CAUTION` (`WARN`) with rule `url-malformed-or-oversized`.
- **Security Requirements:**
  1. **Zero Network Touch (`RULE-01`, `RULE-03`):** Never perform live DNS resolution, HTTP HEAD/GET requests, or TLS handshakes against analyzed URLs.
  2. Normalize Unicode via `NFKD`, strip zero-width joiners (`U+200B`–`U+200D`, `U+FEFF`), decode `xn--` Punycode labels, and highlight mixed-script confusables (Cyrillic/Greek mixed with ASCII).
- **Performance Requirements:** Single URL analysis completes in $<0.50\text{ ms}$ ($p50$) and $<1.0\text{ ms}$ ($p99$).
- **Offline Behavior:** **100% Offline.** Uses local lexical heuristics, Levenshtein brand tables, and local `BloomFilter` / `ThreatIntel`.

---

### Component 05: `Ransomware Shield` (`RansomwareShieldService` + `ShadowVaultService`)
- **Responsibility:** Protect personal user folders (`Documents`, `Pictures`, `Desktop`, and custom folders) against unauthorized modification, detect ransomware encryption/rename bursts and canary tampering in sub-second time, arrest offending processes, and provide 1-click file restoration from the local Copy-on-Write `ShadowVault`.
- **Inputs:** Protected folder configuration, Trusted Application allowlist `(CanonicalPath, SHA256, Signer)`, decoy canary file events, and sliding-window file write/rename/entropy telemetry.
- **Outputs:** `RansomwareIncident` alerts, immediate process tree suspension/termination (`TerminateProcess`), offending binary quarantine, and restored clean files from `ShadowVault`.
- **Trust Boundary:** **Tier 2 High-Privilege Defense Boundary.** Manages protected folder rules and encrypted shadow backups.
- **Failure Behavior:** If `ShadowVault` reaches its disk quota (default `2 GB`), rotates out the oldest unflagged backup blobs (FIFO) while preserving all blobs linked to flagged/active incidents and emitting a `WARNING` health notice.
- **Security Requirements:**
  1. Deploy hidden decoy canary files (`~$_PrivateProtection_Canary_*.docx/.xlsx`) in protected folders and monitor their exact SHA-256 and file handles.
  2. Trigger immediate `RANSOMWARE_BEHAVIOR` containment when: (a) any canary file is modified/renamed/deleted by an untrusted process, OR (b) $\ge 25$ file modifications occur within $3.0\text{ s}$ with $\ge 8$ high-entropy writes ($H > 7.5$) or $\ge 10$ ransomware extension renames, OR (c) shadow-copy deletion commands (`vssadmin delete shadows`) are invoked.
  3. Store `ShadowVault` blobs encrypted in `~/.private-protection/shadow-vault/` so ransomware cannot encrypt the backups.
- **Performance Requirements:** Canary tamper detection $<100\text{ ms}$; velocity/entropy burst detection and process arrest $<500\text{ ms}$ (before $>3$ non-canary user files are modified).
- **Offline Behavior:** **100% Offline.** Canary monitoring, velocity math, process arrest, and Shadow Vault rollback are 100% local.

---

### Component 06: `Quarantine Manager` (`QuarantineService`)
- **Responsibility:** Safely isolate malicious files from the active filesystem into an encrypted, non-executable local vault (`PPVAULT2`), maintain an authenticated encrypted manifest (`manifest.json.enc`), and support verified restoration (with optional SHA-256 exclusion) or 3-pass cryptographic shredding.
- **Inputs:** Target file path, `FileAnalysisResult` metadata, user `restoreItem(id, { trustSha256 })` or `permanentDelete(id)` commands.
- **Outputs:** Encrypted `.ppvault2` container blobs, updated `QuarantineItem[]` manifest, and `AuditLogEntry` records.
- **Trust Boundary:** **Tier 1/2 Hostile Payload Containment Boundary.** Directly handles confirmed malware bytes.
- **Failure Behavior:** If encryption or disk write fails during `isolateFile()` (e.g., `ENOSPC`), aborts without unlinking the original file, removes any partial `.tmp` blob, and alerts the user that quarantine failed due to disk space. If `manifest.json.enc` is corrupted by power loss, automatically recovers from `manifest.json.enc.bak` (never silently wiping the vault).
- **Security Requirements:**
  1. **Streaming `PPVAULT2` AES-256-GCM:** Encrypt files in `64 KB` chunks with per-chunk derived IVs and AAD binding `(fileUuid || chunkIndex || isFinalChunk)` (while preserving backward decryption for `PPVAULT1`).
  2. **DPAPI Key Sealing:** Seal the 32-byte master vault key (`vault.dpapi`) via Windows DPAPI (`safeStorage` / `CryptProtectData`).
  3. **TOCTOU & Reparse Protection:** Open source file with exclusive handle (`O_NOFOLLOW`), reject symlinks/junctions and protected Windows system paths (`RULE-09`), and strip execute permissions on the vault blob.
  4. **Safe Restore + SHA-256 Trust:** Verify all GCM auth tags and full-file SHA-256 before writing restored bytes; sanitize Windows reserved names (`CON`, `PRN`, `NUL`); append `_restored_<timestamp>` on collision; and optionally register the file's SHA-256 in the local allowlist so `RealtimeMonitorService` does not re-quarantine it.
- **Performance Requirements:** Peak heap memory delta $<16\text{ MB}$ even when quarantining or restoring a `500 MB` file; `listQuarantine()` completes in $<5\text{ ms}$.
- **Offline Behavior:** **100% Offline.**

---

### Component 07: `Notification Service` (`NotificationService`)
- **Responsibility:** Dispatch real-time security alerts across Native Windows OS Toast Notifications (`Electron.Notification`), System Tray badges, and the In-App Notification Center while enforcing strict storm rate-limiting.
- **Inputs:** Security events from `RealtimeMonitorService`, `RansomwareShieldService`, `ScannerService`, `WatchdogService`, and `UpdateManager`.
- **Outputs:** Rate-limited Windows OS Toast notifications, coalesced batch summary alerts, and persistent `NotificationEntry[]` inbox items.
- **Trust Boundary:** **Tier 2 UI & OS Presentation Boundary.** Must sanitize untrusted filenames/URLs before rendering in OS notifications.
- **Failure Behavior:** If Windows OS notifications are disabled by OS policy or Electron runs headless, seamlessly records the alert in the In-App Notification Center and top alert banner without throwing.
- **Security Requirements:**
  1. **Storm Rate Limiting (`RULE-15`):** Token-bucket limiter caps native OS toasts at **$\le 3$ toasts per 10-second window**. When $\ge 3$ threats occur within 5 seconds, coalesces subsequent threats into a single **Batch Threat Summary Toast** (*"Privex blocked N threats in Downloads"*).
  2. **Privacy & Bidi Scrubbing:** Strip Unicode bidirectional override characters (`\u202A`–`\u202E`) and never display raw Tier-1 document/message body text in lock-screen OS toasts.
- **Performance Requirements:** Alert dispatch latency $<50\text{ ms}$ from verdict to UI/Toast trigger; $<2\text{ MB}$ memory for bounded 500-item notification inbox.
- **Offline Behavior:** **100% Offline.**

---

### Component 08: `Scan Scheduler` (`ScanSchedulerService`)
- **Responsibility:** Manage and trigger unattended scheduled scans (**Daily Quick Scan**, **Weekly Full Scan**, and **Missed-Scan Startup Catch-Up**) with intelligent battery, idle, and CPU-load guards.
- **Inputs:** `ScheduleConfig` from `Configuration Manager` (`enabled`, `dailyQuickScanTime`, `weeklyFullScanDay`, `pauseOnBattery`, `catchUpMissedScans`, `autoQuarantineScheduled`) and OS power/CPU state.
- **Outputs:** Automated `QuickScan` or `FullScan` executions, background threat isolations, and scheduled run history records.
- **Trust Boundary:** **Tier 2 Internal Automation Boundary.**
- **Failure Behavior:** If a scheduled scan is interrupted by system sleep, low battery ($<20\%$), or user cancellation, records status `DEFERRED_POWER` or `CANCELLED` and queues a catch-up run on next AC-powered idle window.
- **Security Requirements:**Modifying or disabling all scheduled scans when Real-Time Protection is off requires passing the Friction Gate.
- **Performance Requirements:** Runs scheduled scans at low background concurrency (`1` worker thread) so interactive user applications experience zero lag.
- **Offline Behavior:** **100% Offline.** Uses local system clock and monotonic timers.

---

### Component 09: `Update Manager` (`UpdateVerifierService` + `ThreatIntelUpdater`)
- **Responsibility:** Verify, stage, hot-swap, and roll back threat intelligence databases (`.ppdb` / `PPBF` Bloom filters, malware hash tables, and signature rulesets) from either signed online delta checks or offline signed bundle files.
- **Inputs:** `SignedUpdateManifest` (`version`, `versionSequence`, `publishedAt`, `sha256`, `ed25519SignatureHex`), binary payload buffer/path, and current `versionSequence` from DPAPI storage.
- **Outputs:** Verified `UpdateVerificationResult`, hot-swapped `ThreatDatabase` instance, and retained `LastKnownGood` (`N-1`) backup snapshot.
- **Trust Boundary:** **Tier 1 External Ingress Boundary.** Update bundles are treated as untrusted until cryptographic verification succeeds.
- **Failure Behavior:** **Atomic Fail-Closed & Automatic Rollback (`RULE-11`, `RULE-16`):** If Ed25519 verification, SHA-256 check, monotonic `versionSequence > currentSequence` check, or post-load EICAR self-test fails, aborts staging immediately and retains/restores the `N-1` Last-Known-Good database in $<200\text{ ms}$.
- **Security Requirements:**
  1. Verify Ed25519 signature over the canonical tuple `version:versionSequence:publishedAt:sha256` against the pinned Root Public Key (rejecting placeholder/dummy keys in production).
  2. Enforce monotonic `versionSequence` counter persisted in DPAPI-protected storage to defeat rollback/replay attacks.
  3. Allow authenticated local user rollback to the pinned `LastKnownGood` snapshot via Friction Gate if a defective update causes false positives.
- **Performance Requirements:** Ed25519 + SHA-256 verification and atomic RCU pointer swap complete in $<100\text{ ms}$ without dropping in-flight scans.
- **Offline Behavior:** Supports **100% Offline Bundle Import (`.ppdb`)** via local file picker and operates indefinitely on the embedded Factory Seed DB if never connected to the internet.

---

### Component 10: `Threat Database` (`ThreatIntel` + `SignatureAutomaton`)
- **Responsibility:** Store and query local threat intelligence in RAM: Kirsch-Mitzenmacher `BloomFilter` + exact confirmation tables for malicious SHA-256 file hashes, phishing/malware domains, URLs, and C2 IPs, plus the compiled `Int32Array` Aho-Corasick byte/string signature automaton.
- **Inputs:** SHA-256 file hashes, normalized domains/URLs/IPs, 64 KB file buffers, and signed `.ppdb` database snapshots.
- **Outputs:** $O(1)$ hash/domain/IP threat matches (`ThreatIntelEntry`) and single-pass $O(N)$ byte/string signature bitmasks.
- **Trust Boundary:** **Tier 2 Verified Read-Only Engine State.**
- **Failure Behavior:** If the local database file on disk is missing or corrupted at boot, loads the immutable compiled-in **Factory Seed Database** (containing EICAR, top malware families, ransomware commands, LOLBin patterns, and phishing indicators) and sets Health State to `WARNING`.
- **Security Requirements:** Database snapshots on disk are integrity-verified via SHA-256 + Ed25519 on load; in-memory tables are read-only during scan evaluation.
- **Performance Requirements:**
  1. `BloomFilter.has(sha256Hex)` slices the uniform hex digest directly (`O(k)` bit array reads in $<0.02\text{ ms}$, zero redundant SHA-256 re-hashing).
  2. Total RAM footprint for 1,000,000 hashes + 2,000 byte signatures $\le 12\text{ MB}$.
- **Offline Behavior:** **100% Offline.**

---

### Component 11: `Local Reputation` (`LocalReputationService` + `CleanFileCache`)
- **Responsibility:** Evaluate local contextual reputation signals (Path Zone classification, NTFS `:Zone.Identifier` MOTW origin, file creation age, timestomping anomalies, and Authenticode signature status) and maintain the 65,536-entry `CleanFileCache` + 3-Tier Allowlist (System Baseline, Verified Publisher/Hash Cache, User Exclusions).
- **Inputs:** File `stat` metadata (`dev`, `ino`, `size`, `mtimeMs`, `birthtimeMs`), canonical path, `:Zone.Identifier` ADS fields, Authenticode status, and user exclusions (`sha256`, `path`, `domain`, `ttl`).
- **Outputs:** Instant `CleanFileCache` hit (`ALLOW` in $<0.08\text{ ms}$), Tier-A System File protection flag (`isProtectedSystemBinary`), user exclusion match, or Layer 7 reputation `Evidence[]` tokens.
- **Trust Boundary:** **Tier 2 Local State Boundary.**
- **Failure Behavior:** Cache miss or corrupted cache file transparently falls through to full Stage 1–3 analysis (fail-safe).
- **Security Requirements:**
  1. **Automatic Cache Invalidation:** `CleanFileCache` keys bind `(dev, ino, size, mtimeMs, engineVersion, dbVersion)` so any file modification OR threat database update automatically invalidates stale cache entries.
  2. **Hard Exclusion Guardrails (`RULE-17`):** Reject any attempt to exclude root drives (`C:\`), Windows system folders, `Downloads`, `%TEMP%`, `%APPDATA%`, or wildcard executable extensions (`*.exe`, `*.dll`, `*.ps1`, `*.bat`).
- **Performance Requirements:** `CleanFileCache` lookup $<0.05\text{ ms}$; LRU memory bounded to $<8\text{ MB}$.
- **Offline Behavior:** **100% Offline.** Zero cloud reputation queries required.

---

### Component 12: `Audit Logger` (`AuditLoggerService`)
- **Responsibility:** Maintain an encrypted, append-only, **HMAC-SHA256 hash-chained** forensic timeline (`audit.log.enc`) of all security-relevant events on the endpoint, supporting fast filtering, integrity verification, and sanitized JSON/CSV export.
- **Inputs:** Structured `AuditEventInput` records (`category`, `severity`, `action`, `actor`, `targetSummary`, `sha256`, `ruleIds`, `verdict`, `riskScore`).
- **Outputs:** Tamper-evident `AuditLogEntry` records (`index`, `timestamp`, `prevHash`, `entryHmacSha256`) and chain integrity verification status (`verifyChainIntegrity()`).
- **Trust Boundary:** **Tier 2 Encrypted Forensic Boundary.**
- **Failure Behavior:** If HMAC chain verification detects a missing, modified, or reordered log entry, immediately emits `AUDIT_LOG_TAMPER_DETECTED`, transitions Health State to `WARNING`/`CRITICAL`, and starts a new verified epoch chain without crashing.
- **Security Requirements:**
  1. Each entry computes `entryHmacSha256 = HMAC_SHA256(K_audit, "${index}|${timestamp}|${prevHash}|${canonicalPayload}")`.
  2. **Strict Log Privacy (`RULE-18`):** Automatically scrub URL query strings (`?token=...`), environment secrets, and raw document/message contents before persisting.
  3. Completely wiped and overwritten during 3-pass Crypto-Shredding (`PRIVACY_SHRED`).
- **Performance Requirements:** Asynchronous batched append (`fsync` every `250 ms` or immediately on `CRITICAL` events); virtualized query pagination returns 100 entries in $<5\text{ ms}$.
- **Offline Behavior:** **100% Offline.**

---

### Component 13: `Health Monitor` (`HealthMonitorService`)
- **Responsibility:** Continuously evaluate the operational integrity of all antivirus subsystems and compute the canonical **4-State Health Model** (`HEALTHY`, `WARNING`, `DEGRADED`, `CRITICAL`) displayed in the Dashboard and Security Health screen.
- **Inputs:** Real-time shield state, watched directory handle status, Threat DB age (`lastUpdated`), Quarantine Vault & Config HMAC integrity status, Watchdog restart counters, active unquarantined threat count, and process memory RSS/heap metrics.
- **Outputs:** `SystemHealthReport` (`overallState: 'HEALTHY' | 'WARNING' | 'DEGRADED' | 'CRITICAL'`, `subsystems[]`, `issues[]`, `recommendedRemediation`).
- **Trust Boundary:** **Tier 2 Diagnostic & Posture Boundary.**
- **Failure Behavior:** Fails closed: if any core subsystem fails to report status within `3,000 ms`, transitions `overallState` to `DEGRADED` or `CRITICAL`—never reporting `HEALTHY` on unknown state.
- **Security Requirements:** Surfaces any config tampering, vault corruption, or repeated worker crashes prominently with 1-click **"Restore Protection"** remediation actions.
- **Performance Requirements:** Health evaluation runs in $<1.0\text{ ms}$ in memory.
- **Offline Behavior:** **100% Offline.**

---

### Component 14: `Watchdog` (`WatchdogService`)
- **Responsibility:** Monitor the liveness and health of filesystem watchers (`RealtimeMonitorService`), scanner worker threads, scheduler timers, and storage services via a `2,000 ms` heartbeat loop, executing automatic self-healing recovery on fault.
- **Inputs:** Subsystem heartbeats, worker `error`/`exit` signals, and `FSWatcher` error events.
- **Outputs:** Automatic watcher re-initialization, worker respawn (`<500\text{ ms}`), shield snooze auto-re-enable triggers, and `WATCHDOG_RECOVERY` audit events.
- **Trust Boundary:** **Tier 2 Supervision Boundary.**
- **Failure Behavior:** **Crash-Loop Circuit Breaker:** If a worker or watcher crashes $>3$ times within `120 seconds`, isolates the faulting component, switches the scanner to **Safe Minimal Mode** (deterministic Layer 1/2/3 rules active), and sets `HealthMonitor` to `DEGRADED` so the app never enters an infinite CPU-spinning crash loop.
- **Security Requirements:** Enforces the mandatory **Auto-Re-Enable Timer** (`15m`, `30m`, `1h`) whenever the user temporarily pauses `RealtimeMonitorService`, guaranteeing protection automatically turns back on.
- **Performance Requirements:** Heartbeat check takes $<0.1\text{ ms}$ every `2,000 ms` ($<0.01\%$ CPU).
- **Offline Behavior:** **100% Offline.**

---

### Component 15: `Secure IPC` (`IpcValidator` + `IpcHandler` + Preload Bridge)
- **Responsibility:** Enforce a Zero-Trust boundary between the sandboxed React renderer UI and the privileged main/service backend across all IPC channels.
- **Inputs:** Electron `IpcMainInvokeEvent` (`senderFrame`, `sender.getURL()`), channel name, request payload, and optional `frictionToken`.
- **Outputs:** Validated, canonicalized service calls or structured `{ ok: false, error, code: 'SECURITY_VIOLATION' | 'RATE_LIMITED' }` rejections.
- **Trust Boundary:** **Primary Privilege Escalation Boundary (`Renderer <-> Main`).**
- **Failure Behavior:** Any malformed payload, unauthorized frame origin, or rate-limit breach is immediately rejected before reaching any service logic and logged to `AuditLogger`.
- **Security Requirements:**
  1. Verify `event.senderFrame === event.sender.mainFrame` and validate strict `file:` / `app:` origin in packaged builds (`RULE-12`).
  2. Resolve paths via `fs.realpathSync.native()` before checking `isProtectedSystemPath()` to block NTFS 8.3 short-name (`PROGRA~1`) and symlink bypasses.
  3. Enforce per-channel **Token-Bucket Rate Limiting** (`SCAN_START_*`: 2/10s; `QUARANTINE_*`: 5/10s; `SETTINGS_SAVE`: 5/10s; `STATUS_GET`: 20/s).
  4. Require valid cryptographic **Friction Gate Challenge Tokens** (`frictionToken`) on security-lowering mutations (disabling shields, adding exclusions, restoring malware, crypto-shredding).
- **Performance Requirements:** Validation + rate-limit check executes in $<0.05\text{ ms}$ per IPC call.
- **Offline Behavior:** **100% Offline.**

---

### Component 16: `Configuration Manager` (`SecureStorageService`)
- **Responsibility:** Persist and authenticate all user security settings (`DesktopSettings`), exclusions, protected folders, trusted apps, and scheduled scan configurations encrypted at rest on disk (`storage.enc`).
- **Inputs:** Configuration read/write requests and Friction Gate verification tokens.
- **Outputs:** Authenticated `DesktopSettings` objects, tamper alerts (`SECURITY_CONFIG_TAMPERED`), and 3-pass cryptographic erasure (`cryptoShredAll()`).
- **Trust Boundary:** **Tier 2 Persistent State Boundary.**
- **Failure Behavior:** **Fail-Closed to Maximum Protection (`RULE-08`, `RULE-19`):** If `storage.enc` is deleted while an initialization marker exists, or if AES-256-GCM / HMAC authentication fails, immediately enforces **Maximum Protection Defaults** (`realtimeShieldEnabled: true`, `ransomwareShieldEnabled: true`, `autoQuarantineOnBlock: true`, `excludedPaths: []`), logs `SECURITY_CONFIG_TAMPERED`, and sets Health State to `WARNING`.
- **Security Requirements:**
  1. Seal the 32-byte storage encryption key via Windows DPAPI (`safeStorage` / `CryptProtectData` with fallback).
  2. Bind a monotonic `configSequence` and `hmacSha256` inside the encrypted payload.
  3. Write updates atomically via `storage.enc.tmp` + `fsyncSync` + `renameSync` with a `.bak` copy.
- **Performance Requirements:** In-memory cached reads in $<0.01\text{ ms}$; atomic encrypted disk writes in $<5\text{ ms}$.
- **Offline Behavior:** **100% Offline.**

---

## 4. The 10-Layer Malware Detection Engine & 4-Stage Sieve

### 4.1 The 4-Stage Short-Circuit Sieve (CPU Preservation Architecture)
To ensure the 10-Layer Engine never makes the PC slow:
1. **Stage 0 — `CleanFileCache` Sieve ($<0.08\text{ ms}$, $0\text{ bytes}$ read):** Checks `(dev, ino, size, mtimeMs, engineVer, dbVer)`. Hits on ~94% of files during repeat/background scans and returns `ALLOW` immediately.
2. **Stage 1 — Fast Header & Hash Triage ($<0.65\text{ ms}$, $4\text{ KB–64 KB}$ read):**
   - Evaluates **Layer 3** (Magic Header vs. Extension, Double/Triple Extension, Whitespace Padding, Unicode RTLO `\u202E`, and NTFS `:Zone.Identifier` MOTW URL check).
   - Evaluates **Layer 1** (`BloomFilter` + Exact SHA-256 Malware Hash table + Signed System Allowlist).
   - *Short-Circuit:* Confirmed malware hash or disguised executable/RTLO immediately triggers `isCriticalOverride = true` ($R \ge 90$, `BLOCK`/`QUARANTINE`). Clean non-executable media (`.png`, `.jpg`, `.mp4`, `.txt`) with matching magic headers and no MOTW anomalies short-circuit to `ALLOW`.
3. **Stage 2 — Single-Pass Signature & Zero-Alloc Structural Parse ($<2.40\text{ ms}$, $64\text{ KB}$ head + $16\text{ KB}$ tail):**
   - Evaluates **Layer 2** (Flattened `Int32Array` Aho-Corasick multi-pattern automaton + YARA-lite boolean AST over ASCII, UTF-16LE `WIDE`, and case-insensitive byte patterns).
   - Evaluates **Layer 5** (`PeStructuralParser` for DOS/COFF/Optional headers, Section Table, IAT imports, TLS callbacks, Overlay, and Authenticode directory; `ZipStructuralParser` for Central Directory & zip-bomb ratio; `OfficeMacroParser` for `vbaProject.bin`, external templates, and OLE `VBA`/`Equation Native`).
4. **Stage 3 — Deep Heuristics, Behavioral Correlation & Log-Odds Scoring ($<1.20\text{ ms}$, in-RAM):**
   - Evaluates **Layer 4** (Per-section entropy, 4 KB sliding-window entropy via precomputed `ENTROPY_LUT[4097]`, `W+X` section flags, Packer section names, IAT injection/credential API clusters, and Base64/charcode script de-obfuscation).
   - Evaluates **Layer 6** (Process lineage, LOLBin CLI, ransomware velocity, canary triggers) and **Layer 7** (Ingress zone & timestomping).
   - Evaluates **Layer 8** (Cross-Layer Synergy Correlation Matrix, e.g., `Internet MOTW + Unsigned PE + Packed/W+X/Injection IAT -> +85 Override`).
   - Evaluates **Layer 9** (`RiskScorer` non-linear log-odds aggregation with Authenticode clean-installer dampening) and **Layer 10** (`Verdict Policy`: `ALLOW`, `INFORM`, `WARN`, `BLOCK`, `QUARANTINE`, `CONTAIN_PROCESS`).

---

## 5. Complete STRIDE Threat Model (9 Assets & 10 Threats)

### 5.1 Protected Assets (`A-01` – `A-09`)
1. **`A-01` User Files & Personal Documents (`Tier 1`):** Protected against malware corruption and ransomware encryption; zero cloud exfiltration.
2. **`A-02` User Credentials & Local Secrets (`Tier 1`):** Protected against infostealers, Mimikatz/LSASS dumpers, and browser credential harvesting.
3. **`A-03` Browser Activity, URLs & Download Streams (`Tier 1`):** Inspected in volatile RAM; zero URL or DNS telemetry leaks.
4. **`A-04` Security Configuration & Exclusions (`Tier 2`):** Stored in `storage.enc` with DPAPI + HMAC anti-tamper protection.
5. **`A-05` Quarantine Vault & `.ppvault2` Blobs (`Tier 1/2`):** Streaming AES-256-GCM encrypted, non-executable, DPAPI-keyed, atomic manifest.
6. **`A-06` Threat Intelligence Database & Signature Rules (`Tier 2`):** Integrity-verified `.ppdb`/`PPBF` snapshots with Factory Seed fallback.
7. **`A-07` OTA / Offline Update Bundles (`Tier 2/3`):** Ed25519-signed over canonical metadata with monotonic `versionSequence` anti-downgrade.
8. **`A-08` Forensic Audit Logs (`Tier 2`):** Encrypted, append-only HMAC-SHA256 hash-chained log (`audit.log.enc`) with Tier-1 PII scrubbing.
9. **`A-09` Antivirus Processes, Workers & IPC Channels (`Tier 2`):** Hardened Electron Main/Renderer + Worker Pool + Watchdog supervision.

### 5.2 The 10 Canonical Threats & Architectural Countermeasures (`T-01` – `T-10`)
| Threat ID | Threat Name | STRIDE | Target Assets | Architectural Countermeasure |
|---|---|---|---|---|
| **T-01** | **Malware Dropper & Disguised Execution** | T, E | A-01, A-02 | Recursive `ReadDirectoryChangesW` watcher + Stage 1/2 Magic vs. Extension, RTLO `\u202E`, Double-Ext, PE IAT, and Aho-Corasick signatures + MOTW URL correlation. |
| **T-02** | **Ransomware Mass Encryption & VSS Wipe** | T, D | A-01, A-05 | Protected Folders + Canary Trap files + Sliding-window velocity/entropy detector ($\ge 25$ writes / $3\text{s}$) + `vssadmin` CLI block + `TerminateProcess` + CoW `ShadowVault` rollback. |
| **T-03** | **Quarantine & Key Tampering** | T, I, D | A-04, A-05 | Master key wrapped via Windows DPAPI (`safeStorage`); `PPVAULT2` per-chunk AAD AES-256-GCM; atomic `.tmp`+`rename` encrypted manifest with `.bak` recovery. |
| **T-04** | **Weaponized False Positive (System DoS)** | D | A-01, A-09 | `RULE-09` Protected System File Rule: canonical `realpathSync.native()` resolution + Tier-A Microsoft system binary exemption prevents quarantining OS files. |
| **T-05** | **Malicious or Downgraded Update Injection** | S, T, E | A-06, A-07 | Ed25519 signature over `version:versionSequence:publishedAt:sha256` + DPAPI monotonic sequence check + staging EICAR self-test + `<200ms` LKG rollback. |
| **T-06** | **Symlink / NTFS Junction Privilege Abuse** | E | A-01, A-05 | Open files with `O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`; reject `isSymbolicLink()` and reparse points during scan, quarantine, and restore; track `(dev, ino)` cycles. |
| **T-07** | **IPC Spoofing, Traversal & Command Flooding** | S, T, D, E | A-04, A-05, A-09 | `IpcValidator` `mainFrame` + `file:` origin check; rejection of UNC, device names (`CON`, `NUL`), and `..`; per-channel Token-Bucket rate limiter. |
| **T-08** | **Silent Configuration Weakening / Exclusion Abuse** | T, R | A-04, A-08 | DPAPI + HMAC `storage.enc` failing closed to Maximum Protection on tamper; Friction Gate challenge + mandatory Auto-Re-Enable timer; hard block on excluding `C:\`/`Downloads`/`%TEMP%`. |
| **T-09** | **Resource Exhaustion (Zip Bomb / Giant File OOM)** | D | A-09 | 64 KB header slicing; 64 KB streaming SHA-256 & `PPVAULT2` cipher ($<16\text{ MB}$ heap delta); zip-bomb ratio ($\le 100:1$) and depth ($\le 3$) hard abort; notification storm limiter ($\le 3$ toasts/10s). |
| **T-10** | **Evasion & Prompt Injection** | S, T, R | A-01, A-06, A-09 | Precomputed sliding-window entropy defeats null-byte padding; Base64/charcode script de-obfuscation; strict `CORE -> VERDICT -> AI EXPLANATION` boundary (`0%` AI verdict authority). |


---

# MOBILE ANDROID SECURITY ARCHITECTURE — PHASE T

## 1. Architecture Goal
The Android application is a security client built around the existing canonical detection engine. Platform adapters provide Android-specific evidence; they never create an independent verdict authority.

Android Events / User Actions
  |
  +--> Package Install Observer ----> APK Analyzer
  |
  +--> Downloads / MediaStore ------> Universal File Analyzer
  |
  +--> SAF / Shared Storage --------> Full Scan Coordinator
  |
  +--> Browser / URL Input ----------> URL & Phishing Analyzer
  |
  +--> Local Threat DB --------------> Threat Intelligence
  |
  v
Canonical Evidence -> RiskScorer -> EngineVerdict
                                  |
                    +-------------+-------------+
                    |             |             |
                  Notify      Quarantine     User Guidance

## 2. Mobile Components

### M-01 Mobile Security Coordinator
Owns lifecycle, scan scheduling, cancellation, battery/thermal adaptation and canonical service wiring.

### M-02 Package Safety Service
Uses Android PackageManager/package lifecycle APIs to observe installed/updated packages. When APK bytes are available, sends them through APK Analyzer. It records whether analysis occurred pre-install, immediate post-install, or could not be performed.

### M-03 APK Analyzer
Stages:
1. SHA-256.
2. ZIP/APK central-directory inspection.
3. AndroidManifest parsing.
4. certificate/signing metadata.
5. DEX structural indicators.
6. native-library inspection.
7. permission/component risk analysis.
8. local signature/hash/threat-intel lookup.
9. deterministic risk score.
No APK is executed for analysis.

### M-04 Universal File Shield
Uses Android-supported file event/MediaStore/Downloads observation plus user-selected SAF scopes. It canonicalizes file identity and sends stabilized files to the existing scanner. File type is detected from content.

### M-05 Full Scan Coordinator
Maintains a queue of accessible roots. Uses SAF for user-granted trees and platform APIs for shared media/files. Reports scanned, skipped, permission denied, inaccessible, threat count and completion state.

### M-06 Archive & Document Parser Layer
Bounded parsers for ZIP/Office/PDF/image metadata. Never executes macros, scripts, embedded objects or external links. Nested content is treated as data only.

### M-07 URL & Phishing Shield
Pipeline:
Raw URL -> Unicode Normalize -> Punycode/IDN Analysis -> Scheme Check -> Host Canonicalization -> Redirect Evidence -> Local Threat DB -> Heuristic Evidence -> RiskScorer.
HTTPS content is not decrypted by default. Optional VPNService mode, if implemented, inspects only privacy-safe metadata that Android exposes and must not become a covert traffic proxy.

### M-08 Pre-Threat Warning Manager (`PreThreatWarningCoordinator.java` & `pre-threat-warning.service.ts`)
- **Responsibility:** Evidence-backed predictive warning synthesis across URLs (T6), files/downloads (T3/T5), and packages (T2).
- **Confidence Taxonomy:** Separates `CONFIRMED_MALWARE` (signatures, droppers, zip bombs, dangerous schemes) from `STRONG_SUSPICION` (homoglyphs, excessive permissions) and `HEURISTIC_ANOMALY`.
- **Grounded Explanations:** Explains trigger reasons and factual potential consequences in plain language without fear-based hyperbole.
- **Defensive Recommendations:** Prioritizes safe defaults (`GO_BACK`, `CANCEL_INSTALL`, `DELETE_DOWNLOAD`, `QUARANTINE`) with a mandatory 5-second countdown friction gate for dangerous bypass (`CONTINUE_AT_OWN_RISK`).
- **Notification Integration:** Emits high-priority Android notifications linking directly into `PreThreatWarningModal` alertdialog via `PRE_THREAT_WARNING` intent.
- **Rate-Limiting & Deduplication:** 30-second deduplication cache prevents warning storm fatigue while preserving bounded local decision history.

### M-09 Password Generator
Uses Android CSPRNG / SecureRandom. The generator is isolated from telemetry and security logs. Clipboard contents are Tier-1 sensitive data.

### M-10 Mobile Threat Database (`MobileThreatDatabase.java` & `mobile-threat-intel.service.ts`)
- **Storage Architecture:** SQLite-backed versioned `.ppdb` (`mobile_threat_intel.ppdb`) with tables `threat_metadata` and `threat_records` (indexed on `(target_type, target_value)`), backed by a volatile in-memory screening cache for sub-millisecond lookups.
- **Factory Seed:** Embedded seed records including standard EICAR AV hash (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`), synthetic trojan/ransomware APK hashes, and known phishing domains.
- **Cryptographic Trust Pipeline:**
  1. Native Java `Ed25519` signature verification wrapping 32-byte raw public keys with RFC 8410 SPKI DER prefix (`302a300506032b6570032100`).
  2. Canonical signed message format: `${targetSequence}:${formatVersion}:${manifestSha256}`.
  3. SHA-256 digest verification over update payload records.
  4. Unconfigured zero trust key (`0000...`) fails closed with `UNCONFIGURED_TRUST_KEY`. Test keys are rejected in production builds (`TEST_KEY_REJECTED`).
- **Anti-Downgrade & Staging:**
  1. Monotonic sequence check rejects `targetSequence <= currentSequence` (`DOWNGRADE_REJECTED`).
  2. Transactional SQLite staging verifies record schema, capacity bounds ($\le 20,000$ records), and executes `PRAGMA quick_check`.
  3. Atomic pointer swap activates the new database version.
- **Deterministic Cache Invalidation:**
  - `DatabaseChangeListener` publishes invalidation events upon successful update or rollback.
  - Active shields (`WebShieldService`, `UniversalFileShieldService`, `PackageAuditService`) purge cached verdicts to immediately reflect updated intelligence.
- **Shield Integration:**
  - `WebShieldService`: Vector 0 fast-path domain check in `isDomainBlocked()`.
  - `UniversalFileShieldService`: Vector 0 fast-path file SHA-256 check.
  - `PackageAuditService`: Vector 0 fast-path APK file SHA-256 check.
- **Staleness Model:** Client evaluates database age: `FRESH` ($\le 7$ days), `AGED` (8–14 days), `STALE` (15–30 days), and `EXPIRED_CACHE` ($> 30$ days), prompting the user to update while retaining local detection parity.

### M-11 Mobile Quarantine & Remediation (`MobileQuarantineVault.java` & `PackageAuditService.java`)
- **Quarantine Vault Architecture (`PPMVAULT1`):**
  - Storage: App-private directory (`context.getFilesDir()/quarantine_vault/`) with `.vault` payload files and `quarantine_manifest.json`.
  - Authenticated Chunked Encryption: 64 KB chunked streaming `AES-256-GCM` with per-chunk AAD binding (`itemId + ":chunk:" + index`).
  - Binary Header: 64-byte `PPMVAULT` header containing magic (`PPMVAULT`), version `1`, 12-byte IV base, 8-byte plaintext length, and 32-byte plaintext SHA-256 digest.
  - Key Management: Android Keystore (`AndroidKeyStore`) master key with secure software key fallback for JVM test runners.
  - Crash-Consistent Manifest: Transactional `.tmp` write with fsync and `.bak` snapshot recovery on corruption.
  - Truthful Isolation State Machine: Records transition `DETECTED → PENDING_ISOLATION → VAULT_COPY_VERIFIED → ORIGINAL_REMOVAL_PENDING → ISOLATED` (if source unlinked) or `SOURCE_REMAINS` (if source deletion failed or requires user consent). Never falsely marks `ISOLATED` if original file remains at source.
  - Verified Safe Restore: Strict GCM tag and SHA-256 verification against original metadata. Restores atomically via `.restoring.tmp`. Path traversal (`..`) and restricted OS paths (`RESTRICTED_SYSTEM_PATH`) are strictly blocked. Vault file preserved on restore failure.
- **Installed Package Remediation:**
  - Evaluates packages into actionable plans: `UNINSTALL_RECOMMENDED`, `FORCE_STOP_RECOMMENDED`, `DISABLE_RECOMMENDED`, or `SYSTEM_APP_PROTECTED`.
  - User-Guided System Intents: Routes actions through explicit standard Android intents (`Settings.ACTION_APPLICATION_DETAILS_SETTINGS`, `Intent.ACTION_DELETE`). Never claims or simulates silent uninstallation.
  - Critical System Package Protection: Critical system packages (`android`, `com.android.systemui`, `com.google.android.packageinstaller`, etc.) are designated `SYSTEM_APP_PROTECTED` and cannot be targeted for destructive removal.


### M-12 Battery/Thermal Manager
Inputs Android BatteryManager/PowerManager/thermal state. Outputs worker concurrency and scan scheduling limits. Critical scan events have priority over background optimization.

### M-13 Permission & Privacy Center (`PrivacyCenterService.java` & `PermissionsPrivacyService.ts`)
- **Ground-Truth 8-Point Auditing Architecture:**
  - Storage & SAF: Inspects MediaStore and `SafManager` persisted tree permissions; clearly reports accessible scope (Downloads, user-picked folders) vs inaccessible scope (`/data/data/*`, protected OS paths).
  - Notifications: Checks Android 13+ `POST_NOTIFICATIONS` and `NotificationManagerCompat.areNotificationsEnabled()`; discloses that alert receipt depends on device DND/channel settings.
  - VPN & Web Shield: Inspects live `WebShieldService` and `WebShieldVpnService` instances; distinguishes `ACTIVE`, `CONSENT_PENDING`, `COEXISTENCE_CONFLICT`, and `STOPPED`; explains single-VPN Android platform constraint.
  - Install Source: Detects installer package; discloses third-party app sandbox reality (pre-install APK audits and post-install commit audits; zero privileged Play Protect claims).
  - Background Scanning: Reports `RealtimeDownloadProtectionService` ContentObserver status, event counters, OEM battery saver limitations notice, and resume catch-up reconciliation.
  - Battery Optimization: Queries `PowerManager.isIgnoringBatteryOptimizations()`; explains effects on background jobs while clarifying exemption is non-mandatory.
  - Telemetry: Zero-collection audit; confirms 0 bytes uploaded, no analytics SDKs, and no remote endpoints.
  - Threat Database Freshness: Evaluates sequence, record count, and staleness badges (`FRESH`, `AGED`, `STALE`, `EXPIRED_CACHE`) backed by Ed25519 verification.
- **Safe Intent Dispatch & Lifecycle Synchronization:**
  - Provides typed native intent generators for App Notification Settings, Application Details Settings, and Battery Optimization Settings.
  - `MainActivity.onResume` dispatches `privateprotection:app_resume` event into the WebView container, triggering automatic state re-check when the user returns from system Settings.

### M-14 Mobile Notification Manager
Uses notification channels and batching. CRITICAL threats are prioritized; repetitive informational findings are coalesced.

## 3. Install-Time Reality Model
The architecture MUST explicitly distinguish:
- System/Device Owner/Installer role: stronger pre-install control may be possible.
- Normal third-party app: cannot guarantee interception of every installation before package commit.
The product must not simulate a pre-install block by simply claiming success after installation.

## 4. Download/File Reality Model
Android scoped-storage and background execution rules mean "every file on the phone" cannot be promised without necessary user-granted access. The UI therefore reports exact scan coverage. User-selected SAF roots become durable scan scopes where Android permits persisted URI permission.

## 5. Security Boundaries
- Android UI -> Security Coordinator: strict typed boundary.
- Platform event -> Analyzer: untrusted metadata.
- APK/file/document parsers: bounded untrusted-data boundary.
- Threat DB: signed read-only state.
- Quarantine: encrypted isolated state.
- Password generator: Tier-1 secret boundary.
- URL data: Tier-1 sensitive boundary.
- AI explanation: read-only after EngineVerdict.

## 6. Mobile Threat Model
Key threats:
- malicious APK installation,
- sideloaded dropper,
- disguised downloads,
- archive bombs,
- malicious Office/PDF content,
- phishing/homograph URLs,
- permission abuse,
- storage traversal,
- notification spoofing,
- database rollback/tampering,
- battery/resource exhaustion,
- ANR/OOM,
- privacy leakage,
- fake protection claims.
Countermeasures must be covered by RULE-30..42 and tested on a real phone.

## 7. Performance & Reliability
- bounded queues,
- cancellable scans,
- streaming file reads,
- no unbounded decompression,
- cache keyed to secure file identity + engine/db versions,
- background throttling,
- watchdog recovery,
- truthful progress,
- crash-safe scan checkpoints where useful.

## 8. AI Boundary
Core Evidence -> EngineVerdict -> AI Explanation. The mobile AI layer never decides whether an APK/file/URL is safe.

## 9. Release Architecture
Mobile release artifacts:
- signed APK for direct installation/testing,
- AAB only as a build artifact if desired,
- release metadata and SHA-256 manifest,
- physical-device test report,
- security audit report.
No Google Play publication is required unless separately authorized.
