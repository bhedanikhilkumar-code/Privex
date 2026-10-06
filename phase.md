# phase.md — Complete Capability-Grouped Implementation Roadmap & Verification Strategy (Phases A – S)

> **DOCUMENT STATUS:** CANONICAL IMPLEMENTATION ROADMAP & PHASE VERIFICATION GATE SPECIFICATION  
> **PROJECT:** Private Protection — Windows Desktop Strong Antivirus Transformation  
> **EXECUTION GOVERNANCE:** Phases must be executed sequentially along the dependency DAG. No phase may be marked complete until all 10 required verification dimensions (Implementation, Unit, Integration, Security, Performance, Acceptance, Exit Criteria, and Rollback verification) pass 100%.

---

## 1. Phase Dependency Graph (Phases A – S)

```
PHASE A: Baseline & Security Hardening (IPC, DPAPI Storage, Canonical Path Guards)
   │
   ▼
PHASE B: Core Detection Engine Expansion (@private-protection/core Hash, Rule & Scorer Unification)
   │
   ├──────────────────────────────────────────┬──────────────────────────────────────────┐
   ▼                                          ▼                                          ▼
PHASE C: File Protection & 10-Layer Engine  PHASE D: Quarantine Hardening (PPVAULT2)  PHASE O: Threat Intel & Signed Updates
   │                                          │                                          │
   ├────────────────────┬─────────────────────┴────────────────────┐                     │
   ▼                    ▼                                          ▼                     │
PHASE E: Real-Time   PHASE F: Process & Behavior Mon.           PHASE H: Notification    │
Protection Engine       │                                       System & Rate Limiter    │
   │                    ├─────────────────────┐                    │                     │
   ▼                    ▼                     ▼                    │                     │
PHASE J: Web &       PHASE G: Ransomware   PHASE L: Startup &      │                     │
Download (MOTW)      Shield & ShadowVault  Persistence Protection  │                     │
   │                    │                     │                    │                     │
   └────────────────────┼─────────────────────┼────────────────────┘                     │
                        ▼                     ▼                                          │
                 PHASE I: Automatic Response Ladder & False-Positive Exclusions          │
                        │                                                                │
        ┌───────────────┼─────────────────────┬────────────────────┐                     │
        ▼               ▼                     ▼                    ▼                     │
     PHASE K:        PHASE M:              PHASE N:             PHASE P:                 │
  Email & Network  USB / Removable       Scheduled &          Performance &              │
    Protection     Media Protection    On-Demand Scanning   CleanFileCache Opt.          │
        │               │                     │                    │                     │
        └───────────────┴─────────────────────┼────────────────────┴─────────────────────┘
                                              ▼
                       PHASE Q: Self-Health, Watchdog, Audit Log & Tamper Protection
                                              │
                                              ▼
                       PHASE R: Desktop UX & 20-Screen Antivirus Command Center
                                              │
                                              ▼
                       PHASE S: Full System Verification, Soak & Release Gate
```

---

## 2. Detailed Phase Specifications (PHASE A – PHASE S)

---

### PHASE A: Baseline & Security Hardening
- **1. Objective:** Harden existing Desktop IPC, Secure Storage, and Windows path canonicalization boundaries (`apps/desktop/src/ipc/`, `secure-storage.service.ts`, `electron-main.ts`) to establish a Zero-Trust foundation before expanding privileged antivirus capabilities.
- **2. Dependencies:** None (Entry Phase).
- **3. Implementation Tasks:**
  - Upgrade `IpcValidator.isProtectedSystemPath()` to resolve paths via `fs.realpathSync.native()` (falling back safely on non-existent target leaf) to block NTFS 8.3 short-name (`C:\PROGRA~1\`), DOS device (`\\?\`), and junction bypasses.
  - Enforce `event.senderFrame === event.sender.mainFrame` and strict packaged `file:`/`app:` origin checks in `IpcValidator.validateSender()`, plus per-channel Token-Bucket rate limiting in `IpcHandler`.
  - Upgrade `SecureStorageService` to seal `.storage.key` via Windows DPAPI (`safeStorage` / `CryptProtectData` with fallback), write `storage.enc` atomically via `.tmp` + `fsyncSync` + `renameSync`, and fail closed to Maximum Protection Defaults if tampering is detected.
  - Implement cryptographic `FrictionToken` generation and verification in `IpcHandler` for security-lowering actions.
- **4. Unit Tests:** `ipc-validator.test.ts` and `secure-storage.service.test.ts` testing 8.3 paths, device names (`CON`, `NUL`), atomic writes, and tamper fallback.
- **5. Integration Tests:** End-to-end IPC roundtrip tests verifying rate-limiting and Friction Gate token enforcement across `SETTINGS_SAVE` and `PRIVACY_SHRED`.
- **6. Security Tests:** `ipc-security.test.ts` attempting subframe spoofing, `http://localhost` spoofing in packaged mode, path traversal (`..\..\Windows\System32`), and corrupted `storage.enc` injection.
- **7. Performance Tests:** Verify `IpcValidator` + rate-limiter overhead is $<0.05\text{ ms}$ per IPC call.
- **8. Acceptance Criteria:** 100% rejection of unauthorized IPC origins, traversal paths, and un-gated security-weakening mutations; zero plaintext keys when DPAPI/`safeStorage` is available.
- **9. Exit Criteria:** All Phase A unit, integration, and security tests pass with $\ge 90\%$ branch coverage.
- **10. Rollback Strategy:** Revert `ipc-validator.ts` and `secure-storage.service.ts` commits; `SecureStorageService` maintains backward compatibility with v1 `storage.enc` files.

---

### PHASE B: Core Detection Engine Expansion (`@private-protection/core`)
- **1. Objective:** Unify `@private-protection/core` (`ThreatIntel`, `BloomFilter`, `RuleEngine`, `RiskScorer`, `DetectionPipeline`) to support `InputType.FILE` and `InputType.PROCESS`, wire SHA-256 hash lookups, optimize `BloomFilter.has()` for pre-hashed hex strings, and add the 6-tier `EngineVerdict` policy (`ALLOW`, `INFORM`, `WARN`, `BLOCK`, `QUARANTINE`, `CONTAIN_PROCESS`).
- **2. Dependencies:** `PHASE A`.
- **3. Implementation Tasks:**
  - Optimize `BloomFilter` in `packages/core/src/threat-intel/bloom-filter.ts` to slice 64-char SHA-256 hex strings directly (`O(k)` bit checks without redundant SHA-256 hashing).
  - Seed `ThreatIntel.loadSeedData()` with standard EICAR SHA-256 (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`), synthetic test malware hashes, and a `goodHashes` / `fileAllowlist` set for user-trusted SHA-256 hashes.
  - Extend `RiskScorer` in `packages/core/src/scoring/risk-scorer.ts` with detector weights for all 10 layers (`HASH_INTEL`, `SIGNATURE_ENGINE`, `CORRELATION_ENGINE`, `BEHAVIORAL_ENGINE`, `STRUCTURAL_PARSER`, `METADATA_ANALYZER`, `STATIC_HEURISTIC`, `REPUTATION_LOCAL`) and fix the Bitcoin/scam diminishing-returns threshold so high-confidence multi-signal extortion scores $\ge 75$ (`BLOCK`).
  - Add Cross-Layer Synergy Correlation (`Layer 8`) rules to `RiskScorer`.
- **4. Unit Tests:** `bloom-filter.test.ts`, `threat-intel.test.ts`, `risk-scorer.test.ts`.
- **5. Integration Tests:** `detection-pipeline.test.ts` verifying unified scoring across URL, Text, and File inputs.
- **6. Security Tests:** Verify that `isCriticalOverride` signals can never be diluted below `BLOCK` by benign signals (`signal dilution attack` test).
- **7. Performance Tests:** `benchmarks.test.ts` verifying `BloomFilter.has()` runs in $<0.02\text{ ms}$ and `RiskScorer.calculateScore()` runs in $<0.05\text{ ms}$.
- **8. Acceptance Criteria:** `ThreatIntel.lookupHash()` accurately identifies EICAR and bad hashes in $<0.05\text{ ms}$ and respects user SHA-256 allowlist overrides.
- **9. Exit Criteria:** All `@private-protection/core` tests pass 100% with zero regressions on Web, Mobile, or Extension packages.
- **10. Rollback Strategy:** Revert `@private-protection/core` changes via git; existing `ScanResult` interface remains 100% backward-compatible.

---

### PHASE C: File Protection & 10-Layer Static Malware Engine
- **1. Objective:** Upgrade `CoreFileAnalyzer` (`packages/core/src/analyzers/file-analyzer.ts`) and `DesktopFileAnalyzer` (`apps/desktop/src/core/file-analyzer.ts`) into the full 10-Layer Static Malware Engine with the 4-Stage Short-Circuit Sieve.
- **2. Dependencies:** `PHASE B`.
- **3. Implementation Tasks:**
  - **Layer 1 & Stage 0:** Wire `ThreatIntel.lookupHash(sha256)` and `CleanFileCache` into `FileAnalyzer.analyzeFile()`. Defer full-file SHA-256 streaming until after fast 4 KB/64 KB header triage for non-executable media.
  - **Layer 2 (Signature Automaton):** Implement flattened Aho-Corasick / YARA-lite multi-pattern matcher detecting EICAR byte strings (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`), credential dumpers (`Mimikatz`, `sekurlsa::logonpasswords`, `MiniDumpWriteDump`), ransomware shadow deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set ... recoveryenabled no`, `wbadmin delete catalog`), AMSI/ETW bypasses, and LOLBin cradles across ASCII, UTF-16LE `WIDE`, and `NOCASE` encodings.
  - **Layer 3 (Metadata & Spoofing):** Verify `MZ` + `e_lfanew` $\rightarrow$ `PE\0\0`, detect double/triple extensions, whitespace padding (`doc.pdf   .exe`), and Unicode RTLO (`\u202E`). Fix false positives on normal clean `.exe` files (do not penalize standard `.exe` files unless unsigned/packed/anomalous).
  - **Layer 4 & 5 (Zero-Alloc PE32/PE32+, Entropy, ZIP & Office Macro Parser):**
    - Parse PE COFF/Optional headers, Section Table (`W+X` flags, `UPX0`/`.vmp0` packer names, per-section entropy), Import Address Table (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`, credential APIs), TLS callbacks, Overlays, and Authenticode Security Directory presence.
    - Implement precomputed `ENTROPY_LUT[4097]` sliding-window entropy scan to defeat null-byte entropy padding.
    - Implement `ZipStructuralParser` (inspecting Central Directory for disguised executables/scripts and enforcing zip-bomb ratio $>100:1$ / depth $>3$ limits) and `OfficeMacroParser` (`vbaProject.bin`, OLE `VBA`/`Equation Native`, PDF `/JavaScript` & `/Launch`).
    - Implement in-memory Base64 / charcode PowerShell & script de-obfuscation.
- **4. Unit Tests:** `pe-deep-analyzer.test.ts`, `archive-scanner.test.ts`, `file-analyzer.test.ts`.
- **5. Integration Tests:** Scan a mixed directory of EICAR, synthetic Mimikatz/ransomware PE files, encoded PS1 scripts, macro-laden `.docx`, nested `.zip` archives, and 50 clean Windows/developer binaries.
- **6. Security Tests:** Malformed/truncated PE header fuzzing (verifying zero uncaught `RangeError` crashes and fail-closed `WARN` verdicts), zip-bomb (`1000:1` ratio) abort test, and RTLO `\u202E` spoofing test.
- **7. Performance Tests:** Stage 0 cache hit $<0.08\text{ ms}$; Stage 1 clean media triage $<0.50\text{ ms}$; Stage 2/3 deep PE/signature scan $<5.0\text{ ms}$ ($p95$).
- **8. Acceptance Criteria:** $\ge 99\%$ detection rate on synthetic malware/EICAR/script/macro/archive fixtures; $0.00\%$ false `BLOCK` rate on clean signed system binaries and normal media files.
- **9. Exit Criteria:** All unit, security, and benchmark tests pass with $\ge 90\%$ coverage.
- **10. Rollback Strategy:** Feature-flag deep structural parsers behind `enableDeepStructuralAnalysis` setting (enabled by default).

---

### PHASE D: Quarantine Hardening (`PPVAULT2`)
- **1. Objective:** Harden `QuarantineService` (`apps/desktop/src/services/quarantine.service.ts`) with streaming 64 KB `PPVAULT2` AES-256-GCM encryption, DPAPI key protection, atomic encrypted manifests, TOCTOU file-handle locking, and "Restore & Trust SHA-256".
- **2. Dependencies:** `PHASE A`, `PHASE B`.
- **3. Implementation Tasks:**
  - Implement `PPVAULT2` chunked (`64 KB`) streaming `AES-256-GCM` encryption and decryption (with per-chunk AAD binding `fileUuid || chunkIndex || isFinalChunk`) while retaining backward compatibility to decrypt existing `PPVAULT1` blobs.
  - Seal `.vault.key` via Windows DPAPI (`safeStorage` / `CryptProtectData` with fallback).
  - Encrypt `manifest.json.enc` with AES-256-GCM and write atomically via `manifest.json.enc.tmp` + `fsyncSync` + `renameSync`, maintaining `manifest.json.enc.bak` for automatic crash recovery.
  - Open files using pinned file descriptors (`O_NOFOLLOW`), record/strip `:Zone.Identifier` ADS metadata, and support `restoreItem(id, { trustSha256: boolean })` which adds the restored file's SHA-256 to `ThreatIntel` allowlist.
- **4. Unit Tests:** `quarantine-streaming.test.ts`, `quarantine.service.test.ts`, `gap24-quarantine-path-safety.test.ts`.
- **5. Integration Tests:** Isolate $\rightarrow$ Restart service $\rightarrow$ Verify manifest recovery $\rightarrow$ Restore with `trustSha256: true` $\rightarrow$ Verify `RealtimeMonitorService` does not re-quarantine.
- **6. Security Tests:** Flip 1 bit in `PPVAULT2` header, chunk ciphertext, and GCM auth tag; test chunk reordering/truncation; test symlink/junction TOCTOU swap; test `CON`/`NUL`/`..\` restore paths.
- **7. Performance Tests:** Quarantine and restore a 100 MB synthetic file and verify peak V8 heap delta is $<16\text{ MB}$.
- **8. Acceptance Criteria:** Zero OOM on large files, 100% tamper detection, crash-safe manifest recovery from `.bak`, and working Restore+Trust workflow.
- **9. Exit Criteria:** All Category 14 Quarantine tests pass 100%.
- **10. Rollback Strategy:** Dual-magic parser (`PPVAULT1` and `PPVAULT2`) ensures zero data loss across upgrades or rollbacks.

---

### PHASE E: Real-Time Protection Engine & Background Continuity
- **1. Objective:** Upgrade `RealtimeMonitorService` (`apps/desktop/src/services/realtime-monitor.service.ts`) to provide recursive multi-directory watching, burst backpressure control, download completion state tracking, and continuous background execution via the Windows System Tray.
- **2. Dependencies:** `PHASE C`, `PHASE D`.
- **3. Implementation Tasks:**
  - Enable `{ recursive: true }` on Windows `fs.watch` (`ReadDirectoryChangesW`) and expand default watched roots to `Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, and Startup folders, plus user-added directories.
  - Implement a bounded priority event queue (`maxQueueSize = 10,000`) with inode/path deduplication and `.crdownload`/`.part` $\rightarrow$ final rename state tracking so completed downloads are scanned within $<50\text{ ms}$.
  - Add Windows System Tray integration (`Tray` in `electron-main.ts`) with context menu (`Open Dashboard`, `Run Quick Scan`, `Protection Status: Protected`, `Exit Private Protection`) so closing the window hides to Tray while keeping `RealtimeMonitorService` running.
- **4. Unit Tests:** `realtime-monitor.service.test.ts`, `realtime-monitor-burst.test.ts`.
- **5. Integration Tests:** Drop EICAR into a nested subfolder `Downloads\sub1\sub2\eicar.com` and verify automatic quarantine and UI event emission within $<50\text{ ms}$.
- **6. Security Tests:** Simulate `.crdownload` write stream followed by rename to `invoice.pdf.exe`; verify partial file is not prematurely locked and renamed file is immediately quarantined.
- **7. Performance Tests:** Simulate 1,000 rapid file creations in a watched directory and verify bounded memory ($<200\text{ MB}$) and zero dropped threat detections.
- **8. Acceptance Criteria:** 100% recursive subfolder coverage, $<50\text{ ms}$ $p95$ ingress detection latency, and continuous background operation when window is closed.
- **9. Exit Criteria:** All Category 13 Real-Time Burst tests pass.
- **10. Rollback Strategy:** Watcher falls back cleanly to non-recursive directory walk if OS rejects recursive flag on non-NTFS mounts.

---

### PHASE F: Process & Behavior Monitoring
- **1. Objective:** Upgrade `ProcessAuditorService` (`apps/desktop/src/services/process-auditor.service.ts`) and introduce `BehaviorEngineService` to inspect full process executable paths, parent-child PID lineage, LOLBin command lines, and on-disk process binaries, with safe user-mode process containment.
- **2. Dependencies:** `PHASE C`.
- **3. Implementation Tasks:**
  - Query full process metadata (`ProcessId`, `ParentProcessId`, `Name`, `ExecutablePath`, `CommandLine`) via `Get-CimInstance Win32_Process` / `wmic` with `tasklist` fallback.
  - Build `ProcessLineageGraph` to detect parent-child anomalies (`winword.exe`/`excel.exe`/`chrome.exe` $\rightarrow$ `powershell.exe`/`cmd.exe`/`mshta.exe`/`wscript.exe`/`rundll32.exe`/`certutil.exe`).
  - Detect system binary path masquerading (`svchost.exe`, `lsass.exe`, `csrss.exe` running outside `C:\Windows\System32` or `SysWOW64`), processes running from `%TEMP%` or `Downloads`, and encoded/hidden PowerShell or `vssadmin` command lines.
  - Scan accessible process executable paths on disk through `FileAnalyzer` (using `CleanFileCache` for instant known-clean system binary skips).
  - Implement `containProcess(pid)` to safely terminate (`process.kill` / `taskkill /PID <pid> /T /F`) confirmed malicious non-system processes while strictly enforcing `RULE-09` (never terminating/quarantining critical OS processes).
- **4. Unit Tests:** `process-auditor.test.ts` testing 25 LOLBin, parent-child, and path masquerade fixtures.
- **5. Integration Tests:** Spawn a benign test child process from a temp directory with simulated suspicious CLI flags, verify `ProcessAuditorService` detects it, and verify `containProcess(pid)` terminates the child process cleanly.
- **6. Security Tests:** Attempt calling `containProcess()` on PID `0`, `4` (`System`), or a `C:\Windows\System32\svchost.exe` binary without malicious CLI args; assert hard rejection (`PROTECTED_SYSTEM_PROCESS`).
- **7. Performance Tests:** Full process table audit completes in $<500\text{ ms}$.
- **8. Acceptance Criteria:** 100% detection on all 25 behavioral process fixtures; safe termination of test child PIDs.
- **9. Exit Criteria:** All `AV-BEHAVIOR-001`–`003` tests pass.
- **10. Rollback Strategy:** Graceful fallback to read-only process reporting if process termination is disabled in settings.

---

### PHASE G: Ransomware Shield & Shadow Vault Rollback
- **1. Objective:** Implement `RansomwareShieldService` and `ShadowVaultService` (`apps/desktop/src/services/ransomware-shield.service.ts`, `shadow-vault.service.ts`) providing Protected Folders, Trusted Application access control, Decoy Canary Trap files, Sliding-Window Mass-Encryption Velocity detection, and 1-click Copy-on-Write file recovery.
- **2. Dependencies:** `PHASE D`, `PHASE E`, `PHASE F`.
- **3. Implementation Tasks:**
  - Implement **Protected Folders** (`Documents`, `Pictures`, `Desktop`, plus custom user folders) with **Smart Mode** and **Strict Mode** and a **Trusted Applications** registry bound to `(CanonicalPath + SHA256 + Signer)`.
  - Deploy hidden **Decoy Canary Files** (`~$_PrivateProtection_Canary_*.docx/.xlsx`) in monitored roots and hook immediate tamper alerts (`RANSOMWARE_CANARY_TRIPPED`, score `100`).
  - Implement the **64-slot Sliding-Window Velocity & Entropy Detector** ($\ge 25$ modifications in $3.0\text{ s}$ with $\ge 8$ high-entropy writes $H > 7.5$ or $\ge 10$ extension renames `.locked`/`.encrypted`).
  - Implement `ShadowVaultService`: maintains encrypted Copy-on-Write backups of protected user documents (up to `50 MB` per file, `2 GB` total FIFO quota) in `~/.private-protection/shadow-vault/` and exposes `rollbackIncident(incidentId)` to restore clean files to their exact pre-attack SHA-256 hashes.
- **4. Unit Tests:** `ransomware-shield.test.ts` testing canary hashing, velocity window math, trusted app hash verification, and Shadow Vault encryption/restore.
- **5. Integration Tests:** Run the safe `RansomwareSimulationHarness` inside `os.tmpdir()/pp-ransom-sandbox-<uuid>` and verify automatic detection, simulator process termination, binary quarantine, and 100% file restoration.
- **6. Security Tests:** Verify sandbox path confinement guard (`SANDBOX_ESCAPE_ABORT`); test trusted app binary modification (assert automatic trust revocation when binary SHA-256 changes).
- **7. Performance Tests:** Canary tamper detection $<100\text{ ms}$; mass-write burst arrest $<500\text{ ms}$ (with $\le 3$ non-canary files altered before arrest).
- **8. Acceptance Criteria:** 100% containment of simulated ransomware burst in $<500\text{ ms}$ and 100% byte-for-byte SHA-256 restoration of affected sandbox files.
- **9. Exit Criteria:** All Category 10 & Category 15 Ransomware tests pass.
- **10. Rollback Strategy:** Shadow Vault restoration is non-destructive (preserves corrupted copies with `.corrupted` suffix if requested).

---

### PHASE H: Notification System & Storm Rate-Limiter
- **1. Objective:** Implement `NotificationService` (`apps/desktop/src/services/notification.service.ts`) dispatching Native Windows OS Toast Notifications, System Tray alerts, and an In-App Notification Inbox with token-bucket storm rate-limiting (`RULE-15`).
- **2. Dependencies:** `PHASE E`.
- **3. Implementation Tasks:**
  - Implement `NotificationService` using Electron `Notification` (with fallback for headless test environments) and persistent in-app notification state (`unreadCount`, `notifications[]`, `markRead`, `clearAll`).
  - Implement a **Token-Bucket Rate Limiter** (max `3` native OS toasts per `10-second` window) and **Burst Coalescer** (when $\ge 3$ threats occur within `5 seconds`, combine subsequent alerts into a single summary notification: *"N threats blocked in Downloads"*).
  - Scrub bidirectional override characters (`\u202E`) and sensitive Tier-1 content from toast payloads.
- **4. Unit Tests:** `notification-rate-limiter.test.ts`.
- **5. Integration Tests:** Trigger 200 EICAR detections within 1 second via `RealtimeMonitorService` and verify all 200 files are quarantined while at most 3 native OS toasts are fired (plus 1 coalesced batch summary).
- **6. Security Tests:** Verify 255-character RTLO filename in notification payload is sanitized and truncated safely.
- **7. Performance Tests:** Notification dispatch + coalescing overhead $<0.5\text{ ms}$ per event.
- **8. Acceptance Criteria:** $\le 3$ OS toasts per 10s storm window; 100% threat containment during alert storms; $<50\text{ ms}$ initial toast latency.
- **9. Exit Criteria:** Category 12 Notification Storm test suite passes 100%.
- **10. Rollback Strategy:** Can disable native OS toasts in settings while retaining in-app alert banners.

---

### PHASE I: Automatic Response Ladder & False-Positive Exclusion Management (COMPLETE / GO APPROVED)
- **Status:** **COMPLETE / INDEPENDENT AUDIT GO APPROVED** (`docs/PHASE_I_FINAL_INDEPENDENT_AUDIT.md`, `docs/PHASE_I_COMPLETION.md`, `docs/PHASE_I_ARCHITECTURE.md`)
- **1. Objective:** Implement the deterministic **5-Tier Automatic Response Ladder** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `RANSOMWARE_BEHAVIOR`) and the **3-Tier Allowlist & Exclusion Manager** (SHA-256 Hash, Canonical Path, Domain with Expiration TTLs and hard anti-abuse guardrails).
- **2. Dependencies:** `PHASE D`, `PHASE E`, `PHASE F`, `PHASE G`, `PHASE H` (All GO).
- **3. Implementation Tasks:**
  - Implement `ResponsePolicyEngine` mapping `(riskScore, severity, verdict, confidence, isProtectedSystemBinary)` deterministically to the 5 response tiers.
  - Implement `ExclusionManagerService` supporting exclusions by **SHA-256 Hash**, **File/Folder Path**, and **Web Domain** with expiration TTLs (`24h`, `7d`, `30d`, `Permanent`).
  - Enforce hard constitutional guardrails forbidding exclusion of `C:\`, `C:\Windows`, `Downloads`, `%TEMP%`, `%APPDATA%`, or wildcard executable extensions (`*.exe`, `*.dll`, `*.ps1`, `*.bat`).
  - Wire 1-click **"Restore & Trust SHA-256"** in `QuarantineService` and IPC channels (`EXCLUSION_LIST`, `EXCLUSION_ADD`, `EXCLUSION_REMOVE`).
- **4. Unit Tests:** Unit tests for all 5 response tiers and forbidden exclusion path rejections (`response-policy-engine.test.ts`, `exclusion-manager.test.ts`).
- **5. Integration Tests:** Full false-positive lifecycle test: detect suspicious custom build $\rightarrow$ quarantine $\rightarrow$ restore with SHA-256 trust $\rightarrow$ re-scan and verify `ALLOW` (`phase-i-exclusion.integration.test.ts`).
- **6. Security Tests:** Attempt adding `C:\`, `%USERPROFILE%\Downloads`, or `*.exe` via IPC `EXCLUSION_ADD`; assert `SECURITY_VIOLATION` rejection. Attempt adding exclusion without `frictionToken`; assert rejection (`phase-i-security.test.ts`).
- **7. Performance Tests:** $O(1)$ SHA-256 Set lookup and normalized path prefix check in $<0.01\text{ ms}$ (`phase-i-performance.test.ts`).
- **8. Acceptance Criteria:** `0.00%` false-block rate on the 500-fixture clean binary/media/dev-build corpus; 100% enforcement of forbidden exclusion scopes.
- **9. Exit Criteria:** All Category 11 False Positive Corpus tests pass 100% (31/31 Phase I tests pass, 692/692 monorepo total).
- **10. Rollback Strategy:** Exclusions can be cleared in 1 click (`Clear All Exclusions`) without a Friction Gate.

---

### PHASE J: Web & Download Mark-of-the-Web (MOTW) Protection (COMPLETE / GO APPROVED)
- **Status:** **COMPLETE / INDEPENDENT AUDIT GO APPROVED** (`docs/PHASE_J_FINAL_INDEPENDENT_AUDIT.md`, `docs/PHASE_J_COMPLETION.md`, `docs/PHASE_J_ARCHITECTURE.md`)
- **1. Objective:** Integrate NTFS `:Zone.Identifier` Alternate Data Stream (MOTW) extraction into Desktop Download & File Scanning, and expose Web Protection status and shared allowlist/blocklist management with the Browser Extension.
- **2. Dependencies:** `PHASE B`, `PHASE C`, `PHASE E` (All GO).
- **3. Implementation Tasks:**
  - Implement `MotwAnalyzer` (`apps/desktop/src/core/motw-analyzer.ts`) reading `${filePath}:Zone.Identifier` on NTFS (and supporting `.zone.identifier` companion fixtures in cross-platform tests) to parse `ZoneId`, `HostUrl`, and `ReferrerUrl`.
  - Feed extracted `HostUrl` and `ReferrerUrl` through `@private-protection/core` `URLAnalyzer` and `ThreatIntel.checkUrl()`, elevating file risk score by $+35$ to $+85$ when a file was downloaded from a phishing, homograph, or raw-IP host.
  - Add IPC channels and status reporting for Web Protection, Punycode/homograph visual breakdown, and Extension sync status.
- **4. Unit Tests:** `motw-analyzer.test.ts` testing `ZoneId=0..4`, malicious `HostUrl`, phishing `ReferrerUrl`, and missing ADS streams (15/15 pass).
- **5. Integration Tests:** Simulate downloading an unsigned `.exe` tagged with a phishing `:Zone.Identifier` stream into `Downloads`; verify `RealtimeMonitorService` combines the MOTW URL score with PE heuristics to block and quarantine the file (`phase-j-motw.integration.test.ts`, 2/2 pass).
- **6. Security Tests:** Test crafted `:Zone.Identifier` stream with 10 KB oversized lines, RTLO overrides, or control characters; assert bounded parsing ($<4\text{ KB}$) and zero crashes (`phase-j-security.test.ts`, 7/7 pass).
- **7. Performance Tests:** `:Zone.Identifier` parse completes in $0.0049\text{ ms}$; full file + URL analysis in $2.52\text{ ms}$ (`phase-j-performance.test.ts`, 3/3 pass).
- **8. Acceptance Criteria:** 100% accurate MOTW extraction and origin-URL risk correlation; zero network/DNS leaks during URL evaluation.
- **9. Exit Criteria:** Category 16 Web & Download MOTW tests pass 100% (27/27 Phase J tests pass, 673/673 monorepo total).
- **10. Rollback Strategy:** If filesystem does not support NTFS ADS (e.g., FAT32 USB), gracefully skips ADS read (`ENOENT`/`EINVAL`) without error.

---

### PHASE K: Practical Email (`.eml`/`.msg`) & Network Socket Protection (COMPLETE / GO APPROVED)
- **Status:** **COMPLETE / INDEPENDENT AUDIT GO APPROVED** (`docs/PHASE_K_FINAL_INDEPENDENT_AUDIT.md`, `docs/PHASE_K_COMPLETION.md`, `docs/PHASE_K_ARCHITECTURE.md`)
- **1. Objective:** Implement local `.eml`/`.msg` email header, body, and attachment scanning inside `FileAnalyzer`, and upgrade `NetworkMonitorService` (`apps/desktop/src/services/network-monitor.service.ts`) to audit active TCP/UDP sockets (`netstat -ano`), map connections to owning PIDs, match remote IPs against `ThreatIntel`, and query real Windows Defender Firewall profile states.
- **2. Dependencies:** `PHASE C`, `PHASE F` (All GO).
- **3. Implementation Tasks:**
  - Add `EmailMimeParser` to `FileAnalyzer`: parses `.eml` files for `From` vs. `Reply-To`/`Return-Path` domain spoofing, `Authentication-Results` (`spf=fail`, `dmarc=fail`), passes body text and links through `TextAnalyzer` and `URLAnalyzer`, and decodes Base64 attachments through the 10-Layer File Engine.
  - Upgrade `NetworkMonitorService.getNetworkPosture()` to parse active connections (`netstat -ano -p TCP`), correlate remote IPv4/IPv6 endpoints with `ThreatIntel.lookupIp()` and high-risk C2 ports (`4444`, `1337`, `6667`, etc.), map PIDs to process names, and query Windows Firewall status (`netsh advfirewall show allprofiles`).
- **4. Unit Tests:** `network-monitor.test.ts` (7/7 pass) and `email-mime-parser.test.ts` (10/10 pass).
- **5. Integration Tests:** Scan a synthetic `.eml` file containing a spoofed sender, urgent wire-transfer text, and a Base64-encoded EICAR attachment; verify `BLOCK` verdict with combined email + attachment evidence (`phase-k-email-network.integration.test.ts`, 3/3 pass).
- **6. Security Tests:** Test nested/malformed MIME boundaries, oversized Base64 attachments, RTLO bidi scrubbing, path traversal/NUL injection, and zero network leaks; verify bounded memory parsing (`phase-k-security.test.ts`, 7/7 pass).
- **7. Performance Tests:** `.eml` scan $2.16\text{ ms}$ ($<10\text{ ms}$ SLA); `NetworkMonitorService` socket parsing $1.10\text{ ms}$ ($<100\text{ ms}$ SLA) (`phase-k-performance.test.ts`, 4/4 pass).
- **8. Acceptance Criteria:** 100% detection of EICAR/executable attachments inside `.eml` files and accurate PID-to-socket C2 IP matching.
- **9. Exit Criteria:** All Phase K unit, security, integration, and benchmark tests pass 100% (31/31 Phase K tests, 678/679 monorepo total).
- **10. Rollback Strategy:** If `netstat` or `netsh` is restricted by OS policy, returns NIC posture + graceful diagnostic notice.

---

### PHASE L: Startup & Persistence Protection
- **1. Objective:** Upgrade `PersistenceAuditorService` (`apps/desktop/src/services/persistence-auditor.service.ts`) to inspect Per-User Startup, All-Users Startup, binary `.lnk` shortcut targets, Windows Registry `HKCU`/`HKLM` `Run`/`RunOnce` keys, and Scheduled Tasks, scanning referenced binaries/scripts with `FileAnalyzer`.
- **2. Dependencies:** `PHASE C`, `PHASE F`.
- **3. Implementation Tasks:**
  - Expand `PersistenceAuditorService` to enumerate:
    1. Per-User Startup (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) and All-Users Startup (`%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`).
    2. Binary Windows Shell Link (`.lnk`) parser extracting the real target path and command-line arguments.
    3. Windows Registry `HKCU` and `HKLM` `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` keys (via `reg query`).
    4. Windows Scheduled Tasks (`schtasks /Query /FO CSV`).
  - Scan extracted target executable/script paths with `FileAnalyzer` and flag entries pointing to `%TEMP%`, `Downloads`, `%APPDATA%`, or obfuscated scripts (`powershell -enc`, `wscript`, `mshta`).
- **4. Unit Tests:** `persistence-auditor.test.ts` testing `.lnk` binary parsing, `reg query` output parsing, `schtasks` CSV parsing, and risk scoring.
- **5. Integration Tests:** Create a synthetic `.lnk` and `.vbs` persistence fixture in a temp startup directory and verify `PersistenceAuditorService` resolves the target and flags it as `dangerous`/`suspicious`.
- **6. Security Tests:** Test `.lnk` file with truncated header or relative traversal target; verify safe bounds-checked parsing.
- **7. Performance Tests:** Full persistence audit across folders + registry + tasks completes in $<600\text{ ms}$.
- **8. Acceptance Criteria:** 100% coverage of Startup folders, `.lnk` targets, Registry `Run`/`RunOnce`, and Scheduled Tasks (`AV-BEHAVIOR-004`).
- **9. Exit Criteria:** All `persistence-auditor.test.ts` assertions pass.
- **10. Rollback Strategy:** Individual persistence sources (e.g., `schtasks`) fail independently without blocking Startup folder or Registry results.

---

### PHASE M: USB & Removable Media Protection (COMPLETE / GO APPROVED)
- **Status:** **COMPLETE / INDEPENDENT AUDIT GO APPROVED** (`docs/PHASE_M_FINAL_INDEPENDENT_AUDIT.md`, `docs/PHASE_M_COMPLETION.md`, `docs/PHASE_M_ARCHITECTURE.md`)
- **1. Objective:** Upgrade `RemovableMediaService` (`apps/desktop/src/services/removable-media.service.ts`) to accurately detect removable USB volumes (`DRIVE_REMOVABLE` / `DriveType=2`), report real disk capacity, automatically scan newly mounted USB roots for `autorun.inf` and `.lnk` worms in $<200\text{ ms}`, and wire USB scanning into `IpcHandler` and the UI.
- **2. Dependencies:** `PHASE C`, `PHASE E`, `PHASE L`.
- **3. Implementation Tasks:**
  - Query logical volume drive types and free/total bytes via WMI/CIM (`Win32_LogicalDisk Where DriveType=2`) or `fs.statfsSync` fallback.
  - Start `removableMediaService.startMonitoring()` in `IpcHandler` and emit `MEDIA_DRIVE_ATTACHED` events when a USB drive is mounted.
  - Implement `scanRemovableDriveRoot(mountPath)` to immediately inspect `autorun.inf`, hidden directories replaced by same-named `.lnk` shortcut worms, and root executables upon insertion.
- **4. Unit Tests:** `removable-media.test.ts`, `autorun-parser.test.ts`, `lnk-parser.test.ts` testing drive enumeration, `autorun.inf` parsing, and `.lnk` worm detection (27/27 pass).
- **5. Integration Tests:** Simulate mounting a removable drive directory containing `autorun.inf` (`open=worm.vbs`) and a malicious `.lnk` file; verify automatic root threat detection within $<200\text{ ms}` (`phase-m-removable-media.integration.test.ts`, 2/2 pass).
- **6. Security Tests:** Verify drive mount path validation prevents scanning arbitrary UNC paths, fuzz malformed/oversized LNK and autorun files (`phase-m-security.test.ts`, 8/8 pass).
- **7. Performance Tests:** USB root quick-triage completes in $17.08\text{ ms}$ on mount ($<200\text{ ms}$ SLA) (`phase-m-performance.test.ts`, 4/4 pass).
- **8. Acceptance Criteria:** Accurate USB drive detection with real byte capacity and automatic `autorun.inf`/worm protection (`AV-REALTIME-004`).
- **9. Exit Criteria:** All Phase M tests pass 100% (41/41 Phase M tests, 719/720 monorepo total).
- **10. Rollback Strategy:** Users can toggle automatic USB mount scanning on/off in Settings.

---

### PHASE N: Scheduled & On-Demand Scanning
- **1. Objective:** Implement `ScanSchedulerService` (`apps/desktop/src/services/scan-scheduler.service.ts`) supporting Daily Quick Scans, Weekly Full Scans, and Missed-Scan Startup Catch-Up with battery and CPU-load awareness, and upgrade `QuickScanService` to also sweep active process binaries and startup persistence targets.
- **2. Dependencies:** `PHASE C`, `PHASE F`, `PHASE L`.
- **3. Implementation Tasks:**
  - Implement `ScanSchedulerService` with configurable schedule persistence (`enabled`, `frequency: 'daily' | 'weekly'`, `timeOfDay`, `scanType: 'quick' | 'full'`, `pauseOnBattery`, `runMissedOnStartup`, `autoQuarantine`).
  - Implement battery/CPU check before starting a scheduled run (deferring if battery $<20\%$ or CPU load $>80\%$).
  - Upgrade `QuickScanService` to include active user process binaries and Startup persistence targets alongside `Downloads`, `Temp`, and `Desktop`.
  - Wire IPC channels (`SCHEDULE_GET`, `SCHEDULE_SAVE`, `SCHEDULE_RUN_NOW`).
- **4. Unit Tests:** Scheduler timer calculation, missed-scan catch-up logic, and battery/load deferral unit tests.
- **5. Integration Tests:** Configure a scheduled scan, trigger `runScheduledJobNow()`, and verify scan execution, threat quarantine, and history logging.
- **6. Security Tests:** Verify disabling scheduled scans when Real-Time Shield is also off requires a valid `frictionToken`.
- **7. Performance Tests:** Scheduled background scan runs with throttled concurrency and `<16ms` UI frame time.
- **8. Acceptance Criteria:** Full support for Daily, Weekly, and Catch-Up scheduled scans with resource guards (`AV-PERF-003`).
- **9. Exit Criteria:** All scheduler unit and integration tests pass.
- **10. Rollback Strategy:** Scheduler can be paused or reset to default schedule at any time.

---

### PHASE O: Threat Intelligence & Cryptographically Signed Updates
- **1. Objective:** Upgrade `UpdateVerifierService` (`apps/desktop/src/services/update-verifier.service.ts`) and wire a complete **Signed Threat Database Update & Offline `.ppdb` Bundle Import + Last-Known-Good (`LKG`) Rollback** workflow.
- **2. Dependencies:** `PHASE A`, `PHASE B`.
- **3. Implementation Tasks:**
  - Update `UpdateVerifierService.verifyUpdatePackage()` to verify Ed25519 signatures over the canonical string `${manifest.version}:${manifest.versionSequence}:${manifest.publishedAt}:${manifest.sha256}` against a pinned production Root Public Key.
  - Persist `currentVersionSequence`, `installedVersion`, `lastUpdated`, and the `LastKnownGood` (`N-1`) database snapshot in `SecureStorageService`.
  - Implement `importUpdateBundle(bundlePath)` and `rollbackToLastKnownGood()` on `IpcHandler` (`UPDATE_APPLY_BUNDLE`, `UPDATE_ROLLBACK_LKG`), running a post-staging EICAR self-test before atomic swap.
- **4. Unit Tests:** `update-verifier.test.ts` testing canonical Ed25519 signature verification, bit-flip rejection, anti-downgrade (`versionSequence <= current`), and LKG rollback.
- **5. Integration Tests:** Apply a valid signed `v2` update bundle over IPC, verify `ThreatIntel` ruleset version increments to `2` and `CleanFileCache` invalidates, then execute `rollbackToLastKnownGood()` and verify restoration of `v1`.
- **6. Security Tests:** Inject forged signature, replay `v1` manifest with modified `versionSequence: 99`, and inject a corrupted payload that fails EICAR self-test; assert 100% rejection and automatic rollback.
- **7. Performance Tests:** Bundle verification + atomic hot-swap completes in $<100\text{ ms}$; LKG rollback completes in $<200\text{ ms}$.
- **8. Acceptance Criteria:** 100% cryptographic update verification, working offline `.ppdb` import, and $<200\text{ ms}$ LKG rollback (`AV-UPDATE-001`).
- **9. Exit Criteria:** Category 10 Update Rollback and Category 4 Update Injection tests pass 100%.
- **10. Rollback Strategy:** Built-in `rollbackToLastKnownGood()` + immutable compiled-in Factory Seed DB guarantee the engine can always recover.

---

### PHASE P: Performance, Worker Pool & Low-Resource Optimization
- **1. Objective:** Implement the 65,536-entry `CleanFileCache`, worker-thread / non-blocking I/O batching, IPC progress throttling (`30 Hz` cap), and adaptive low-memory/battery scaling for 4 GB RAM Windows PCs.
- **2. Dependencies:** `PHASE C`, `PHASE E`, `PHASE N`.
- **3. Implementation Tasks:**
  - Implement `CleanFileCache` (`apps/desktop/src/core/clean-file-cache.ts`) keyed by `(dev, ino, size, mtimeMs, engineVersion, dbVersion)` with $O(1)$ Map LRU eviction at 65,536 entries.
  - Throttle `SCAN_PROGRESS_EVENT` emissions in `ScannerService` / `IpcHandler` to at most `1` event per `50 ms` (`20 Hz`) (plus final completion event) so scanning 10,000 small files never floods Electron IPC or freezes React rendering.
  - Add adaptive concurrency scaling based on `os.totalmem()` and `os.cpus()` (capping concurrency on $\le 4\text{ GB}$ RAM devices).
- **4. Unit Tests:** `CleanFileCache` hit, miss, mtime invalidation, DB-version invalidation, and LRU eviction unit tests.
- **5. Integration Tests:** Run a Full Scan twice on a 1,000-file directory; verify second scan completes $\ge 10\times$ faster via `CleanFileCache` hits while immediately re-scanning any file whose `mtime` changed.
- **6. Security Tests:** Modify 1 byte of a cached clean file to include EICAR; verify `size`/`mtimeMs` change invalidates cache and detects the threat.
- **7. Performance Tests:** `performance-benchmark.test.ts` verifying: Idle CPU $<1\%$, Idle RAM $<50\text{ MB}$, Peak Scan RAM $<200\text{ MB}$, `CleanFileCache` hit $<0.08\text{ ms}$, and fast-path scan $p50 < 2.0\text{ ms}$.
- **8. Acceptance Criteria:** All `RULE-14` resource budgets met on benchmark suite.
- **9. Exit Criteria:** Category 5 Performance Benchmarks pass 100%.
- **10. Rollback Strategy:** `CleanFileCache` can be cleared or bypassed (`bypassCache: true`) on any scan.

---

### PHASE Q: Self-Health, Watchdog, Tamper Protection & Forensic Audit Logger
- **1. Objective:** Implement `AuditLoggerService` (encrypted, append-only HMAC-SHA256 hash-chained forensic log), `HealthMonitorService` (4-State Health Model: `HEALTHY`, `WARNING`, `DEGRADED`, `CRITICAL`), `WatchdogService` (watcher/worker auto-recovery + shield snooze auto-re-enable timer), and Tamper Protection.
- **2. Dependencies:** `PHASE A` through `PHASE P`.
- **3. Implementation Tasks:**
  - Implement `AuditLoggerService` (`apps/desktop/src/services/audit-logger.service.ts`) with HMAC-SHA256 hash chaining (`prevHash` $\rightarrow$ `entryHmacSha256`), Tier-1 PII scrubbing, category/severity filtering, chain integrity verification, and sanitized JSON/CSV export.
  - Implement `HealthMonitorService` (`apps/desktop/src/services/health-monitor.service.ts`) evaluating all subsystems into `HEALTHY`, `WARNING`, `DEGRADED`, or `CRITICAL` with actionable 1-click remediation steps.
  - Implement `WatchdogService` (`apps/desktop/src/services/watchdog.service.ts`) with `2,000 ms` health checks, automatic watcher re-binding ($<500\text{ ms}$), crash-loop circuit breaking (Safe Minimal Mode after $>3$ crashes in 120s), and mandatory **Auto-Re-Enable Countdown Timer** (`15m`, `30m`, `1h`) when Real-Time Shield is paused.
- **4. Unit Tests:** `watchdog-crash-recovery.test.ts` and `audit-logger.test.ts` testing HMAC chain verification, tamper detection, 4-state transitions, and snooze auto-re-enable.
- **5. Integration Tests:** Simulate a dropped filesystem watcher and a paused shield timer expiry; verify `WatchdogService` restores both automatically and logs `WATCHDOG_RECOVERY` to `AuditLoggerService`.
- **6. Security Tests:** Modify a single character in an historical `AuditLogEntry` on disk; verify `verifyChainIntegrity()` immediately returns `false` with the exact tampered index and raises `HealthMonitor` to `WARNING`/`CRITICAL`.
- **7. Performance Tests:** HMAC log append $<0.2\text{ ms}$; Watchdog heartbeat check $<0.1\text{ ms}$.
- **8. Acceptance Criteria:** Tamper-evident HMAC audit chain, 4-state health posture, $<500\text{ ms}$ watchdog recovery, and automatic shield re-enable (`AV-SEC-002`, `AV-PRIVACY-002`).
- **9. Exit Criteria:** Category 8 Crash Recovery & Watchdog tests pass 100%.
- **10. Rollback Strategy:** If `audit.log.enc` is corrupted by disk fault, archives the damaged epoch file and starts a fresh verified genesis chain.

---

### PHASE R: Desktop UX & 20-Screen Antivirus Command Center
- **1. Objective:** Upgrade `apps/desktop/src/renderer/` to implement all **20 Required Antivirus Screens/Components** specified in `design.md`, featuring the 3-Tier Posture Hero Banner (`🟢 PROTECTED`, `🟡 ATTENTION REQUIRED`, `🔴 ACTION REQUIRED`), 4-Pillar Plain-Language Alerts, virtualized tables, and WCAG AA accessibility—with 100% real backend wiring and zero stub/fake controls (`RULE-24`).
- **2. Dependencies:** `PHASE A` through `PHASE Q`.
- **3. Implementation Tasks:**
  - Upgrade existing screens and add dedicated components/screens for all 20 views:
    1. `Protection Dashboard` (`HomeScreen.tsx` with 3-tier posture hero & 4-pillar summary)
    2. `Quick Scan` (`QuickScanScreen.tsx`)
    3. `Full Scan` (`FullScanScreen.tsx`)
    4. `Custom Scan` (`CustomScanScreen.tsx` with drag-and-drop & USB presets)
    5. `Scheduled Scan` (`ScheduledScanScreen.tsx`)
    6. `Real-Time Protection` (`RealtimeProtectionScreen.tsx` with sub-shield toggles & snooze timer)
    7. `Threat Detection Alert / Interstitial` (`ThreatDetectionModal.tsx` & Banner)
    8. `Threat Details & AI Briefing` (`ScanResultsScreen.tsx` + `AssistantScreen.tsx`)
    9. `Quarantine Vault` (`QuarantineScreen.tsx` with `Restore & Trust SHA-256`)
    10. `History — Forensic Audit Timeline` (`HistoryScreen.tsx` with filters, HMAC badge & JSON/CSV export)
    11. `Ransomware Shield` (`RansomwareShieldScreen.tsx` with Protected Folders & Canary status)
    12. `Web Protection` (`WebProtectionScreen.tsx` with URL scanner, Punycode diff, MOTW toggle & Extension status)
    13. `Notifications Center` (`NotificationsScreen.tsx` with storm rate-limit status)
    14. `Security Health & Watchdog` (`ProtectionStatusScreen.tsx` with 4-state health model, Process lineage & Persistence auditor)
    15. `Definitions & Updates` (`UpdateStatusScreen.tsx` with `.ppdb` bundle import & LKG rollback)
    16. `Settings` (`SettingsScreen.tsx`)
    17. `Exclusions Manager` (`ExclusionsScreen.tsx` with SHA-256/Path/Domain + TTL + Friction Gate)
    18. `Trusted Applications` (`TrustedAppsScreen.tsx` for Ransomware Shield app access)
    19. `Recovery — Shadow Vault Rollback` (`RecoveryScreen.tsx` + `PrivacyScreen.tsx` Crypto-Shredder)
    20. `About & Security Status` (`AboutSecurityScreen.tsx` showing architecture honesty, Network/Firewall posture & AI boundary verification)
- **4. Unit Tests:** Component rendering tests for all 20 screens across empty, loading, success, warning, critical, and error states (`ui-render.test.ts`).
- **5. Integration Tests:** Full IPC-to-React state transition tests (`phase11-remediation.test.tsx`, `desktop-flow.test.ts`).
- **6. Security Tests:** Verify every security-lowering toggle on every screen opens `FrictionGateModal` and requires user confirmation before invoking IPC; verify untrusted RTLO filenames and phishing URLs are rendered as non-clickable escaped text.
- **7. Performance Tests:** Verify virtualized lists render 1,000+ rows in $<16\text{ ms}$ and scan progress updates never block button interactions.
- **8. Acceptance Criteria:** All 20 screens implemented, accessible (WCAG AA), responsive, and wired end-to-end to real backend services (`AV-UX-001`, `SC-20`).
- **9. Exit Criteria:** 100% UI and E2E test pass rate.
- **10. Rollback Strategy:** Modular screen components under `src/renderer/screens/` allow isolated hotfixes without affecting core services.

---

### PHASE S: Full System Verification, Soak Testing & Release Gate
- **1. Objective:** Execute the complete **16-Category Test Matrix**, verify all **20 Master Prompt Success Criteria (`SC-01`–`SC-20`)**, verify 100% air-gapped offline parity, verify zero regressions across Web, Android, Browser Extension, Core, ML, and Desktop, and build the verified Windows Desktop release artifacts.
- **2. Dependencies:** `PHASE A` through `PHASE R`.
- **3. Implementation Tasks:**
  - Execute all 16 test categories:
    1. Unit Tests
    2. Integration Tests
    3. System / E2E Tests
    4. Security & Adversarial Tests (TOCTOU, symlinks/junctions, zip bombs, path traversal, IPC spoofing, update downgrade, prompt injection)
    5. Performance & Resource Budget Benchmarks
    6. Reliability & Accelerated Soak Tests (handle leak & heap slope check)
    7. Offline Air-Gapped Parity Tests (`offline-parity.test.ts`)
    8. Crash Recovery & Watchdog Tests (`watchdog-crash-recovery.test.ts`)
    9. Upgrade & Migration Tests (`storage-migration.test.ts`)
    10. Rollback Tests (Update LKG rollback & Ransomware Shadow Vault rollback)
    11. False Positive Corpus Tests (`false-positive-corpus.test.ts`)
    12. Notification Rate-Limiting & Storm Tests (`notification-rate-limiter.test.ts`)
    13. Real-Time Monitoring & Burst Backpressure Tests (`realtime-monitor-burst.test.ts`)
    14. Quarantine Streaming, DPAPI & Restore Safety Tests (`quarantine-streaming.test.ts`)
    15. Ransomware Simulation Harness Tests (`ransomware-shield.test.ts`)
    16. Web & Download MOTW Protection Tests (`motw-ads-analyzer.test.ts`)
  - Synchronize `PRD.md`, `Architecture.md`, `rules.md`, `phase.md`, `design.md`, and `memory.md` with final verification evidence.
- **4. Unit / 5. Integration / 6. Security / 7. Performance Tests:** Full monorepo test suite (`pnpm test`) + coverage report ($\ge 90\%$) + TypeScript build (`pnpm build`).
- **8. Acceptance Criteria:** All 20 Master Prompt Success Criteria (`SC-01`–`SC-20`) verified passing with concrete test metrics.
- **9. Exit Criteria:** Zero failing tests, zero stub/TODO violations, $\ge 90\%$ code coverage, and Independent Reviewer (`SUBAGENT 14`) sign-off.
- **10. Rollback Strategy:** Tag verified release commit and retain signed `LastKnownGood` installer and threat database artifacts.
