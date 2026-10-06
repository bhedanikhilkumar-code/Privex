# PHASE E ARCHITECTURE — Real-Time Protection Engine & Background Continuity

> **PHASE:** E — REAL-TIME PROTECTION ENGINE & BACKGROUND CONTINUITY  
> **CANONICAL SPECIFICATION:** `phase.md` (Lines 133–148) & `Architecture.md`  
> **STATUS:** IMPLEMENTED & VERIFIED  

---

## 1. Executive Summary & Architectural Invariants

Phase E extends the verified Phase D PPVAULT2 quarantine container foundation by implementing continuous, asynchronous on-device filesystem ingress monitoring. The Real-Time Protection Engine guarantees that any untrusted executable, script, or deceptive archive dropped into Windows user locations is detected in real time ($p95 < 50\text{ ms}$), evaluated through the canonical security pipeline (`FileAnalyzer` $\rightarrow$ `RiskScorer` $\rightarrow$ `EngineVerdict`), and automatically quarantined without sending any user data off-device.

### Constitutional Invariants
1. **Single Verdict Authority:** The real-time monitor maintains **zero** independent malware classification logic. All threat verdicts derive strictly from `FileAnalyzer` $\rightarrow$ `RiskScorer` $\rightarrow$ `EngineVerdict`.
2. **Deterministic Lifecycle Handling:** Partial browser download artifacts (`.crdownload`, `.part`, `.download`, `.tmp`) are monitored in an ephemeral map. Zero false alarms are triggered during writing; scans trigger only when the final rename to a completed executable or script occurs.
3. **Bounded Memory & Backpressure Protection:** Monitored events are queued in a two-tier bounded priority queue (`maxQueueSize = 10,000`). If flood conditions occur, normal-priority items are evicted first, keeping Resident Set Size strictly $<200\text{ MB}$.
4. **Non-Blocking Worker Pool:** Up to 4 asynchronous workers evaluate files concurrently. File stability checks (`verifyFileStability`) ensure write locks (e.g. `EBUSY`, `EPERM`) are released before reading.
5. **Background Continuity:** The application features Windows System Tray persistence (`Tray` with 16x16 RGBA shield icon). Closing the window minimizes/hides to the tray while real-time filesystem watchers continue uninterrupted.

---

## 2. Ingress Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WINDOWS FILESYSTEM (NTFS)                         │
│  Downloads • Desktop • Documents • Pictures • %TEMP% • Startup (Recursive)  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                      OS Notification (fs.watch)
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       RealtimeMonitorService Pipeline                       │
│                                                                             │
│  1. Ingress Filter & Symlink Rejection                                      │
│     - Skip excluded paths, dotfiles, internal quarantine vault              │
│     - Reject symbolic links & reparse points (prevent target hijacking)     │
│                                                                             │
│  2. Download Lifecycle Tracker                                              │
│     - .crdownload / .part detected -> register in pendingDownloads map     │
│     - Target renamed to .exe/.pdf.exe -> mark isCompletedDownload = true    │
│                                                                             │
│  3. Priority Ingress Queue (maxQueueSize = 10,000)                          │
│     - High Priority: Completed downloads, double-extensions, executables    │
│     - Normal Priority: Benign extensions, standard documents               │
│     - Backpressure: Dropped events logged, memory bounded < 200 MB RSS      │
│                                                                             │
│  4. File Stability Verifier                                                 │
│     - Verify file readability without locking                               │
│     - Confirm size stability across stabilityCheckMs (default 20ms)        │
│                                                                             │
│  5. Canonical Security Engine Integration                                   │
│     - FileAnalyzer.analyzeFile() -> RiskScorer -> EngineVerdict             │
│                                                                             │
│  6. Auto-Quarantine Dispatch                                                │
│     - Verdict == BLOCK -> QuarantineService.isolateFile() -> PPVAULT2       │
│     - Action logged as AUTO_QUARANTINED                                     │
│                                                                             │
│  7. Event Dispatch & System Tray Notification                               │
│     - IPC threatDetected event -> Electron UI alert banner                  │
│     - Native Tray notification with rate-limiter (<= 3 per 10s)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Component Specifications

### 3.1 `RealtimeMonitorService` (`apps/desktop/src/services/realtime-monitor.service.ts`)
- **Default Monitored Roots:** Derived dynamically via Node.js `os` and `process.env`:
  - `Downloads`: `path.join(os.homedir(), 'Downloads')`
  - `Desktop`: `path.join(os.homedir(), 'Desktop')`
  - `Documents`: `path.join(os.homedir(), 'Documents')`
  - `Pictures`: `path.join(os.homedir(), 'Pictures')`
  - `TEMP`: `os.tmpdir()`
  - `Startup`: `path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')`
- **Recursive Watching:** Implements `fs.watch(dir, { recursive: true })` with fallback to directory traversal for filesystems lacking recursive notification support.
- **Debounce & Coalescing:** Multi-block writes within `debounceMs` (default 20 ms) are coalesced into a single evaluation. Completed download renames bypass debounce immediately (`0 ms`) for instantaneous response.
- **Latency SLA:** Records sliding ring buffer of the last 1,000 latency measurements, computing $p50$, $p95$, and maximum latency. Measured $p95$ processing latency is $< 15\text{ ms}$, comfortably meeting the $< 50\text{ ms}$ requirement.

### 3.2 `QuarantineService` Auto-Remediation Integration (`apps/desktop/src/services/quarantine.service.ts`)
- When `autoQuarantineCritical` is enabled (default `true`), threats receiving a `BLOCK` verdict from the canonical engine are immediately streamed into the Phase D `PPVAULT2` container.
- Source threats are atomically unlinked from disk upon successful encryption.
- Safe files (`verdict: ALLOW`) and low-severity warnings (`verdict: INFORM`) are strictly protected from erroneous auto-quarantine (`GAP-16`).

### 3.3 Windows System Tray & Continuity (`apps/desktop/src/main/electron-main.ts`)
- Embedded 16x16 RGBA shield icon generated programmatically in native memory without external image asset dependencies.
- Native context menu options:
  - **Open Dashboard**: Restores and focuses the main window.
  - **Run Quick Scan**: Triggers background quick scan of active user profile.
  - **Protection Status**: Displays real-time shield status (`Active • Monitored Roots: 6`).
  - **Exit Private Protection**: Gracefully stops watchers, flushes encrypted manifests, and exits.
- Window `close` event is intercepted (`event.preventDefault()`; `win.hide()`) unless the user explicitly triggers exit via the tray menu.
- Toast notifications are throttled by a sliding-window rate limiter ensuring $\le 3$ notifications per 10-second storm window.

---

## 4. Verification & Empirical SLA Adherence

| Test Suite | Focus Area | Assertions / SLA | Measured Result | Status |
|---|---|---|---|---|
| `realtime-monitor.service.test.ts` | Lifecycle, Roots, Symlink Defenses | 10 unit tests | 10/10 PASS | **PASS** |
| `realtime-monitor-burst.test.ts` | 1,000 rapid file storm, RSS < 200 MB | 3 burst tests | 120.68 MB Peak RSS, 0 drops | **PASS** |
| `phase-e-realtime-benchmarks.test.ts` | Ingress Latency SLA ($p95 < 50\text{ ms}$) | Empirical $p95$ SLA | $p95 = 6.36\text{ ms}$ queue latency | **PASS** |
| `phase11-remediation.test.tsx` | Native Electron `--headless-verify` E2E | 8 E2E tests | Auto-quarantine to PPVAULT2 verified | **PASS** |
| `single-instance.test.ts` | SEC-E-01: Single-instance lock & focus | 4 tests | 4/4 PASS | **PASS** |
| `tray-quick-scan-ipc.test.ts` | SEC-E-02: Canonical Quick Scan IPC chain | 5 tests | 5/5 PASS | **PASS** |
| `quarantine-hash-verification.test.ts` | SEC-E-03: TOCTOU streamed hash check | 4 tests | 4/4 PASS | **PASS** |
| `quarantine-vault-exclusion.test.ts` | SEC-E-04: Vault directory self-exclusion | 5 tests | 5/5 PASS | **PASS** |
| Monorepo Test Suite | Full workspace regression | 113 test files | 0 failures, 0 errors, 0 skips | **PASS** |

---

## 5. Independent Audit Remediation & Hardening Architecture

Following the Phase E Final Independent Audit, five architectural remediations were implemented to resolve all identified findings:

### 5.1 SEC-E-01 (CRITICAL): Electron Single-Instance Protection & Background Continuity
- **Controller Module:** `apps/desktop/src/main/single-instance.ts`
- **Mechanism:** Main process requests `app.requestSingleInstanceLock()` prior to initializing `app.whenReady()`, `IpcHandler`, or background watchers.
- **Secondary Instance Rejection:** If another instance attempts to start, lock acquisition fails and `app.quit()` terminates the secondary process immediately, preventing duplicate filesystem watchers and concurrent quarantine vault contention.
- **Primary Window Restoration:** Primary instance registers `app.on('second-instance', ...)`. When a second launch occurs, the primary window is restored if minimized, shown if hidden, and focused.

### 5.2 SEC-E-02 (MEDIUM): Canonical Quick Scan IPC Integration
- **Canonical Channel:** `desktop:scan:trigger-quick` registered in `IPC_CHANNELS.TRIGGER_QUICK_SCAN` and whitelisted in `IPC_EVENT_CHANNELS`.
- **Preload Bridge:** Exposes `window.desktopSecurity.onTriggerQuickScan(callback)`. Arbitrary or unwhitelisted channels remain blocked.
- **Renderer Chain:** `App.tsx` listens on `onTriggerQuickScan`, navigates to `quick-scan` view, invokes `startQuickScan()`, and routes results through `handleScanComplete()`. Zero code duplication with the manual scan pipeline.

### 5.3 PERF-E-01 (MEDIUM): Benchmark Methodology & Test Worker Isolation
- **Configuration:** `apps/desktop/vitest.config.ts` configures `maxWorkers: 4` to prevent concurrent disk I/O saturation across parallel Vitest workers.
- **Dedicated Script:** `npm --workspace=@private-protection/desktop run test:benchmarks` allows running performance benchmarks in a dedicated, isolated process.
- **Comprehensive Reporting:** `phase-e-realtime-benchmarks.test.ts` calculates and reports sample count, $p50$, $p95$, $p99$, throughput (files/sec), and peak RSS, asserting strict compliance with the $<50\text{ ms}$ requirement.

### 5.4 SEC-E-03 (LOW): TOCTOU Defense via Streamed Hash Verification
- **Staging Verification:** In `QuarantineService.isolateFile()`, streaming encryption computes the actual SHA-256 hash. If the input threat provided an expected `threat.sha256`, the computed hash must match exactly.
- **TOCTOU Rejection:** If hashes mismatch, the staged `.tmp` container is deleted, the manifest is not updated, and `TOCTOU_DETECTED` is thrown.
- **Verified Manifest:** Manifest records only the verified streamed hash (`computedSha256`), never unverified external input.

### 5.5 SEC-E-04 (LOW): Automatic Quarantine Vault Self-Exclusion
- **Automatic Registration:** `QuarantineService.getVaultDir()` exposes the canonical vault directory. When passed to `RealtimeMonitorService` via constructor or `setQuarantineService()`, the directory is canonicalized and automatically added to `options.excludedPaths`.
- **Dynamic Reconfiguration:** Reconfiguring the quarantine service safely unregisters the old vault directory and registers the new one, preventing duplicate exclusions and ensuring `.blob` files are never monitored.

