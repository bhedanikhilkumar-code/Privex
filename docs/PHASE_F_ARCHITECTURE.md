# PHASE F ARCHITECTURE — Process Lineage, LOLBin & Continuous Event Monitoring

> **PHASE:** F — PROCESS LINEAGE + LOLBIN MONITORING  
> **CANONICAL SPECIFICATION:** `phase.md` (Lines 150–166), `Architecture.md` (Component 03), `PRD.md` (AV-BEHAVIOR-001..003)  
> **STATUS:** REMEDIATED / BLOCKED (Awaiting Fresh Independent Phase F Audit)  
> **TARGETED REMEDIATION:** SEC-F-02 Continuous Windows Process Creation Monitoring  

---

## 1. Executive Summary & Architectural Topology

Phase F implements behavioral process monitoring, lineage reconstruction, and containment within Private Protection's Desktop Security Engine. It inspects runtime process creation events, reconstructs execution lineage trees (parent-child PID relationships), identifies Living-off-the-Land Binaries (LOLBins) and deceptive path masquerading, and enables safe containment of confirmed malicious user-mode processes without risking operating system stability.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             RUNTIME EXECUTION MODEL                             │
│                                                                                 │
│   Windows OS Process Creation Event                                             │
│   (WMI Win32_ProcessStartTrace - Microsoft Extrinsic Kernel Trace Event)        │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   WindowsProcessEventSource (Primary Event Source)     │                    │
│   │   • Extrinsic ETW-backed event subscription            │                    │
│   │   • Push-driven: zero polling interval dependence      │                    │
│   │   • Atomic start(callback) & startup buffering (1K)   │                    │
│   │   • Stdio JSON streaming via isolated helper process   │                    │
│   └───────────────────┬────────────────────────────────────┘                    │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   ProcessMonitorService (Continuous Shield)            │                    │
│   │   • Atomic registration: Consumer attached BEFORE OS   │                    │
│   │   • Startup race closed: Event buffered & reconciled   │                    │
│   │   • Snapshot SECOND: Reconciled with LRU seen cache    │                    │
│   │   • Dual Bounded Priority Queues (LOLBin high, normal) │                    │
│   │   • 4-Worker Concurrency Pool + Load Shedding          │                    │
│   │   • Truthful Health: RUNNING | DEGRADED | STOPPED      │                    │
│   └───────────────────┬────────────────────────────────────┘                    │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   BehaviorEngineService (Lineage & Rules)              │                    │
│   │   • ProcessLineageGraph (max 1,024 nodes, 5m TTL)      │                    │
│   │   • Pure Regex CLI Evaluator (transient stack frames)  │                    │
│   │   • SEC-F-04 Privacy: sanitizedCommandLine stored ONLY │                    │
│   │   • 25+ LOLBin Classifiers + Path Masquerading         │                    │
│   └───────────────────┬────────────────────────────────────┘                    │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   Canonical RiskScorer (Core Non-Linear Engine)        │                    │
│   └───────────────────┬────────────────────────────────────┘                    │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   EngineVerdict & Authorization Token (SEC-F-01)       │                    │
│   │   • Single-use ProcessContainmentAuthorization         │                    │
│   │   • 30-second TTL, strictly bound to PID/Name/Time     │                    │
│   └───────────────────┬────────────────────────────────────┘                    │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   ProcessAuditorService & Containment (SEC-F-05)       │                    │
│   │   • RULE-09 OS Immunity (PID 0, PID 4, System32 core)  │                    │
│   │   • TOCTOU Identity Revalidation before termination    │                    │
│   │   • Verified taskkill / process.kill enforcement       │                    │
│   └────────────────────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Windows Process Creation Event Mechanism (SEC-F-02 Remediation)

### A. Evaluated Mechanisms & Final Selection
Three candidate mechanisms were evaluated for real-time Windows process monitoring:

1. **Kernel ETW Session (`Microsoft-Windows-Kernel-Process`) Direct C++ Addon**:
   - *Analysis:* Provides native kernel callbacks, but requires custom C++ native binary compilation, strict administrative privilege (`SeSecurityPrivilege`), and poses significant cross-compilation/packaging friction.
2. **WMI `__InstanceCreationEvent OF Win32_Process WITHIN 0.25` (REJECTED AS PRIMARY)**:
   - *Analysis:* Evaluated in the previous audit (SEC-F-02-A). Because it uses the `WITHIN` intrinsic polling syntax, WMI periodically enumerates process tables. Any transient process that starts and exits entirely between polling passes (<250 ms) cannot be reliably guaranteed. It is strictly demoted to fallback status.
3. **WMI `Win32_ProcessStartTrace` (SELECTED PRIMARY)**:
   - *Selection Justification:*
     - **True Extrinsic Event Class:** Backed by the OS kernel ETW trace provider (`root\cimv2:Win32_ProcessStartTrace`). Unlike intrinsic WMI instance queries, this is push-driven and does NOT use a `WITHIN` polling clause.
     - **Short-Lived Process Capture:** The Windows kernel emits the event synchronously at process instantiation time. The event payload includes `ProcessID`, `ParentProcessID`, `ProcessName`, and `TIME_CREATED` (64-bit Windows FILETIME epoch).
     - **Transient Process Resiliency:** Even if the process terminates immediately after launch (<10 ms), the event record is dispatched by the OS trace provider and consumed by the listener.
     - **Isolated Worker Lifecycle:** Operates inside a background helper process streaming newline-delimited JSON over stdio, completely decoupling OS tracing from the Node.js event loop.
     - **Clean Shutdown & Resource Safety:** Cleanly disposes the WMI event watcher, stdout/stderr streams, and terminates child processes on shutdown.

### B. Privilege Boundary & Truthful Operational Matrix

| User Execution Context | Primary Mechanism Behavior | Service Health State | Continuous Guarantee |
|---|---|---|---|
| **Elevated / Administrator** | `Win32_ProcessStartTrace` succeeds | `RUNNING` (`WMI_TRACE`) | **Proven:** Continuous, event-driven, captures short-lived processes |
| **Performance Log Users** | `Win32_ProcessStartTrace` succeeds | `RUNNING` (`WMI_TRACE`) | **Proven:** Continuous, event-driven, captures short-lived processes |
| **Standard Unprivileged User** | `Win32_ProcessStartTrace` fails (`Access denied`) | `DEGRADED` (`POLLING_FALLBACK`) | **Best-effort:** Polling snapshot every 1,000 ms; truthfully warns that short-lived processes may be missed |

### C. Startup Ordering & Race Condition Elimination (SEC-F-02-B)
To guarantee that no process event is missed during service startup:
1. **Atomic Callback Registration & Startup Buffering:**
   - `IProcessEventSource` supports `start(callback?: (event) => void)`.
   - `ProcessMonitorService.start()` attaches its handler `eventSource.onProcessCreated(...)` **BEFORE** calling `eventSource.start(callback)`.
   - Both `WindowsProcessEventSource` and `MockProcessEventSource` maintain an internal FIFO `startupBuffer` (capacity 1,000). Any OS events arriving while the event source initializes are immediately buffered and flushed synchronously the moment the consumer callback attaches.
2. **Deterministic Sequence:**
   $$\text{Register Consumer Callback} \longrightarrow \text{Activate OS Subscription} \longrightarrow \text{Confirm READY} \longrightarrow \text{Initial Snapshot} \longrightarrow \text{Reconcile}$$
3. **Compound Identity Deduplication:**
   Every event and snapshot entry generates a compound instance key:
   $$\text{dedupeKey} = \text{evt}:\text{PID}:\text{CreationTimestamp}:\text{ProcessName}$$
   - Managed via a bounded LRU cache (`MAX_SEEN_CACHE = 2,000`).
   - If a process starts during startup initialization, it is buffered and received.
   - If it is also enumerated in the snapshot, the deterministic key deduplicates it without redundant behavioral evaluation.
   - Zero race window exists; zero process creation events are lost.

### D. Proven vs Best-Effort Guarantees

#### Proven Guarantee
- When running with appropriate Windows permissions (Elevated / Performance Log Users), `Win32_ProcessStartTrace` is proven by real OS integration testing (`windows-process-event-source.integration.test.ts`) to capture short-lived child processes (`cmd.exe /c exit 0`) that exit substantially faster than traditional polling intervals.

#### Best-Effort Fallback
- When running in an unprivileged standard user context or non-Windows platform, `ProcessMonitorService` automatically falls back to periodic snapshot polling.
- The service truthfully reports:
  - `status = 'DEGRADED'`
  - `isContinuous = false`
  - `eventSource = 'POLLING_FALLBACK'`
  - Diagnostic error: `"Win32_ProcessStartTrace access denied (requires Administrator or Performance Log Users); running in degraded polling fallback mode (short-lived processes may be missed)"`.
- The system **never** reports `RUNNING` or claims continuous real-time protection under unprivileged polling fallback.

---

## 3. Detection Capabilities Matrix

### A. Living-off-the-Land Binaries (LOLBins)
Covers 25+ Windows dual-use utilities frequently abused for living-off-the-land attacks:
- **Command Shells & Interpreters:** `powershell.exe`, `pwsh.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `bash.exe`, `wsl.exe`.
- **Execution & Proxy Binaries:** `rundll32.exe`, `regsvr32.exe`, `installutil.exe`, `cmstp.exe`, `msbuild.exe`, `pcalua.exe`, `forfiles.exe`, `scriptrunner.exe`.
- **Download & Ingress Tools:** `certutil.exe`, `bitsadmin.exe`.
- **System Administration & Registry:** `reg.exe`, `regasm.exe`, `regsvcs.exe`, `vssadmin.exe`, `wmic.exe`, `schtasks.exe`, `at.exe`, `sc.exe`, `net.exe`, `net1.exe`, `hh.exe`.

### B. Parent-Child Lineage Anomalies
- `behav-office-spawns-shell`: Microsoft Office / Document Reader (`winword.exe`, `excel.exe`, `powerpnt.exe`, `acrord32.exe`) spawning a shell or interpreter (`cmd.exe`, `powershell.exe`, `mshta.exe`).
- `behav-browser-spawns-lolbin`: Web browser (`chrome.exe`, `msedge.exe`, `firefox.exe`, `brave.exe`) spawning a shell or LOLBin utility.
- `behav-chained-interpreter`: Chained interpreters (e.g. `cmd.exe` $\rightarrow$ `powershell.exe` $\rightarrow$ `mshta.exe`).
- `behav-writable-spawns-lolbin`: Executable located in user-writable directory (`%TEMP%`, `Downloads`, `Public`, `ProgramData`) spawning a LOLBin.

### C. Suspicious Command-Line Heuristics
- `behav-ps1-encoded-command`: Base64 encoded PowerShell arguments (`-enc`, `-EncodedCommand`).
- `behav-ps1-hidden-bypass`: Hidden window and ExecutionPolicy bypass (`-w hidden`, `-ep bypass`).
- `behav-ps1-hidden-download-cradle`: .NET / WebClient download cradles (`DownloadString`, `Invoke-WebRequest`, `curl`).
- `behav-certutil-urlcache-download`: Certutil URL cache download (`-urlcache -split -f`).
- `behav-bitsadmin-transfer`: Bitsadmin job transfer (`/transfer`).
- `behav-mshta-remote-script`: Mshta executing inline script protocol (`javascript:`, `vbscript:`) or remote HTTP URLs.
- `behav-regsvr32-squiblydoo`: Regsvr32 remote COM scriptlet (`/i:http... scrobj.dll`).
- `behav-rundll32-inline-script`: Rundll32 executing DLL from `%TEMP%` or inline script.
- `behav-ransomware-shadow-delete`: Volume Shadow Copy deletion (`vssadmin delete shadows /all /quiet`).
- `behav-piped-interpreter-chain`: Piping output directly into a shell interpreter (`| powershell`).
- `behav-installutil-uninstall-bypass`: InstallUtil uninstall bypass (`/u`).
- `behav-cmstp-profile-install`: CMSTP silent INF installation (`/s /ni`).
- `behav-msbuild-inline-task`: MSBuild compiling inline project payload (`.csproj`, `.proj`).

### D. Path Masquerading Detection
Flags processes mimicking critical Windows system components when located outside legitimate system directories:
- Mimicked binaries: `svchost.exe`, `lsass.exe`, `csrss.exe`, `smss.exe`, `services.exe`, `explorer.exe`.
- Legitimate paths: `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Windows\WinSxS`, `C:\Windows\SystemApps`.
- Any system binary outside these paths triggers `behav-system-path-masquerade` (Score 85, Critical).

---

## 4. Process Containment Protocol & RULE-09 Hardening (SEC-F-01 & SEC-F-05)

Process containment is strictly gated by `containProcess(options)`:

```
                  ┌───────────────────────────────┐
                  │   containProcess(options)     │
                  └──────────────┬────────────────┘
                                 │
                 Is pid === 0 or pid === 4?
                 ├────────── YES ──────────► REJECTED_PROTECTED
                 │
                 ▼
         Is protected system process in lineage?
         (smss, csrss, wininit, services,
          lsass, lsm, winlogon, svchost)
                 ├────────── YES ──────────► Is Path Masquerading?
                 │                               ├──── NO  ──► REJECTED_PROTECTED
                 │                               └──── YES ──► Continue
                 ▼
         Is caller authorized? (SEC-F-01)
         (Requires valid authorizationId + token issued by BehaviorEngine)
                 ├────────── NO ───────────► REJECTED_UNAUTHORIZED
                 │
                 ▼
         TOCTOU Pre-Containment Identity Query (SEC-F-05)
         (Queries live OS for existence, creation timestamp, proc name)
                 │
                 ├───── PID recycled? (>1000ms drift) ──► REJECTED_PID_REUSE
                 ├───── Name mismatch? ──────────────────► REJECTED_IDENTITY_MISMATCH
                 ├───── Process exited? ─────────────────► NOT_FOUND
                 ▼
          Is dryRun enabled?
                 ├────────── YES ──────────► TERMINATED (Simulated)
                 ▼
       Execute Termination:
       • Windows: taskkill /PID <pid> /T /F
       • POSIX: process.kill(pid, 'SIGKILL')
                 │
                 ├────────── SUCCESS ──────► TERMINATED
                 ├────────── ESRCH / 128 ──► NOT_FOUND
                 └────────── EPERM ────────► FAILED (Access Denied)
```

### Authorization Token Invariant
1. Tokens are single-use, bounded (TTL 30s), issued exclusively when `EngineVerdict === 'CONTAIN_PROCESS'` on non-protected processes.
2. Tokens are bound to `(authorizationId, singleUseToken, pid, creationTime, processName)`.
3. Consumed tokens are evicted immediately; expired tokens are pruned periodically.

---

## 5. Privacy & Command-Line Sanitization (SEC-F-04)

Per Privacy Rules and SEC-F-04:
- `ProcessLineageNode` stores only `sanitizedCommandLine: string`.
- Raw `commandLine` is never retained in graph memory.
- Passwords, access tokens, API keys, and bearer tokens are redacted prior to storage:
  - `--password <secret>` $\rightarrow$ `--password [REDACTED]`
  - `token=<secret>` $\rightarrow$ `token=[REDACTED]`
  - `Bearer eyJ...` $\rightarrow$ `Bearer [REDACTED_JWT]`
- Scanned process telemetry is retained exclusively in volatile memory; zero raw telemetry or command arguments are persisted unencrypted or sent over network sockets.

---

## 6. Performance Benchmarks & Empirical Verification

Under Category 14 Burst Testing (`apps/desktop/src/__tests__/benchmarks/phase-f-process-burst.test.ts`):

| Burst Size | Processed | Dropped | Queue Peak | p50 Latency | p95 Latency | p99 Latency | Throughput | RSS Delta | Heap Delta |
|---|---|---|---|---|---|---|---|---|---|
| **100 Events** | 100 | 0 | 0 | **7.26 ms** | **7.55 ms** | **7.57 ms** | 13,136 events/s | +0.24 MB | +0.78 MB |
| **1,000 Events** | 1,000 | 0 | 0 | **12.12 ms** | **15.18 ms** | **15.40 ms** | 64,349 events/s | +4.80 MB | +4.88 MB |
| **10,000 Events** | 2,004 | 7,996 | 0 | **56.28 ms** | **103.21 ms** | **107.84 ms** | 18,045 events/s | +39.55 MB | +13.48 MB |

- **RSS Bound:** Total resident memory remains $< 150\text{ MB}$ even during 10,000-event storms (strictly below the 200 MB threshold).
- **Truthful Dropped Accounting:** Overflows are truthfully counted and reported via `getHealth().droppedEvents`.
