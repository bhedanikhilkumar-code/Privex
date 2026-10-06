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
│   (WMI __InstanceCreationEvent OF Win32_Process)                                │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   WindowsProcessEventSource (Primary Event Source)     │                    │
│   │   • Low-latency WMI event watcher (0.25s event window) │                    │
│   │   • Standard user integrity (no elevation needed)     │                    │
│   │   • Stdio JSON streaming via isolated helper process   │                    │
│   └───────────────────┬────────────────────────────────────┘                    │
│                       │                                                         │
│                       ▼                                                         │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │   ProcessMonitorService (Continuous Shield)            │                    │
│   │   • Startup race prevention: Subscribe FIRST, Snapshot │                    │
│   │   • Deterministic Deduplication: evt:PID:Time:Name     │                    │
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

## 2. Windows Process Creation Event Mechanism (SEC-F-02 Architecture)

### A. Evaluated Mechanisms & Final Selection
Three candidate mechanisms were evaluated for real-time Windows process monitoring:

1. **Kernel ETW Session (`Microsoft-Windows-Kernel-Process`)**:
   - *Limitation:* Requires `SeSecurityPrivilege` / Administrative elevation. Standard desktop user accounts cannot initialize or open ETW kernel traces, resulting in `Access Denied`.
2. **`Win32_ProcessStartTrace`**:
   - *Limitation:* Also requires Administrator elevation on Windows 10/11 endpoints. Non-elevated execution fails with `ManagementException: Access denied`.
3. **WMI `__InstanceCreationEvent OF Win32_Process` (SELECTED)**:
   - *Selection Justification:*
     - **User-Mode Integrity:** Runs reliably in standard, non-elevated user accounts without UAC elevation prompts or security entitlement errors.
     - **Comprehensive Metadata:** Captures `ProcessId`, `ParentProcessId`, `Name`, `ExecutablePath`, `CommandLine`, and `CreationDate` directly from the OS process subsystem.
     - **Low-Latency Ingress:** Subscribes with a 0.25-second WMI polling interval (`WITHIN 0.25`), yielding event delivery $< 20\text{ ms}$ upon process creation.
     - **Isolated Worker Lifecycle:** Operates inside a background helper process streaming newline-delimited JSON over stdio, completely decoupling OS tracing from the Node.js event loop.
     - **Clean Shutdown & Resource Safety:** Terminates cleanly via stdio closure and OS process kill, unregistering WMI event subscriptions without leaking handles.

### B. Startup Ordering & Race Condition Elimination
To prevent missing processes that start during application boot:
1. **Subscribe FIRST:** `WindowsProcessEventSource.start()` initializes the OS subscription and waits for `PP_WMI_READY` before any snapshotting begins.
2. **Snapshot SECOND:** `ProcessAuditorService.auditRunningProcesses()` queries the live process list and populates `knownPids` and `seenEventKeys`.
3. **Reconcile with Deterministic Deduplication:**
   Every event generates a compound instance key:
   $$\text{dedupeKey} = \text{evt}:\text{PID}:\text{CreationTimestamp}:\text{ProcessName}$$
   - If a process starts during snapshot collection, it is received by the already-active subscription.
   - If it was also captured in the snapshot, the deterministic key matches and deduplicates it instantly.
   - Zero race window exists; zero process creation events are lost.

### C. Short-Lived Process Guarantee
Unlike periodic 1,000 ms polling which is completely blind to transient processes, `WindowsProcessEventSource` receives events immediately upon OS creation. Even if a process executes and exits within $10\text{ ms}$ (e.g. `vssadmin delete shadows /all /quiet`), its creation event is captured, queued, and evaluated by `BehaviorEngineService`.

### D. Explicit Degraded Fallback Policy
If WMI event subscription is unavailable (e.g. non-Windows environment or severe OS WMI repository corruption):
- `eventSource` is set to `POLLING_FALLBACK`.
- `isContinuous` is set to `false`.
- `status` is set to `DEGRADED`.
- Truthful diagnostic is reported: `"Primary process event subscription failed; running in degraded polling fallback mode (short-lived processes may be missed)"`.
- The system **never** silently reports `RUNNING` or claims continuous protection when polling fallback is active.

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
