# PHASE F ARCHITECTURE — Process Lineage & LOLBin Monitoring

> **PHASE:** F — PROCESS LINEAGE + LOLBIN MONITORING  
> **CANONICAL SPECIFICATION:** `phase.md` (Lines 150–166), `Architecture.md` (Component 03), `PRD.md` (AV-BEHAVIOR-001..003)  
> **STATUS:** IMPLEMENTED & VERIFIED  

---

## 1. Executive Summary & Architectural Invariants

Phase F implements behavioral process monitoring and containment within Private Protection's Desktop Security Engine. It inspects active runtime processes, reconstructs execution lineage trees (parent-child PID relationships), identifies Living-off-the-Land Binaries (LOLBins) and deceptive path masquerading, and enables safe containment of confirmed malicious user-mode processes without risking operating system stability.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             RUNTIME EXECUTION MODEL                             │
│                                                                                 │
│   Windows Tasklist / CIM Query ────────┐                                        │
│                                        ▼                                        │
│                       ┌─────────────────────────────────┐                       │
│                       │    ProcessAuditorService        │                       │
│                       └────────────────┬────────────────┘                       │
│                                        │                                        │
│                                        ▼                                        │
│                       ┌─────────────────────────────────┐                       │
│                       │     BehaviorEngineService       │                       │
│                       │  • ProcessLineageGraph          │                       │
│                       │  • LOLBin Catalog (25+ Tools)   │                       │
│                       │  • Pure CLI Regex Evaluator     │                       │
│                       │  • Path Masquerading Detector   │                       │
│                       │  • PID Reuse Compound Keys      │                       │
│                       └────────────────┬────────────────┘                       │
│                                        │                                        │
│                                        ▼                                        │
│                       ┌─────────────────────────────────┐                       │
│                       │   Canonical RiskScorer (Core)   │                       │
│                       │      Non-Linear Math & Weights  │                       │
│                       └────────────────┬────────────────┘                       │
│                                        │                                        │
│                                        ▼                                        │
│                       ┌─────────────────────────────────┐                       │
│                       │   EngineVerdict (CONTAIN_PROCESS)│                      │
│                       └────────────────┬────────────────┘                       │
│                                        │                                        │
│                                        ▼                                        │
│                       ┌─────────────────────────────────┐                       │
│                       │ Process Containment & RULE-09   │                       │
│                       │ • Hard-reject PID 0 / PID 4     │                       │
│                       │ • Hard-reject System32 Core     │                       │
│                       │ • Safe taskkill / process.kill  │                       │
│                       └─────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Constitutional Invariants
1. **Single Verdict Authority:** The behavior engine is strictly an **evidence producer**. It outputs structured `Evidence` tokens scored exclusively by the canonical `RiskScorer`. Zero duplicate verdict engines exist.
2. **Zero Execution / Pure Regex Inspection:** Process command lines are inspected using strict regex pattern matching. Under no circumstance does the engine execute, evaluate, or invoke untrusted command lines.
3. **PID Reuse Resilience:** Operating systems reuse PIDs aggressively. The `ProcessLineageGraph` tracks processes using compound keys (`${pid}:${creationTime}:${instanceCounter}`) to prevent historical process contamination.
4. **RULE-09 Operating System Immunity:** Hard-coded guards prevent containment of critical Windows kernel and operating system processes:
   - PID 0 (`System Idle Process`)
   - PID 4 (`System`)
   - Critical system binaries in System32: `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `lsm.exe`, `winlogon.exe`, and legitimate `svchost.exe`.
5. **Bounded Memory & Latency SLA:**
   - Graph capacity strictly bounded (`maxTrackedProcesses = 1024`, `maxLineageDepth = 10`).
   - Eviction via TTL (5 minutes) and FIFO pruning.
   - Resident memory footprint $< 4.0\text{ MB}$.
   - Process audit execution latency $< 500\text{ ms}$.
6. **Zero Telemetry / 100% Offline Parity:** Operates completely air-gapped in volatile RAM. Command lines are sanitized to redact credentials and tokens prior to logging.

---

## 2. Detection Capabilities Matrix

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

## 3. Process Containment Protocol & RULE-09 Hardening (SEC-F-01 & SEC-F-05)

Process containment is strictly gated by `containProcess(pid, options)`:

```
                  ┌───────────────────────────────┐
                  │ containProcess(pid, options)  │
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

## 4. Privacy & Command-Line Sanitization (SEC-F-04)

Per Privacy Rules and SEC-F-04:
- `ProcessLineageNode` stores only `sanitizedCommandLine: string`.
- Raw `commandLine` is never retained in graph memory.
- Passwords, access tokens, API keys, and bearer tokens are redacted prior to storage:
  - `--password <secret>` $\rightarrow$ `--password [REDACTED]`
  - `token=<secret>` $\rightarrow$ `token=[REDACTED]`
  - `Bearer eyJ...` $\rightarrow$ `Bearer [REDACTED_JWT]`
- Scanned process telemetry is retained exclusively in volatile memory; zero raw telemetry or command arguments are persisted unencrypted or sent over network sockets.

---

## 5. Continuous Process Creation Monitoring (SEC-F-02)

Implemented in `ProcessMonitorService`:
1. **Bounded Priority Queues**: Max 1,000 events (`highPriorityQueue` for LOLBins / shell scripts, `normalPriorityQueue` for benign apps).
2. **Backpressure Shedding**: When queue capacity is reached, normal priority events are dropped first, and status transitions truthfully to `DEGRADED`.
3. **Bounded Worker Pool**: Concurrency limited to 4 workers.
4. **Deduplication LRU**: Bounded ring cache of 2,000 recent `eventId` hashes preventing redundant evaluations and memory leaks (<200 MB RSS).
5. **Truthful Health Reporting**: Emits `ProcessMonitorHealth` reporting exact operational state (`RUNNING`, `DEGRADED`, `STOPPED`, `FAILED`), queue depth, active workers, dropped events, and event source (`WMI_TRACE`, `CIM_EVENT`, `POLLING_FALLBACK`, `MOCK`).

---

## 6. Process Binary Inspection Defaults (SEC-F-03)

In `ProcessAuditorService`:
- `scanBinaryOnDisk` defaults to `true`.
- On-disk executables are passed through `FileAnalyzer.analyzeFile()`.
- Reuses `CleanFileCache` ($O(1)$ fast path) to prevent redundant disk I/O and maintain latency SLAs (<500 ms).

