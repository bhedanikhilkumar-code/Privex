# PHASE N: SCHEDULED & ON-DEMAND SCANNING ARCHITECTURE
**PRIVATE PROTECTION WINDOWS DESKTOP ANTIVIRUS**

**Status:** IMPLEMENTATION ARCHITECTURE SPECIFICATION  
**Author:** Architecture & Core Security Engineering  
**Version:** 1.0.0  

---

## 1. Executive Summary & Goals

Phase N implements production-grade **Scheduled & On-Demand Scanning** for Private Protection Windows Desktop Antivirus. It unifies automated background maintenance with on-demand threat hunting, introducing battery-aware, CPU-aware, and restart-resilient execution that honors the system's core doctrine: **LOCAL-FIRST • PRIVACY-FIRST • LOW-LATENCY • FAIL-CLOSED • RESOURCE-SAFE**.

### Core Capabilities:
1. **Daily & Weekly Scan Schedules:** Configurable local 24-hour time (`HH:mm`), weekday selection for weekly recurrence, timezone and DST safety.
2. **Missed-Scan Startup Catch-Up:** Evaluates whether a scheduled run was missed during system power-off or application closure, executing catch-up once without repeated loops.
3. **Battery & Power Awareness:** Checks real system battery status; defers scheduled execution with `DEFERRED_BATTERY` when battery is $<20\%$ and discharging, while safely identifying AC-powered desktops as unconstrained.
4. **CPU Load Awareness:** Evaluates CPU utilization ($>80\%$ triggers `DEFERRED_CPU`), preventing background scans from starving user applications.
5. **Scan Concurrency & Priority Matrix:** Interactive scans and realtime shields take absolute priority over scheduled background scans; prevents duplicate or overlapping scans (`SKIPPED_ALREADY_RUNNING`).
6. **Quick Scan Expansion:** Extends Quick Scan to active user-mode process binaries (via `ProcessAuditorService`) and Startup/Persistence targets (via `PersistenceAuditorService`) without code execution.
7. **Canonical Engine & Auto-Quarantine Pipeline:** Routes all discovered targets through `FileAnalyzer` $\rightarrow$ `RiskScorer` $\rightarrow$ `EngineVerdict` $\rightarrow$ `ResponsePolicyEngine` $\rightarrow$ `QuarantineService` (when `autoQuarantine` is enabled).
8. **Scan History & Audit Trail:** Records complete execution telemetry (`scanId`, trigger, timing, files scanned, findings, quarantine count, deferred reasons, final status) encrypted at rest.
9. **Zero-Trust IPC & Friction Gate:** Validates schedule configuration strictly, protecting against prototype pollution, path injection, and unauthorized schedule alterations.

---

## 2. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SCHEDULE CONFIGURATION & STATE                        │
│                   (Stored in ~/.private-protection/schedule.enc)                │
└───────────────────────────────────────┬─────────────────────────────────────────┘
                                        │ (AES-256-GCM Encrypted)
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    ScanSchedulerService (Core Engine)                           │
│                                                                                 │
│   ┌────────────────────────┐  ┌────────────────────────┐  ┌─────────────────┐   │
│   │ Schedule Timer Engine  │  │ Missed-Run Evaluator   │  │ Resource Guards │   │
│   │ (Daily / Weekly Calc)  │  │ (Startup Catch-up)     │  │ (Battery / CPU) │   │
│   └───────────┬────────────┘  └───────────┬────────────┘  └────────┬────────┘   │
│               │                           │                        │            │
│               └───────────────────────────┼────────────────────────┘            │
│                                           ▼                                     │
│                     ┌─────────────────────────────────────────┐                 │
│                     │       Scan Dispatcher & Arbiter         │                 │
│                     │ (Concurrency Guard / Priority Arbiter)  │                 │
│                     └─────────────────────┬───────────────────┘                 │
└───────────────────────────────────────────┼─────────────────────────────────────┘
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               ▼                                                         ▼
┌───────────────────────────────┐                         ┌───────────────────────────────┐
│       QuickScanService        │                         │        ScannerService         │
│ • Downloads / Temp / Desktop  │                         │ • Full Filesystem Traversal   │
│ • Active Process Binaries     │                         │ • Custom Paths                │
│ • Persistence/Startup Targets │                         │ • Directory Filters           │
└──────────────┬────────────────┘                         └──────────────┬────────────────┘
               │                                                         │
               └────────────────────────────┬────────────────────────────┘
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     CANONICAL DETECTION & RESPONSE PIPELINE                     │
│                                                                                 │
│   FileAnalyzer ──► ThreatIntel ──► RiskScorer ──► EngineVerdict ──► Response    │
│                                                                         │       │
│   ┌─────────────────────────────────────────────────────────────────────┘       │
│   ▼                                                                             │
│   • Auto-Quarantine: Isolates confirmed threats into PPVAULT2 via QuarantineService│
│   • Notifications: Emits rate-limited toasts & updates Inbox via NotificationService│
│   • Scan History: Records outcome into encrypted audit log                      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Configuration & Domain Models

### 3.1 ScanScheduleConfig
```ts
export interface ScanScheduleConfig {
  readonly enabled: boolean;
  readonly frequency: 'daily' | 'weekly';
  readonly timeOfDay: string;                  // 'HH:mm' (24-hour format)
  readonly weekday?: number;                   // 0-6 (0=Sun, 1=Mon, ..., 6=Sat)
  readonly scanType: 'quick' | 'full';
  readonly pauseOnBattery: boolean;            // default: true
  readonly runMissedOnStartup: boolean;        // default: true
  readonly autoQuarantine: boolean;            // default: true
  readonly maxCpuThresholdPct?: number;        // default: 80
  readonly minBatteryThresholdPct?: number;    // default: 20
}
```

### 3.2 Schedule Execution Status
```ts
export type ScheduleExecutionStatus =
  | 'COMPLETED'
  | 'COMPLETED_WITH_FINDINGS'
  | 'CANCELLED'
  | 'FAILED'
  | 'DEFERRED_BATTERY'
  | 'DEFERRED_CPU'
  | 'SKIPPED_ALREADY_RUNNING';
```

---

## 4. Scheduling & Resource Guard Algorithms

### 4.1 Next Run Calculation (Local Timezone & DST Safe)
1. Parse `timeOfDay` into integer `[hours, minutes]`.
2. For `daily`:
   - Construct `next` date object from reference timestamp `T`.
   - Set hours, minutes, seconds=0, ms=0.
   - If `next.getTime() <= T`, advance date by $+1$ day.
3. For `weekly`:
   - Retrieve target `weekday` ($0..6$).
   - Determine current weekday $C$.
   - Calculate delta $D = (weekday - C + 7) \pmod 7$.
   - If $D = 0$ and target time on current day $\le T$, set $D = 7$.
   - Advance date by $+D$ days.

### 4.2 Missed-Scan Startup Catch-Up
1. Verify `config.enabled === true` and `config.runMissedOnStartup === true`.
2. If `lastScheduledRun === 0` (first boot), record baseline next run without catch-up.
3. Calculate the most recent scheduled execution slot $S_{last}$ prior to current timestamp $T_{now}$.
4. If $S_{last} > T_{lastRun}$ and $T_{now} - S_{last} < 7\text{ days}$, mark missed run and schedule catch-up execution with trigger `MISSED_CATCHUP`.

### 4.3 Battery & CPU Load Evaluation
- **Battery Guard:** Inspects system power state. If running on battery (`hasBattery === true && !isCharging`) and charge level $<20\%$, defers scan with `DEFERRED_BATTERY`. Desktop PCs with no battery report `hasBattery = false` and are never deferred.
- **CPU Guard:** Samples CPU active vs idle ticks over 100ms. If average load $>80\%$, defers scan with `DEFERRED_CPU`. If metrics are unavailable, fails open safely ($0\%$ load).

---

## 5. Security & Privacy Invariants

1. **Zero Raw Payload Leakage:** File contents, process command lines, and path strings are never sent over network telemetry.
2. **Zero Shell Execution:** Process binary resolution and persistence targets are resolved purely from disk metadata without executing untrusted binaries.
3. **RULE-09 OS Immunity:** Protected Windows system utilities (`System32`) are immune to auto-quarantine or deletion during scheduled scans.
4. **RULE-15 Notification Rate Limiting:** All scan completion and threat notifications pass through the token-bucket rate limiter.
5. **Fail-Closed Verification:** Quarantined items are verified with SHA-256 integrity checks before marking `quarantined: true`.
