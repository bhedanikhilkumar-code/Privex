# PHASE T12 — BATTERY, THERMAL & LOW-RAM ADAPTIVE PROTECTION ARCHITECTURE

## 1. System Overview

Phase T12 introduces **Adaptive Resource Management** to the Private Protection Android mobile endpoint. On resource-constrained mobile hardware, aggressive background virus scanning, file hashing, and real-time inspections can degrade battery life, trigger thermal throttling, or lead to Out-Of-Memory (OOM) / Application Not Responding (ANR) terminations.

The core doctrine of Phase T12 is:
1. **Dynamic Resource Adaptation:** Scale worker concurrency, streaming buffer sizes, and background job pacing according to battery level, charging status, thermal severity, system RAM pressure, and user foreground activity.
2. **Critical Threat Invariant:** Resource constraints throttle or defer **scheduled, non-urgent background batch work** (e.g. daily scheduled deep device scans), but **NEVER drop, defer, or convert active real-time threat evaluations** (e.g., active file downloads, manual user scans, APK installations, live URL filtering) into silent `ALLOW` verdicts.
3. **Truth-Grounded Observability:** Never simulate battery levels, invent thermal temperatures, or fabricate system load. Provide exact, truthful hardware telemetry via standard Android OS APIs, with graceful fallbacks and explicit disclosure when hardware sensors are unavailable.

---

## 2. Architecture & State Machines

```
┌──────────────────────────────────────────────────────────────────────────┐
│                             Android OS Signals                           │
│   • BatteryManager (LEVEL, STATUS_CHARGING, PLUGGED)                     │
│   • PowerManager.OnThermalStatusChangedListener (API 29+)                │
│   • ActivityManager.MemoryInfo / ComponentCallbacks2 (TRIM_MEMORY)       │
│   • Window / Interaction state (Foreground Heavy Workload)              │
└─────────────────────────────────────┬────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                   AdaptiveResourceManager (Singleton)                    │
│                                                                          │
│   • Computes ResourceMode: NORMAL | BATTERY_SAVER | THERMAL_THROTTLED |  │
│                            LOW_RAM | CRITICAL_RESOURCE_PRESSURE          │
│   • Computes ThermalStatus: UNAVAILABLE | NONE | LIGHT | MODERATE |      │
│                             SEVERE | CRITICAL | EMERGENCY | SHUTDOWN     │
│   • Manages Streaming Buffer: 64 KB (Normal) -> 16 KB (Low RAM)          │
│   • Manages Worker Concurrency: Dynamic Pool Resizing                    │
│   • Emits Notifications: OnResourceStateChangeListener                  │
└───────────────────┬──────────────────────────────────┬───────────────────┘
                    │                                  │
                    ▼                                  ▼
┌──────────────────────────────────────┐   ┌───────────────────────────────┐
│       MobileSecurityCoordinator      │   │   UniversalFileShieldService  │
│                                      │   │                               │
│ • Resizes BoundedWorkerExecutor      │   │ • Dynamic chunk sizing:       │
│   concurrency on thermal/RAM alerts  │   │   64 KB -> 16 KB              │
│ • Inspects Battery before deep scans:│   │ • Bounded memory usage during │
│   <20% + discharging -> DEFERRED     │   │   streaming SHA-256 / AES-GCM │
│ • Preserves real-time priority queue │   └───────────────────────────────┘
└───────────────────┬──────────────────┘
                    │
                    ▼
┌──────────────────────────────────────┐
│        MainActivity Native Bridge    │
│  • getAdaptiveResourceStatus()       │
│  • setForegroundHeavyWorkload()      │
│  • triggerScheduledDeepScan()        │
└───────────────────┬──────────────────┘
                    │
                    ▼
┌──────────────────────────────────────┐
│  Mobile TypeScript / UI (React)      │
│  • adaptive-protection.service.ts    │
│  • ProtectionStatusScreen.tsx        │
│    (Adaptive Power & Thermal Shield) │
└──────────────────────────────────────┘
```

---

## 3. Operational Rules & Policies

### 3.1 Battery-Aware Scanning Policy
- **Threshold:** Battery level $< 20\%$ while in discharging state (`isDischarging = true`).
- **Deferred Workload:** Scheduled, non-urgent background batch scans (e.g. `JobType.STORAGE_SCAN` with `isScheduled = true`).
- **State Transition:** Transitioned to `JobState.DEFERRED` with reason `BATTERY_LOW_DEFERRED`.
- **Manual Scan Bypass:** If a user explicitly clicks "Scan Now", `isScheduled = false`, and the scan proceeds immediately regardless of battery level, honoring user explicit intent.
- **Charging Exemption:** When the device is connected to AC, USB, or Wireless charging, the battery level restriction is completely bypassed.

### 3.2 Thermal-Aware Concurrency Policy
- **Listener:** `PowerManager.OnThermalStatusChangedListener` (Android 10 / API 29+). On API $< 29$, reports `ThermalStatus.UNAVAILABLE` without fabricated metrics.
- **Throttle Tiers:**
  - `NONE` or `LIGHT`: Default worker pool concurrency ($N = \text{defaultMaxThreads}$, typically 4).
  - `MODERATE`: Concurrency clamped to $\max(1, N - 1)$.
  - `SEVERE`, `CRITICAL`, `EMERGENCY`: Concurrency clamped to $1$ thread. Inter-file inspection sleep pauses ($100\text{ ms}$) introduced between batch items to allow the heatsink to cool down.
  - Active real-time single-item scans are prioritized over background queue execution.

### 3.3 Low-RAM & Bounded Buffer Policy
- **Signals:** System broadcast `ComponentCallbacks2.onTrimMemory(level)` and `onLowMemory()`.
  - `TRIM_MEMORY_RUNNING_CRITICAL`, `TRIM_MEMORY_COMPLETE`, `TRIM_MEMORY_RUNNING_LOW`.
- **Adaptive Buffer Scaling:**
  - Normal RAM mode: `64 KB` ($65,536$ bytes) chunked streaming buffer for file inspection and vault crypto.
  - Low RAM mode: Dynamically compressed to `16 KB` ($16,384$ bytes) buffer.
  - Ensures garbage collection (GC) pressure drops by $75\%$ during active file inspection.
- **Worker Concurrency Reduction:** Bounded pool core/max threads reduced to $1$ thread during active RAM trimming.

### 3.4 Foreground Heavy Workload Throttling
- When the user is actively interacting with the UI or launching resource-intensive operations, `setForegroundHeavyWorkload(true)` is asserted.
- Non-critical background maintenance tasks yield CPU time slices to prevent UI stutter (jank) and ensure a consistent 60+ FPS user experience.

---

## 4. Security Job State Machine Updates

The `JobState` enum and state transitions were extended in Phase T12:
- **`THROTTLED`:** Job is currently executing with reduced thread priority or throttled worker concurrency due to thermal or memory pressure.
- **`DEFERRED`:** Job has been postponed because device conditions (battery $< 20\%$ while discharging) do not allow high-energy batch operations. Can be resumed when conditions improve.
- **`PARTIAL`:** Job completed a subset of tasks but was halted prematurely to protect the device (e.g., severe thermal emergency reached during a batch run).

---

## 5. Security Invariant Sign-Off

1. **Zero Silent Cloud Telemetry:** Telemetry remains 100% on-device. Resource state is read strictly via local Android OS system services.
2. **Zero Weakened Detection:** Threat detection algorithms (YARA rules, APK hash lookups, Bloom filters, regexes) execute identically regardless of resource mode. No heuristic or signature check is skipped.
3. **No Fake Hardware Claims:** Ambient temperatures and CPU frequencies are not guessed or hardcoded; only standard OS thermal statuses (`THERMAL_STATUS_*`) are exposed.
