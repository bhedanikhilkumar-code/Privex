# Phase R Specialist Analysis & Aggregated Findings Report
# Desktop UX & 20-Screen Antivirus Command Center

> **Date:** October 7, 2026  
> **Status:** APPROVED & RATIFIED  
> **Authority:** `phase.md` (Phase R), `design.md`, `PRD.md`, `Architecture.md`, `rules.md`

---

## 1. Specialist Reports

### 1.1 Specialist 1: UX / Information Architecture
- **Audit Findings:**
  - Current `Sidebar.tsx` has only 11 flat navigation items (`home`, `quick-scan`, `full-scan`, `custom-scan`, `results`, `quarantine`, `status`, `assistant`, `privacy`, `settings`, `updates`).
  - `design.md` and `phase.md` mandate **20 distinct antivirus screens/components**, structured into 5 logical categories:
    1. *Overview & Security Posture*: Protection Dashboard (Screen 01), About & Security Status (Screen 20).
    2. *Scanning Engine*: Quick Scan (Screen 02), Full Scan (Screen 03), Custom Scan (Screen 04), Scheduled Scan (Screen 05).
    3. *Active Shields*: Real-Time Protection (Screen 06), Ransomware Shield (Screen 11), Web Protection (Screen 12).
    4. *Forensics & Incident Response*: Threat Alert Interstitial (Screen 07), Threat Details & AI Briefing (Screen 08), Quarantine Vault (Screen 09), Forensic Audit Timeline (Screen 10), Recovery & Shadow Vault (Screen 19).
    5. *System Health & Configuration*: Notifications Center (Screen 13), Security Health & Watchdog (Screen 14), Definitions & Updates (Screen 15), Settings (Screen 16), Exclusions Manager (Screen 17), Trusted Applications (Screen 18).
- **Design Tokens:**
  - Shell geometry: 240px sidebar, 60px header, `#0f172a` slate sidebar, `#f8fafc` canvas, `#ffffff` cards with `#e2e8f0` border.
  - 3-Tier Posture Hero Banner: `🟢 PROTECTED` (`#dcfce7`), `🟡 ATTENTION REQUIRED` (`#fef3c7`), `🔴 ACTION REQUIRED` (`#fee2e2`).
  - 4-Pillar Plain Language Contract: WHAT happened, WHY it matters, WHAT Private Protection did, WHAT user should do.

---

### 1.2 Specialist 2: Security & IPC Architecture
- **Audit Findings:**
  - UI is strictly **NOT** a security authority. All verdicts, posture states, quarantine operations, process terminations, and updates are determined by backend services.
  - IPC handler inspection: `ipc-handler.ts` already implements and validates handlers for almost all phases. However, in `preload.ts`, Ransomware Shield channels (`RANSOMWARE_STATUS_GET`, `RANSOMWARE_PROTECTED_FOLDERS_GET/ADD/REMOVE`, `RANSOMWARE_TRUSTED_APPS_GET/ADD/REMOVE`, `RANSOMWARE_INCIDENTS_GET`, `RANSOMWARE_INCIDENT_ROLLBACK`, `RANSOMWARE_CANARY_RESET`, `RANSOMWARE_EVENT`) are registered on `ipcMain` but not yet exposed in the `DesktopSecurityApi` interface and bridge.
  - Security-lowering operations require `FrictionGateModal`: turning off Real-Time Shield, adding exclusions, disabling auto-quarantine, purging quarantine, restoring files to custom paths, rolling back threat DB, crypto-shredding, and resetting canaries.
  - RTLO & Unicode Spoofing: file names, processes, and paths displayed in modals or lists must strip or neutralize bidirectional override characters (`\u202A`–`\u202E`, `\u2066`–`\u2069`) to prevent spoofed file extensions (e.g. `file\u202Egpj.exe` appearing as `fileexe.jpg`).
  - Dangerous URLs and paths must render as non-clickable `<code>` blocks without triggering OS execution or web navigation (`RULE-25`).

---

### 1.3 Specialist 3: Backend Integration
- **Audit Findings:**
  - Full trace of existing backend services in `apps/desktop/src/services/` and `core/`:
    - `ScannerService` / `QuickScanService`: real scanning, Phase P `CleanFileCache` integration, 20 Hz throttled progress.
    - `QuarantineService`: AES-256-GCM encrypted vault (`PPVAULT2`), SHA-256 verification, restore, shred.
    - `AuditLoggerService`: HMAC-SHA256 hash chaining, crash-safe tail recovery, PII scrubbing (`RULE-18`), sanitized export.
    - `WatchdogService`: 2,000 ms heartbeat loop, auto-recovery, crash-loop circuit breaker, shield snooze countdown (`RULE-19`).
    - `HealthMonitorService`: 4-State Health Model (`HEALTHY`, `WARNING`, `DEGRADED`, `CRITICAL`), 1-click remediation.
    - `TamperDetectorService`: settings encryption auth tag check, quarantine manifest check, audit log chain verify.
    - `ThreatIntelManagerService`: Ed25519 update verification, monotonic sequence counter, LKG rollback, offline `.ppdb` import.
    - `RansomwareShieldService`: Canary traps, protected folders, trusted applications, ShadowVault rollback.
    - `ScanSchedulerService`: daily/weekly schedule, battery guard, CPU load guard, missed scan catch-up.
    - `NotificationService`: in-app inbox, storm rate limiter (`RULE-15`, max 3 toasts/10s).
    - `ExclusionsManager`: SHA-256 hash, path, domain exclusions with TTL and protected folder defense.
    - `ProcessAuditorService` & `PersistenceService`: process enumeration, containment, startup persistence inspection.
    - `RemovableMediaService`: Windows USB drive detection, autorun/LNK worm scanning.
    - `NetworkMonitorService`: Windows Defender Firewall profile check, TCP socket C2 IP audit.
  - Zero duplicate backend services needed. The renderer only needs to bind to these existing services.

---

### 1.4 Specialist 4: Accessibility (a11y)
- **Audit Findings:**
  - WCAG AA compliance requires:
    - Text contrast ratio $\ge 4.5:1$ across all states.
    - Semantic elements: `<button>`, `<nav>`, `<main>`, `<dialog>`, `<input>`, `<label>`, `<fieldset>`, `<legend>`.
    - Modal dialogs: `role="dialog"` or `role="alertdialog"`, `aria-modal="true"`, focus trapped within modal, `Escape` key closes modal, initial focus on safe CTA (`Keep in Quarantine`).
    - Screen reader announcements: `aria-live="polite"` on status changes and progress bars, `aria-live="assertive"` on critical threat interstitial modals.
    - Visible `:focus-visible` styling (`2px solid #2563eb` outline with `2px` offset) on all interactive controls.
    - Visual status badges must pair color with shape/text labels (never color alone).

---

### 1.5 Specialist 5: Large Data Performance
- **Audit Findings:**
  - Data sources with high potential volume:
    - Audit history logs ($1,000+$ entries)
    - Quarantine vault ($1,000+$ items)
    - Notifications inbox ($500+$ items)
    - Scan progress event stream (rapid file traversal)
  - Architectural requirements:
    - Use bounded query limits (Phase Q `AuditQueryFilter` limits to $\le 1,000$).
    - Implement virtualization or windowed pagination for large tables to prevent DOM bloat and ensure $<16\text{ ms}$ render frames.
    - Scan progress events must respect Phase P throttling ($20\text{ Hz}$ cap) to avoid locking up React state transitions or freezing Pause/Cancel buttons.

---

### 1.6 Specialist 6: State Management & Data Flow
- **Audit Findings:**
  - State boundaries:
    - **Global Application State** (`App.tsx`): Active navigation tab, authoritative security posture, unacknowledged threat interstitial modal (`realtimeAlert`), quarantine badge count, unread notifications badge count, active scan state.
    - **Screen-Level State**: Internal tab selection, table search filters, form draft values, pagination offset.
  - Fail-Closed Posture Derivation:
    - If `HealthMonitor` reports `CRITICAL` or `DEGRADED`, posture is `🔴 ACTION REQUIRED`.
    - If `HealthMonitor` reports `WARNING` or unread threats exist, posture is `🟡 ATTENTION REQUIRED`.
    - Only if all subsystems report `HEALTHY` and 0 unquarantined threats exist, posture is `🟢 PROTECTED`.
    - If backend is offline or disconnected, posture fails closed to `🟡 ATTENTION REQUIRED`.

---

### 1.7 Specialist 7: Testing & Verification Matrix
- **Audit Findings:**
  - Testing suite requirements:
    - Component unit tests for all 20 screens across empty, loading, success, warning, critical, and error states.
    - Navigation and tab switching tests across all 20 screens.
    - Security and adversarial UI tests:
      1. RTLO filename injection neutralization.
      2. Dangerous URL script injection neutralization.
      3. Arbitrary path traversal in file inputs.
      4. Friction gate bypass resistance.
      5. Malformed/tampered backend health response handling.
      6. Offline air-gapped UI operation (zero network requests).
    - Performance benchmarks:
      1. 1,000-row history table rendering latency.
      2. High-frequency scan progress UI responsiveness.
    - Monorepo full regression: 100% pass across core, ml, desktop, extension, mobile, web.

---

## 2. Aggregated Architectural Decisions & Execution Plan

1. **Expose Missing Ransomware APIs in Preload:**
   - Update `apps/desktop/src/preload/preload.ts` to expose `getRansomwareStatus`, `getProtectedFolders`, `addProtectedFolder`, `removeProtectedFolder`, `getTrustedApps`, `addTrustedApp`, `removeTrustedApp`, `getRansomwareIncidents`, `rollbackRansomwareIncident`, `resetCanary`, `onRansomwareEvent`.
2. **Upgrade Sidebar Navigation:**
   - Update `Sidebar.tsx` to support grouped 5-category navigation covering all 20 screens/views with badges.
3. **Implement and Upgrade All 20 Screens:**
   - Screen 01: `HomeScreen.tsx` (Protection Dashboard with 3-tier posture, 4-pillar alert, live summary metrics)
   - Screen 02: `QuickScanScreen.tsx` (High-risk sweep with live throttled progress, target pills, pause/cancel)
   - Screen 03: `FullScanScreen.tsx` (Recursive fixed drive scan, CleanFileCache acceleration, batch quarantine)
   - Screen 04: `CustomScanScreen.tsx` (Targeted path, file/folder picker, dropzone, USB presets)
   - Screen 05: `ScheduledScanScreen.tsx` (Daily/weekly scheduling, battery guard, CPU guard, missed run catch-up)
   - Screen 06: `RealtimeProtectionScreen.tsx` (Filesystem shield, sub-shields, custom watch dirs, snooze countdown)
   - Screen 07: `ThreatDetectionModal.tsx` & Alert Banner (Instant $<50\text{ ms}$ alert dialog, RTLO sanitized, safe default CTA)
   - Screen 08: `ScanResultsScreen.tsx` + `AssistantScreen.tsx` (10-layer evidence table + Grade 6/8 AI explanation)
   - Screen 09: `QuarantineScreen.tsx` (PPVAULT2 list, restore to disk, restore & trust SHA-256, 3-pass shred)
   - Screen 10: `HistoryScreen.tsx` (HMAC-SHA256 verified timeline, filters, search, sanitized JSON/CSV export)
   - Screen 11: `RansomwareShieldScreen.tsx` (Protected folders, canary status, Smart/Strict mode, rollback CTA)
   - Screen 12: `WebProtectionScreen.tsx` (On-device URL/message scanner, Punycode diff, MOTW toggle, extension sync)
   - Screen 13: `NotificationsScreen.tsx` (In-app inbox, storm rate limiter status, toast toggles)
   - Screen 14: `ProtectionStatusScreen.tsx` (4-state health monitor, watchdog heartbeat, process & persistence auditor)
   - Screen 15: `UpdateStatusScreen.tsx` (ThreatIntel version, sequence counter, Ed25519 verification, .ppdb import, LKG rollback)
   - Screen 16: `SettingsScreen.tsx` (Protection policies, file size limits, cognitive reading level, friction gated)
   - Screen 17: `ExclusionsScreen.tsx` (SHA-256 hash, path, domain exclusions with TTL and system path protection)
   - Screen 18: `TrustedAppsScreen.tsx` (Ransomware trusted apps with SHA-256 binding, binary change verification)
   - Screen 19: `RecoveryScreen.tsx` (ShadowVault emergency rollback, USB rescue scanner, 3-pass Crypto-Shredder)
   - Screen 20: `AboutSecurityScreen.tsx` (Architectural honesty, 100% offline status, AI boundary check, Windows Firewall & socket audit)
4. **Wire Everything in `App.tsx`:**
   - Integrate all 20 screens and modals into unified state and event handling.
5. **Add Comprehensive Test Suites:**
   - Unit tests for all screens across all states.
   - Integration & navigation tests.
   - Security & adversarial tests (RTLO, XSS, Friction Gate, tampered health).
   - Performance benchmark tests.
