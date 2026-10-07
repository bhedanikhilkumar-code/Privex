# PHASE R ARCHITECTURE SPECIFICATION
## Desktop UX & 20-Screen Antivirus Command Center

**Repository:** `bhedanikhilkumar-code/Private-Protection`  
**Package:** `apps/desktop`  
**Status:** COMPLETED & VERIFIED  
**Canonical Reference:** `design.md`, `phase.md`, `rules.md`

---

## 1. Executive Summary & Foundational Invariants

Phase R transforms the Private Protection Windows Desktop application into a production-grade, 20-screen Antivirus Command Center. 

### The Cardinal Constitutional Invariant
> **THE UI IS NOT A SECURITY AUTHORITY.**  
> The React renderer layer does **NOT** generate verdicts, calculate risk scores, downgrade threats, or invent posture states. The UI is strictly a read-only presentation and controlled IPC command-dispatch layer. All security intelligence originates from the canonical detection pipeline:
> $$\text{FileAnalyzer} \longrightarrow \text{RiskScorer} \longrightarrow \text{EngineVerdict} \longrightarrow \text{QuarantineService} \longrightarrow \text{NotificationService}$$

### Core Operating Principles
1. **Zero Fake UI / Zero Placeholders:** Every button, toggle, table, and metric is wired to real backend IPC APIs via the context-isolated preload bridge (`window.desktopSecurity`).
2. **Fail-Closed Security Posture:** In the absence of backend telemetry or upon degraded subsystem health, the UI never presents a false green ("Protected") state. It immediately switches to `ACTION_REQUIRED` or `ATTENTION`.
3. **Friction Gates for Weakening Actions:** Sensitive operations (disabling shields, restoring quarantined malware, creating exclusions, authorizing trusted apps, crypto-shredding) require explicit confirmation through a 3-second mandatory friction gate modal.
4. **RTLO Spoofing Defenses:** File names and paths rendered in modals or lists are strictly scrubbed of Right-to-Left Override (RTLO) and bidirectional Unicode control characters (`\u202A`–`\u202E`, `\u2066`–`\u2069`).
5. **Zero-Knowledge Privacy:** The renderer operates 100% offline. Zero user URLs, file paths, or telemetry are transmitted off-device.

---

## 2. 20-Screen Topology & Navigation Hierarchy

The Command Center organizes all 20 screens into 5 logical navigation groups:

```
┌────────────────────────────────────────────────────────────────────────┐
│               PRIVATE PROTECTION ANTIVIRUS COMMAND CENTER              │
├───────────────────┬────────────────────────────────────────────────────┤
│ 1. OVERVIEW       │ Screen 01: Home / Dashboard (HomeScreen)           │
│                   │ Screen 20: About & Security (AboutSecurityScreen)  │
├───────────────────┼────────────────────────────────────────────────────┤
│ 2. SCANNING       │ Screen 02: Quick Scan (QuickScanScreen)            │
│                   │ Screen 03: Full PC Scan (FullScanScreen)           │
│                   │ Screen 04: Custom Scan (CustomScanScreen)          │
│                   │ Screen 05: Scheduled Scan (ScheduledScanScreen)    │
├───────────────────┼────────────────────────────────────────────────────┤
│ 3. ACTIVE SHIELDS │ Screen 06: Real-Time Shield (RealtimeProtection)   │
│                   │ Screen 11: Ransomware Shield (RansomwareShield)    │
│                   │ Screen 12: Web & MOTW Protection (WebProtection)   │
├───────────────────┼────────────────────────────────────────────────────┤
│ 4. FORENSICS &    │ Screen 07: Threat Detection Modal (Interstitial)   │
│    RECOVERY       │ Screen 08: AI Security Assistant (AssistantScreen) │
│                   │ Screen 09: Scan Results & Telemetry (ScanResults)  │
│                   │ Screen 10: Forensic Audit Log (HistoryScreen)      │
│                   │ Screen 19: Recovery & Crypto-Shred (RecoveryScreen)│
├───────────────────┼────────────────────────────────────────────────────┤
│ 5. SYSTEM &       │ Screen 13: Notification Center (NotificationsScreen│
│    SETTINGS       │ Screen 14: Health & Watchdog (ProtectionStatus)    │
│                   │ Screen 15: Updates & Definitions (UpdateStatus)    │
│                   │ Screen 16: Protection Settings (SettingsScreen)    │
│                   │ Screen 17: Exclusions Manager (ExclusionsScreen)   │
│                   │ Screen 18: Trusted Apps Allowlist (TrustedApps)    │
└───────────────────┴────────────────────────────────────────────────────┘
```

---

## 3. Screen Specifications & IPC Contracts

### Screen 01: Home / Dashboard (`HomeScreen.tsx`)
- **Purpose:** Primary security posture dashboard and subsystem matrix.
- **Key Metrics:** Files Inspected (`filesScannedTotal`), Active Threats (`threatsCount`), Quarantine Vault (`quarantineCount`), Threat Definitions (`threatIntelStatus.currentVersionSequence`).
- **Posture Math:**
  - `ACTION_REQUIRED` (Red): Active threats present $>0$, or health state `CRITICAL`/`DEGRADED`, or Real-Time Shield disabled without active snooze.
  - `ATTENTION` (Amber): Subsystem health `WARNING`, or shield actively snoozed, or definition database `STALE`/`EXPIRED_CACHE`.
  - `PROTECTED` (Green): All shields active, zero threats, fresh definitions, watchdog nominal.

### Screen 02: Quick Ingress Scan (`QuickScanScreen.tsx`)
- **Purpose:** Fast sweep of critical ingress vectors: Downloads directory, `%TEMP%`, running process binaries, and Windows startup persistence keys.
- **IPC Hook:** `desktopSecurity.startQuickScan()`.
- **Target SLA:** $<15$ seconds on standard endpoint.

### Screen 03: Full PC Scan (`FullScanScreen.tsx`)
- **Purpose:** Recursive inspection across all fixed NTFS/FAT drives with symlink cycle protection and locked-file tolerance.
- **IPC Hook:** `desktopSecurity.startFullScan()`.

### Screen 04: Custom Location Scan (`CustomScanScreen.tsx`)
- **Purpose:** Targeted scan of user-specified directories or files via drag-and-drop or path entry.
- **IPC Hook:** `desktopSecurity.startCustomScan([path])`.

### Screen 05: Scheduled Scan (`ScheduledScanScreen.tsx`)
- **Purpose:** Configurable recurrence (Daily/Weekly), time-of-day execution, battery charge guard ($<20\%$), and missed-scan catch-up on Windows startup.
- **IPC Hooks:** `desktopSecurity.getScanSchedule()`, `desktopSecurity.saveScanSchedule()`.

### Screen 06: Real-Time Protection Shield (`RealtimeProtectionScreen.tsx`)
- **Purpose:** Continuous filesystem interception (`ReadDirectoryChangesW`), ingress sub-shields (Downloads, Temp), byte entropy heuristics ($H>7.5$), and snooze controls.
- **IPC Hooks:** `desktopSecurity.snoozeShield(minutes)`, `desktopSecurity.saveSettings()`.

### Screen 07: Threat Detection Modal (`ThreatDetectionModal.tsx`)
- **Purpose:** High-priority warning interstitial popping immediately upon realtime threat interception. Auto-focuses safe default action ("Keep in Quarantine").
- **Security:** RTLO bidirectional character stripping on file name and path.
- **WCAG Compliance:** `role="alertdialog"`, `aria-modal="true"`.

### Screen 08: AI Security Assistant (`AssistantScreen.tsx`)
- **Purpose:** Translates technical detection evidence (PE header anomalies, entropy, packer signatures) into plain language at Grade 6 or Grade 8 cognitive reading level.
- **Constraint:** AI Assistant is strictly read-only. It has zero authority to alter risk scores or dismiss threats.
- **IPC Hook:** `desktopSecurity.explainThreat(threat, level)`.

### Screen 09: Scan Results & Threat Telemetry (`ScanResultsScreen.tsx`)
- **Purpose:** Itemized listing of detected threats with SHA-256 hashes, severity badges, and manual vault isolation triggers.

### Screen 10: Forensic Audit Log (`HistoryScreen.tsx`)
- **Purpose:** Tamper-evident, HMAC-SHA256 hash-chained timeline of all security events, scans, and configuration modifications.
- **IPC Hooks:** `desktopSecurity.queryAuditLogs()`, `desktopSecurity.verifyAuditChainIntegrity()`.

### Screen 11: Ransomware Shield & Shadow Vault (`RansomwareShieldScreen.tsx`)
- **Purpose:** Protected folder monitoring (NTFS junctions resolved), decoy canary trap status (`~$_PrivateProtection_Canary_*`), sliding-window velocity math, and Shadow Vault pre-attack AES-256-GCM rollback.
- **IPC Hooks:** `desktopSecurity.getRansomwareStatus()`, `desktopSecurity.rollbackIncident(id)`.

### Screen 12: Web & MOTW Protection (`WebProtectionScreen.tsx`)
- **Purpose:** On-device URL lexical entropy analysis, NTFS Mark-of-the-Web (`:Zone.Identifier`) verification, and deceptive SMS/email message parser.
- **IPC Hooks:** `desktopSecurity.analyzeUrl(url)`, `desktopSecurity.getWebProtectionStatus()`.

### Screen 13: Notification Center (`NotificationsScreen.tsx`)
- **Purpose:** Centralized in-app security alert inbox with RULE-15 burst storm rate-limiter telemetry (max 3 OS toasts per 10s).
- **IPC Hooks:** `desktopSecurity.getNotificationsInbox()`, `desktopSecurity.getRateLimiterTelemetry()`.

### Screen 14: Endpoint Health & Watchdog (`ProtectionStatusScreen.tsx`)
- **Purpose:** 4-state subsystem health monitoring (`HEALTHY`, `WARNING`, `DEGRADED`, `CRITICAL`), active process and persistence audits, and watchdog supervisor loop status.
- **IPC Hooks:** `desktopSecurity.getHealthStatus()`, `desktopSecurity.getWatchdogStatus()`, `desktopSecurity.auditProcesses()`.

### Screen 15: Cryptographic Update Status (`UpdateStatusScreen.tsx`)
- **Purpose:** Ed25519 root key verification status, anti-downgrade monotonic sequence counter enforcement, and signed delta update checking.
- **IPC Hook:** `desktopSecurity.getThreatIntelStatus()`.

### Screen 16: Protection Settings (`SettingsScreen.tsx`)
- **Purpose:** Persistent security settings with immediate SQLite/JSON storage synchronization and friction gate protection.
- **IPC Hook:** `desktopSecurity.saveSettings(settings)`.

### Screen 17: Exclusions & False-Positive Manager (`ExclusionsScreen.tsx`)
- **Purpose:** Hash-based (recommended), path-based, and domain-based exclusion rules with mandatory TTL expiration (24h, 7d, 30d, permanent) and justification requirements.
- **IPC Hooks:** `desktopSecurity.getExclusions()`, `desktopSecurity.createExclusion()`, `desktopSecurity.removeExclusion()`.

### Screen 18: Trusted Applications Allowlist (`TrustedAppsScreen.tsx`)
- **Purpose:** Authorizes specific binaries to perform bulk writes in Protected Folders, pinned strictly to Canonical Path + SHA-256 hash.
- **IPC Hooks:** `desktopSecurity.getTrustedApplications()`, `desktopSecurity.addTrustedApplication()`, `desktopSecurity.revokeTrustedApplication()`.

### Screen 19: Recovery, USB Rescue & Crypto-Shredder (`RecoveryScreen.tsx`)
- **Purpose:** Auto-detection and scanning of removable USB storage devices, and zero-knowledge permanent crypto-shredding (DoD 5220.22-M 3-pass overwrite + truncate).
- **IPC Hooks:** `desktopSecurity.getRemovableMedia()`, `desktopSecurity.scanRemovableMedia()`, `desktopSecurity.privacyShred()`.

### Screen 20: About & Security Architecture (`AboutSecurityScreen.tsx`)
- **Purpose:** Architecture transparency display: live Windows Firewall profile status, core engine version, and live execution of 5 constitutional invariant self-tests (INV-01 through INV-05).
- **IPC Hooks:** `desktopSecurity.getFirewallStatus()`, `desktopSecurity.runInvariantSelfTest()`.

---

## 4. Security UI Mechanics

### 4.1 RTLO Unicode Sanitization
Filename spoofing attacks utilize Unicode bidirectional override characters (such as Right-to-Left Override `\u202E`) to make executable extensions appear as innocuous documents (e.g., `invoice[U+202E]exe.pdf` renders as `invoicefdp.exe`).
The Command Center applies `sanitizeUnicodeDisplay()` before rendering untrusted file strings:
```typescript
export function sanitizeUnicodeDisplay(str: string): string {
  if (!str) return '';
  return str.replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '');
}
```

### 4.2 Security Friction Gate
Modifications that degrade endpoint protection invoke `requestFrictionGate()`:
- Renders `FrictionGateModal` with high-contrast amber warning banner.
- Forces a 3-second disabled countdown on the confirmation CTA to prevent click-jacking and reflex clicks.
- Requires explicit user acknowledgement of the security risk.

---

## 5. Verification Matrix & Quality Standards

| Verification Pillar | Standard Enforced | Status |
|---|---|---|
| **TypeScript Compilation** | 0 errors (`tsc --noEmit`) across monorepo | **PASS** |
| **Unit & Screen Tests** | 21/21 screens and shell navigation tests pass | **PASS** |
| **Security UI Tests** | 11/11 RTLO, Posture Math, Friction Gate tests pass | **PASS** |
| **Dashboard Presentation Tests**| 5/5 settings & tab switching tests pass | **PASS** |
| **WCAG 2.1 AA Accessibility** | Minimum 4.5:1 text contrast, `alertdialog` semantics | **PASS** |
| **Zero Mock Regressions** | Real IPC channels wired via `DesktopSecurityApi` | **PASS** |
