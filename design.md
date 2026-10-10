# design.md — Complete 20-Screen Desktop Antivirus UX & Design Specification

> **DOCUMENT STATUS:** CANONICAL UX & INTERFACE SPECIFICATION  
> **PROJECT:** Privex — Windows Desktop Strong Antivirus Transformation  
> **DESIGN PHILOSOPHY:** Calm Authority • Plain-Language Clarity (Grade $\le 8$) • Zero Alarmism • Instant Actionability • Friction-Gated Security Mutations

---

## 1. Design System Baseline & Visual Tokens

Inspection of `apps/desktop/src/renderer/` (`App.tsx`, `Sidebar.tsx`, `Header.tsx`, `SecurityBadge.tsx`, `FrictionGateModal.tsx`, `ScanProgressBar.tsx`) establishes our canonical design tokens:

### 1.1 Shell Geometry & Layout
- **Window Shell:** Frameless custom-chrome Windows desktop viewport (`100vh x 100vw`, `minWidth: 1024px`, `minHeight: 680px`), paired with persistent Windows System Tray integration.
- **Navigation Sidebar (`240px` fixed left):** Deep Slate `#0f172a` background, grouped into 5 logical antivirus categories (*Overview*, *Scanning*, *Active Shields*, *Forensics & Recovery*, *System & Configuration*).
- **Top Header Bar (`60px` height):** Crisp `#ffffff` background, `1px solid #e2e8f0` bottom border, live posture pill, unread notification indicator, and window controls (`Minimize to Tray`, `Maximize`, `Close`).
- **Main Content Canvas:** `#f8fafc` (Slate-50) scrollable surface (`padding: 24px`, `maxWidth: 1040px`) with `#ffffff` elevated cards (`border: 1px solid #e2e8f0`, `borderRadius: 10px`).

### 1.2 Semantic Color & Contrast Tokens (WCAG AA/AAA Verified)
| Semantic Role | Background | Text / Foreground | Border / Accent | Contrast Ratio | Usage |
|---|---|---|---|---|---|
| **`safe` / `🟢 PROTECTED`** | `#dcfce7` / `#f0fdf4` | `#166534` / `#16a34a` | `#86efac` | `7.2:1` (AAA) | All shields active, clean scan results, verified signatures |
| **`low` / `INFO`** | `#e0f2fe` | `#0369a1` | `#7dd3fc` | `5.8:1` (AA) | Air-gapped status, informational telemetry, active scan progress |
| **`suspicious` / `🟡 ATTENTION`** | `#fef3c7` / `#fffbeb` | `#92400e` / `#d97706` | `#fcd34d` | `6.4:1` (AA) | Paused shield, stale definitions ($>7\text{d}$), heuristic warnings |
| **`dangerous` / `🟠 HIGH RISK`** | `#ffedd5` | `#9a3412` | `#fb923c` | `6.1:1` (AA) | High-risk files/processes requiring immediate quarantine or review |
| **`critical` / `🔴 ACTION REQ`** | `#fee2e2` / `#fef2f2` | `#991b1b` / `#dc2626` | `#f87171` | `6.9:1` (AA) | Confirmed malware, ransomware canary trip, config/vault tamper |

### 1.3 The 4-Pillar Plain-Language Explanation Contract
Every status hero banner, threat detection modal, and notification card MUST structure its communication into four plain-language pillars (Flesch-Kincaid Grade $\le 6$ default, toggleable to Grade 8 Technical):
1. **WHAT HAPPENED:** Concrete description of the file, process, or URL event without cryptic hex dumps.
2. **WHY IT MATTERS:** Clear explanation of the real-world risk to personal documents, passwords, or system stability.
3. **WHAT PRIVEX DID:** Exact automated defense action already taken (`Quarantined in PPVAULT2`, `Terminated process PID`, `Blocked phishing link`).
4. **WHAT THE USER SHOULD DO:** Unambiguous next step (`No action needed`, `Review quarantined file`, `Restore clean copy from Shadow Vault`).

---

## 2. Complete Specification of All 20 Required Antivirus Screens & Components

---

### Screen 01: Protection Dashboard (`HomeScreen.tsx`)
- **Purpose:** Primary command center displaying the 3-Tier Posture Hero Banner (`🟢 PROTECTED`, `🟡 ATTENTION REQUIRED`, `🔴 ACTION REQUIRED`), the 4-Pillar status explanation, live protection metrics, and 1-click scan/remediation launchers.
- **User Actions:**
  - Click primary Hero CTA (`Run Quick Scan`, `Re-Enable Real-Time Shield`, or `Quarantine All Threats Now`).
  - Launch `Quick Scan`, `Full Scan`, or `Custom Scan`.
  - Click summary cards to jump to `Real-Time Protection`, `Ransomware Shield`, `Quarantine`, or `Security Health`.
- **States:**
  - *Empty (First Launch):* `🟢 PROTECTED` hero with `0` files scanned and onboarding prompt to run initial Quick Scan.
  - *Loading:* Skeleton placeholders during `<50ms` initial IPC status hydration.
  - *Success (`🟢 PROTECTED`):* Emerald hero banner; Real-Time Shield, Ransomware Shield, and Definitions all nominal.
  - *Warning (`🟡 ATTENTION REQUIRED`):* Amber hero banner when Real-Time Shield is snoozed, definitions are $>7$ days old, or medium warnings exist; shows 1-click `Fix Now` button.
  - *Critical (`🔴 ACTION REQUIRED`):* Red hero banner when unquarantined critical threats exist, Real-Time Shield is disabled, or Ransomware Canary was tripped; shows prominent `Restore Protection / Quarantine Now` CTA.
  - *Error:* IPC bridge failure renders fail-closed `🟡 ATTENTION REQUIRED` state with `Reconnect Service` button.
- **Accessibility:** Hero banner uses `role="region"`, `aria-labelledby="dashboard-posture-title"`, and `aria-live="polite"`. All action cards are semantic `<button>` elements with `:focus-visible` `2px solid #2563eb` outlines.
- **Performance:** Memoized selectors (`React.memo`); zero renderer polling loops (driven by push IPC events).
- **Security Implications:** Fail-closed posture logic ensures the Dashboard never displays `🟢 PROTECTED` if any core service or integrity check is degraded.

---

### Screen 02: Quick Scan (`QuickScanScreen.tsx`)
- **Purpose:** Fast ($<10\text{ s}$ target) high-risk sweep of `Downloads`, `%TEMP%`, `Desktop`, active user process binaries, and Windows Startup persistence locations.
- **User Actions:** Start Quick Scan, Pause/Resume/Cancel via `ScanProgressBar`, inspect detected threats (`Threat Details`), or click `Quarantine All`.
- **States:**
  - *Empty (Idle):* Shows target scope pills (`Downloads`, `Temp`, `Desktop`, `Active Processes`, `Startup`) and last scan timestamp.
  - *Loading (Scanning / Paused):* Live `ScanProgressBar` displaying `filesScanned`, `filesPerSecond`, elapsed time, and truncated `currentPath`.
  - *Success:* Green `SECURE` badge, 4-metric summary (`Files Scanned`, `0 Threats`, `Duration ms`, `CleanCache Hits`).
  - *Warning:* Completed with `suspicious` heuristic matches or locked system files (`skippedFiles`).
  - *Critical:* `threatsFound > 0` with `critical`/`dangerous` severity; renders threat action cards with `Isolate in Quarantine` CTA.
  - *Error:* Scan target permission error rendered in `#fef2f2` alert card with retry button.
- **Accessibility:** `ScanProgressBar` includes `role="progressbar"`, `aria-valuenow`, and throttled `aria-live="polite"` progress announcements every 5 seconds.
- **Performance:** Progress IPC events throttled to `20–30 Hz` (`50ms`) so rapid file traversal never blocks Pause/Cancel clicks.
- **Security Implications:** Scans execute via bounded 64 KB header/stream reads without loading or executing target binaries.

---

### Screen 03: Full Scan (`FullScanScreen.tsx`)
- **Purpose:** Deep recursive scan across all fixed drives and user directories with `CleanFileCache` acceleration, archive inspection, and symlink cycle protection.
- **User Actions:** Start Full System Scan, Pause/Resume, Cancel, toggle background CPU priority (`Balanced` vs. `Turbo`), and batch-quarantine detected threats.
- **States:**
  - *Empty (Idle):* Displays detected local drives, `CleanFileCache` entry count, and estimated scan duration.
  - *Loading (Running / Paused):* Live progress bar with drive phase indicator, throughput (`files/s`), and `Pause`/`Resume`/`Cancel` buttons.
  - *Success:* Full system clean certificate card with total files inspected, cache hits, and elapsed time.
  - *Warning:* Lists `suspicious` heuristic items and normal OS-locked files (`pagefile.sys`, `hiberfil.sys`).
  - *Critical:* Displays all detected malware across drives with 1-click `Quarantine All Confirmed Threats`.
  - *Error:* Hardware read error (`EIO`) or worker recovery notice while preserving partial scan results.
- **Accessibility:** Keyboard shortcuts (`Space` to Pause/Resume when control card focused) and `aria-live="assertive"` completion alert if threats are found.
- **Performance:** Virtualized threat and skipped-file lists (`56px` fixed row height) support $10,000+$ items at 60 FPS.
- **Security Implications:** Enforces `(dev, ino)` symlink/junction cycle tracking and zip-bomb ratio limits ($\le 100:1$, depth $\le 3$).

---

### Screen 04: Custom Scan (`CustomScanScreen.tsx`)
- **Purpose:** Targeted on-demand scanning of user-picked folders, individual files, drag-and-drop items, or mounted USB drives.
- **User Actions:** Click `Browse Folder...` / `Browse File...` (native Windows dialog), drag-and-drop files onto the dropzone, select a quick preset (`Downloads`, `Desktop`, or mounted `USB Drive D:\`), and start/cancel scan.
- **States:**
  - *Empty (Idle):* Interactive dropzone + path input + dynamically populated removable USB drive chips.
  - *Loading:* Scoped `ScanProgressBar` for the selected target path.
  - *Success:* Per-file breakdown showing `ALLOW` verdict, SHA-256 hash, magic header, and Shannon entropy.
  - *Warning:* Flags deceptive extensions, unsigned packed binaries, or MOTW internet origins (`WARN`).
  - *Critical:* Malware/EICAR detected in target path; offers immediate `Quarantine File` CTA.
  - *Error:* Non-existent or invalid path validation message (`Please select a valid local file or directory`).
- **Accessibility:** Input explicitly bound to `<label htmlFor="custom-scan-path">` with `aria-invalid` and keyboard-accessible file picker button.
- **Performance:** Asynchronous path validation over IPC prior to starting scan.
- **Security Implications:** Rejects UNC network shares (`\\server\share`) and Windows reserved device names (`CON`, `NUL`, `AUX`) at `IpcValidator`.

---

### Screen 05: Scheduled Scan (`ScheduledScanScreen.tsx`)
- **Purpose:** Configure automated background scans (`Daily Quick Scan`, `Weekly Full Scan`, `Startup Catch-Up`) with battery and system-load guards.
- **User Actions:** Toggle Scheduled Scanning On/Off, select frequency (`Daily` / `Weekly`), time of day, scan type (`Quick` / `Full`), toggle `Pause on battery power (<20%)`, `Run missed scan on startup`, and click `Run Scheduled Scan Now`.
- **States:**
  - *Empty:* Displays recommended default schedule (`Daily Quick Scan at 12:00 PM`).
  - *Loading:* Saving schedule configuration to encrypted storage.
  - *Success:* Green `SCHEDULE ACTIVE` badge showing calculated `Next Run` timestamp and last 5 scheduled run outcomes.
  - *Warning:* Last scheduled run deferred due to low battery (`Deferred — Battery Saver Active`).
  - *Critical:* Unattended scheduled scan isolated threats; displays prominent banner linking to `Quarantine`.
  - *Error:* Invalid time format or storage save error.
- **Accessibility:** Uses semantic `<fieldset>` and `<legend>` for schedule frequency and power guard checkboxes.
- **Performance:** Background scheduled runs automatically use throttled worker concurrency so foreground apps remain lag-free.
- **Security Implications:** Disabling scheduled scans when Real-Time Protection is off requires `FrictionGateModal` confirmation.

---

### Screen 06: Real-Time Protection (`RealtimeProtectionScreen.tsx`)
- **Purpose:** Granular control center and live event monitor for the recursive `ReadDirectoryChangesW` filesystem shield and sub-shields.
- **User Actions:**
  - Toggle Master Real-Time Shield On/Off (turning Off requires `FrictionGateModal` + mandatory **Auto-Re-Enable Timer**: `15m`, `30m`, `1h`, or `Until Reboot`).
  - Toggle sub-shields: `Downloads Ingress Shield`, `System Temp (%TEMP%) Guard`, `Desktop & Documents Watcher`, and `Auto-Quarantine Critical Threats`.
  - Add/remove custom monitored directories and view a live 20-item rolling micro-feed of inspected file events.
- **States:**
  - *Empty:* Micro-feed listening for new filesystem events (`Monitoring 5 recursive directories...`).
  - *Loading:* Re-binding recursive directory watchers.
  - *Success:* All sub-shields `ACTIVE` (`🟢`), showing live `eventsProcessed` and `threatsBlocked` counters.
  - *Warning:* Shield temporarily snoozed (`Snoozed — Auto-resumes in 14m 10s`) with 1-click `Resume Now` button.
  - *Critical:* Master Real-Time Shield disabled; displays red alert banner with immediate `Enable Shield` CTA.
  - *Error:* Watcher handle error on a removed folder; displays automatic `Watchdog` recovery status.
- **Accessibility:** Shield switches use `role="switch"` and `aria-checked`, with live snooze countdown accessible to screen readers.
- **Performance:** Micro-feed uses a bounded 20-entry circular buffer throttled to `2 Hz` UI updates.
- **Security Implications:** Enforces `RULE-19` (no permanent silent shield disablement; mandatory auto-resume countdown).

---

### Screen 07: Threat Detection — Active Alert & Interstitial (`ThreatDetectionModal.tsx` & `PreThreatWarningModal.tsx`)
- **Purpose:** Instant ($<50\text{ ms}$) high-visibility interception modal and top banner displayed when a real-time file, download, process threat, or predictive pre-threat (URL, file, package) is caught.
- **Mobile Pre-Threat Warning (`PreThreatWarningModal.tsx` — Phase T7):**
  - Displays evidence-backed warning before risky actions across URLs, downloads, or unverified app packages.
  - Distinct badge taxonomy: `CONFIRMED_MALWARE`, `STRONG_SUSPICION`, `HEURISTIC_ANOMALY`.
  - Grounded trigger summary ("What was detected") and factual consequence disclosure ("Potential consequences").
  - Auto-focused primary safe recommendation CTA (`← Go Back to Safety`, `Delete Download`, `Cancel Installation`).
  - Integrated 5-second countdown friction gate for hazardous bypass (`Continue at your own risk...`).
  - Collapsible technical evidence token list.
- **User Actions:**
  - Click auto-focused primary safe CTA: `Keep in Quarantine (Recommended)` or `Quarantine Threat Now`.
  - Click `Inspect Evidence & AI Explanation` (opens **Screen 08: Threat Details**).
  - Click high-friction secondary option: `Restore & Trust SHA-256...` (gated by `FrictionGateModal`).
- **States:**
  - *Empty:* Hidden when no active unacknowledged threat alert is present.
  - *Loading:* Deterministic 4-Pillar summary renders synchronously in `<16ms`; AI explanation hydrates asynchronously.
  - *Success:* Confirmation state after user clicks `Keep in Quarantine` (`✅ Threat safely isolated in PPVAULT2`).
  - *Warning (`SUSPICIOUS` / `WARN`):* Amber modal prompting user to `Quarantine` or `Keep Once`.
  - *Critical (`BLOCK` / `AUTO_QUARANTINED` / `RANSOMWARE_BEHAVIOR`):* Red alert confirming automatic containment of the file/process.
  - *Error:* File locked by running process; offers 1-click `Terminate Process PID & Quarantine`.
- **Accessibility:** `role="alertdialog"`, `aria-modal="true"`, focus trapped inside modal with initial focus strictly on the safe primary CTA.
- **Performance:** Zero network or LLM blocking on initial modal render.
- **Security Implications:** Strips Unicode bidirectional control characters (`\u202A`–`\u202E`) and middle-truncates long paths so crafted filenames cannot spoof UI buttons.

---

### Screen 08: Threat Details — Evidence Breakdown & AI Explanation (`ScanResultsScreen.tsx` + `AssistantScreen.tsx`)
- **Purpose:** Forensic drilldown for any detected file, process, or URL threat, pairing deterministic 10-Layer technical evidence (`RiskScore`, `SHA-256`, `MagicHeader`, `Entropy`, `PE Sections/IAT`, `MOTW Origin`, `Rule IDs`) with the read-only On-Device AI Security Assistant (`Grade 6` vs. `Grade 8` toggle).
- **User Actions:**
  - Toggle explanation reading level (`Grade 6 Plain Language` vs. `Grade 8 Technical`) and click `Synthesize Explanation`.
  - Copy `SHA-256` hash or evidence report to clipboard.
  - Execute `Move to Quarantine`, `Permanent Shred`, or `Add SHA-256 Exclusion` (Friction Gated).
- **States:**
  - *Empty:* Prompt to select a threat from Scan Results, Quarantine, or History.
  - *Loading:* Deterministic evidence visible immediately; AI explanation card shows local synthesis indicator.
  - *Success:* Displays `CONTAINED IN QUARANTINE` badge + complete 4-Pillar AI explanation and evidence table.
  - *Warning / Critical:* Unquarantined threat shows prominent red `Quarantine Now` action bar at top.
  - *Error:* If AI output fails schema check, seamlessly renders deterministic template explanation (`RULE-04`) with zero crash.
- **Accessibility:** Score bars and layer badges include full text equivalents for screen readers.
- **Performance:** Split master-detail view virtualizes the threat list while keeping the detail pane instantaneous.
- **Security Implications:** Enforces `CORE -> VERDICT -> AI EXPLANATION`: raw file bytes are never fed to the AI prompt, and AI output can never alter `verdict` or `riskScore`.

---

### Screen 09: Quarantine (`QuarantineScreen.tsx`)
- **Purpose:** Inspect, permanently shred, or safely restore encrypted `.ppvault2` / `.ppvault1` threat blobs isolated in the local Quarantine Vault.
- **User Actions:**
  - Review isolated items (`Original Path`, `Quarantined Date`, `SHA-256`, `Severity`, `Detection Reason`).
  - Click `Permanent Delete (3-Pass Shred)` on individual items or `Purge Entire Vault`.
  - Click `Restore to Disk...` or **`Restore & Trust SHA-256...`** (both gated by `FrictionGateModal` 3-second countdown).
- **States:**
  - *Empty:* `🛡️ Quarantine Vault is Empty — No isolated threat blobs.`
  - *Loading:* Reading and authenticating `manifest.json.enc`.
  - *Success:* Toast/banner confirming `✅ Item permanently shredded` or `✅ Restored and SHA-256 added to allowlist`.
  - *Warning:* Vault size approaching storage threshold (`>500 MB`); suggests shredding old blobs.
  - *Critical:* Highlights `critical` ransomware/trojan blobs with red warning badges.
  - *Error:* Tampered blob (`INTEGRITY_CHECK_FAILED`) or locked destination path reported clearly without crashing.
- **Accessibility:** Semantic table/cards with explicit `aria-label` on each Restore and Delete button.
- **Performance:** Streaming 64 KB `PPVAULT2` decryption ensures restoring large files never freezes the UI.
- **Security Implications:** Restoring never executes the file, prevents path traversal/reserved names, and optionally pins the exact SHA-256 in the allowlist to prevent immediate re-quarantine loops.

---

### Screen 10: History — Audit & Forensic Timeline (`HistoryScreen.tsx`)
- **Purpose:** Chronological, tamper-evident forensic log viewer (`AuditLoggerService`) displaying all scans, detections, quarantines, process containments, shield changes, exclusions, and updates, verified by an **HMAC-SHA256 Hash Chain**.
- **User Actions:**
  - Filter events by Category (`All`, `Threats`, `Scans`, `Quarantine`, `Shields & Config`, `Updates`) and Severity (`Critical`, `Warning`, `Info`).
  - Search events locally by filename, SHA-256, or rule ID.
  - Click `Verify Log Chain Integrity` (runs HMAC chain check) or `Export Sanitized Audit Report (JSON / CSV)`.
- **States:**
  - *Empty:* `No audit events match the current filter.`
  - *Loading:* Paginated query from encrypted `audit.log.enc`.
  - *Success:* `🟢 HMAC Chain Verified (N entries intact)` badge at top of timeline.
  - *Warning:* Highlights security-weakening user events (`Shield Snoozed`, `Exclusion Added`) in amber.
  - *Critical / Error:* `🔴 AUDIT LOG TAMPERING DETECTED at Entry #k` if any historical record was modified on disk.
- **Accessibility:** Filter tabs use `role="tablist"` / `aria-selected`; event table supports keyboard navigation.
- **Performance:** Virtualized viewport renders up to $10,000+$ log entries with $<5\text{ ms}$ filter response.
- **Security Implications:** Scrubs all Tier-1 raw content and URL query parameters (`RULE-18`) while proving forensic integrity via HMAC chaining.

---

### Screen 11: Ransomware Shield — Protected Folders & Canary Status (`RansomwareShieldScreen.tsx`)
- **Purpose:** Configure folder write protection (`Documents`, `Pictures`, `Desktop`, custom folders), switch between `Smart Mode` and `Strict Mode`, monitor decoy **Canary Trap Files**, and view `ShadowVault` backup readiness.
- **User Actions:**
  - Toggle Master Ransomware Shield On/Off (turning Off requires `FrictionGateModal`).
  - Switch Mode (`Smart Mode — Allow verified signed apps` vs. `Strict Mode — Block all untrusted apps`).
  - Add/remove **Protected Folders** and click `Verify / Re-Seed Canary Traps`.
  - Jump to **Screen 18: Trusted Applications** or **Screen 19: Recovery (Shadow Vault)**.
- **States:**
  - *Empty:* Default protected folders (`Documents`, `Pictures`, `Desktop`) active out-of-the-box.
  - *Loading:* Checking canary file SHA-256 hashes and Shadow Vault quota.
  - *Success:* `🟢 CANARY TRAPS INTACT • SHADOW VAULT READY` badge.
  - *Warning:* A canary file was accidentally removed during user cleanup; offers 1-click `Re-Deploy Canary`.
  - *Critical (`🔴 RANSOMWARE ATTACK CONTAINED`):* Displays stopped process PID, binary path, count of protected files, and prominent 1-click **`Rollback Modified Files from Shadow Vault`** CTA.
  - *Error:* Selected folder does not exist or is a read-only optical drive.
- **Accessibility:** Mode selector and folder cards include full ARIA descriptions and keyboard controls.
- **Performance:** Event-driven canary and velocity monitoring (`0%` idle CPU polling).
- **Security Implications:** Masks exact canary filenames in UI by default (`~$_••••_Canary.docx`) and requires `FrictionGateModal` to remove a Protected Folder.

---

### Screen 12: Web Protection — URL Scanner, Download MOTW Shield & Extension Sync (`WebProtectionScreen.tsx`)
- **Purpose:** On-device URL/Phishing/Message scanner, NTFS Mark-of-the-Web (`:Zone.Identifier`) download shield control, and Browser Extension synchronization dashboard.
- **User Actions:**
  - Paste any suspicious URL or SMS/email text into the **Instant On-Device Scanner** (`Analyze URL` / `Analyze Message`).
  - Toggle **NTFS Mark-of-the-Web (`:Zone.Identifier`) Origin Enforcement** on downloaded files.
  - Inspect Punycode/homograph character diffs and view Browser Extension connection status.
- **States:**
  - *Empty:* Ready input fields with 1-click test presets (`Test Homograph Phishing URL`, `Test Crypto Extortion Message`).
  - *Loading:* Sub-millisecond evaluation (`<1.0ms`).
  - *Success:* `ALLOW` verdict badge with breakdown confirming clean domain and zero homographs.
  - *Warning:* `CAUTION` / `WARN` badge for newly registered/suspicious TLD or high-entropy URL.
  - *Critical:* `BLOCK` verdict highlighting spoofed brand or Cyrillic/Greek confusable characters and offering 1-click AI explanation.
  - *Error:* Input exceeds constitucional byte limit ($2,048\text{ B}$ URL / $10,000\text{ B}$ text) $\rightarrow$ fails closed to `WARN`.
- **Accessibility:** Confusable character highlights pair color with explicit `[Punycode / Homograph]` text labels.
- **Performance:** 100% synchronous in-memory evaluation via `@private-protection/core` ($<1\text{ ms}$).
- **Security Implications:** **Zero Network Touch:** Analyzed URLs are rendered strictly as non-clickable `<code>` blocks and never queried over DNS or HTTP.

---

### Screen 13: Notifications — Native Windows Toast & In-App Notification Center (`NotificationsScreen.tsx`)
- **Purpose:** Central inbox for all security notifications and configuration panel for Windows Native Toast alerts and **Storm Rate-Limiting (`RULE-15`)**.
- **User Actions:**
  - Filter notifications (`All`, `Unread`, `Critical`, `Batch Coalesced`), `Mark All Read`, or `Clear Inbox`.
  - Toggle `Enable Windows Native OS Toast Alerts` and `Suppress Non-Critical Toasts in Fullscreen Apps`.
  - View live Storm Rate-Limiter telemetry (`Max 3 OS Toasts / 10s • Burst Coalescing Active`).
- **States:**
  - *Empty:* `🔔 Notification Inbox is Clear — Zero unread security alerts.`
  - *Loading:* Loading notification history from local state.
  - *Success:* Routine scan/update completion notices.
  - *Warning (`⚡ Batch Storm Coalesced`):* Displays grouped summary card when a burst of $\ge 3$ threats was condensed into a single toast.
  - *Critical:* Unread malware block or ransomware containment alert pinned at top with action link.
  - *Error:* OS notification permission blocked; displays fallback notice that in-app alerts remain active.
- **Accessibility:** Header bell counter announces unread count (`aria-label="N unread notifications"`); inbox items support keyboard dismissal.
- **Performance:** Bounded 500-item ring buffer in memory; token-bucket limiter prevents OS notification queue flooding.
- **Security Implications:** Prevents alert-fatigue DoS attacks and scrubs sensitive Tier-1 text from OS lock-screen toasts.

---

### Screen 14: Security Health — 4-State Self-Health Monitor, Watchdog & Process/Persistence Inspector (`ProtectionStatusScreen.tsx`)
- **Purpose:** Comprehensive endpoint posture & self-health diagnostics displaying the canonical **4-State Health Model** (`HEALTHY`, `WARNING`, `DEGRADED`, `CRITICAL`), `WatchdogService` heartbeat/recovery counters, active **Process Lineage Auditor**, and **Startup Persistence Inspector**.
- **User Actions:**
  - Inspect live health state of all subsystems (`Real-Time Shield`, `Ransomware Shield`, `Quarantine Vault`, `Threat DB`, `Storage HMAC`, `Watchdog`).
  - Click `Audit Running Processes` (shows PID, PPID, full path, command-line summary, and `Terminate Process` for flagged non-system threats).
  - Click `Audit Startup & Registry Persistence` (shows User/Common Startup, `.lnk` targets, `HKCU`/`HKLM` `Run` keys, and Scheduled Tasks).
  - Click `Run Self-Healing Repair` if health state is `WARNING`, `DEGRADED`, or `CRITICAL`.
- **States:**
  - *Empty / Idle:* Subsystem health matrix displayed; click to run full Process & Persistence sweep.
  - *Loading:* `Enumerating Windows processes (WMI/CIM), Registry Run keys, and Scheduled Tasks...`
  - *Success (`🟢 HEALTHY`):* All subsystems green, Watchdog heartbeat normal, zero anomalous processes or startup entries.
  - *Warning (`🟡 WARNING`):* Stale definitions ($>7\text{d}$), snoozed shield, or suspicious startup script flagged for review.
  - *Critical (`🟠 DEGRADED` / `🔴 CRITICAL`):* Shield disabled, config tamper detected, or active LOLBin/masquerading process (`svchost.exe` in `%TEMP%`) detected with 1-click **`Contain & Terminate Process`** button.
  - *Error:* Partial WMI permission fallback reported transparently.
- **Accessibility:** 4-State Health badge pairs color with distinct shape/text labels (`HEALTHY`, `WARNING`, `DEGRADED`, `CRITICAL`).
- **Performance:** Process and persistence audits run asynchronously off the UI thread and render in virtualized tables.
- **Security Implications:** Enforces `RULE-09` (Terminate button is disabled/blocked on verified `C:\Windows\System32` system processes).

---

### Screen 15: Definitions & Updates — Ed25519 Signed DB & Rollback UI (`UpdateStatusScreen.tsx`)
- **Purpose:** Manage local threat intelligence databases (`ThreatIntel` + `SignatureAutomaton`), verify Ed25519 signatures and monotonic sequence numbers, import offline signed bundles (`.ppdb`), and roll back to the Last-Known-Good (`LKG`) snapshot.
- **User Actions:**
  - Click `Import Signed Update Bundle (.ppdb / .json)` (via file picker) or `Verify Current Database Integrity`.
  - Inspect cryptographic metadata (`Engine Version`, `Monotonic Sequence #`, `Last Updated`, `Ed25519 Root Key Fingerprint`, `Loaded Hash & Signature Counts`).
  - Click `Rollback to Last-Known-Good (LKG) Database` (gated by `FrictionGateModal`).
- **States:**
  - *Empty / Default:* Running on verified embedded Factory Seed DB (`Seq #1`, `100% Offline Ready`).
  - *Loading:* `Verifying Ed25519 signature, SHA-256 digest, and running EICAR staging self-test...`
  - *Success:* `✅ Update Verified & Applied (Seq #N)` with updated rule and hash counts.
  - *Warning:* Definitions $>7$ days old or currently running on a rolled-back LKG snapshot.
  - *Critical (`🔴 UPDATE REJECTED`):* Displays exact cryptographic rejection reason (`SIGNATURE_INVALID`, `HASH_MISMATCH`, or `ANTI_DOWNGRADE_REJECT`).
  - *Error:* Unreadable bundle file; existing database remains 100% untouched.
- **Accessibility:** Monospace tabular numerals for hashes and sequence counters with accessible status announcements.
- **Performance:** Verification and atomic hot-swap complete in $<100\text{ ms}$ without interrupting active shields.
- **Security Implications:** Enforces `RULE-11` (Ed25519 canonical signature + anti-downgrade check + automatic rollback on broken update).

---

### Screen 16: Settings (`SettingsScreen.tsx`)
- **Purpose:** Central configuration for protection policies, scan file-size limits, AI reading grade (`Grade 6` vs. `Grade 8`), USB auto-scan toggles, and notification preferences.
- **User Actions:**
  - Toggle `Real-Time File Shield`, `Auto-Quarantine Critical Threats`, `Shannon Byte Entropy Heuristics`, `Friction Gate Protection`, and `Auto-Scan Removable USB Drives`.
  - Configure `Max Scan File Size Limit (1–2048 MB)` and `Default AI Explanation Reading Level`.
  - Click `Save Settings` or `Reset to Maximum Protection Defaults`.
- **States:**
  - *Empty / Default:* Loaded from DPAPI-authenticated `storage.enc`.
  - *Loading:* Saving and re-computing configuration HMAC.
  - *Success:* `✅ Settings saved and verified` confirmation banner.
  - *Warning:* Inline warning if user lowers protection settings (e.g., turning off `autoQuarantineOnBlock`).
  - *Critical:* `⚠️ Configuration Tamper Detected — Restored Maximum Protection Defaults` if `storage.enc` was modified externally.
  - *Error:* Validation error on out-of-range numeric inputs.
- **Accessibility:** Every checkbox/input is paired with `<label>` and `aria-describedby` explaining its security impact.
- **Performance:** Instantaneous local state updates backed by atomic disk writes.
- **Security Implications:** Weakening any protection toggle requires passing `FrictionGateModal` and obtaining a valid `frictionToken`.

---

### Screen 17: Exclusions — SHA-256 Hash, Path & Domain Exclusions (`ExclusionsScreen.tsx`)
- **Purpose:** Manage false-positive exclusions by **SHA-256 File Hash** (recommended), **Canonical File/Folder Path**, or **Web Domain** with mandatory Expiration TTLs and strict anti-abuse guardrails.
- **User Actions:**
  - Select exclusion type (`SHA-256 Hash`, `File/Folder Path`, `Domain`), enter value, choose **Expiration TTL** (`24 Hours`, `7 Days`, `30 Days`, `Permanent`), and click `Add Exclusion` (requires `FrictionGateModal`).
  - Remove individual exclusions or click `Clear All Exclusions` (no friction gate required to tighten security).
- **States:**
  - *Empty:* `✅ Zero Exclusions Active — 100% inspection coverage.`
  - *Loading:* Validating path canonicalization or 64-char SHA-256 hex syntax.
  - *Success:* Exclusion added to active table showing `Type`, `Value`, `Created`, and `Expires At`.
  - *Warning:* Active path exclusions show an informational banner recommending SHA-256 hash exclusions instead.
  - *Critical (`🔴 FORBIDDEN EXCLUSION BLOCKED`):* Hard blocks attempts to exclude `C:\`, `C:\Windows`, `Downloads`, `%TEMP%`, `%APPDATA%`, or wildcard executable extensions (`*.exe`, `*.ps1`, `*.bat`).
  - *Error:* Malformed SHA-256 hash or relative path rejection.
- **Accessibility:** Accessible table with keyboard row deletion and clear validation error announcements.
- **Performance:** $O(1)$ in-memory Set/Trie lookup adds $<0.01\text{ ms}$ per scan.
- **Security Implications:** Defeats malware exclusion-tampering attacks via hard-blocked staging directories + Friction Gate + DPAPI HMAC storage.

---

### Screen 18: Trusted Applications — Ransomware Shield App Allowlist/Blocklist (`TrustedAppsScreen.tsx`)
- **Purpose:** Manage which applications are trusted or blocked from modifying files inside **Protected Folders** (`Ransomware Shield`), pinning trust to `(CanonicalPath + SHA-256 Hash + Signer)`.
- **User Actions:**
  - Add a Trusted Application (via file picker or path input, gated by `FrictionGateModal`) which automatically computes and pins the binary's SHA-256 hash.
  - Toggle an app between `TRUSTED (ALLOW)` and `BLOCKED`, or `Revoke Trust`.
  - Click `Verify All Trusted App Hashes` to check if any trusted binary on disk was modified.
- **States:**
  - *Empty:* Default signed OS productivity baseline active; no custom apps added.
  - *Loading:* Computing SHA-256 and checking PE Authenticode header of selected binary.
  - *Success:* `🟢 Verified — Binary SHA-256 matches pinned trust record`.
  - *Warning:* Warning displayed if user attempts to trust a command shell or script interpreter (`powershell.exe`, `cmd.exe`, `python.exe`).
  - *Critical (`🔴 BINARY MODIFIED — TRUST AUTOMATICALLY REVOKED`):* If a trusted binary's on-disk SHA-256 no longer matches its pinned hash, trust is immediately revoked (fail-closed).
  - *Error:* Binary path no longer exists on disk.
- **Accessibility:** Clear status badges (`TRUSTED`, `BLOCKED`, `HASH MISMATCH`) and accessible action buttons.
- **Performance:** Hash verification uses fast streaming reads and cached `mtime`/`size` checks.
- **Security Implications:** Binding trust to SHA-256 prevents process replacement or trojanized updater attacks against Protected Folders.

---

### Screen 19: Recovery — Ransomware Shadow Vault Rollback & Privacy Crypto-Shredder (`RecoveryScreen.tsx` + `PrivacyScreen.tsx`)
- **Purpose:** Unified emergency recovery and zero-knowledge data erasure center providing: (1) **1-Click Ransomware Shadow Vault Rollback** to restore personal files modified during a contained attack, (2) **USB / Removable Media Emergency Scanner**, and (3) **One-Click 3-Pass Cryptographic Erasure (`Crypto-Shredder`)**.
- **User Actions:**
  - Inspect **Shadow Vault Recovery Snapshots & Incidents** (`Incident ID`, `Timestamp`, `Affected Files`, `Pre-Attack SHA-256`) and click **`Restore All Clean Files from Shadow Vault`**.
  - Scan connected **Removable USB Drives** (`RemovableDrive[]`) for `autorun.inf` and `.lnk` worms.
  - Execute **One-Click Cryptographic Erasure (`Crypto-Shredder`)** (gated by `FrictionGateModal` 5s countdown) to overwrite and destroy all local history, vault blobs, and keys.
- **States:**
  - *Empty:* `🛡️ Zero Active Incidents — Shadow Vault Standing By (Quota: 2.0 GB Free)`.
  - *Loading:* Decrypting and verifying SHA-256 of Shadow Vault backup blobs during restoration.
  - *Success:* `✅ Emergency Rollback Complete — 100% of modified files restored to clean SHA-256 state` (or `✅ Crypto-Shred Complete`).
  - *Warning:* Shadow Vault quota $>80\%$ full or USB drive attached awaiting scan.
  - *Critical:* Active contained ransomware incident with modified files ready for 1-click rollback.
  - *Error:* Target drive write error during restore; offers alternative safe output folder.
- **Accessibility:** Clear separation between restorative actions (` Emerald / Blue` buttons) and destructive Crypto-Shredder (`Red` button behind Friction Gate).
- **Performance:** Streaming decompression and restore completes in $<50\text{ ms}$ per document.
- **Security Implications:** Shadow Vault backups are encrypted at rest and immune to `vssadmin delete shadows`.

---

### Screen 20: About & Security Status (`AboutSecurityScreen.tsx`)
- **Purpose:** Transparent architectural and security posture reference screen displaying **Architectural Honesty (`RULE-26`)**, **100% Air-Gapped Offline Verification Status**, **AI Boundary Invariant Verification (`CORE -> VERDICT -> AI EXPLANATION`)**, and **Live Network Socket & Windows Firewall Posture (`NetworkMonitorService`)**.
- **User Actions:**
  - Inspect active **Network Connections & C2 IP Audit** (`Local Port`, `Remote IP:Port`, `PID`, `Process Name`, `ThreatIntel Verdict`) and **Windows Defender Firewall Profile Status** (`Domain`, `Private`, `Public`).
  - Run `Verify Air-Gapped & AI Boundary Self-Test` to confirm zero cloud dependence and immutable AI verdict isolation.
  - View engine version, 10-Layer pipeline active status, and security compliance matrix.
- **States:**
  - *Empty / Idle:* Displays architectural overview and cached network posture.
  - *Loading:* Refreshing active TCP socket table (`netstat -ano`) and Windows Firewall profiles.
  - *Success:* `🟢 ALL CONSTITUTIONAL INVARIANTS VERIFIED • FIREWALL ACTIVE • 0 C2 CONNECTIONS`.
  - *Warning:* Windows Firewall disabled on one or more profiles (`⚠️ Public Profile Firewall Off`).
  - *Critical:* Active socket connected to a blocklisted C2 IP in `ThreatIntel` (`🔴 SUSPICIOUS OUTBOUND CONNECTION PID {pid}`) with 1-click `Contain Process` action.
  - *Error:* Socket enumeration restricted by policy; displays local NIC summary.
- **Accessibility:** Semantic tables and compliance checklists with full screen-reader support.
- **Performance:** Socket and firewall query runs asynchronously in $<400\text{ ms}$.
- **Security Implications:** Upholds `RULE-25` and `RULE-26` by transparently reporting exact user-mode capabilities, firewall status, and zero-cloud privacy guarantees.


---

# MOBILE APP SECURITY UX & INTERACTION DESIGN

## 1. Mobile Home / Protection Status
The home screen must immediately show:
- Protection ON/OFF
- App Install Shield
- Download/File Shield
- Web/Phishing Shield
- Threat Database status
- Last Full Scan
- Device Health
- battery/resource mode

The main CTA is Scan Now with Quick / Standard / Full options.

## 2. Installation Warning UX
When a newly installed or installable APK is risky:
- show app name/package,
- risk level,
- evidence categories,
- dangerous permissions,
- signer/certificate information,
- recommended action,
- whether the scan occurred before or immediately after installation.
Never use deceptive "Google Play Protect" branding.

## 3. Download Warning UX
When a downloaded file is suspicious:
- intercept the user-facing "safe" state where technically possible,
- show file type detected from content,
- explain the threat,
- offer Remove / Quarantine / Review,
- show an Android access limitation if the OS prevented automatic scanning.

## 4. Full Scan UX
Use a real progress model:
- files discovered,
- files scanned,
- threats,
- skipped/permission denied,
- current location,
- estimated remaining time,
- pause/cancel/resume.
Do not display fake 0–100% progress.

## 5. Phishing Warning UX
Warnings must be concise but evidence-based:
"This website may be unsafe"
- deceptive domain,
- suspicious redirect,
- credential theft indicators,
- known local threat match,
- unsafe download.
Actions: Go Back, Open Anyway (with friction), Report/Review.

## 6. Password Generator UX
Provide:
- strength meter based on entropy,
- length slider,
- character-set controls,
- passphrase mode,
- copy button with automatic clipboard clearing where supported.
Never display or store generated passwords in analytics/logs.

## 7. Notification Design
Use high-priority notifications only for active threats. Batch repetitive findings. The notification itself must identify the reason and action.

## 8. Permission UX
Each permission screen must answer:
- Why does Privex need this?
- What functionality stops if denied?
- What data remains local?
- How can the user revoke it?

## 9. Accessibility
Mobile security flows must support:
- TalkBack,
- large text,
- high contrast,
- touch target minimums,
- screen-reader labels,
- no color-only severity indicators.

## 10. Trust & Honesty
Every protection state must distinguish:
- PROTECTED
- PROTECTED WITH LIMITATIONS
- DEGRADED
- ACTION REQUIRED
The UI must never say "fully protected" if Android denied required access.

## 11. Mobile Threat Intelligence & Update Diagnostics UX (`ProtectionStatusScreen.tsx`)
- **Metadata Card:** Displays live database properties:
  - Sequence number (e.g., `#1000` for factory seed)
  - Feed source (`factory_seed` or verified OTA bundle publisher)
  - Active record counts (malicious SHA-256 hashes, phishing domains, certificate blocks)
  - Staleness status with color-coded badges (`FRESH`, `AGED`, `STALE`, `EXPIRED_CACHE`)
- **User Actions:**
  - One-click **"Check for Signed Threat Database Updates"** triggering staged signature verification and atomic activation.
  - Emergency **"Rollback to Factory Seed"** action with confirmation dialog, reverting sequence and invalidating caches in $<50\text{ ms}$.
- **Honest Staleness Representation:** If definitions are aged or offline, the UI transparently reports age in days, maintains 100% heuristic baseline protection, and never displays a false "outdated vulnerability" scare banner.
 
+## 12. Mobile Quarantine & Remediation UX (`ProtectionStatusScreen.tsx`)
+- **Quarantine Vault Card:**
+  - Live Vault Statistics: Displays total quarantined items count and aggregate encrypted vault storage size in KB/MB.
+  - Quarantined Item List: Lists each isolated threat with original filename, threat category, isolation timestamp, and current isolation state (`ISOLATED` vs `SOURCE_REMAINS`).
+  - Item Actions:
+    - **Verified Restore:** Confirms restore path, verifies cryptographic GCM auth tag and SHA-256 hash, and atomically restores the original file.
+    - **Permanent Purge:** Deletes encrypted `.vault` blob, updates the atomic manifest, and permanently removes the item from the device.
+- **Package Remediation Guidance:**
+  - Clear Plan Badges: Labels candidate packages with their explicit remediation recommendation (`UNINSTALL_RECOMMENDED`, `FORCE_STOP_RECOMMENDED`, `DISABLE_RECOMMENDED`, or `SYSTEM_APP_PROTECTED`).
+  - Safe OS Intent Launchers: Directs users into Android's native Application Details Settings or standard system uninstall confirmation dialog.
+  - Honest Capability Representation: Explicitly clarifies that Android sandbox rules require user confirmation and does not pretend that background silent uninstallation took place.

