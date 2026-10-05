# PRD.md — Product Requirements Document: Private Protection Windows Antivirus Transformation

> **DOCUMENT STATUS:** CANONICAL PRODUCT REQUIREMENTS DOCUMENT (PRD)  
> **PROJECT:** Private Protection — Windows Desktop Strong Antivirus Transformation  
> **PROBLEM STATEMENT:** PS-05 (Local-First, Offline-First, Low-Latency, Privacy-First Endpoint Protection)  
> **SOURCE POLICY:** Every external claim in this document is explicitly labeled as **`[SOURCE-DERIVED FACT]`** (with official vendor/Microsoft documentation URLs), **`[MODEL/ENGINEERING INFERENCE]`**, or **`[PROJECT DECISION]`**.

---

## 1. Executive Vision & Product Transformation Goal

### 1.1 Primary Objective
Transform **Private Protection Windows Desktop** (`apps/desktop/`) from an on-demand file/URL security scanner into a **real, strong, local-first Windows Antivirus and Endpoint Protection product** capable of continuous background protection, multi-layered malware detection, behavioral process monitoring, ransomware containment and rollback, download/MOTW inspection, encrypted quarantine, and plain-language on-device explanations.

### 1.2 Non-Negotiable Constitutional Principles
1. **LOCAL-FIRST:** All file analysis, signature matching, PE structural parsing, behavioral monitoring, ransomware protection, quarantine encryption, and AI explanation synthesis execute 100% locally on the user's Windows PC.
2. **OFFLINE-FIRST:** The core antivirus engine operates with **100% functional detection parity when completely air-gapped** without internet connectivity.
3. **LOW-LATENCY & RESOURCE-EFFICIENT:** Sub-millisecond cache/header fast paths ($<1.0\text{ ms}$), bounded worker-thread scanning, $<1\%$ idle CPU, $<50\text{ MB}$ idle daemon RSS, and smooth operation on low-end 4 GB RAM Windows laptops.
4. **PRIVACY-FIRST & ZERO-KNOWLEDGE:** Zero Tier-1 user data (files, filenames, paths, document contents, URLs, process lists) is ever uploaded to any cloud service.
5. **STRICT AI BOUNDARY (`CORE -> VERDICT -> AI EXPLANATION`):** The AI Assistant is strictly a read-only explanation synthesizer. It has **zero authority** to compute verdicts, alter risk scores, disable shields, quarantine/restore files, or modify policy.

---

## 2. Official Competitor & OS Mechanism Research (Areas 01–28)

### 2.1 Official Sources Consulted (`[SOURCE-DERIVED FACT]`)
- **Avast Free Antivirus (Official Support & Technical Documentation):**
  - Core Shields (`File Shield`, `Behavior Shield`, `Web Shield`, `Mail Shield`): `https://support.avast.com/en-us/article/antivirus-shield-settings/`
  - Ransomware Shield (Protected Folders, Smart vs. Strict Mode, Protected File Types): `https://support.avast.com/en-us/article/antivirus-ransomware-shield-faq/` & `https://support.avast.com/en-us/article/use-antivirus-ransomware-shield/`
  - Quarantine (Virus Chest encryption, max size, restore & exception): `https://support.avast.com/en-us/article/use-antivirus-quarantine/`
  - Scans & Boot-Time Scan (`aswBoot.exe`): `https://support.avast.com/en-us/article/antivirus-scan-types/` & `https://support.avast.com/en-us/article/antivirus-boot-time-scan/`
  - Advanced `geek:area` Configuration (Transient/Persistent caching, Archive policies): `https://support.avast.com/en-us/article/antivirus-geek-area-settings/`
- **AVG AntiVirus Free (Official Support & Technical Documentation):**
  - Real-Time Shields (`File Shield`, `Behavior Shield`, `Web Shield`, `Email Shield`): `https://support.avg.com/SupportArticleView?urlname=AVG-Antivirus-Shields-Settings`
  - Ransomware Protection (Protected Folders, Blocked/Allowed Apps): `https://support.avg.com/SupportArticleView?urlname=AVG-Antivirus-Ransomware-Protection-FAQ` & `https://support.avg.com/SupportArticleView?urlname=Use-AVG-Antivirus-Ransomware-Protection`
  - Quarantine (Isolation, Restore & Add Exception, `geek:area` file limits): `https://support.avg.com/SupportArticleView?urlname=Use-AVG-Antivirus-Quarantine` & `https://support.avg.com/SupportArticleView?urlname=AVG-Antivirus-Geek-Area`
  - Scans, Boot-Time Scan, and Passive Mode: `https://support.avg.com/SupportArticleView?urlname=AVG-Antivirus-Scan-Types`, `https://support.avg.com/SupportArticleView?urlname=AVG-Antivirus-Boot-Time-Scan`, & `https://support.avg.com/SupportArticleView?urlname=AVG-Antivirus-Passive-Mode`
- **Bitdefender Antivirus Free & Core Engine (Official Support & TechZone Documentation):**
  - Bitdefender Shield (On-Access scanning, "Scan only new and changed files" cache, archive toggles): `https://www.bitdefender.com/consumer/support/answer/13426/` & `https://www.bitdefender.com/consumer/support/answer/28557/`
  - Advanced Threat Defense (Behavioral Process Inspector, danger score threshold, automatic rollback): `https://www.bitdefender.com/consumer/support/answer/2393/` & `https://techzone.bitdefender.com/en/security-layers/prevention/process-inspector.html`
  - Ransomware Remediation (Tamper-proof shadow backups independent of Windows VSS): `https://www.bitdefender.com/consumer/support/answer/2457/`
  - Web Protection (Online Threat Prevention, TLS certificate check, Search Advisor): `https://www.bitdefender.com/consumer/support/answer/1976/`
  - Quarantine (30-day auto-delete, restore with exception): `https://www.bitdefender.com/consumer/support/answer/2092/`
  - Photon Adaptive Scanning Cache: `https://www.bitdefender.com/consumer/support/answer/28558/`
- **Microsoft Windows Official Antivirus & Security Documentation (`learn.microsoft.com`):**
  - File System Minifilter Drivers vs. User-Mode File Monitoring (`ReadDirectoryChangesW`, USN Journal `FSCTL_READ_USN_JOURNAL`, Oplocks `FSCTL_REQUEST_OPLOCK`): `https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-minifilter-drivers`, `https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw`, `https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals`, `https://learn.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks`
  - Process & ETW Monitoring (`Microsoft-Windows-Kernel-Process`, `NtSuspendProcess`, Job Objects): `https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing`, `https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects`
  - Antimalware Scan Interface (AMSI) & Controlled Folder Access: `https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal`, `https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders`
  - Windows Service Hardening (SCM, `SERVICE_FAILURE_ACTIONS`, Restricted Tokens, DACLs, PPL): `https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights`, `https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-`
  - Windows Filtering Platform (WFP): `https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page`

---

### 2.2 Competitor Feature & Mechanism Matrix

| Feature / Capability | Avast Free Antivirus `[SOURCE-DERIVED FACT]` | AVG AntiVirus Free `[SOURCE-DERIVED FACT]` | Bitdefender Antivirus Free `[SOURCE-DERIVED FACT]` | Private Protection (Current Verified State) | Private Protection (Target Antivirus Architecture) `[PROJECT DECISION]` |
|---|---|---|---|---|---|
| **Real-time protection** | Yes (`File Shield` via `aswMonFlt.sys` + `AvastSvc.exe` on open/exec/write) | Yes (`File Shield` via `avgSvc.exe` on open/modify/save/exec) | Yes (`Bitdefender Shield` on open/create/modify/exec with new/changed file cache) | **EXISTS + WEAK** (`fs.watch` non-recursive on `Downloads`/`Temp` only; stops when UI closes) | **YES — Strong User-Mode Service (`pp-guard-service`)**: Recursive `ReadDirectoryChangesW` + NTFS USN Journal catch-up + `CleanFileCache` |
| **File scanning** | Yes (PE, scripts, docs, archives; repair $\rightarrow$ quarantine $\rightarrow$ delete cascade) | Yes (PE, scripts, docs, archives; transient & persistent safe-file cache) | Yes (Multi-layer signature + B-HAVE static/dynamic heuristics + Photon cache) | **EXISTS + WEAK** (64KB magic byte + global entropy + double-extension check only; 0 hash/YARA/PE-import rules) | **YES — 10-Layer Engine**: Hash Bloom + Exact Table, Aho-Corasick/YARA signatures, Magic/MOTW/RTLO, PE32/PE32+ sections/IAT/Authenticode, ZIP/Office parsers |
| **Behavior monitoring** | Yes (`Behavior Shield` / `aswidsagent.exe` monitors process injection & parent-child anomalies) | Yes (`Behavior Shield` monitors suspicious runtime behavior & zero-day actions) | Yes (`Advanced Threat Defense` / Process Inspector scores live process actions; kills at 99% score) | **EXISTS + WEAK** (Manual `tasklist /FO CSV` checking 4 hardcoded names; no paths/CLI/events) | **YES — Real-Time Process & Behavior Engine**: WMI/ETW process creation hooks, PPID lineage tree, LOLBin command-line analysis, cumulative behavior scoring |
| **Ransomware shield** | Yes (`Ransomware Shield` protects `Documents`/`Pictures`/`Desktop` in Smart or Strict Mode) | Yes (Protected Folders in Smart/Strict Mode with Blocked/Allowed app lists) | Yes (`Ransomware Remediation` + ATD entropy/encryption detection + tamper-proof shadow rollback) | **MISSING** (Zero protected folders, zero canary traps, zero burst/entropy velocity detection) | **YES — Multi-Layer Ransomware Shield**: Protected Folders, Kernel Oplock Canary Trap files, Sliding-Window Velocity/Entropy detector, `NtSuspendProcess` tree arrest, CoW Shadow Vault rollback |
| **Web protection** | Yes (`Web Shield` WFP proxy scans HTTP/HTTPS/QUIC, blocks phishing/botnets) | Yes (`Web Shield` blocks malicious URLs, scripts, and downloads) | Yes (`Online Threat Prevention` WFP URL/TLS certificate check + Search Advisor) | **EXISTS + VERIFIED** (`@private-protection/core` URLAnalyzer + MV3 Extension + Desktop URL Scanner) | **YES — Shared Core + MOTW + Optional Hosts/WFP Blocklist**: Unified `@private-protection/core` URL engine across Extension, Web, and Desktop MOTW stream scanner |
| **Download protection** | Yes (Web Shield stream scan + File Shield on disk write completion) | Yes (Web Shield + File Shield on download completion) | Yes (HTTP stream scan + On-Access scan on `.crdownload` $\rightarrow$ final rename) | **EXISTS + WEAK** (Watches top-level `Downloads`, skips `.crdownload`, but ignores subfolders & MOTW `Zone.Identifier`) | **YES — Complete Download Lifecycle Shield**: `.crdownload`/`.part` state machine + NTFS `:Zone.Identifier` (`HostUrl`/`ReferrerUrl`) extraction fed into `URLAnalyzer` + 10-layer file scan |
| **Email protection** | Yes (`Mail Shield` scans POP3/IMAP/SMTP attachments & tags subjects) | Yes (`Email Shield` scans POP3/IMAP/SMTP local client traffic) | Yes (Scans attachments on disk access & webmail links via Online Threat Prevention) | **PARTIAL** (Text/scam message analyzer works; zero `.eml`/`.msg` MIME/attachment parser) | **YES — Practical Local-First Email Protection**: `.eml`/`.msg` MIME header & attachment extraction in `FileAnalyzer` + real-time attachment drop scanning (no brittle TLS MITM proxy) |
| **Quarantine** | Yes (`Virus Chest` encrypted in `ProgramData\Avast Software\Avast\chest`, restore + exception) | Yes (`Quarantine` encrypted vault, 16MB default limit, restore + add exception) | Yes (`Quarantine` encrypted storage, 30-day auto-delete, restore + create exception) | **EXISTS + WEAK** (`PPVAULT1` AES-256-GCM works, but `.vault.key` is plaintext on NTFS, full-file RAM buffer, non-atomic `manifest.json`) | **YES — Hardened `PPVAULT2` Quarantine**: Streaming 64KB AES-256-GCM, Windows DPAPI key wrapping, atomic encrypted manifest, NTFS execute-deny ACLs, Restore + SHA-256 Exclusion |
| **Scheduled scans** | Yes (Daily/Weekly/Monthly/Once, battery pause, CPU priority, wake PC) | Yes (Configurable schedule, battery pause, low priority) | Yes (Custom/Scheduled scans in paid tiers; Free relies on continuous Shield + On-Demand) | **MISSING** (Only manual Quick, Full, and Custom scans exist) | **YES — Battery & Idle-Aware Scan Scheduler**: Daily/Weekly/Startup Catch-Up schedules with automatic pause on battery $<20\%$ or fullscreen load |
| **Quick scan** | Yes (`Smart Scan` / `Quick Scan` targeting high-risk folders & startup) | Yes (`Smart Scan` targeting active processes & common malware zones) | Yes (`Quick Scan` targeting critical system & user locations) | **EXISTS + VERIFIED** (`QuickScanService` scans `Downloads`, `Temp`, `Desktop`) | **YES — Enhanced Quick Scan**: Scans active process binaries, Startup/Run persistence targets, `Downloads`, `Temp`, and `Desktop` in $<10\text{ s}$ |
| **Full scan** | Yes (`Full Virus Scan` across all drives and archives) | Yes (`Deep Scan` across all drives, boot sectors, memory, archives) | Yes (`System Scan` across all local drives with Photon cache) | **EXISTS + WEAK** (`ScannerService` traverses drives sequentially on main thread without safe-file cache) | **YES — Worker-Pool Full Scan with `CleanFileCache`**: Multi-threaded worker pool skipping unchanged clean files in $<0.05\text{ ms}$ |
| **Custom scan** | Yes (`Targeted Scan` + Windows Explorer right-click context menu) | Yes (`File or Folder Scan` + Explorer context menu) | Yes (`Custom Scan` + Explorer right-click "Scan with Bitdefender") | **EXISTS + VERIFIED** (`CustomScanScreen` with native folder/file dialog) | **YES — Custom & Drag-and-Drop Scan**: Folder/file picker, drag-and-drop dropzone, and removable USB presets |
| **Boot / recovery** | Yes (`Boot-Time Scan` via `aswBoot.exe` in Windows boot sequence) | Yes (`Boot-Time Scan` via `sched.exe /A:*` before Windows shell loads) | Yes (`Rescue Environment` reboots into WinRE/Linux clean OS) | **ARCHITECTURALLY BLOCKED** (No boot/WinRE driver) | **Safe Startup Early-Launch Scan + Shadow Vault Recovery**: Pre-login Windows Service startup scan + Ransomware CoW Shadow Vault rollback (Kernel/BCD boot tampering avoided for stability) |
| **Notifications** | Yes (Color-coded Red/Yellow/Blue popups + Silent Mode for fullscreen) | Yes (Toast alerts + Silent/Do-Not-Disturb Mode) | Yes (Autopilot quiet notifications + Special Offers off) | **PARTIAL** (In-app React banner only; zero native Windows OS Toasts or Tray alerts; zero rate limiter) | **YES — Native Windows Toast + Tray + Rate-Limited Notification Center**: Max 3 OS toasts per 10s window, burst coalescing into single summary alert, Fullscreen suppression |
| **Exclusions** | Yes (Global File Paths, URLs, CyberCapture hashes) | Yes (Files, Folders, Websites exceptions list) | Yes (Files, Folders, Extensions scoped to On-Access, On-Demand, or ATD) | **PARTIAL** (`ScannerService` path exclusion array exists in memory; no SHA-256 file allowlist on restore; no UI) | **YES — 3-Tier Exclusion & Trust Manager**: SHA-256 hash exclusions (preferred), canonical path exclusions with TTLs, hard block on excluding `C:\`/`Downloads`/`%TEMP%`, Friction Gate |
| **Offline detection** | **Partial** (Local VPS definitions + static heuristics work offline; CyberCapture & FileRep require cloud) | **Partial** (Local VPS definitions work offline; Cloud reputation & CyberCapture require internet) | **Partial** (Local signatures + B-HAVE + ATD work offline; Global Protective Network cloud lookup offline) | **EXISTS + VERIFIED** (100% air-gapped operation, though file detection depth is weak) | **YES — 100% Air-Gapped Core Parity**: All 10 detection layers, behavioral monitoring, ransomware shield, quarantine, and AI explanations work 100% offline with zero cloud dependency |
| **Cloud dependency** | Moderate (Streaming updates, FileRep, CyberCapture sandbox uploads by default) | Moderate (Cloud reputation queries & sample uploads enabled by default) | High (Heavy reliance on Bitdefender Global Protective Network cloud queries) | **ZERO** (100% local processing) | **ZERO REQUIRED CLOUD DEPENDENCY**: 100% local processing; only Ed25519-signed definition updates (optional/importable offline) |
| **Privacy model** | Commercial telemetry + suspicious sample upload (`CyberCapture`) unless opted out in settings | Commercial telemetry + automatic sample submission unless opted out | Cloud hash/URL telemetry to GPN by default | **STRICT LOCAL-FIRST** (Tier 1 raw payloads never leave device) | **CONSTITUTIONAL ZERO-KNOWLEDGE**: Tier 1 data never leaves device; DPAPI-encrypted local state; HMAC-chained local logs; 1-click Crypto-Shredder |
| **Resource usage** | Moderate-Heavy (Multiple kernel drivers + background processes + UI shells) | Moderate-Heavy (Shared Gen Digital background service + UI processes) | Light-Moderate (`Photon` cache minimizes repeat scans; minimal Free UI) | **Light** (Electron app, but blocks main thread during large file hash/quarantine) | **Ultra-Efficient**: `<1%` idle CPU, `<50MB` service RAM, `<200MB` peak scan RAM, `CleanFileCache` skips 94%+ unchanged files in `<0.05ms` |

---

## 3. Exhaustive Synthesis of All 28 Research Areas

### Research Area 01: File Protection
- **How Competitors Work `[SOURCE-DERIVED FACT]`:** Avast (`aswMonFlt.sys`), AVG (`avgSvc.exe`), and Bitdefender (`Bitdefender Shield`) intercept file open, execution, creation, and modification events, inspect magic headers rather than trusting file extensions, scan PE structures and scripts, and cache clean files keyed by file ID and modification timestamp so unchanged files are not rescanned until definitions update.
- **What Private Protection Must Implement `[PROJECT DECISION]`:**
  1. **4-Stage Sieve Architecture:** Stage 0 (`CleanFileCache` stat check in $<0.08\text{ ms}$) $\rightarrow$ Stage 1 (`4 KB` header slice: Magic Header vs. Extension, RTLO `\u202E` check, NTFS `:Zone.Identifier` MOTW check, SHA-256 Bloom/Exact lookup) $\rightarrow$ Stage 2 (`64 KB` head + `16 KB` tail: Single-pass Aho-Corasick byte/string signature automaton + Zero-allocation `DataView` PE32/PE32+, ZIP Central Directory, and Office OLE/OOXML macro parser) $\rightarrow$ Stage 3 (Section/Sliding-window entropy, `W+X` section check, suspicious IAT API clusters, script de-obfuscation, cross-layer correlation).
  2. **Archive & Document Safety:** Inspect `.zip` central directories and extract/scan inner executables/scripts in bounded memory streams with strict zip-bomb guards (max recursion depth `3`, max compression ratio `100:1`, max decompressed stream `50 MB`). Inspect `.docx/.docm/.xlsx/.xlsm/.pptx/.pptm` for `vbaProject.bin` and external template relationships, OLE2 documents for `VBA`/`Equation Native`, and PDFs for `/JavaScript`, `/JS`, `/Launch`, and `/OpenAction`.

### Research Area 02: Real-Time Protection
- **How Competitors Work `[SOURCE-DERIVED FACT]`:** Run as persistent Windows Services (`AvastSvc.exe`, `avgSvc.exe`, `bdservicehost.exe`) configured with Service Control Manager (`SCM`) auto-restart policies so protection remains active even when the GUI window is closed.
- **What Private Protection Must Implement `[PROJECT DECISION]`:**
  1. **Decoupled Background Protection Daemon / Windows Service (`pp-guard-service`) + System Tray Agent:** Closing the Electron dashboard window minimizes to the Windows System Tray while the background protection service continues running uninterrupted.
  2. **Recursive `ReadDirectoryChangesW` + NTFS USN Journal Catch-Up:** Replace non-recursive `fs.watch` with recursive Windows directory watching across `Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, `%APPDATA%`, and Startup folders, paired with NTFS USN Change Journal (`FSCTL_READ_USN_JOURNAL`) checkpointing to catch files created while the service was starting or resuming from sleep.

### Research Area 03: Process & Behavior Protection
- **How Competitors Work `[SOURCE-DERIVED FACT]`:** Bitdefender ATD (`Process Inspector`) and Avast/AVG `Behavior Shield` track process creation, parent-child trees (e.g., `winword.exe` spawning `powershell.exe`), command-line arguments, and file modification velocity, accumulating a behavioral danger score and terminating the process tree when the threshold is crossed.
- **What Private Protection Must Implement `[PROJECT DECISION]`:**
  1. **Real-Time Process Monitor:** Subscribe to Windows process creation events (`Win32_ProcessStartTrace` / ETW / CIM `Win32_Process` with `ProcessId`, `ParentProcessId`, `ExecutablePath`, `CommandLine`) and maintain an in-memory `ProcessLineageGraph`.
  2. **Parent-Child & LOLBin Anomaly Engine:** Flag high-risk chains (`winword.exe`/`excel.exe`/`outlook.exe`/`acrord32.exe` $\rightarrow$ `powershell.exe`/`cmd.exe`/`mshta.exe`/`wscript.exe`/`rundll32.exe`/`certutil.exe`/`regsvr32.exe`), system binary path masquerading (`svchost.exe` or `lsass.exe` outside `C:\Windows\System32`), encoded PowerShell download cradles (`-enc`, `IEX`, `DownloadString`), and shadow-copy deletion commands (`vssadmin delete shadows`).
  3. **Safe Process Containment:** Suspend (`NtSuspendProcess`) or terminate (`TerminateProcess` / Job Object kill) user-space processes scoring $\ge 90$ (`CONTAIN_PROCESS`), while strictly protecting signed OS system processes (`RULE-09`).

### Research Area 04: 10-Layer Malware Detection Engine
- **How We Combine Signals Without Making the Engine CPU-Heavy `[PROJECT DECISION]`:**
  - Execute the **10-Layer Detection Model** (`L1: Known-Good/Bad Hashes & CleanFileCache`, `L2: Aho-Corasick/YARA Signatures`, `L3: Metadata/MOTW/Authenticode/RTLO`, `L4: Static Heuristics/Entropy/IAT`, `L5: Zero-Alloc Structural PE/ZIP/Office`, `L6: Behavioral Signals`, `L7: Local Reputation`, `L8: Cross-Layer Correlation`, `L9: Non-Linear Log-Odds Risk Scorer`, `L10: Verdict Policy`) as a **4-Stage Short-Circuit Sieve** where ~94% of unchanged files exit at Stage 0 in $<0.08\text{ ms}$, ~4.5% of clean non-executable media exit at Stage 1 in $<0.50\text{ ms}$, and only ~1.5% candidate files undergo Stage 2/3 deep inspection in Worker Threads.

### Research Area 05: Ransomware Protection
- **How Competitors Work `[SOURCE-DERIVED FACT]`:** Avast and AVG implement **Protected Folders** (`Documents`, `Pictures`, `Desktop`) with **Smart Mode** (trusted signed apps allowed, untrusted apps blocked/prompted) and **Strict Mode** (all untrusted apps blocked). Bitdefender combines behavioral entropy/encryption detection with **Ransomware Remediation** (local tamper-proof shadow backups independent of Windows VSS so files can be restored even if `vssadmin delete shadows` was attempted).
- **What Our Ransomware Shield Must Do `[PROJECT DECISION]`:**
  1. **Protected Folders & App Access Control:** Protect `Documents`, `Pictures`, `Desktop`, and user-added folders with Smart Mode (default) and Strict Mode, verifying application identity via `(CanonicalPath + SHA256 + Authenticode Signer)`.
  2. **Decoy Canary Trap Files with Kernel Oplocks:** Seed hidden decoy files (`~$_PrivateProtection_Canary_*.docx/.xlsx`) in protected folders and hold read/handle opportunistic locks (`FSCTL_REQUEST_OPLOCK`) or priority watcher hooks so any write/rename/delete by a non-system process triggers sub-50ms process arrest.
  3. **Sliding-Window Velocity & Entropy Spike Detector:** Detect $\ge 25$ file modifications in $3.0\text{ s}$ combined with $\ge 8$ high-entropy writes ($H > 7.5$, $\Delta H > 1.5\text{ bits/byte}$) or $\ge 10$ mass extension renames (`.locked`, `.encrypted`).
  4. **Copy-on-Write Shadow Vault (`~/.private-protection/shadow-vault/`):** Maintain an encrypted, SYSTEM/Service-ACL-protected local backup cache (default `2 GB` quota, max `50 MB` per document, LZ4 compressed) independent of Windows VSS, enabling 1-click restoration of any personal document modified before process termination.

### Research Area 06: Quarantine
- **What Must Be Improved Over Existing `QuarantineService` `[PROJECT DECISION]`:**
  1. Upgrade from full-file in-memory `PPVAULT1` to **streaming 64 KB chunked `PPVAULT2` AES-256-GCM** (keeping backward decrypt compatibility for `PPVAULT1`) so quarantining a 500 MB file uses $<16\text{ MB}$ heap.
  2. Wrap the master vault key (`vault.dpapi`) using **Windows DPAPI (`CryptProtectData` / Electron `safeStorage`)** instead of storing plaintext `.vault.key` on NTFS.
  3. Acquire **exclusive file handles (`FILE_SHARE_NONE`)** and verify `FILE_ATTRIBUTE_REPARSE_POINT` before reading/unlinking to eliminate TOCTOU race conditions.
  4. Write `manifest.json.enc` atomically via write-to-temp + `fsync` + atomic `rename` with a `.bak` recovery snapshot.
  5. Add **"Restore & Trust this file version (SHA-256)"** so restored false positives are not immediately re-quarantined by `RealtimeMonitorService`.

### Research Area 07: Web Protection
- **How Desktop + Extension + Web Share the Same Protection Core `[PROJECT DECISION]`:**
  - All platforms share `@private-protection/core` (`URLAnalyzer`, `RuleEngine`, `BloomFilter`, `ThreatIntel`, `RiskScorer`).
  - On Windows Desktop, Web Protection operates through three zero-MITM layers: (1) Native Messaging / local IPC synchronization with the Private Protection MV3 Browser Extension; (2) Desktop **Mark-of-the-Web (`:Zone.Identifier`) URL Inspector** that automatically extracts `HostUrl` and `ReferrerUrl` from every downloaded file on NTFS and scans them through `URLAnalyzer` + `ThreatIntel`; and (3) Interactive On-Device URL & Phishing Scanner in the Desktop UI.

### Research Area 08: Download Protection
- **When a Downloaded File Must Be Scanned `[PROJECT DECISION]`:**
  - **Phase 1 (In-Flight Suppression):** While browser temporary extensions (`.crdownload`, `.part`, `.download`, `.partial`, `.opdownload`) are being written, suppress premature quarantine and track the pending download state.
  - **Phase 2 (Immediate Completion Interception, $<50\text{ ms}$):** At the exact moment the browser renames `.crdownload` $\rightarrow$ final filename (or closes the write handle), immediately open the file, read `:Zone.Identifier` (`HostUrl` / `ReferrerUrl`), run `@private-protection/core` `URLAnalyzer` on the origin URLs, and run the 10-Layer File Detection Engine on the file bytes before the user can double-click it.

### Research Area 09: Email Protection
- **Which Email Protection Is Practical for Our Local-First Architecture `[PROJECT DECISION]`:**
  - We **reject** installing a local POP3/IMAP TLS MITM proxy certificate (which breaks mail client certificate pinning and introduces severe attack surface).
  - Instead, we implement **Two-Pronged Local Email Protection**:
    1. **Native `.eml` / `.msg` / `.mbox` File & Attachment Parser in `FileAnalyzer`:** Parses MIME headers (`From` vs. `Reply-To`/`Return-Path` spoofing, `Authentication-Results` SPF/DKIM/DMARC failures), extracts body text/URLs into `TextAnalyzer` and `URLAnalyzer`, and decodes Base64/quoted-printable attachments in memory through the 10-Layer File Engine.
    2. **Real-Time Email Attachment Drop Protection:** Monitors local mail client attachment cache/download directories (`Downloads`, `%LOCALAPPDATA%\Packages\microsoft.windowscommunicationsapps*`, Outlook temp `Content.Outlook` / `INetCache`) and scans every saved attachment immediately.

### Research Area 10: Network Protection
- **Firewall vs. Windows-Native Integration Decision `[PROJECT DECISION]`:**
  - Building a custom NDIS/WFP packet-filtering firewall driver is **not justified** and is classified as `NOT RECOMMENDED` for the core release due to kernel driver signing requirements and network throughput risks.
  - Instead, we implement **User-Mode Network Connection & Windows Firewall Integration**:
    1. **Active Socket-to-Process Auditor (`NetworkMonitorService`):** Enumerate active TCP/UDP connections (`GetExtendedTcpTable` / `netstat -ano`), map remote IPs/ports to owning `PID` and binary path, and check remote IPs against `@private-protection/core` `ThreatIntel.lookupIp()` and suspicious C2 port heuristics.
    2. **Windows Firewall Posture & Optional Outbound Block Rule Helper:** Query real Windows Defender Firewall profile states (`Domain`, `Private`, `Public`) via `netsh advfirewall` / WMI and allow blocking a confirmed malicious process's outbound network access via native Windows Firewall rules or process termination.

### Research Area 11: Startup & Persistence Protection
- **What Must Be Monitored `[PROJECT DECISION]`:**
  - Upgrade `PersistenceAuditorService` to monitor and audit:
    1. Per-User & All-Users Startup Folders (`%APPDATA%\...\Startup` and `%ProgramData%\...\Startup`), including parsing binary `.lnk` shortcut target paths and command-line arguments.
    2. Windows Registry Persistence Keys (`HKCU` & `HKLM` `Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `RunOnceEx`, `Winlogon\Shell`, `Winlogon\Userinit`, and `Image File Execution Options` debugger hijacks).
    3. Windows Scheduled Tasks (`schtasks /Query /FO CSV /V`) and non-Microsoft Windows Services pointing to unsigned binaries or scripts in `Users\`, `AppData\`, `Temp\`, or `Downloads\`.

### Research Area 12: USB & Removable Media Protection
- **What Must Happen on USB Insertion `[PROJECT DECISION]`:**
  - Upgrade `RemovableMediaService` to detect true removable volumes (`DRIVE_REMOVABLE` / `DriveType=2` with real total/free byte capacity), automatically inspect the root directory and first-level folders within $<200\text{ ms}$ of mount for `autorun.inf`, hidden `.lnk` shortcut worms (where folders are hidden with `+h +s` and replaced by `.lnk` files invoking `cmd.exe`/`powershell.exe`), and root executables, and prompt the user via a native toast/banner to run a 1-click USB Drive Scan.

### Research Area 13: Scheduled Scanning
- **What Scheduled Scans Must Support `[PROJECT DECISION]`:**
  - Implement `ScanSchedulerService` supporting configurable **Daily Quick Scan**, **Weekly Full Scan**, and **Startup Catch-Up Scan** (if a scheduled scan was missed while the PC was off).
  - Enforce **Battery & Activity Guards:** Automatically pause or defer scheduled scans when running on battery power (`<20%`), when system CPU load $>80\%$, or when a fullscreen game/presentation is active.

### Research Area 14: Boot / Offline Recovery
- **Honest Capability Decision `[PROJECT DECISION]`:**
  - Pre-OS kernel boot-time drivers (`aswBoot.exe`) and custom WinRE Linux ISOs are classified as `ARCHITECTURALLY BLOCKED / P4 FUTURE` for an unprivileged/user-mode architecture.
  - Instead, we provide **Two Practical Recovery Capabilities**:
    1. **Early-Startup High-Priority Sweep:** Immediately upon service/system startup, scan all active processes, loaded modules, and Startup/Run persistence targets before user workflows begin.
    2. **Ransomware Shadow Vault & Quarantine Recovery Screen (`RecoveryScreen.tsx`):** 1-click restoration of clean pre-encryption file snapshots from the local Copy-on-Write Shadow Vault and safe restoration of false-positive quarantined items.

### Research Area 15: Automatic Notifications
- **When and How to Notify Without Spamming `[PROJECT DECISION]`:**
  - Implement `NotificationService` combining **Native Windows OS Toast Notifications** (`Electron.Notification` / Windows Toast XML), **System Tray Icon Status Badges**, and **In-App Threat Banners/Modals**.
  - **Strict Rate-Limiting & Coalescing (`RULE-15`):** Cap native OS toasts at **$\le 3$ toasts per 10-second window**. If $\ge 3$ threats occur within 5 seconds, coalesce all subsequent detections into a single **Batch Threat Summary Notification**. Suppress `LOW`/`MEDIUM` toasts during fullscreen apps while executing `CRITICAL` containment automatically.

### Research Area 16: Automatic Response Ladder
- **Deterministic 5-Tier Response Policy `[PROJECT DECISION]`:**
  - `LOW` (Score $15\text{–}39$, `INFORM`): Log silently to encrypted audit history; allow access.
  - `MEDIUM` (Score $40\text{–}69$, `WARN`): Emit non-intrusive Amber warning toast + prompt user (`Quarantine` vs. `Keep & Ignore Once`).
  - `HIGH` (Score $70\text{–}89$, `BLOCK`): Hold/block file; auto-quarantine if `autoQuarantineOnBlock` is enabled and `confidence >= 0.85`, or prompt immediate `Quarantine File` modal.
  - `CRITICAL` (Score $90\text{–}100$, `BLOCK`, `confidence >= 0.90`): Immediately auto-quarantine into `.ppvault2`, terminate associated untrusted process if running from `Temp`/`Downloads`, and emit Red critical toast.
  - `RANSOMWARE_BEHAVIOR` (Canary modified OR mass encryption burst): Immediately suspend/terminate offending user-space process tree (`CONTAIN_PROCESS`), quarantine binary, lock protected folders, and open Shadow Vault Recovery prompt.

### Research Area 17: False Positive Management
- **How False Positives Are Prevented & Remediated `[PROJECT DECISION]`:**
  - **3-Tier Allowlist:** Tier A (Immutable Microsoft/OS signed system binaries in `C:\Windows\System32` — never quarantined), Tier B (Verified Authenticode publisher & known-good SHA-256 hash cache), Tier C (User-defined exclusions by **SHA-256 Hash**, **Canonical Path**, or **Domain** with optional expiration TTL).
  - **Restore + Trust Workflow:** Restoring an item from Quarantine offers a 1-click **"Restore & Trust this file version (SHA-256)"** option so `RealtimeMonitorService` never enters an infinite re-quarantine loop.

### Research Area 18: Threat Intelligence Architecture
- **Offline Threat Database Format `[PROJECT DECISION]`:**
  - Package offline threat intelligence into a compact, memory-mapped binary format (`PPBF` Kirsch-Mitzenmacher Bloom Filter + Exact Confirmation Table + Compiled Aho-Corasick Signature Automaton) totaling **$< 10\text{ MB}$ on disk**, seeded with EICAR + malware SHA-256 hashes, YARA-lite byte/string signatures, malicious domains/URLs/IPs, and verified clean system hashes.

### Research Area 19: Engine & Signature Updates
- **Cryptographically Signed Update Pipeline `[PROJECT DECISION]`:**
  - Support both **Online Signed Delta Updates** and **Offline Signed Bundle Import (`.ppdb`)** for air-gapped PCs.
  - Every bundle is verified via **Ed25519 signature** over canonical `(version || versionSequence || publishedAt || sha256)`, checked against a DPAPI-persisted monotonic `versionSequence` counter (anti-downgrade), smoke-tested in a staging directory, swapped atomically via RCU/rename, and automatically rolled back to the previous `N-1` snapshot if post-activation validation fails.

### Research Area 20: Performance Optimization
- **How We Keep the PC Fast `[PROJECT DECISION]`:**
  - `CleanFileCache` (LRU of 65,536 entries keyed by `(dev, ino, size, mtimeNs, engineVer, dbVer)`), 4 KB/64 KB header-first slicing, deferred SHA-256 streaming, precomputed `ENTROPY_LUT[4097]` lookup table (zero `Math.log2()` calls at runtime), single-pass `Int32Array` Aho-Corasick automaton, and a bounded **Worker Thread Pool** (`max(1, min(4, cores - 1))`) with automatic battery/CPU throttling.

### Research Area 21: Self-Protection
- **Honest User-Mode Self-Protection `[PROJECT DECISION]`:**
  - Harden process DACLs (`SetKernelObjectSecurity` stripping `PROCESS_TERMINATE` and `PROCESS_VM_WRITE` for non-elevated tokens where supported), enforce `sandbox: true` and `contextIsolation: true` on the Electron renderer, restrict NTFS ACLs on the Quarantine Vault and config directories, and verify startup SHA-256/Ed25519 integrity of application bundles and threat databases.

### Research Area 22: Tamper Protection
- **Preventing Silent Disabling of Protection `[PROJECT DECISION]`:**
  - Protect security-lowering actions (disabling Real-Time Shield, disabling Ransomware Shield, adding Exclusions, restoring critical malware, or triggering Crypto-Shredder) behind an interactive **Friction Gate Challenge** (cryptographic challenge nonce + 3–5 second hold timer), require a mandatory **Auto-Re-Enable Timer** (`15m`, `30m`, `1h`, or `Until Reboot`) when pausing shields, and fail closed to Maximum Protection Defaults if `settings.enc` is tampered with on disk.

### Research Area 23: Self-Health & Watchdog
- **4-State Health Model & Watchdog Recovery `[PROJECT DECISION]`:**
  - Continuously evaluate system health across 4 canonical states: **`HEALTHY`** (Green), **`WARNING`** (Amber — e.g., definitions stale $>7$ days or temporary shield snooze active), **`DEGRADED`** (Orange — e.g., worker recovered from crash or sub-shield disabled), and **`CRITICAL`** (Red — Real-Time Shield off, vault/config tamper detected, or unquarantined critical threat).
  - Run an internal `WatchdogService` that monitors scanner worker threads, filesystem watcher handles, and storage integrity every `2,000 ms`, automatically respawning crashed workers or re-binding dropped directory watchers in $<500\text{ ms}$.

### Research Area 24: Logging & Local Forensics
- **Tamper-Evident, Privacy-Preserving Audit Log `[PROJECT DECISION]`:**
  - Implement `AuditLoggerService` recording structured events (`THREAT_DETECTED`, `FILE_QUARANTINED`, `FILE_RESTORED`, `PROCESS_CONTAINED`, `RANSOMWARE_CANARY_TRIPPED`, `SCAN_COMPLETED`, `SHIELD_STATE_CHANGED`, `EXCLUSION_MODIFIED`, `UPDATE_APPLIED`, `CONFIG_TAMPER_DETECTED`) in an encrypted local store where each entry contains `prevHash` and `entryHmacSha256 = HMAC(K_audit, prevHash || canonicalJson)` to guarantee tamper-evidence while scrubbing all Tier-1 raw file/message contents.

### Research Area 25: User Experience & Clear Explanations
- **Calm, Authoritative, Plain-Language UX `[PROJECT DECISION]`:**
  - Every alert and hero banner answers 4 questions at a Grade 6–8 reading level: **WHAT HAPPENED**, **WHY IT MATTERS**, **WHAT PRIVATE PROTECTION DID**, and **WHAT THE USER SHOULD DO**.

### Research Area 26: AI Assistant Role & Strict Boundary
- **Immutable Unidirectional Pipeline `[PROJECT DECISION]`:**
  - `CORE ENGINE -> VERDICT -> AI EXPLANATION`. Enforced via `PromptSanitizer`, `<UNTRUSTED_EVIDENCE_DATA>` structural isolation, `SchemaValidator`, and `ResponsePolicy.enforceAuthority()`.

### Research Area 27: Low-End Windows Device Support
- **Hardware Floor & Adaptive Scaling `[PROJECT DECISION]`:**
  - Engineered for smooth operation on entry-level Windows 10/11 laptops (**4 GB RAM, dual-core CPU, SATA SSD/HDD**): limits worker pool to 1–2 threads on $\le 4\text{ GB}$ RAM systems, caps active scan memory at $<200\text{ MB}$ via 64 KB streaming, and disables non-essential UI animations when low-memory pressure is detected.

### Research Area 28: Offline vs. Online Mode Matrix
- **100% Core Protection Offline `[PROJECT DECISION]`:**
  - **Works 100% Offline:** All 10 file detection layers, `CleanFileCache`, Aho-Corasick signatures, PE/ZIP/Office structural parsing, MOTW analysis, Process & Behavior monitoring, Ransomware Shield & Shadow Vault rollback, Quarantine, Scheduled/Quick/Full/Custom scans, AI Explanations (local templates/SLM), Native Notifications, and Audit History.
  - **Uses Optional Network Only:** Checking/downloading Ed25519-signed threat database updates (also supported via offline `.ppdb` file import).

---

## 4. Existing Repository Audit & Gap Analysis Summary

| # | Capability Area | Current Status | File Citations & Key Gap Summary |
|---|---|---|---|
| **01** | File Protection | `EXISTS + WEAK` | `apps/desktop/src/core/file-analyzer.ts:1-95`, `packages/core/src/analyzers/file-analyzer.ts:1-504`. Reads 64KB magic/entropy/double-ext only; ignores computed SHA-256; lacks PE section/IAT, archive, macro, and byte signatures. |
| **02** | Real-Time Protection | `EXISTS + WEAK` | `apps/desktop/src/services/realtime-monitor.service.ts:1-216`. Uses non-recursive `fs.watch` on top-level `Downloads`/`Temp` only; stops when Electron window closes; no `CleanFileCache`. |
| **03** | Process / Behavior Protection | `EXISTS + WEAK` | `apps/desktop/src/services/process-auditor.service.ts:1-112`. Manual `tasklist /FO CSV` checking 4 dummy names (`svchost32.exe`, etc.); no full path, PPID, command-line, or real-time hook. |
| **04** | Malware Detection Engine | `PARTIAL` | `packages/core/src/rules/rule-engine.ts:1-502`. Has 21 URL/Text rules but **0 File rules**; does not detect EICAR or payload strings (`Mimikatz`, `vssadmin`) unless filename has a double extension. |
| **05** | Ransomware Protection | `MISSING` | Zero Protected Folders, zero canary trap files, zero rapid encryption/velocity detector, zero Shadow Vault rollback. |
| **06** | Quarantine | `EXISTS + WEAK` | `apps/desktop/src/services/quarantine.service.ts:1-391`. `PPVAULT1` AES-256-GCM works, but `.vault.key` is plaintext on NTFS, buffers whole file in RAM, `manifest.json` is non-atomic, and lacks Restore+Allowlist. |
| **07** | Web Protection | `EXISTS + VERIFIED` | `packages/core/src/analyzers/url-analyzer.ts:1-459`, `apps/extension/`. Verified phishing/homograph/typosquatting detection; needs NTFS `:Zone.Identifier` MOTW integration on Desktop. |
| **08** | Download Protection | `EXISTS + WEAK` | `realtime-monitor.service.ts:16,138`. Skips `.crdownload`/`.part`, but non-recursive and does not read `:Zone.Identifier` `HostUrl`/`ReferrerUrl`. |
| **09** | Email Protection | `PARTIAL` | `packages/core/src/analyzers/text-analyzer.ts:1-360` scans pasted email text; lacks `.eml`/`.msg` MIME header & attachment file parser. |
| **10** | Network Protection | `EXISTS + WEAK` | `apps/desktop/src/services/network-monitor.service.ts:1-52`. Lists NICs only; does not inspect active TCP sockets (`netstat -ano`), C2 IPs, or real Windows Firewall status; not wired in UI. |
| **11** | Startup / Persistence | `EXISTS + WEAK` | `apps/desktop/src/services/persistence-auditor.service.ts:1-78`. Checks per-user Startup folder filenames only; ignores All-Users Startup, Registry `Run`/`RunOnce`, Scheduled Tasks, and `.lnk` targets. |
| **12** | USB / Removable Media | `EXISTS + WEAK` | `apps/desktop/src/services/removable-media.service.ts:1-91`. Checks `D:\`–`Z:\` existence only; cannot distinguish fixed vs. USB drives; `startMonitoring()` never called; no UI or `autorun.inf` scan. |
| **13** | Scheduled Scanning | `MISSING` | Zero scheduler service, storage schema, or UI exists. |
| **14** | Boot / Offline Recovery | `ARCHITECTURALLY BLOCKED` | Kernel boot driver blocked in user-mode; will implement Startup Early Sweep + Ransomware Shadow Vault Recovery UI (`RecoveryScreen`). |
| **15** | Automatic Notifications | `PARTIAL` | `apps/desktop/src/renderer/App.tsx:289-402`. In-app banner exists; zero native Windows OS Toast notifications, zero System Tray icon, zero storm rate-limiter. |
| **16** | Automatic Response | `EXISTS + VERIFIED` | `realtime-monitor.service.ts:159-174`. Auto-quarantines `BLOCK` verdicts; will expand to 5-tier response ladder including `CONTAIN_PROCESS`. |
| **17** | False Positive Management | `PARTIAL` | `scanner.service.ts:50-77` has in-memory path exclusions; missing SHA-256 file hash allowlist, Restore+Trust workflow, and Exclusions UI. |
| **18** | Threat Intelligence | `EXISTS + WEAK` | `packages/core/src/threat-intel/threat-intel.ts:48-94`. `BloomFilter` exists, but seed DB has 0 file hashes and `lookupHash()` is never called during file scanning. |
| **19** | Engine Updates | `PARTIAL` | `update-verifier.service.ts:1-73`. Ed25519 verifier exists, but `App.tsx:222` hardcodes version `1` and has no bundle import or rollback workflow. |
| **20** | Performance | `EXISTS + WEAK` | 64KB header read is fast, but full-file SHA-256 runs before triage, scans run on the main thread, and no `CleanFileCache` exists. |
| **21** | Self-Protection | `PARTIAL` | `ipc-validator.ts` blocks system path quarantine and bad origins, but `.vault.key`/`.storage.key` lack DPAPI protection and `electron-main.ts:144` has `sandbox: false`. |
| **22** | Self-Health | `PARTIAL` | `ProtectionStatusScreen.tsx` shows basic status, but lacks 4-state Health Model (`HEALTHY`/`WARNING`/`DEGRADED`/`CRITICAL`) and Watchdog auto-recovery. |
| **23** | Logging / Forensics | `PARTIAL` | `secure-storage.service.ts:75-87` stores aggregate scan counts only; lacks per-event HMAC-chained `AuditLogger` and History UI screen. |
| **24** | UX Dashboard | `EXISTS + WEAK` | 11 views exist; needs expansion to the complete 20-Screen Antivirus Command Center (`Scheduled Scan`, `History`, `Ransomware Shield`, `Web Protection`, `Notifications`, `Exclusions`, `Trusted Apps`, `Recovery`). |
| **25** | AI Boundary | `EXISTS + VERIFIED` | `packages/ml/src/security/prompt-boundary.ts:1-72`, `response-policy.ts:1-32`. Strictly enforced and verified by red-team tests. |

---

## 5. Feature Prioritization Matrix (P0 – P4)

| Priority Tier | Definition | Included Capabilities |
|---|---|---|
| **P0: Must-Have Core Antivirus** | Essential capabilities required for Private Protection to function as a real, trustworthy Windows Antivirus. | • **10-Layer Malware Detection Engine** (Hash Bloom/Exact table, EICAR, Aho-Corasick/YARA byte & string signatures, Magic/RTLO/Double-Ext, Zero-Alloc PE32/PE32+ sections/IAT/Authenticode, Script & Office Macro analysis, ZIP Central Directory & inner scan)<br>• **Recursive Real-Time File & Download Shield** (`ReadDirectoryChangesW` / recursive watcher, `.crdownload` completion hook, NTFS `:Zone.Identifier` MOTW URL correlation, System Tray background persistence)<br>• **Hardened `PPVAULT2` Quarantine Vault** (Streaming 64KB AES-256-GCM, DPAPI key protection, atomic encrypted manifest, TOCTOU handle locking, Restore + SHA-256 Trust)<br>• **False-Positive Immunity** (Signed OS binary protection, CleanFileCache, SHA-256/Path Exclusions) |
| **P1: High-Value Protection** | Active behavioral defense, ransomware containment, and core operational visibility. | • **Ransomware Shield** (Protected Folders `Documents`/`Pictures`/`Desktop`, Smart/Strict app access control, Canary trap files, Sliding-Window Velocity & Entropy Spike detector, Copy-on-Write Shadow Vault 1-click rollback)<br>• **Real-Time Process & Behavior Monitor** (WMI/CIM full path, PPID lineage tree, LOLBin command-line analysis, process suspension/termination containment)<br>• **Startup & Persistence Protection** (Both Startup folders + `.lnk` parser, Registry `HKCU`/`HKLM` `Run`/`RunOnce`, Scheduled Tasks)<br>• **Native Windows Toast Notifications & Storm Rate-Limiter** ($\le 3$ toasts / 10s, batch coalescing)<br>• **Tamper-Evident Audit History & 4-State Health/Watchdog Monitor** |
| **P2: Important Supporting Features** | Unattended automation, removable media defense, and extended file/network visibility. | • **Battery & Idle-Aware Scheduled Scanning** (Daily Quick, Weekly Full, Startup Catch-Up)<br>• **USB & Removable Media Auto-Protection** (`DRIVE_REMOVABLE` detection, `autorun.inf` & hidden `.lnk` worm scanner, USB scan prompt)<br>• **Local Email (`.eml`/`.msg`) & Attachment Scanner**<br>• **User-Mode Network Socket & Windows Firewall Posture Auditor** (`netstat -ano` PID mapping + C2 IP lookup + Firewall profile status)<br>• **Signed Offline Update Bundle Import (`.ppdb`) & Last-Known-Good Rollback UI** |
| **P3: Advanced Features** | Deep optimization and cross-platform desktop synergy. | • **Worker Thread Pool Adaptive Scaling & Low-End PC Mode** (`CleanFileCache` persistence across restarts, fullscreen/battery auto-throttling)<br>• **Browser Extension Local Sync Status & Shared Allowlist/Blocklist Management** |
| **P4: Future / Out-of-Scope** | Excluded from current user-mode release for OS stability, licensing, or constitutional reasons. | • **Kernel-Mode Minifilter Driver (`FltMgr.sys`) & ELAM/PPL Driver** (Requires Microsoft WHQL + EV Hardware HSM signing; risks BSOD)<br>• **Pre-OS Boot-Time Kernel Scanner / Custom Linux WinRE ISO**<br>• **Local TLS MITM Network/Email Proxy** (Breaks certificate pinning and weakens endpoint TLS security)<br>• **Mandatory Cloud Sandbox Upload (`CyberCapture`-style file exfiltration)** (Violates Constitutional Tier-1 Privacy Rule) |

---

## 6. Canonical Requirement ID System & Specifications

### 6.1 File Protection & 10-Layer Malware Detection (`AV-FILE-*`)
- **`AV-FILE-001` (Known-Bad & Known-Good Hash Engine — Layer 1):** The engine SHALL maintain an in-memory Kirsch-Mitzenmacher `BloomFilter` and exact confirmation lookup table seeded with malware SHA-256 hashes and standard EICAR hashes (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`), plus a Known-Good signed system binary cache, wired directly into `FileAnalyzer.analyzeFile()` and `CoreFileAnalyzer.analyzeBuffer()`.
- **`AV-FILE-002` (Multi-Pattern Byte & String Signature Engine — Layer 2):** The engine SHALL evaluate a flattened `Int32Array` Aho-Corasick automaton and YARA-style boolean conditions in a single $O(N)$ pass over file buffers to detect EICAR byte strings, credential dumpers (`Mimikatz`, `sekurlsa::logonpasswords`, `MiniDumpWriteDump`), ransomware commands (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set ... recoveryenabled no`, `wbadmin delete catalog`), AMSI/ETW bypasses, and reverse-shell cradles.
- **`AV-FILE-003` (Magic Header, Double Extension & RTLO Detection — Layer 3):** The engine SHALL verify true magic headers (`PE/MZ` with valid `e_lfanew` $\rightarrow$ `PE\0\0`, `ELF`, `Mach-O`, `DEX`, `OLE2`, `ZIP`, `RAR`, `7z`, `PDF`, `LNK`, `OneNote`, `ISO`, `Script`) against declared extensions, and block double/triple extensions (`.pdf.exe`), whitespace padding (`doc.pdf   .exe`), and Unicode Right-to-Left Override (`\u202E`) spoofing.
- **`AV-FILE-004` (Zero-Allocation PE32/PE32+ Structural & IAT Analyzer — Layers 4 & 5):** The engine SHALL parse DOS/COFF/Optional headers, Section Tables (`W+X` permissions, anomalous/packer section names like `UPX0`/`.vmp0`, per-section and sliding-window Shannon entropy via precomputed `ENTROPY_LUT`), Import Address Tables (co-occurring injection APIs `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`, credential harvesting APIs, dynamic `LoadLibrary`+`GetProcAddress` stubs), TLS callbacks, overlays, and Authenticode `IMAGE_DIRECTORY_ENTRY_SECURITY` presence.
- **`AV-FILE-005` (Bounded Archive & Container Inspector — Layer 5):** The engine SHALL inspect `.zip` Central Directories and stream-scan inner executables/scripts up to recursion depth `3`, enforcing hard zip-bomb limits (compression ratio $\le 100:1$, max decompressed bytes $\le 50\text{ MB}$).
- **`AV-FILE-006` (Script, Office Macro, LNK & Email `.eml` Inspector — Layers 4 & 5):** The engine SHALL de-obfuscate Base64/charcode PowerShell/VBScript/JScript/Batch files in memory, detect `vbaProject.bin` and external template links in OOXML (`.docx/.docm/.xlsx/.xlsm`), detect `VBA`/`Equation Native` streams in OLE2 files, parse binary `.lnk` target arguments, and parse `.eml` MIME headers/attachments.
- **`AV-FILE-007` (Cross-Layer Correlation & Non-Linear Scoring — Layers 7–10):** The engine SHALL correlate weak/medium static, origin (MOTW/Ingress path), and behavioral signals in `RiskScorer` to output a deterministic score ($0\text{–}100$) and 6-tier verdict (`ALLOW`, `INFORM`, `WARN`, `BLOCK`, `QUARANTINE`, `CONTAIN_PROCESS`).

### 6.2 Real-Time & Download Protection (`AV-REALTIME-*`)
- **`AV-REALTIME-001` (Recursive Multi-Directory File Shield):** `RealtimeMonitorService` SHALL monitor `Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, Startup folders, and user-configured paths using recursive `ReadDirectoryChangesW` (`fs.watch(..., { recursive: true })`) with automatic watcher health recovery.
- **`AV-REALTIME-002` (Download Completion & NTFS MOTW Correlation):** `RealtimeMonitorService` SHALL track in-progress browser downloads (`.crdownload`, `.part`, `.download`), trigger immediate inspection ($<50\text{ ms}$) upon rename/completion, and parse NTFS `:Zone.Identifier` (`ZoneId`, `HostUrl`, `ReferrerUrl`) through `@private-protection/core` `URLAnalyzer`.
- **`AV-REALTIME-003` (System Tray & Continuous Background Protection):** Closing the main window SHALL minimize Private Protection to the Windows System Tray with live posture icon badges while keeping all real-time shields active in the background.
- **`AV-REALTIME-004` (USB & Removable Media Shield):** `RemovableMediaService` SHALL detect newly mounted removable drives (`DRIVE_REMOVABLE`), report accurate storage capacity, automatically inspect root `autorun.inf` and hidden `.lnk` worms within $<200\text{ ms}$, and surface a 1-click USB Scan action.

### 6.3 Process, Behavior & Persistence Protection (`AV-BEHAVIOR-*`)
- **`AV-BEHAVIOR-001` (Full Process Lineage & Command-Line Auditor):** `ProcessAuditorService` SHALL retrieve full `ProcessId`, `ParentProcessId`, `ExecutablePath`, and `CommandLine` (via WMI/CIM `Win32_Process` with fallback), build a parent-child lineage map, and scan accessible process binaries on disk using `FileAnalyzer`.
- **`AV-BEHAVIOR-002` (LOLBin & Parent-Child Anomaly Detection):** The behavior engine SHALL detect Office/Browser/PDF apps spawning shells (`cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe`, `rundll32.exe`, `certutil.exe`), system process path masquerading (`svchost.exe` outside `System32`), encoded/hidden PowerShell commands, and shadow-copy deletion commands.
- **`AV-BEHAVIOR-003` (Safe User-Mode Process Containment):** When a non-system process triggers a `CONTAIN_PROCESS` verdict (score $\ge 90$), the engine SHALL support immediate process suspension/termination (`TerminateProcess` / `taskkill /F /T`) and binary quarantine while strictly exempting critical signed Windows OS binaries (`RULE-09`).
- **`AV-BEHAVIOR-004` (Comprehensive Startup & Persistence Auditor):** `PersistenceAuditorService` SHALL audit Per-User Startup, All-Users Startup (including `.lnk` target resolution), Registry `HKCU`/`HKLM` `Run`/`RunOnce`, and Scheduled Tasks, flagging and scanning any entry pointing to untrusted/temp paths or scripts.

### 6.4 Ransomware Protection (`AV-RANSOM-*`)
- **`AV-RANSOM-001` (Protected Folders & Trusted App Access Control):** `RansomwareShieldService` SHALL protect `Documents`, `Pictures`, `Desktop`, and custom user folders in Smart Mode (default) or Strict Mode, verifying application trust via `(CanonicalPath + SHA256 + Signer)`.
- **`AV-RANSOM-002` (Decoy Canary Trap Files):** `RansomwareShieldService` SHALL deploy and monitor integrity-pinned canary files in protected folders; any unauthorized modification, rename, or deletion SHALL immediately trigger `RANSOMWARE_BEHAVIOR` containment ($R=100$).
- **`AV-RANSOM-003` (Sliding-Window Mass Encryption & Velocity Detector):** `RansomwareShieldService` SHALL detect rapid file modification bursts ($\ge 25$ modifications in $3.0\text{ s}$ with $\ge 8$ high-entropy writes $H > 7.5$ or $\ge 10$ ransomware extension renames) and arrest the offending process in $<500\text{ ms}$.
- **`AV-RANSOM-004` (Copy-on-Write Shadow Vault Rollback):** `RansomwareShieldService` SHALL maintain an encrypted local Copy-on-Write backup cache (`ShadowVault`, default `2 GB` quota) for protected folder files and provide 1-click restoration (`rollbackRansomwareIncident`) to exact pre-attack SHA-256 hashes.

### 6.5 Web, Email & Network Protection (`AV-WEB-*`)
- **`AV-WEB-001` (Unified Core URL & MOTW Engine):** Desktop URL scanning and download MOTW `HostUrl`/`ReferrerUrl` inspection SHALL use `@private-protection/core` `URLAnalyzer`, `RuleEngine`, and `ThreatIntel` with 100% offline parity.
- **`AV-WEB-002` (Active Network Socket & Firewall Posture Auditor):** `NetworkMonitorService` SHALL enumerate active TCP/UDP connections (`netstat -ano` / `Get-NetTCPConnection`), map sockets to PIDs, flag connections to blocklisted C2 IPs in `ThreatIntel`, and report real Windows Defender Firewall profile states.

### 6.6 Quarantine & Remediation (`AV-QUAR-*`)
- **`AV-QUAR-001` (Streaming `PPVAULT2` AES-256-GCM Encryption):** `QuarantineService` SHALL encrypt and decrypt isolated files using 64 KB chunked streaming `AES-256-GCM` (`PPVAULT2` format while supporting legacy `PPVAULT1` decryption), keeping peak heap delta $<16\text{ MB}$ on 100 MB+ files.
- **`AV-QUAR-002` (DPAPI Key Wrapping & Atomic Encrypted Manifest):** `QuarantineService` SHALL protect the master vault key via Windows DPAPI (`safeStorage` / `CryptProtectData` with fallback) and write `manifest.json.enc` atomically via `.tmp` + `fsync` + `rename` with a `.bak` backup so crashes never wipe the manifest.
- **`AV-QUAR-003` (Race-Free Isolation & Restore + SHA-256 Trust):** `QuarantineService` SHALL pin file handles during isolation, record `:Zone.Identifier` metadata, verify GCM tags and SHA-256 on restore, and support 1-click **"Restore & Add SHA-256 to Allowlist"** to prevent re-quarantine loops.

### 6.7 Notifications & Alert Coalescing (`AV-NOTIFY-*`)
- **`AV-NOTIFY-001` (Native Windows Toast + In-App Notification Center):** `NotificationService` SHALL dispatch native OS toast notifications and persist an in-app notification inbox with unread counters and severity filtering.
- **`AV-NOTIFY-002` (Token-Bucket Storm Rate-Limiter):** `NotificationService` SHALL enforce a strict limit of $\le 3$ native OS toasts per 10-second window, automatically coalescing burst detections ($\ge 3$ threats in 5s) into a single **Batch Threat Summary Alert**.

### 6.8 Updates & Threat Intelligence (`AV-UPDATE-*`)
- **`AV-UPDATE-001` (Ed25519 Canonical Signature & Anti-Downgrade):** `UpdateVerifierService` SHALL verify Ed25519 signatures over `(version || versionSequence || publishedAt || sha256)`, enforce monotonic `versionSequence`, support offline `.ppdb` bundle import, and support 1-click rollback to the Last-Known-Good (`LKG`) snapshot.

### 6.9 Performance & Scheduled Scanning (`AV-PERF-*`)
- **`AV-PERF-001` (`CleanFileCache` & Fast-Path Sieve):** The engine SHALL maintain a 65,536-entry `CleanFileCache` keyed by `(dev, ino, size, mtimeMs, engineVer, dbVer)` that skips known-clean unchanged files in $<0.08\text{ ms}$.
- **`AV-PERF-002` (Worker Pool & Low-End Resource Budgets):** File scanning SHALL support non-blocking execution, maintaining $<1\%$ idle CPU, $<50\text{ MB}$ idle daemon RSS, $<200\text{ MB}$ peak scan RSS, and throttled `10–30 Hz` IPC progress updates.
- **`AV-PERF-003` (Battery & Idle-Aware Scan Scheduler):** `ScanSchedulerService` SHALL execute scheduled Daily Quick and Weekly Full scans with automatic pause on battery power ($<20\%$) or high system load.

### 6.10 Privacy & Audit Forensics (`AV-PRIVACY-*`)
- **`AV-PRIVACY-001` (Zero Tier-1 Exfiltration & Air-Gapped Parity):** Zero file contents, paths, URLs, or process arguments SHALL ever be transmitted over the network; 100% of core detection SHALL work air-gapped.
- **`AV-PRIVACY-002` (HMAC Hash-Chained Encrypted Audit Log & Crypto-Shredder):** `AuditLoggerService` SHALL record security events in an encrypted, append-only HMAC-SHA256 hash-chained log (`audit.log.enc`) with Tier-1 data minimization and full destruction support via the 3-pass Crypto-Shredder.

### 6.11 Security, Self-Protection & Watchdog (`AV-SEC-*`)
- **`AV-SEC-001` (Zero-Trust IPC, Rate Limiting & Friction Gate):** `IpcValidator` and `IpcHandler` SHALL enforce strict origin checks, canonical `realpathSync.native()` system-path guards, per-channel Token Bucket rate limiting, and cryptographic Friction Gate tokens + Auto-Re-Enable timers for shield disabling or exclusions.
- **`AV-SEC-002` (4-State Health Monitor & Watchdog Auto-Recovery):** `HealthMonitorService` and `WatchdogService` SHALL continuously evaluate `HEALTHY`, `WARNING`, `DEGRADED`, and `CRITICAL` posture states, detect config/vault tampering (failing closed to Maximum Protection), and auto-recover crashed watchers/workers in $<500\text{ ms}$.
- **`AV-SEC-003` (Immutable AI Security Boundary):** The AI Assistant SHALL remain strictly read-only (`CORE -> VERDICT -> AI EXPLANATION`), receiving only sanitized `Evidence` tokens and validated against Flesch-Kincaid Grade $\le 8$ JSON schemas.

### 6.12 Desktop Antivirus User Experience (`AV-UX-*`)
- **`AV-UX-001` (20-Screen Antivirus Command Center & 4-Pillar Explanations):** The Desktop UI SHALL implement all 20 required antivirus screens/components with the 3-tier posture hero banner (`🟢 PROTECTED`, `🟡 ATTENTION REQUIRED`, `🔴 ACTION REQUIRED`), 4-Pillar plain-language alerts (*What Happened*, *Why It Matters*, *What Private Protection Did*, *What You Should Do*), virtualized lists, and WCAG AA accessibility.

---

## 7. Master Requirement Traceability Matrix

| Requirement ID | Feature Name | Target Architecture Component | Implementation Phase | Primary Verification Test Suite | Measurable Success Metric / SLA |
|---|---|---|---|---|---|
| `AV-FILE-001` | Layer 1 Hash Bloom & Exact Table + EICAR | `ThreatIntel`, `FileAnalyzer` | Phase B, Phase C | `file-analyzer.test.ts` | $100\%$ EICAR & bad-hash detection in $<0.5\text{ ms}$ |
| `AV-FILE-002` | Layer 2 Aho-Corasick & YARA-Lite Signatures | `SignatureAutomaton`, `CoreFileAnalyzer` | Phase C | `pe-deep-analyzer.test.ts` | Single-pass 64KB scan in $<0.3\text{ ms}$; $\ge 99\%$ TPR on test corpus |
| `AV-FILE-003` | Layer 3 Magic, Double-Ext & RTLO Detection | `CoreFileAnalyzer` | Phase C | `file-analyzer.test.ts` | $100\%$ detection of disguised PE, `.pdf.exe`, and `\u202E` RTLO |
| `AV-FILE-004` | Layer 4/5 Zero-Alloc PE32/PE32+, IAT & Authenticode | `PeStructuralParser`, `AuthenticodeVerifier` | Phase C | `pe-deep-analyzer.test.ts`, `authenticode-verifier.test.ts` | Parses PE sections/IAT in $<0.4\text{ ms}$; $0\%$ crash on malformed PE |
| `AV-FILE-005` | Layer 5 Bounded ZIP/Archive Scanner & Bomb Guard | `ZipStructuralParser`, `FileAnalyzer` | Phase C | `archive-scanner.test.ts` | Detects inner EICAR depth $\le 3$; aborts $>100:1$ zip bomb in $<200\text{ ms}$ |
| `AV-FILE-006` | Layer 4/5 Script, Office Macro, LNK & `.eml` Parser | `ScriptAnalyzer`, `OfficeMacroParser` | Phase C, Phase K | `pe-deep-analyzer.test.ts` | Detects encoded PS1, `vbaProject.bin`, OLE macros, & `.eml` attachments |
| `AV-FILE-007` | Layer 7–10 Cross-Layer Correlation & Verdict Engine | `RiskScorer`, `DesktopSecurityAdapter` | Phase B, Phase C | `desktop-security-adapter.test.ts` | Deterministic 0–100 score & 6-tier verdict; $0\%$ false block on clean OS files |
| `AV-REALTIME-001` | Recursive Multi-Directory Real-Time Shield | `RealtimeMonitorService` | Phase E | `realtime-monitor-burst.test.ts` | Recursive subfolder detection in $<50\text{ ms}$ $p95$ |
| `AV-REALTIME-002` | Download Completion & NTFS `:Zone.Identifier` MOTW | `RealtimeMonitorService`, `MotwAnalyzer` | Phase E, Phase J | `motw-ads-analyzer.test.ts` | $0$ partial `.crdownload` false blocks; $+35\text{..}85$ score on malicious `HostUrl` |
| `AV-REALTIME-003` | System Tray & Background Service Continuity | `ElectronMain`, `TrayController` | Phase E | `desktop-runtime-e2e.test.ts` | Protection remains $100\%$ active when main window is closed |
| `AV-REALTIME-004` | USB & Removable Media Auto-Protection | `RemovableMediaService` | Phase M | `removable-media.test.ts` | Detects `autorun.inf` & `.lnk` worms within $<200\text{ ms}$ of mount |
| `AV-BEHAVIOR-001` | Process Lineage Tree & Binary Disk Scanner | `ProcessAuditorService` | Phase F | `process-auditor.test.ts` | Extracts full path, PPID, & CLI; maps parent-child process tree |
| `AV-BEHAVIOR-002` | LOLBin & Parent-Child Behavioral Scoring | `BehaviorEngine`, `ProcessAuditorService` | Phase F | `process-auditor.test.ts` | $100\%$ detection on 25 LOLBin, Office-spawns-shell, & masquerade fixtures |
| `AV-BEHAVIOR-003` | Safe User-Mode Process Containment | `ProcessAuditorService` | Phase F | `process-auditor.test.ts` | Suspends/kills test malicious child PID in $<100\text{ ms}$; never kills OS processes |
| `AV-BEHAVIOR-004` | Startup, Registry `Run` & Scheduled Task Auditor | `PersistenceAuditorService` | Phase L | `persistence-auditor.test.ts` | Audits both Startup folders, `.lnk` targets, `HKCU`/`HKLM` Run, & Tasks |
| `AV-RANSOM-001` | Protected Folders & Trusted App Access Control | `RansomwareShieldService` | Phase G | `ransomware-shield.test.ts` | Blocks untrusted process writes to Protected Folders in Smart/Strict mode |
| `AV-RANSOM-002` | Decoy Canary Trap File Monitoring | `RansomwareShieldService` | Phase G | `ransomware-shield.test.ts` | Canary tamper triggers containment in $<100\text{ ms}$ ($R=100$) |
| `AV-RANSOM-003` | Sliding-Window Velocity & Entropy Burst Detector | `RansomwareShieldService` | Phase G | `ransomware-shield.test.ts` | Stops simulator in $<500\text{ ms}$ before $>3$ non-canary files are altered |
| `AV-RANSOM-004` | Copy-on-Write Shadow Vault & 1-Click Rollback | `ShadowVaultService` | Phase G | `ransomware-shield.test.ts` | Restores $100\%$ of modified sandbox files to exact pre-attack SHA-256 |
| `AV-WEB-001` | Shared Core URL Scanner & Extension Sync | `DesktopSecurityAdapter`, `UrlAnalyzer` | Phase J | `desktop-flow.test.ts` | $<1.0\text{ ms}$ offline URL/phishing evaluation; zero network touch |
| `AV-WEB-002` | Active Socket-to-PID & Windows Firewall Auditor | `NetworkMonitorService` | Phase K | `network-monitor.test.ts` | Maps active TCP sockets to PIDs; flags C2 IPs; queries Firewall status |
| `AV-QUAR-001` | Streaming 64KB `PPVAULT2` AES-256-GCM Vault | `QuarantineService` | Phase D | `quarantine-streaming.test.ts` | Peak heap delta $<16\text{ MB}$ on 100 MB file; $100\%$ GCM tag verification |
| `AV-QUAR-002` | DPAPI Key Wrapping & Atomic Encrypted Manifest | `QuarantineService` | Phase D | `quarantine-streaming.test.ts` | Key sealed via DPAPI/`safeStorage`; atomic `.tmp`+`rename` manifest swap |
| `AV-QUAR-003` | Restore + SHA-256 Trust & Collision Safety | `QuarantineService`, `ThreatIntel` | Phase D, Phase I | `quarantine.service.test.ts` | Restored file with `trustSha256: true` is not re-quarantined by realtime shield |
| `AV-NOTIFY-001` | Native Windows Toast & Notification Center | `NotificationService` | Phase H | `notification-rate-limiter.test.ts` | Renders native toast & in-app alert in $<50\text{ ms}$ |
| `AV-NOTIFY-002` | Token-Bucket Alert Storm Rate-Limiter | `NotificationService` | Phase H | `notification-rate-limiter.test.ts` | $\le 3$ OS toasts per 10s window during 200-file burst; coalesces summary |
| `AV-UPDATE-001` | Ed25519 Signed DB Updates, `.ppdb` Import & Rollback | `UpdateVerifierService`, `UpdateManager` | Phase O | `update-verifier.test.ts` | $100\%$ rejection of forged/downgraded DB; $<200\text{ ms}$ LKG rollback |
| `AV-PERF-001` | 65,536-Entry `CleanFileCache` Fast Sieve | `CleanFileCache`, `FileAnalyzer` | Phase C, Phase P | `performance-benchmark.test.ts` | Cache hit latency $<0.08\text{ ms}$; invalidated automatically on DB update |
| `AV-PERF-002` | Bounded Resource Usage & Throttled Progress | `ScannerService`, `WorkerPool` | Phase P | `performance-benchmark.test.ts` | Idle CPU $<1\%$, Idle RAM $<50\text{ MB}$, Peak Scan RAM $<200\text{ MB}$ |
| `AV-PERF-003` | Battery & Idle-Aware Scan Scheduler | `ScanSchedulerService` | Phase N | `scanner.service.test.ts` | Runs Daily/Weekly/Catch-Up scans; auto-pauses on battery $<20\%$ |
| `AV-PRIVACY-001` | 100% Air-Gapped Parity & Zero Tier-1 Upload | All Core & Desktop Services | Phase A–S | `offline-parity.test.ts`, `network-isolation.test.ts` | $0$ outbound sockets during all scans; $100\%$ offline detection parity |
| `AV-PRIVACY-002` | HMAC Hash-Chained Audit Log & Crypto-Shredder | `AuditLoggerService`, `SecureStorageService` | Phase Q | `secure-storage.service.test.ts` | Detects any log tampering via HMAC chain; 3-pass shred wipes $100\%$ state |
| `AV-SEC-001` | Zero-Trust IPC, Rate Limiter & Friction Gate Tokens | `IpcValidator`, `IpcHandler` | Phase A, Phase Q | `ipc-security.test.ts` | $100\%$ rejection of spoofed origins, traversal, & un-gated shield disables |
| `AV-SEC-002` | 4-State Health Monitor & Watchdog Auto-Recovery | `HealthMonitorService`, `WatchdogService` | Phase Q | `watchdog-crash-recovery.test.ts` | Auto-recovers crashed watcher/worker in $<500\text{ ms}$; fails closed on tamper |
| `AV-SEC-003` | Immutable Read-Only AI Explanation Boundary | `DesktopSecurityAdapter`, `@private-protection/ml` | Phase R | `assistant-prompt-injection.test.ts` | $0/500$ prompt injections alter verdict/score; reading grade $\le 8.0$ |
| `AV-UX-001` | 20-Screen Antivirus Command Center UX | `apps/desktop/src/renderer/` | Phase R | `desktop-runtime-e2e.test.ts` | All 20 screens/views wired to real backend services; WCAG AA contrast |

---

## 8. Measurable Acceptance Criteria for All 20 Master Prompt Success Criteria

1. **Detect known malicious hashes (`SC-01`):** `100%` detection of EICAR and seeded malware SHA-256 hashes in $<0.5\text{ ms}$ via `BloomFilter` + exact confirmation table (`AV-FILE-001`).
2. **Detect suspicious executables (`SC-02`):** $\ge 99.0\%$ True Positive Rate on synthetic PE fixtures (disguised headers, `W+X` sections, packed entry points, injection IAT clusters, double extensions, RTLO) with $p95 < 15\text{ ms}$ (`AV-FILE-003`, `AV-FILE-004`).
3. **Detect suspicious scripts (`SC-03`):** `100%` detection of encoded PowerShell (`-enc`), AMSI bypass patterns, VBScript/JScript download cradles, and Office macro (`vbaProject.bin` / `AutoOpen`) test fixtures (`AV-FILE-002`, `AV-FILE-006`).
4. **Monitor real-time file creation/modification (`SC-04`):** Recursive `ReadDirectoryChangesW` monitoring captures file drops across `Downloads`, `Desktop`, `Documents`, `Pictures`, `%TEMP%`, and subdirectories within $p95 < 50\text{ ms}$ (`AV-REALTIME-001`).
5. **Protect downloads (`SC-05`):** Defers scanning on partial `.crdownload`/`.part` files, scans immediately upon rename completion, and correlates NTFS `:Zone.Identifier` (`HostUrl`/`ReferrerUrl`) with `URLAnalyzer` (`AV-REALTIME-002`).
6. **Monitor suspicious process behavior (`SC-06`):** Detects Office/Browser child shell spawning, path masquerading (`svchost.exe` outside `System32`), and LOLBin command lines, and safely suspends/terminates test child PIDs (`AV-BEHAVIOR-001`–`003`).
7. **Provide ransomware protection (`SC-07`):** Enforces Protected Folders, detects canary modifications in $<100\text{ ms}$ and rapid encryption bursts in $<500\text{ ms}$ (before $>3$ non-canary files are altered), and restores `100%` of modified files from the local Shadow Vault (`AV-RANSOM-001`–`004`).
8. **Quarantine threats safely (`SC-08`):** Isolates files using streaming 64 KB `PPVAULT2` AES-256-GCM ($<16\text{ MB}$ heap delta on 100 MB files), wraps keys via DPAPI/`safeStorage`, writes atomic encrypted manifests, and verifies GCM tag + SHA-256 on restore (`AV-QUAR-001`–`002`).
9. **Support restore and exclusions (`SC-09`):** Supports 1-click **"Restore & Trust SHA-256"**, granular SHA-256/Path/Domain exclusions with TTLs behind a Friction Gate, and hard-blocks excluding `C:\`, `Downloads`, or `%TEMP%` (`AV-QUAR-003`).
10. **Provide web/URL protection (`SC-10`):** Evaluates URLs and download MOTW origins locally in $<1.0\text{ ms}$ using `@private-protection/core` without DNS/HTTP leaks (`AV-WEB-001`).
11. **Provide scheduled and on-demand scans (`SC-11`):** Supports Quick, Full, Custom, USB, and Scheduled (Daily/Weekly/Catch-Up) scans with Pause, Resume, Cancel, and battery/load guards (`AV-PERF-003`).
12. **Notify users clearly (`SC-12`):** Dispatches native Windows OS Toasts and in-app 4-Pillar alerts within $<50\text{ ms}$, rate-limited to $\le 3$ OS toasts per 10s storm window (`AV-NOTIFY-001`–`002`).
13. **Explain threats using AI safely (`SC-13`):** Synthesizes plain-language explanations at Flesch-Kincaid Grade $\le 8.0$ from sanitized `Evidence` structs with `0%` authority over verdicts or scores (`AV-SEC-003`).
14. **Operate offline (`SC-14`):** `100%` functional parity across all detection, behavioral, ransomware, quarantine, and explanation modules when all network APIs are blocked (`AV-PRIVACY-001`).
15. **Keep user data private (`SC-15`):** `0 bytes` of Tier-1 user data transmitted over the network or logged in plaintext; verified 3-pass Crypto-Shredder erasure (`AV-PRIVACY-001`–`002`).
16. **Remain lightweight and fast (`SC-16`):** Idle CPU $<1.0\%$, Idle Daemon RAM $<50\text{ MB}$, Peak Scan RAM $<200\text{ MB}$, `CleanFileCache` hit $<0.08\text{ ms}$ (`AV-PERF-001`–`002`).
17. **Verify updates cryptographically (`SC-17`):** `100%` rejection of unsigned, tampered, or downgraded update manifests via Ed25519 + monotonic sequence check + $<200\text{ ms}$ LKG rollback (`AV-UPDATE-001`).
18. **Protect configuration and quarantine integrity (`SC-18`):** DPAPI + HMAC verification on `settings.enc` and `manifest.json.enc`; fails closed to Maximum Protection on tamper; requires Friction Gate + Auto-Re-Enable timer on shield pause (`AV-SEC-001`–`002`).
19. **Recover cleanly from crashes (`SC-19`):** `WatchdogService` auto-recovers crashed workers/watchers in $<500\text{ ms}$; atomic `.tmp`+`rename` storage prevents manifest corruption on abrupt kill (`AV-SEC-002`).
20. **Pass full test and security verification (`SC-20`):** `100%` test pass rate across all 16 test categories, $\ge 90\%$ code coverage, and `0.00%` false-block rate across the clean signed binary/developer corpus (`RULE-20`).
