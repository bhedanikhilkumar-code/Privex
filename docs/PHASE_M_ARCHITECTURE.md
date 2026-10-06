# PHASE M: USB & REMOVABLE MEDIA PROTECTION ARCHITECTURE

## 1. Executive Overview

Phase M implements production-grade USB & Removable Media Protection for Private Protection Windows Antivirus. It establishes truthful Windows volume discovery, real storage capacity and free-space reporting, non-invasive mount/dismount monitoring, and automatic high-speed ($<200\text{ ms}$) root quick-triage for `autorun.inf` directives, binary `.lnk` shortcut worms, and deceptive root payloads.

All threat analysis strictly flows through the unified canonical detection pipeline (`FileAnalyzer` $\rightarrow$ `RiskScorer` $\rightarrow$ `EngineVerdict`), preserving 100% offline air-gap parity, zero external network sockets, and strict system-process immunity (`RULE-09`).

---

## 2. Architectural Architecture & Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                     WINDOWS OPERATING SYSTEM                           │
│   • Win32_LogicalDisk (DriveType=2 / DRIVE_REMOVABLE)                  │
│   • Periodic polling & mount discovery (2,000ms interval)              │
│   • Real volume capacity & free-space byte query                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   RemovableMediaService (apps/desktop)                  │
│   • Discovers valid removable volumes; rejects fixed drives (C:, D:)   │
│   • Emits 'driveAttached' and 'driveDetached' events                   │
│   • Dispatches high-speed root quick-triage (<200 ms SLA)             │
└───────────────────┬──────────────────────────────────┬─────────────────┘
                    │                                  │
                    ▼                                  ▼
┌───────────────────────────────────────┐  ┌─────────────────────────────┐
│             AutorunParser             │  │          LnkParser          │
│ • Safe bounds-checked INI lexer       │  │ • MS-SHLLINK binary parser  │
│ • Size <= 64 KB, lines <= 500         │  │ • Size <= 1 MB, CLSID check │
│ • RTLO, NUL, and traversal stripping  │  │ • LOLBin & script detection │
│ • Executable & interpreter extraction │  │ • Deceptive folder icon mask│
└───────────────────┬───────────────────┘  └──────────────┬──────────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     CANONICAL DETECTION PIPELINE                       │
│                                                                        │
│     FileAnalyzer (10-Layer PE, Macro, Hashes, Entropy Inspection)     │
│                                  │                                     │
│                                  ▼                                     │
│                       RiskScorer Math Engine                           │
│                                  │                                     │
│                                  ▼                                     │
│                 EngineVerdict & ResponsePolicyEngine                   │
│                                  │                                     │
│              ┌───────────────────┴───────────────────┐                 │
│              ▼                                       ▼                 │
│     QuarantineService                       NotificationService        │
│     (PPVAULT2 Isolation)                    (Security Alert & Toasts)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Subsystems & Components

### 3.1 Truthful Removable Volume Detection (`RemovableMediaService`)
- **Query Mechanism:** Executes PowerShell `Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType,VolumeSerialNumber | ConvertTo-Json -Compress` with `windowsHide: true` and a 3,000 ms timeout.
- **DriveType=2 Invariant:** Only volumes with `DriveType === 2` (`DRIVE_REMOVABLE`) are classified as removable media. Fixed hard drives (3), network shares (4), CD-ROMs (5), and RAM disks (6) are strictly excluded.
- **Real Capacity Reporting:** Exposes actual `totalBytes` and `freeBytes` from WMI/CIM or `fs.statfsSync`. Never hardcodes fake 0-byte sizes.
- **POSIX Fallback:** For cross-platform testing and POSIX targets, enumerates `/Volumes` and `/media` with `fs.statfsSync` byte calculations.

### 3.2 Safe Bounds-Checked Autorun Parser (`AutorunParser`)
- **Resource Constraints:** Max file size $64\text{ KB}$, max lines $500$, max line length $2048$ characters.
- **Sanitization Pipeline:**
  1. Strips all NUL bytes (`\0`) and ASCII control characters ($< 0x20$ except `\t`, `\r`, `\n`).
  2. Strips Unicode Right-to-Left Override (RTLO) and bidirectional control codepoints (`\u202E`, `\u202B`, etc.).
  3. Rejects and sanitizes parent directory traversal (`..\`, `../`) and remote UNC paths (`\\...`).
- **Heuristic Indicators:**
  - `AUTORUN_SCRIPT_INTERPRETER` (risk +85): `open` or `shellexecute` targeting `wscript.exe`, `cscript.exe`, `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`.
  - `AUTORUN_EXECUTABLE_DIRECTIVE` (risk +70): `open` or `shellexecute` executing `.exe`, `.scr`, `.pif`, `.bat`, `.cmd`, `.vbs`, `.ps1`.
  - `AUTORUN_SUSPICIOUS_CLI_FLAGS` (risk +90): contains `-enc`, `hidden`, `downloadstring`, `/c start`, `bypass`, `executionpolicy`.
  - `AUTORUN_TRAVERSAL_TARGET` (risk +80): points outside the root directory.
  - `AUTORUN_UNC_OR_DEVICE_TARGET` (risk +75): references remote UNC share.
- **Payload Correlation:** Passes referenced on-disk executables through `FileAnalyzer.analyzeFile()`.

### 3.3 Safe Binary Shell Link Parser (`LnkParser`)
- **Format Compliance:** Strictly parses the Microsoft MS-SHLLINK binary specification.
- **Header Validation:** Validates HeaderSize ($0x0000004C$) and LinkCLSID (`00021401-0000-0000-C000-000000000046`).
- **Defensive Offsets:** Verifies all buffer offsets against `buffer.length`. Zero out-of-bounds reads or uncaught `RangeError` exceptions.
- **Worm Pattern Detection:**
  - `LNK_WORM_SPOOFED_FOLDER_NAME` (risk +65): `.lnk` file having common folder/drive names (`Documents.lnk`, `Pictures.lnk`, `USB.lnk`, `FlashDrive.lnk`).
  - `LNK_INVOKES_SCRIPT_INTERPRETER` (risk +85): targets script interpreter LOLBins.
  - `LNK_SUSPICIOUS_CLI_ARGUMENTS` (risk +90): executes hidden payloads, encoded PowerShell, or temporary file scripts.
  - `LNK_DECEPTIVE_FOLDER_ICON_MASK` (risk +85): masks executable targets with system folder icons (`shell32.dll,3` or `imageres.dll,4`).
  - `LNK_RELATIVE_TRAVERSAL_TARGET` (risk +80): references parent directory traversal.

### 3.4 High-Speed Root Quick-Triage (`scanRemovableDriveRoot`)
- **SLA Target:** Quick triage completes in $<200\text{ ms}$ ($p95$).
- **Non-Recursive Execution:** Inspects only the immediate root items (up to 50 items) on drive mount.
- **Canonical Decision Flow:**
  - Evaluates `autorun.inf`, `.lnk` files, and root executables.
  - Generates unified `riskScore` (0-100), `ThreatSeverity` (`safe`, `low`, `suspicious`, `dangerous`, `critical`), and `ThreatVerdict` (`ALLOW`, `WARN`, `BLOCK`).
  - Emits `scanCompleted` event with `RemovableDriveScanResult`.

---

## 4. IPC & Preload Interface Contracts

```typescript
// IPC Channels
REMOVABLE_MEDIA_GET: 'desktop:removableMedia:get'
REMOVABLE_MEDIA_SCAN: 'desktop:removableMedia:scan'
MEDIA_DRIVE_ATTACHED: 'desktop:removableMedia:attached'

// Preload Bridge Methods
window.desktopSecurity.getRemovableMedia(): Promise<RemovableDrive[]>
window.desktopSecurity.scanRemovableMedia(mountPath: string): Promise<RemovableDriveScanResult>
window.desktopSecurity.onMediaDriveAttached(callback: (drive: RemovableDrive) => void): () => void
```

---

## 5. Security & Privacy Guarantees

1. **Zero Privilege Escalation:** Renderer receives only structured scan metadata; no shell execution or raw file descriptor handles are ever exposed.
2. **Strict Air-Gap & Offline Parity:** Audited with socket-level interception to verify zero outbound network sockets or telemetry exfiltration during USB scans.
3. **RULE-09 System Immunity:** Windows operating system processes and system folders are completely shielded from containment or quarantine during media scans.
4. **No Arbitrary Drives:** Fixed drives (C:, D:) cannot be spoofed as removable USB volumes.
