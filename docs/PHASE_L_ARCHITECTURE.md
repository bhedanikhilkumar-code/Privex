# PHASE L ARCHITECTURE SPECIFICATION
## Privex — Windows Startup & Persistence Protection

**Status:** CANONICAL ARCHITECTURAL SPECIFICATION  
**Target Platform:** Windows 10/11 Desktop (Electron + TypeScript + @private-protection/core)  
**Security Classification:** Level 4 (Privileged System & Registry Inspection / Quarantine)  

---

## 1. System Vision & Purpose

Phase L implements production-grade, local-first, offline-first **Startup & Persistence Protection** for Privex Windows Antivirus. Its mission is to audit, inspect, monitor, explain, and safely remediate persistence mechanisms that malware and threat actors use to achieve execution across reboots, user logons, and application restarts.

Unlike legacy utilities that treat every startup entry as suspicious or rely on destructive registry deletions, Phase L enforces:
1. **Zero-Trust Input Parsing:** Command lines and paths are parsed without execution, shell expansion, or child processes.
2. **Canonical Detection Integration:** Discovered persistence items are routed directly through `@private-protection/core` (`FileAnalyzer` $\rightarrow$ `RiskScorer` $\rightarrow$ `EngineVerdict`) as *evidence*, preventing redundant or divergent scoring.
3. **RULE-09 OS Immunity:** Windows system binaries in canonical system directories are strictly immune from deletion and quarantine.
4. **Targeted Value Remediation:** Registry remediation removes *only* the specific value name under the specified hive/key, verifying removal without deleting parent keys.
5. **PPVAULT2 Quarantine Isolation:** Startup folder files are isolated into the encrypted streaming AES-256-GCM vault with rollback capability.

---

## 2. Persistence Topology & Supported Surfaces

```
┌────────────────────────────────────────────────────────────────────────┐
│               WINDOWS PERSISTENCE AUDITOR & MONITOR                    │
│                                                                        │
│   ┌───────────────────────────┐      ┌─────────────────────────────┐   │
│   │   Registry Persistence    │      │  Startup Folder Persistence │   │
│   │ • HKCU Run / RunOnce      │      │ • User Startup Folder       │   │
│   │ • HKLM Run / RunOnce      │      │ • Common Startup Folder     │   │
│   │ • WOW6432Node Run/RunOnce │      │ • Binary .LNK Shortcuts     │   │
│   └─────────────┬─────────────┘      └──────────────┬──────────────┘   │
└─────────────────┼───────────────────────────────────┼──────────────────┘
                  │                                   │
                  ▼                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 SAFE PERSISTENCE PARSERS (ZERO-EXECUTION)              │
│  • PersistenceCommandParser: Quoted/Unquoted, Env expansion, Sanitizer │
│  • LnkParser: MS-SHLLINK binary spec, CLSID check, Arguments extractor │
│  • WindowsRegistryReader: Safe execFile('reg.exe'), 32/64-bit views    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             CANONICAL DETECTION PIPELINE (@private-protection/core)    │
│  1. FileAnalyzer (10-layer static/heuristic/entropy/signature triage)  │
│  2. ThreatIntel (SHA-256 Bloom filter & known bad hashes)              │
│  3. RiskScorer (Multi-signal Bayesian log-odds aggregation)            │
│  4. EngineVerdict (ALLOW | INFORM | WARN | BLOCK | QUARANTINE)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 AUTOMATIC RESPONSE & SAFE REMEDIATION                  │
│  • Registry: Exact value deletion (reg delete /v) with post-check      │
│  • Filesystem: QuarantineService streaming isolation (PPVAULT2)       │
│  • NotificationService: Token-bucket storm rate-limited OS toasts      │
│  • IPC Layer: Zero-trust verified IPC invoke & event channels          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Component Specifications

### 3.1 PersistenceCommandParser (`apps/desktop/src/core/persistence-command-parser.ts`)
- **Quoted Path Extraction:** Accurately isolates quoted executable paths (`"C:\Program Files\Vendor\app.exe" /arg1 /arg2`).
- **Unquoted Path Heuristic:** Uses extension boundaries (`.exe`, `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1`, `.scr`, `.pif`, `.dll`, `.hta`, `.cpl`, `.com`) to separate executable paths containing spaces from trailing arguments.
- **Environment Variable Expansion:** Pure string map replacement (`%APPDATA%`, `%PROGRAMDATA%`, `%SYSTEMROOT%`, `%WINDIR%`, `%TEMP%`, `%PROGRAMFILES%`) without spawning child processes.
- **Sanitization:** Eliminates NUL bytes (`\0`), Unicode Right-to-Left Override characters (`\u202E`, `\u202B`), control characters, and flags directory traversal (`..\`).
- **Heuristic Indicators:**
  - LOLBin execution (`powershell.exe`, `wscript.exe`, `cscript.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `schtasks.exe`).
  - Obfuscation and evasion arguments (`-enc`, `-encodedcommand`, `-w hidden`, `-nop`, `-ep bypass`, `downloadstring`, `iex`, `/e:vbscript`, `-decode`).
  - Execution from temporary or public directories (`%TEMP%`, `AppData\Local\Temp`, `Users\Public`).
  - Deceptive double extensions (`report.pdf.exe`).

### 3.2 WindowsRegistryReader (`apps/desktop/src/core/windows-registry-reader.ts`)
- **Direct Executable Invocation:** Calls `execFile('reg.exe', ['query', key, ...])` directly with an argument array, preventing shell command injection.
- **Multi-Hive & Multi-View Support:** Queries HKCU and HKLM standard keys as well as 32-bit `WOW6432Node` keys on 64-bit systems.
- **Safe Output Parsing:** Parses `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, and `REG_BINARY` types.
- **Targeted Deletion:** `deleteRunValue(hive, subKey, valueName)` calls `reg.exe delete "<hive>\<subKey>" /v "<valueName>" /f` and verifies deletion post-operation by re-querying.

### 3.3 PersistenceAuditorService (`apps/desktop/src/services/persistence-auditor.service.ts`)
- **Deterministic Canonical Identity:** Generates unique, reproducible IDs:
  $$\text{id} = \text{"persist-"} + \text{SHA256}(\text{locationType} + ":" + \text{locationPath} + ":" + \text{name})[0..16]$$
- **Target Analysis:** Resolves target paths, extracts binary `.lnk` metadata with `LnkParser`, and passes target executables/scripts to `FileAnalyzer`.
- **False-Positive & System Binary Immunity:**
  - Known clean binaries signed by trusted vendors or located in Windows system directories remain `ALLOW` / `safe`.
  - Enforces `RULE-09` OS immunity to protect critical Windows infrastructure.
- **Remediation:** Orchestrates registry value deletion or `QuarantineService.isolateFile()` with full rollback support.

### 3.4 PersistenceMonitorService (`apps/desktop/src/services/persistence-monitor.service.ts`)
- **Event-Driven Folder Watching:** Uses `fs.watch` on Startup directories with 300ms debouncing.
- **Periodic Registry Snapshot Diffing:** Polls Run/RunOnce keys at configurable intervals (10s default), diffing against known snapshots.
- **Storm Rate Limiter (RULE-15):** Enforces a token-bucket rate limiter allowing a maximum of 3 events per 10-second window to prevent notification floods.
- **Event Dispatch:** Emits `persistenceChanged` (`PersistenceChangeEvent`) and `threatDetected` (`PersistenceItem`) events to the UI and `NotificationService`.

---

## 4. IPC Channels & Security Boundary

| Channel Name | Type | Payload / Parameters | Access Rule |
|---|---|---|---|
| `desktop:persistence:audit` | Invoke | None | Main frame only, returns `PersistenceItem[]` |
| `desktop:persistence:remediate` | Invoke | `{ itemId: string, frictionToken?: string }` | Main frame only, requires valid `itemId` |
| `desktop:persistence:changed` | Event | `PersistenceChangeEvent` | Renderer broadcast |

---

## 5. Remediation Safety & Rollback Guarantee

1. **Registry Values:**
   - Deleted via targeted `reg delete /v`.
   - Never deletes parent registry keys (`Run`, `RunOnce`).
   - If deletion cannot be verified by re-querying, returns `success: false`.
2. **Startup Folder Files:**
   - Isolated into the encrypted streaming AES-256-GCM vault (`PPVAULT2`).
   - Retains original path, SHA-256 hash, and metadata in `manifest.json.enc`.
   - Can be restored in 1-click via `QuarantineService.restoreItem(quarantineId, { trustSha256: true })`.
