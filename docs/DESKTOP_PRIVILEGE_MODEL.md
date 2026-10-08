# DESKTOP PRIVILEGE & PROCESS BOUNDARY MODEL (Phase 7)
## Least Privilege Architecture for Privex Desktop

> **SYSTEM STATUS: SECURITY SPECIFICATION ACTIVE**  
> **Target Component:** `apps/desktop/` (Desktop Architecture & IPC)  
> **Governing Standards:** AGENTS.md Constitution, Windows Security Hardening Guide, OWASP Desktop Application Security

---

## 1. CORE PRINCIPLE: USER-MODE LEAST PRIVILEGE

PRIVEX Desktop operates strictly under the principle of least privilege:
1. **No Kernel Drivers**: The application does **NOT** install or require kernel-mode drivers (`.sys` on Windows, KEXTs on macOS). It operates completely in user mode.
2. **Unprivileged UI Renderer**: The UI dashboard executes in a heavily sandboxed Chromium renderer with zero Node.js integration and zero direct filesystem access.
3. **No Unnecessary Elevation**: Standard user operations (scanning user files, quarantining user downloads, displaying threat explanations) execute under standard user rights without prompting for UAC elevation.
4. **Elevation Isolation**: If an operation ever targets protected system directories (e.g. system-wide persistence registry keys), it must be mediated via explicit user-approved OS elevation prompts, never running the entire application as Administrator.

---

## 2. 3-TIER PROCESS ISOLATION TOPOLOGY

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 1: UNTRUSTED RENDERER PROCESS (Chromium Web Sandbox)               │
│                                                                         │
│ • Configuration: `sandbox: true`, `contextIsolation: true`              │
│                  `nodeIntegration: false`, `webSecurity: true`          │
│ • Privileges: Standard browser sandbox; no direct OS syscalls           │
│ • Storage: In-memory React state; no direct disk persistence            │
│ • Attack Surface: Rendered web content, CSS, user input forms           │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     │ contextBridge.exposeInMainWorld
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 2: PRELOAD SECURITY BRIDGE & IPC VALIDATOR                         │
│                                                                         │
│ • Strict Method Whitelist: Exposes only declared asynchronous APIs      │
│ • Strict Parameter Validation: Validates path strings, lengths, types   │
│ • Path Traversal Defense: Resolves canonical paths; rejects `..`, null  │
│   bytes, and forbidden administrative commands                          │
│ • Rate Limiting & Backpressure: Prevents IPC flooding                   │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     │ Typed Electron IPC (`ipcRenderer.invoke`)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 3: TRUSTED SECURITY CORE DAEMON (Node.js User-Space Daemon)        │
│                                                                         │
│ • Privileges: Standard logged-in user OS permissions                    │
│ • Capabilities:                                                         │
│   - Recursive filesystem traversal via `fs.promises`                   │
│   - Encrypted quarantine vault storage in `%USERPROFILE%\.quarantine`  │
│   - Ingress folder monitoring via `ReadDirectoryChangesW` / `fs.watch` │
│   - Execution of `@private-protection/core` and `@private-protection/ml`│
│ • Hardening: Sanitized child processes; zero `eval()` or dynamic shell │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. IPC SECURITY MATRIX & DEFENSE IN DEPTH

| IPC Channel | Allowed Directions | Payload Schema | Security Enforcement |
|---|---|---|---|
| `desktop:scan:start` | Renderer $\rightarrow$ Main | `{ targetPath: string, scanType: 'quick' \| 'full' \| 'custom' }` | Path must resolve within user storage; path length capped at 1,024 chars; path traversal characters rejected. |
| `desktop:scan:cancel` | Renderer $\rightarrow$ Main | `{ scanId: string }` | Validates UUID format. Signals cancellation token. |
| `desktop:scan:pause` | Renderer $\rightarrow$ Main | `{ scanId: string }` | Validates UUID format. Pauses directory traversal worker. |
| `desktop:scan:resume` | Renderer $\rightarrow$ Main | `{ scanId: string }` | Validates UUID format. Resumes traversal worker. |
| `desktop:quarantine:list` | Renderer $\rightarrow$ Main | None | Returns read-only sanitized metadata list. File content is never transmitted across IPC. |
| `desktop:quarantine:isolate` | Renderer $\rightarrow$ Main | `{ filePath: string }` | Validates canonical file path; verifies target is regular file; executes atomic move to vault. |
| `desktop:quarantine:restore` | Renderer $\rightarrow$ Main | `{ quarantineId: string, destinationDir?: string }` | Validates UUID format; checks destination path safety; requires friction gate confirmation. |
| `desktop:quarantine:delete` | Renderer $\rightarrow$ Main | `{ quarantineId: string }` | Validates UUID format; performs multi-pass pseudo-random overwrite before unlinking. |
| `desktop:status:get` | Renderer $\rightarrow$ Main | None | Returns telemetry: engine status, memory footprint, active shield state. |
| `desktop:assistant:explain` | Renderer $\rightarrow$ Main | `{ evidence: Evidence[], cognitiveLevel: 'grade6' \| 'grade8' }` | Validates Evidence array structure; delegates to read-only `@private-protection/ml`. |
| `desktop:privacy:shred` | Renderer $\rightarrow$ Main | None | Wipes all quarantine files, local scan history, and cache. |

---

## 4. COMMAND INJECTION & SHELL EXECUTION PROHIBITIONS

1. **Zero Shell Execution from UI**:
   - The UI renderer has no mechanism to invoke `child_process.exec`, `child_process.spawn`, or PowerShell commands.
   - Any IPC command attempting to pass shell syntax (`|`, `&`, `;`, `$`, `` ` ``, `>`) is rejected immediately with a fatal security violation.
2. **Safe Native Task Listing**:
   - Process enumeration uses structured OS APIs or strictly argument-vector parameterized execution (`tasklist /FO CSV /NH` without shell interpolation).
3. **Registry Auditing**:
   - Startup persistence inspection uses read-only registry query APIs with fixed key targets. Arbitrary registry modification is forbidden.
