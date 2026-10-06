# PHASE G ARCHITECTURE SPECIFICATION
## Ransomware Shield & Shadow Vault Rollback

> **STATUS:** PRODUCTION IMPLEMENTATION COMPLETE  
> **COMPONENT:** `@private-protection/desktop`  
> **PRIMARY SERVICES:** `RansomwareShieldService`, `ShadowVaultService`  
> **GOVERNANCE:** LOCAL-FIRST • ZERO-CLOUD • DETERMINISTIC • FAIL-CLOSED

---

## 1. System Topology & Architectural Overview

Phase G delivers a local, offline Ransomware Shield and Copy-on-Write encrypted rollback system. The architecture operates defense-in-depth across six distinct layers:

```
[ Filesystem Ingress (Protected Folders / FS Watcher) ]
                          │
                          ▼
        ┌───────────────────────────────────┐
        │ 1. Decoy Canary Traps (~$_...)    │──(Tampered?)──► RANSOMWARE_CANARY_TRIPPED (Score 100)
        └───────────────────────────────────┘                      │
                          │ (Clean)                                │
                          ▼                                        ▼
        ┌───────────────────────────────────┐        ┌─────────────────────────────┐
        │ 2. Trusted Application Registry   │        │ 5. Safe Containment Engine  │
        │    (CanonicalPath + SHA256)       │        │    (Token-Gated, RULE-09)   │
        └───────────────────────────────────┘        └─────────────────────────────┘
                          │ (Untrusted / Suspicious)               ▲
                          ▼                                        │
        ┌───────────────────────────────────┐                      │
        │ 3. 64-Slot Sliding Window         │                      │
        │    (25 writes/3s, H>7.5, renames) ├──────(Burst?)────────┤
        └───────────────────────────────────┘                      │
                          │                                        │
                          ▼                                        ▼
        ┌───────────────────────────────────┐        ┌─────────────────────────────┐
        │ 4. Pre-Attack Copy-on-Write       │        │ 6. ShadowVault Rollback     │
        │    (AES-256-GCM Authenticated)    │        │    (Exact SHA-256 Check)    │
        └───────────────────────────────────┘        └─────────────────────────────┘
```

---

## 2. Protected Folders & Mode Topology

### Protected Folders
- **Default Monitored Roots:** `Documents`, `Pictures`, `Desktop` (resolved via `os.homedir()` / native shell paths).
- **Custom Folders:** User-specified directories configured via IPC (`desktop:ransomware:foldersAdd`).
- **Path Canonicalization:**
  - Strict input validation via `IpcValidator.validatePath()`.
  - Resolution of canonical paths using `path.resolve()` and native directory traversal normalization.
  - Hard rejection of path traversal (`..`), null bytes (`\0`), UNC network shares (`\\`), and NTFS alternate data streams (`:Zone.Identifier`).
  - Symlink/junction escape guard: protected root directories cannot be symbolic links or junctions pointing outside authorized boundaries.

### Operating Modes
1. **Smart Mode (Default):**
   - Automatically permits verified trusted applications.
   - Blocks or alerts on untrusted or suspicious binaries modifying protected documents.
   - Evaluates write velocity, Shannon entropy, and file extension changes.
2. **Strict Mode:**
   - Blocks all untrusted applications from modifying any protected file.
   - Only explicitly registered applications with valid cryptographic identities are allowed write access.

---

## 3. Trusted Application Registry & Cryptographic Identity

### Identity Tuple
An application’s trust is bound strictly to:
$$\text{Application Identity} = (\text{CanonicalPath}, \text{SHA-256}, \text{Signer})$$

### Invariant: Automatic Trust Invalidation
A file path alone is **never** trusted. If a trusted executable is modified, upgraded, patched, or injected with malware:
1. `verifyApplicationTrust(executablePath)` calculates the live SHA-256 hash of the binary on disk.
2. If the live hash does not match the registered hash:
   - Trust is **immediately revoked** (`isRevoked = true`).
   - A `trustRevoked` event is emitted.
   - The application transitions to `untrusted` status.
   - All subsequent write operations in protected folders are blocked or treated as untrusted.

---

## 4. Decoy Canary Trap Files

### Deployment Pattern
- Hidden decoy files are placed into monitored protected folders.
- Naming format:
  - `~$_PrivateProtection_Canary_Financial_Ledger_<hex>.docx`
  - `~$_PrivateProtection_Canary_Payroll_Report_<hex>.xlsx`
- Mimics temporary Microsoft Office lock files to entice automated ransomware crawlers before reaching user data.

### Integrity Pinning
- Decoy content is deterministically generated and pinned in memory upon deployment (`expectedSha256`, `expectedSize`).
- **Tamper Alert Protocol:**
  - Any modification, truncation, deletion, or rename of a canary file triggers immediate detection:
    $$\text{Verdict} = \text{RANSOMWARE\_CANARY\_TRIPPED}, \quad \text{RiskScore} = 100, \quad \text{Severity} = \text{CRITICAL}$$
  - Routes directly to process containment and incident logging.

---

## 5. 64-Slot Sliding-Window Velocity & Entropy Detector

### Window Specifications
- **Slot Capacity:** Exactly 64 discrete event slots in memory.
- **Window Duration:** $3.0\text{ seconds}$ (`WINDOW_DURATION_MS = 3000`).
- **Timestamp Pruning:** Evaluates real event timestamps. Events older than $t_{\text{now}} - 3000\text{ ms}$ are evicted dynamically.
- **Event Deduplication:** Duplicate write/close events occurring on the same file within $10\text{ ms}$ are coalesced and do not inflate the velocity counter.

### Primary Detection Condition
A ransomware velocity burst is confirmed when:
$$\text{Modifications in } 3.0\text{s} \ge 25$$
$$\mathbf{AND}$$
$$\left( \text{High-Entropy Writes } (H > 7.5) \ge 8 \quad \mathbf{OR} \quad \text{Ransomware Extension Renames} \ge 10 \right)$$

### Shannon Entropy Engine ($H > 7.5$)
- Uses the LUT-accelerated `EntropyScanner.calculateEntropy(buffer)` from `@private-protection/core`.
- Evaluates the file header and initial 64 KB slice.
- **False-Positive Mitigation:** Known media and archive formats (`.jpg`, `.png`, `.mp4`, `.zip`, `.7z`, `.rar`, etc.) naturally have high Shannon entropy ($H \approx 7.9$). These formats are identified by extension and magic header to prevent false positive triggers during normal user media saves.

### Ransomware Extension Signatures
- Detects bulk renaming to known ransomware extensions:
  `.locked`, `.encrypted`, `.crypto`, `.cry`, `.lock`, `.enc`, `.crypted`, `.ransom`, `.wnry`, `.wncry`, `.wcry`, `.dark`, `.vault`, `.djvu`, `.stop`, `.pay`, `.mallox`, `.lockbit`, `.blackcat`, `.alphv`.

---

## 6. Safe Process Containment & RULE-09 OS Immunity

When ransomware behavior is detected:
1. **Attribution:** Correlates responsible process PID and executable identity from the filesystem event.
2. **RULE-09 Invariant:**
   - PID 0 (`[System Idle Process]`) and PID 4 (`System`) can **never** be terminated (`REJECTED_PROTECTED`).
   - Core Windows system processes (`smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `svchost.exe` located in `%SystemRoot%\System32`) cannot be terminated unless running from an unauthorized masqueraded directory.
3. **Phase F Token Authorization:**
   - Containment requires a cryptographically validated, single-use token issued by `BehaviorEngineService.issueContainmentAuthorization()`.
   - Re-queries the live process table to prevent PID reuse (TOCTOU) before executing user-mode termination (`taskkill /PID <pid> /T /F` or POSIX `SIGKILL`).
4. **Attribution Ambiguity:**
   - If the PID cannot be definitively attributed, the system fails safely: it does not terminate random processes. The incident is flagged with `responsiblePid: undefined` and triggers file-level containment and alerting.

---

## 7. ShadowVault: Encrypted Copy-on-Write Backups

### Vault Storage & Geometry
- **Location:** `~/.private-protection/shadow-vault/`
- **Permissions:** Restricted directory mode `0o700`; files `0o600`.
- **Symlink Prohibition:** Refuses execution if vault directory is a symlink or junction.
- **File Limit:** Maximum 50 MB per file (`EXCEEDS_FILE_SIZE_LIMIT`).
- **Quota Limit:** Maximum 2 GB total capacity.
- **FIFO Eviction:** When a new backup would exceed 2 GB, the oldest backups are evicted sequentially until sufficient capacity is freed.

### Authenticated Encryption Container (`PPSHADOW1`)
Backups are encrypted using authenticated AES-256-GCM:
```
┌──────────────┬──────────────┬──────────────┬───────────────────────────────┐
│ MAGIC (9 B)  │  IV (12 B)   │  TAG (16 B)  │   CIPHERTEXT (Variable)       │
│ 'PPSHADOW1'  │ Cryptorandom │ GCM Auth Tag │ Encrypted User Document Bytes │
└──────────────┴──────────────┴──────────────┴───────────────────────────────┘
```
- **AAD Binding:** Additional Authenticated Data binds `canonicalPath|preAttackSha256`, preventing ciphertext substitution across different file paths.
- **Manifest:** `shadow-manifest.json.enc` encrypted with AES-256-GCM (`PPSMANIF1`), written atomically with `.bak` recovery.

---

## 8. Incident Rollback & Exact SHA-256 Revalidation

1. User or automated response triggers `rollbackIncident(incidentId)`.
2. Locates all backup blobs associated with the incident ID.
3. Validates AES-256-GCM authentication tag and decrypts payload.
4. Writes restored file atomically to the destination.
5. Recomputes SHA-256 of the restored file on disk:
   $$\text{SHA-256}_{\text{restored}} \stackrel{?}{=} \text{SHA-256}_{\text{pre-attack}}$$
6. **Fail-Closed Condition:**
   - If the restored hash differs from the pre-attack hash, the restored file is **immediately deleted**, and the operation fails closed with `RESTORATION_HASH_MISMATCH`.
   - Rollback is marked successful **only if 100% of affected files match their pre-attack SHA-256 hashes**.
