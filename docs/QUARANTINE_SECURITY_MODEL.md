# QUARANTINE SECURITY & ISOLATION MODEL (Phase 7)
## Cryptographic Containment & Safe Remediation Architecture

> **SYSTEM STATUS: SECURITY SPECIFICATION ACTIVE**  
> **Target Component:** `apps/desktop/src/services/quarantine.service.ts`  
> **Standard:** OWASP / MITRE ATT&CK Defense-in-Depth / NIST SP 800-83

---

## 1. QUARANTINE SECURITY OBJECTIVES

The quarantine system is designed to neutralize threats with mathematical and operational rigor:
1. **Accidental Execution Prevention**: A quarantined file must be physically un-executable by the host operating system, even if a user manually double-clicks it in File Explorer.
2. **Metadata Integrity**: Original path, timestamps, file size, SHA-256 hash, and detection evidence must be preserved securely in a separate metadata manifest.
3. **Safe Remediation (Restore)**: False positives can be restored to disk, but with strict path traversal defenses, collision renaming, and mandatory friction gate confirmation.
4. **Permanent Cryptographic Erasure**: Quarantined threats marked for deletion must be securely wiped with pseudo-random byte overwriting before unlinking.

---

## 2. ISOLATION & NEUTRALIZATION PIPELINE

```
SUSPICIOUS / DETECTED FILE (e.g. C:\Users\Alice\Downloads\invoice.pdf.exe)
      │
      ▼
1. CANONICAL VALIDATION & SYMLINK RESOLUTION
   • Resolve `fs.realpathSync()` to verify genuine file identity.
   • Reject symlinks pointing to system files or directory junctions.
      │
      ▼
2. METADATA EXTRACTION & HASHING
   • Compute SHA-256 hash of entire file.
   • Extract file stat (size, modified time, original permissions).
   • Assign unique UUID (`quarantineId`).
      │
      ▼
3. CRYPTOGRAPHIC HEADER NEUTRALIZATION (BLOB CONTAINER)
   • Read file bytes and apply XOR / AES-256-GCM container envelope.
   • Scrambles PE/MZ, ELF, and Mach-O magic headers so the OS loader
     rejects the file as corrupted/unsupported binary if invoked.
      │
      ▼
4. ATOMIC MOVE TO VAULT STORAGE
   • Store blob as `%USERPROFILE%\.private-protection\vault\<quarantineId>.blob`.
   • Remove original file from ingress path atomically.
   • Strip execution permissions (`chmod 000` / deny execute ACL).
      │
      ▼
5. SECURE METADATA MANIFEST
   • Write encrypted record into `quarantine_manifest.json` with hash checksum.
```

---

## 3. THREAT VECTORS & RIGOROUS MITIGATIONS

| Attack Vector | Threat Scenario | Mitigation Enforcement |
|---|---|---|
| **Path Traversal on Isolate** | Malicious file path containing `../../` or Windows device paths (`\\.\`, `COM1`). | Canonical path resolution via `path.resolve` and `fs.realpathSync`. Only files under accessible user drives are eligible. |
| **Symlink / TOCTOU Attack** | Attacker creates a symlink pointing to `C:\Windows\System32\kernel32.dll` and triggers quarantine to delete system files. | Quarantine service uses `fs.lstatSync`. If `stats.isSymbolicLink()` is true, the symlink target is inspected and rejected from destructive moves. |
| **Malicious Filenames** | File named with Unicode RTL overrides (`invoice‮exe.pdf`), null bytes (`file\0.txt`), or shell metacharacters. | Original filename is sanitized and stored as JSON string data. Vault filename is strictly a generated UUID-v4 (`550e8400-e29b-41d4-a716-446655440000.blob`). |
| **Restore Collision** | Restoring a file to original location where another file now exists or has been recreated. | Quarantine service checks if target path exists. If present, it appends a collision suffix (`_restored_<timestamp>`) or prompts user, preventing accidental overwrite. |
| **Restore Path Traversal** | Corrupted metadata pointing original path to `C:\Windows\System32` or startup root. | Destination path is re-validated to ensure it does not escape to arbitrary system-critical directories without administrator privileges. |
| **Metadata Corruption** | Attacker tampers with `quarantine_manifest.json` to forge hashes or IDs. | Manifest includes an integrity HMAC/hash checksum. Corrupted entries are flagged and prevented from blind restoration. |

---

## 4. PERMANENT ERASURE (CRYPTO-SHREDDING)

When a user permanently deletes a quarantined item:
1. Open file descriptor with write access.
2. Overwrite entire file allocation with cryptographically strong pseudo-random bytes (`crypto.randomBytes`).
3. Flush to disk via `fs.fsyncSync()`.
4. Truncate file to 0 bytes.
5. Unlink (`fs.unlinkSync()`) the file from the filesystem.
6. Remove entry from `quarantine_manifest.json`.
