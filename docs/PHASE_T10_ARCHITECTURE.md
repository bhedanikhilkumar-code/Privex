# docs/PHASE_T10_ARCHITECTURE.md — Mobile Quarantine & Remediation Architecture

> **DOCUMENT STATUS:** CANONICAL ARCHITECTURE SPECIFICATION  
> **PHASE:** T10 — Mobile Quarantine & Remediation  
> **COMPONENT:** `apps/mobile/android/app/src/main/java/com/privateprotection/mobile/shield/MobileQuarantineVault.java` & `PackageAuditService.java`  
> **GOVERNANCE:** Strict Local-First • Offline-First • Zero-Cloud • Zero-Knowledge • Fail-Closed • RULE-42

---

## 1. Executive Summary & Goals

Phase T10 establishes a secure, reversible, authenticated on-device quarantine isolation vault (`PPMVAULT1`) and honest package remediation architecture for Private Protection on Android.

### 1.1 Core Objectives
1. **Authenticated Mobile Vault (`PPMVAULT1`):** App-private encrypted storage (`context.getFilesDir()/quarantine_vault/`) using 64 KB chunked streaming `AES-256-GCM` with per-chunk AAD binding (`itemId + ":chunk:" + index`) and 64-byte `PPMVAULT` binary header.
2. **Android Keystore Key Management:** Hardware-backed Master Key generated and stored in `AndroidKeyStore` with secure software key fallback for JVM unit test execution.
3. **Crash-Consistent Atomic Manifest:** Persisted in `quarantine_manifest.json` using atomic write-to-temporary (`.tmp`), `FileDescriptor.sync()`, and rename, with automatic `.bak` recovery.
4. **Truthful Isolation State Machine:** Strict state transition:
   $$\text{DETECTED} \longrightarrow \text{PENDING\_ISOLATION} \longrightarrow \text{VAULT\_COPY\_VERIFIED} \longrightarrow \text{ORIGINAL\_REMOVAL\_PENDING} \longrightarrow \text{ISOLATED} \text{ or } \text{SOURCE\_REMAINS}$$
   The system never reports `ISOLATED` if unlinking the source file failed or requires user permission.
5. **Verified Safe Restoration:** Verifies GCM auth tag and checks plaintext SHA-256 against original metadata before restoration. Restores atomically via `.restoring.tmp`. Path traversal (`..`) and restricted OS paths (`RESTRICTED_SYSTEM_PATH`) are strictly blocked. Vault file is preserved on restore failure.
6. **Installed Package Remediation Safeguards:** Evaluates packages into actionable plans (`UNINSTALL_RECOMMENDED`, `FORCE_STOP_RECOMMENDED`, `DISABLE_RECOMMENDED`, or `SYSTEM_APP_PROTECTED`). Routes user actions through explicit, standard Android intents (`Settings.ACTION_APPLICATION_DETAILS_SETTINGS`, `Intent.ACTION_DELETE`). Never claims or simulates silent uninstallation. Critical system packages (`android`, `com.android.systemui`, `com.google.android.packageinstaller`, etc.) are designated `SYSTEM_APP_PROTECTED` and cannot be targeted for destructive removal.

---

## 2. Vault Binary Format (`PPMVAULT1`)

Every quarantined file is encrypted into a standalone `.vault` file with a fixed 64-byte binary header followed by 64 KB encrypted chunks:

```
+-------------------------------------------------------------------------+
|                        64-BYTE PPMVAULT HEADER                          |
+-------------------+------------------+------------------+---------------+
| Bytes 0..7        | Byte 8           | Bytes 9..20      | Bytes 21..28  |
| Magic: "PPMVAULT" | Version: 0x01    | 12-byte IV Base  | File Length   |
+-------------------+------------------+------------------+---------------+
| Bytes 29..60: 32-byte Plaintext SHA-256 Digest                          |
| Bytes 61..63: Reserved (Zero-padded)                                    |
+-------------------------------------------------------------------------+
|                        CHUNKED PAYLOAD STREAM                           |
+-------------------------------------------------------------------------+
| Chunk 0: Encrypted Data (up to 64 KB) + 16-byte GCM Tag                 |
|          AAD: itemId + ":chunk:0"                                       |
+-------------------------------------------------------------------------+
| Chunk 1: Encrypted Data (up to 64 KB) + 16-byte GCM Tag                 |
|          AAD: itemId + ":chunk:1"                                       |
+-------------------------------------------------------------------------+
| ...                                                                     |
+-------------------------------------------------------------------------+
```

### 2.1 Per-Chunk IV Derivation
To prevent IV reuse across chunks while using a single master key, each chunk uses a derived IV:
$$\text{Chunk IV} = \text{baseIv}[0..7] \parallel \text{bigEndian}(chunkIndex)$$

### 2.2 Per-Chunk Additional Authenticated Data (AAD)
Every chunk binds its position and unique item identifier into the GCM authentication tag:
$$\text{AAD} = \text{itemId} + \text{":chunk:"} + chunkIndex$$
This prevents chunk reordering, substitution, or transplantation attacks across vault items.

---

## 3. Truthful Isolation State Machine

```
               [ Threat Detected in Ingress File ]
                                │
                                ▼
                        [ PENDING_ISOLATION ]
                                │
                                ▼
           [ Stream Encrypt into .vault.tmp & Compute SHA-256 ]
                                │
                                ▼
                   [ Atomic Rename to .vault ]
                                │
                                ▼
                      [ VAULT_COPY_VERIFIED ]
                                │
                                ▼
                   [ ORIGINAL_REMOVAL_PENDING ]
                                │
              ┌─────────────────┴─────────────────┐
     [ Source File Unlinked ]          [ Unlink Failed / SAF ]
              │                                   │
              ▼                                   ▼
        [ ISOLATED ]                      [ SOURCE_REMAINS ]
```

---

## 4. Package Remediation Architecture

Under standard Android sandboxing, third-party apps cannot silently uninstall other packages without root or device-owner privileges. Privex adheres strictly to `RULE-26` (Architectural Honesty) and `RULE-42`:

| Package Category | Remediation Plan | Action Intent | Safety Classification |
|---|---|---|---|
| Critical OS (`android`, `com.android.systemui`, etc.) | `SYSTEM_APP_PROTECTED` | None (Blocked) | Immutable System Component |
| Standard System App | `DISABLE_RECOMMENDED` | `Settings.ACTION_APPLICATION_DETAILS_SETTINGS` | Requires System Settings UI |
| Malicious User App | `UNINSTALL_RECOMMENDED` | `Intent.ACTION_DELETE` (`package:uri`) | Explicit OS Confirmation Dialog |
| Suspicious Background Service | `FORCE_STOP_RECOMMENDED` | `Settings.ACTION_APPLICATION_DETAILS_SETTINGS` | Requires System Settings UI |

---

## 5. Security Threat Analysis (STRIDE)

| Threat | Risk Level | Mitigation in Phase T10 |
|---|---|---|
| **Spoofing (Forged vault files)** | High | GCM 128-bit authentication tags and SHA-256 integrity digests validated on access and restore. |
| **Tampering (Chunk reordering)** | High | Per-chunk AAD commits to `itemId + ":chunk:" + index`. Tampering causes `AEADBadTagException`. |
| **Repudiation (Fake isolation claims)** | Medium | Truthful isolation state machine tracks `ISOLATED` vs `SOURCE_REMAINS`. Never claims isolation when unlink failed. |
| **Information Disclosure (Plaintext leak)** | High | AES-256-GCM encryption in app-private directory. Plaintext zeroed from volatile memory after processing. |
| **Denial of Service (OOM on large files)** | High | Fixed 64 KB chunk streaming pipeline; bounded memory delta ($<16\text{ MB}$). |
| **Elevation of Privilege (Path traversal)** | Critical | Canonical path resolution blocks `..` and restricted system folders (`RESTRICTED_SYSTEM_PATH`). |
