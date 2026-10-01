# LOCAL_STORAGE_ARCHITECTURE.md — Encrypted Persistence, Schemas & Crypto-Shredding

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION LOCAL STORAGE**  
> This document specifies the local storage architecture, encrypted relational schemas, key derivation protocols, retention lifecycles, and cryptographic shredding mechanisms across all client platforms.

---

## 1. STORAGE PHILOSOPHY & PROHIBITION OF HOARDING

> **STORAGE CONSTITUTIONAL INVARIANT**: Data is persisted **ONLY** when strictly necessary for user auditability or local configuration. Unencrypted Tier 1 user content (raw URLs, message bodies, file contents, camera frames) is **NEVER WRITTEN TO DISK UNDER ANY CIRCUMSTANCE**.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ HOST OPERATING SYSTEM SECURE KEYSTORE                                                                 │
│ (Windows DPAPI • macOS Keychain • Android Keystore • iOS Keychain • Web Crypto Non-Exportable Key)   │
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │ Argon2id Key Derivation
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ENCRYPTED LOCAL STORAGE ENGINE (AES-256-GCM / SQLCIPHER)                                               │
│                                                                                                        │
│   ┌───────────────────────────────┐     ┌──────────────────────────────┐     ┌──────────────────────┐  │
│   │ custom_allowlist              │     │ security_events              │     │ system_config        │  │
│   │ • User-trusted domain entries │     │ • Anonymized threat audits   │     │ • Policy thresholds  │  │
│   │ • Encrypted at rest (AES-256) │     │ • Truncated SHA-256 hashes   │     │ • Update versions    │  │
│   └───────────────────────────────┘     └──────────────────────────────┘     └──────────────────────┘  │
└───────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                    │
                                                    ▼ Crypto-Shredding Command
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ CRYPTOGRAPHIC SHREDDING: Master Key Destroyed in Keystore -> All Disk Ciphertext Rendered Irrecoverable │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. DATA CATEGORIES, ENCRYPTION & RETENTION MATRIX

| Data Category | Purpose & Necessity | Sensitivity | Encryption Engine | Retention Period | Purge Workflow |
|---|---|---|---|---|---|
| **Custom Allowlists** | Stores user-trusted domain overrides to prevent repeated friction. | **Tier 2** | SQLCipher / AES-256-GCM | Persistent until user removal | Deleted via UI or master reset |
| **Security Events** | Anonymized audit trail allowing user to review past detected threats. | **Tier 2** | SQLCipher / AES-256-GCM | 30 Days (Rolling window FIFO) | Auto-purged after 30d or user wipe |
| **System Settings** | User preferences (sensitivity, theme, notifications). | **Tier 2** | SQLCipher / Web Crypto | Persistent | Restorable to defaults |
| **Threat Intelligence**| Memory-mapped binary Bloom filter (`threats.bf`). | **Tier 4** | Plaintext Binary File | Overwritten by updates | Overwritten atomically |
| **Model Weights** | ONNX quantized model artifacts. | **Tier 4** | Plaintext Binary File | Overwritten by updates | Overwritten atomically |
| **Raw Visited URLs** | **PROHIBITED** | **Tier 1** | **NEVER STORED** | **0 ms (RAM Only)** | Zeroed from RAM immediately |
| **Raw Message Text** | **PROHIBITED** | **Tier 1** | **NEVER STORED** | **0 ms (RAM Only)** | Zeroed from RAM immediately |
| **Scanned Files** | **PROHIBITED** (Unless quarantined) | **Tier 1** | **AES-256-GCM (.vault)** | Retained only if in quarantine | User quarantine delete |

---

## 3. RELATIONAL SCHEMAS (SQLITE / SQLCIPHER)

The relational database is initialized with full-page encryption via SQLCipher (`PRAGMA key = '<derived_key>'; PRAGMA cipher_page_size = 4096;`).

### 3.1 Table: `custom_allowlist`
Stores user-approved domain exceptions.
```sql
CREATE TABLE IF NOT EXISTS custom_allowlist (
    id TEXT PRIMARY KEY NOT NULL,             -- UUIDv4
    domain_hash TEXT NOT NULL UNIQUE,         -- SHA-256(canonical_domain)
    normalized_pattern TEXT NOT NULL,         -- e.g., "*.internal-company.net"
    created_at INTEGER NOT NULL,              -- Epoch ms
    reason TEXT,                              -- User-provided note
    expires_at INTEGER                        -- Nullable expiration timestamp
);
CREATE INDEX IF NOT EXISTS idx_allowlist_domain_hash ON custom_allowlist(domain_hash);
```

### 3.2 Table: `security_events`
Stores zero-knowledge audit events for the local security dashboard.
```sql
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY NOT NULL,             -- UUIDv4
    timestamp INTEGER NOT NULL,               -- Epoch ms
    target_type TEXT NOT NULL,                -- 'URL', 'MESSAGE', 'FILE'
    target_hash TEXT NOT NULL,                -- Truncated SHA-256 (Never raw payload)
    verdict TEXT NOT NULL,                    -- 'ALLOW', 'INFORM', 'CAUTION', 'SUSPICIOUS', 'DANGEROUS'
    risk_score INTEGER NOT NULL,              -- 0 - 100
    primary_threat TEXT NOT NULL,             -- e.g., 'brand-spoofing'
    user_action TEXT NOT NULL,                -- 'BLOCKED', 'BYPASSED', 'IGNORED'
    reported_false_positive INTEGER DEFAULT 0 -- 0 or 1
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
```

### 3.3 Table: `system_config`
Stores local operational flags and update tracking.
```sql
CREATE TABLE IF NOT EXISTS system_config (
    config_key TEXT PRIMARY KEY NOT NULL,
    config_value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
```

### 3.4 Table: `quarantine_records` (Desktop Only)
Tracks securely quarantined files moved into the encrypted vault container.
```sql
CREATE TABLE IF NOT EXISTS quarantine_records (
    id TEXT PRIMARY KEY NOT NULL,             -- UUIDv4
    original_path_hash TEXT NOT NULL,         -- SHA-256 of original path
    vault_storage_filename TEXT NOT NULL,     -- Randomized filename in .vault directory
    file_sha256 TEXT NOT NULL,                -- SHA-256 of file content
    file_size_bytes INTEGER NOT NULL,
    threat_description TEXT NOT NULL,
    quarantined_at INTEGER NOT NULL
);
```

---

## 4. KEY DERIVATION & CRYPTOGRAPHIC SHREDDING

```
OS HARDWARE ENCLAVE
       │
       ▼ (Hardware Master Secret: 32 bytes)
Argon2id KDF (Salt: 16 bytes, Memory: 64 MB, Iterations: 3, Parallelism: 2)
       │
       ▼
Local Database Encryption Key (256-bit AES-GCM Key)
       │
       ▼ Encrypts
SQLite Pages / IndexedDB Blobs
```

### The Crypto-Shredding Protocol
When a user selects "Erase All Security History & Reset" in settings:
1. The client sends an atomic wipe command to the host OS Keystore: `keystore.deleteKey("private_protection_db_master_key")`.
2. The operating system securely zeroes the hardware secret.
3. The client executes `DELETE FROM custom_allowlist; DELETE FROM security_events; VACUUM;` followed by deleting the physical database file.
4. **Guaranteed Outcome**: Even if forensic carving tools recover disk sectors, without the hardware-derived 256-bit AES key, the page data is mathematically indistinguishable from random noise.
