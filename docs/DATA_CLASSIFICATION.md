# Data Classification Specification: PRIVEX

## 1. Overview & Data Philosophy

PRIVEX operates under an uncompromising data protection framework designed to guarantee that users never surrender their digital privacy in exchange for cybersecurity.

Every piece of data generated, processed, or persisted within the ecosystem is strictly categorized into one of four immutable security classifications:
1. **HIGHLY SENSITIVE (Class 1)**
2. **SENSITIVE (Class 2)**
3. **INTERNAL (Class 3)**
4. **PUBLIC (Class 4)**

---

## 2. Four-Tier Data Classification Matrix

| Classification | Definition | Concrete System Examples | Storage Mandates | Network Transmission Rules | Retention Policy | Encryption Standard | Access Control |
|---|---|---|---|---|---|---|---|
| **HIGHLY SENSITIVE (Class 1)** | Raw, identifiable user communication payloads, browsing data, and personal artifacts. | • Raw message text (SMS, WhatsApp, chat)<br>• Visited URLs & full paths<br>• Camera frames & screenshots<br>• Downloaded file contents & filenames | **NEVER stored on disk.** Volatile RAM only during active scan window. Zeroed immediately after analysis. | **ABSOLUTELY FORBIDDEN.** Zero bytes may be transmitted off-device under any circumstance. | Ephemeral (lifespan < 500ms; duration of scan execution). | Ephemeral memory buffer zeroing (`memset_s` / secure zeroization). | Local scanner process only. No external IPC access. |
| **SENSITIVE (Class 2)** | Device security state, user overrides, and localized threat history. | • Local custom allowlists & overrides<br>• User security settings & toggles<br>• Local scan count counters & timestamps<br>• Quarantine file encryption metadata | Local encrypted database on device filesystem only. | **FORBIDDEN BY DEFAULT.** Can only leave device if user initiates an encrypted manual backup with user-held passphrase. | Retained until user initiates "Clear All Data" or uninstalls. | AES-256-GCM / SQLCipher. Encryption keys stored in OS Keystore (Keychain, DPAPI). | Authenticated local client app only. |
| **INTERNAL (Class 3)** | Operational state, compiled threat databases, and anonymized diagnostic metrics. | • Compiled Bloom filter binary files<br>• Monotonic ruleset version integers<br>• Cryptographic verification public keys<br>• Anonymized rule-trigger counters | Local client filesystem and temporary caches. | Permitted via Oblivious HTTP (OHTTP) privacy relay only. Must possess zero IP addresses or persistent IDs. | Persisted locally until replaced by new delta update. Telemetry retained 30 days max. | Local files verified via SHA-256 Merkle root; TLS 1.3 in transit. | Application runtime components. |
| **PUBLIC (Class 4)** | Non-sensitive, public cybersecurity definitions and release assets. | • Open-source detection rules & regexes<br>• Public threat intelligence feeds (PhishTank)<br>• Application release changelogs<br>• Architectural documentation & licenses | Stored in public git repository and edge CDNs. | Publicly transmissible over HTTPS / CDN distribution networks. | Indefinite public retention. | Signed with official Ed25519 release keys; TLS 1.3. | Unrestricted public access. |

---

## 3. Data Classification Mapping Table

| Data Item | Assigned Classification | Storage Rule | Network Egress Rule | Deletion Guarantee |
|---|---|---|---|---|
| **Inbound SMS Message** | `HIGHLY SENSITIVE` | Volatile RAM only | **STRICTLY BLOCKED** | Overwritten with zeros immediately after scan |
| **Browser Visited URL** | `HIGHLY SENSITIVE` | Volatile RAM only | **STRICTLY BLOCKED** | Discarded immediately after navigation check |
| **Camera QR Code Frame** | `HIGHLY SENSITIVE` | Camera buffer only | **STRICTLY BLOCKED** | Frame memory recycled on next frame capture |
| **Downloaded Executable** | `HIGHLY SENSITIVE` | Quarantined vault if malicious | **STRICTLY BLOCKED** | Permanent deletion when user clicks "Purge Vault" |
| **User Custom Allowlist** | `SENSITIVE` | Local SQLite DB | **STRICTLY BLOCKED** | Deleted on user "Reset Settings" command |
| **Device Hardware UUID** | `SENSITIVE` | **NEVER QUERIED OR STORED** | **STRICTLY BLOCKED** | N/A (Architecture prohibits querying hardware UUIDs) |
| **User Account Credentials** | `SENSITIVE` | **NONE (Accountless architecture)** | **STRICTLY BLOCKED** | N/A (No user accounts or cloud passwords exist) |
| **Detection Result Object** | `INTERNAL` | Local SQLite DB | Blocked (Only aggregated counts permitted) | Purged via scan history wipe |
| **Bloom Filter Database** | `INTERNAL` | Local app cache | Inbound download only (from CDN) | Replaced on OTA delta update |
| **Rule Trigger Counter** | `INTERNAL` | Local cache | Outbound via OHTTP (Opt-in only) | Flushed after transmission |
| **Public Threat Feeds** | `PUBLIC` | CDN / Git repository | Public download | Updated hourly on CDN |
| **Software Release Notes** | `PUBLIC` | Public website / GitHub | Public download | Permanent |

---

## 4. Enforcement Protocols

1. **Automated Egress Static Analysis**: CI/CD security linters scan all network socket calls to verify that no variables referencing Tier 1 payloads (`messageText`, `targetUrl`, `fileBytes`) are passed into network serialization libraries.
2. **Runtime Memory Zeroization**: In native Rust and C implementations, sensitive payload buffers are allocated in guarded pages and overwritten with zeros using memory fences prior to deallocation.
3. **Hardware Keystore Binding**: Encryption keys for Class 2 data are non-exportable and tied to device biometric / screen lock authentication where supported by the OS platform.
