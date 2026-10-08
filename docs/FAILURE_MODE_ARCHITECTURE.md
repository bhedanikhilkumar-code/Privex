# Failure Mode & Safe-Fail Architecture: PRIVEX

## 1. Foundational Reliability Philosophy

A security product must never fail dangerously. When encountering hardware exhaustion, memory corruption, network partition, or hostile manipulation, PRIVEX adheres strictly to **Safe-Fail Defaults**:
- The user is never left with a false sense of security.
- System failures never allow unverified malicious payloads to execute silently.
- Graceful degradation maintains maximum possible protection at every failure tier.

```
                    ┌───────────────────────────────┐
                    │      CATASTROPHIC FAILURE     │
                    │   (Crash / Corruption / OOM)  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      FAIL-SAFE QUARANTINE     │
                    │   Default to Caution/Warning  │
                    └───────────────┬───────────────┘
                                    │
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
┌──────────────────────────────┐                ┌──────────────────────────────┐
│  DEGRADED PROTECTION MODE    │                │  TRANSPARENT USER ADVISORY   │
│  (Fast-Path Heuristic Fallback)              │  ("Offline / Reduced Engine") │
└──────────────────────────────┘                └──────────────────────────────┘
```

---

## 2. Comprehensive Failure Modes & Remediation Matrix

### 2.1 AI Model Unavailable (Out of Memory / Cold Start / Missing Weights)
- **Failure Trigger**: Host device has <500MB free RAM, mobile OS kills inference process, or local model file was deleted.
- **System Behavior**:
  1. Detection Pipeline catches the model inference timeout/error.
  2. Threat scoring immediately falls back to the deterministic **Rule Engine** and **Lexical Heuristics**.
  3. The **Explanation Engine** switches instantly to pre-compiled, template-based plain-language explanations.
  4. The user receives full threat detection without disruption.
- **Fail-Safe Verdict**: **NO IMPACT ON CORE DETECTION**. Rule + Heuristic pipeline still catches >90% of threats.

---

### 2.2 Threat Intelligence Cache Unavailable / Corrupted
- **Failure Trigger**: Local Bloom filter file corrupted on disk, database read lock failure, or file integrity hash mismatch.
- **System Behavior**:
  1. The engine rejects the corrupted Bloom filter byte stream and falls back to the factory-embedded immutable seed table.
  2. The Lexical and Heuristic Analyzers increase their decision sensitivity weight by $+15\%$ to compensate for the missing reputation layer.
  3. A background task attempts to rebuild the Bloom filter from the local SQLite log.
- **Fail-Safe Verdict**: System warns user of "Reduced Reputation Database", maintains heuristic defense.

---

### 2.3 Internet Unavailable (Air-Gapped / Flight Mode / Disconnected)
- **Failure Trigger**: Zero network connectivity (`ENETUNREACH`, `EAI_AGAIN`).
- **System Behavior**:
  1. The system operates in 100% normal mode for all local scanning (URLs, messages, downloads, QR codes).
  2. Telemetry and update pollers enter exponential backoff with zero network retries to conserve battery.
  3. UI displays green "Shield Active (Offline Mode)".
- **Fail-Safe Verdict**: **FULL LOCAL PROTECTION REMAINS OPERATIONAL**.

---

### 2.4 Cloud Backend Unavailable (CDN Outage / Server Maintenance / Blocked)
- **Failure Trigger**: 500-series HTTP response or TLS handshake timeout on `api.privateprotection.io`.
- **System Behavior**:
  1. Client continues uninterrupted with currently cached models and threat database.
  2. Update check timestamps are recorded locally to calculate staleness days.
  3. Zero user-facing alerts unless staleness exceeds 14 days.
- **Fail-Safe Verdict**: Zero disruption to on-device scanning.

---

### 2.5 Browser Extension Unavailable / Disabled / Crashed
- **Failure Trigger**: User opens an unsupported browser, extension is disabled by administrator policy, or extension crashes.
- **System Behavior**:
  1. If the **Desktop Security Software** is active, desktop-level network/download monitoring catches malicious downloaded payloads.
  2. The Desktop application tray displays an advisory: "Install the Browser Extension for pre-navigation link protection".
- **Fail-Safe Verdict**: Secondary protection layer (Desktop file/download inspector) absorbs download-phase attacks.

---

### 2.6 OS Permission Denied or Revoked
- **Failure Trigger**: User revokes SMS or notification listener permission on Android; Safari extension disabled on iOS.
- **System Behavior**:
  1. Ambient background listeners cleanly shut down without throwing unhandled exceptions.
  2. Application UI surfaces a clear, actionable guide explaining why protection is limited.
  3. The app activates **On-Demand Mode**: Share Sheet, clipboard analysis, and manual input bars remain 100% functional.
- **Fail-Safe Verdict**: Graceful feature degradation to user-initiated scanning.

---

### 2.7 Model File Cryptographic Signature Failure (Tampered / Corrupted Model)
- **Failure Trigger**: An OTA model update arrives with an invalid Ed25519 signature, or local model file fails SHA-256 integrity verification.
- **System Behavior**:
  1. **Immediate Rejection**: The corrupt or tampered binary is purged from disk before being loaded into memory.
  2. Revert to the previous known-good model version via atomic symlink / file swap.
  3. If no prior model is valid, revert to template-based heuristics.
  4. Security audit log records: `SEC_INTEGRITY_VIOLATION: Model signature mismatch`.
- **Fail-Safe Verdict**: **FAIL-CLOSED**. Untrusted or unverified models are never executed.

---

### 2.8 Outdated Threat Database (>30 Days Stale)
- **Failure Trigger**: Device kept in air-gapped environment or isolated storage for extended duration.
- **System Behavior**:
  1. Threat Intel module applies linear confidence decay: threat intelligence weight reduced by 50%.
  2. Scoring engine increases weight of lexical and behavioral heuristics.
  3. Shield status changes to Amber: "Threat database is 30 days old. Connect to internet when possible to refresh."
- **Fail-Safe Verdict**: Protection persists; heuristics and rules prevent reliance on outdated domain records.

---

### 2.9 Detection Engine Panic or Unhandled Exception
- **Failure Trigger**: Out-of-bounds input or unexpected regex catastrophic backtracking during parsing.
- **System Behavior**:
  1. Pipeline wraps all analysis operations in a top-level `try/catch` or Rust `panic::catch_unwind`.
  2. If an analyzer crashes on a specific payload, the pipeline marks that payload as `SUSPICIOUS` (Weight: 65, Action: `WARN`), with reason: "Input contains malformed or obfuscated patterns that could not be verified safe."
  3. The crash is logged to an encrypted local diagnostic ring buffer.
- **Fail-Safe Verdict**: **FAIL-SAFE/FAIL-SECURE**. Unknown/malformed inputs default to CAUTION, never ALLOW.

---

### 2.10 Uncertain or Borderline Detection Verdict (Score 50–59)
- **Failure Trigger**: Input exhibits conflicting signals (e.g., brand-like name on an unverified domain with no explicit phishing keywords).
- **System Behavior**:
  1. Threshold maps to `INFORM` / `SUSPICIOUS` (Amber badge).
  2. Non-blocking user advisory: "Proceed with caution. We could not verify this sender/link."
  3. Transparent evidence points listed: "Domain is very new; sender is not in your contacts."
- **Fail-Safe Verdict**: Does not block legitimate user activity, but eliminates blind trust.

---

### 2.11 Conflicting Detection Signals (e.g. Heuristic Flags vs. Allowlist Entry)
- **Failure Trigger**: A legitimate domain on the allowlist (e.g., `google.com`) contains an unencrypted HTTP link or unusual characters in the path.
- **System Behavior**:
  1. **Deterministic Precedence**: Cryptographically verified Allowlist entries strictly suppress domain-level reputation blocks.
  2. However, explicit high-severity in-page payload triggers (e.g., `javascript:` scheme or embedded credential `@` tokens) retain `WARN` status for the specific link target.
  3. Disagreement is resolved toward user safety without causing alert fatigue on major search engines.
- **Fail-Safe Verdict**: Allowlist prevents domain blocking; explicit hostile payload patterns are still surfaced.
