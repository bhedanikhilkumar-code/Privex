# ERROR_ARCHITECTURE.md — Unified Error Taxonomy, Sanitization & Escalation

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION ERROR ARCHITECTURE**  
> This document specifies the unified error taxonomy, exception handling, data sanitization, retry strategies, and fail-closed safety behaviors across all PRIVATE PROTECTION subsystems.

---

## 1. THE CARDINAL DOCTRINES OF ERROR HANDLING

1. **The Fail-Closed Mandate**: When an internal detector, parser, or security subsystem crashes or encounters an unhandled exception during target analysis, the system must **NEVER FAIL OPEN** to silent `ALLOW`. It must fail safely to `CAUTION` with an explicit `ANALYSIS_DEGRADED` disclosure.
2. **Zero-PII Error Sanitization**: Error messages shown to users or recorded in local logs must **NEVER** include raw analyzed user payloads (URLs, message text, file paths) or internal sensitive process memory.
3. **No Stack Traces in Production UI**: User interfaces present human-friendly, cognitive Grade 6 explanations and recommended actions rather than technical stack traces or raw exception names.

---

## 2. UNIFIED ERROR TAXONOMY MATRIX

The platform classifies all exceptions into ten canonical error categories:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       UNIFIED ERROR TAXONOMY                                           │
│                                                                                                        │
│   [ERR-100] INVALID_INPUT         • Malformed URL syntax, character overflows, illegal encoding        │
│   [ERR-200] UNSUPPORTED_CONTENT   • Unknown file headers, unsupported protocols (e.g. gopher://)       │
│   [ERR-300] DETECTOR_FAILURE      • Parser panic, division by zero, unhandled heuristic exception       │
│   [ERR-400] TIMEOUT               • SLA budget exceeded (>100ms overall, >30ms ML inference)           │
│   [ERR-500] MODEL_FAILURE         • ONNX weight corruption, missing SLM runtime, out of memory        │
│   [ERR-600] STORAGE_FAILURE       • SQLCipher locked, disk full, Keystore key retrieval failure        │
│   [ERR-700] PERMISSION_FAILURE    • OS camera denied, notification listener denied, file read denied   │
│   [ERR-800] NETWORK_FAILURE       • Update CDN unreachable, OHTTP relay handshake timeout              │
│   [ERR-900] UPDATE_FAILURE        • Ed25519 signature invalid, downgrade attempt, patch corruption    │
│   [ERR-999] SECURITY_VIOLATION    • Indirect prompt injection detected, binary tampering detected      │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. CATEGORY SPECIFICATIONS & RECOVERY BEHAVIORS

---

### Category 1: `INVALID_INPUT` (`ERR-100`)
- **Root Cause**: Submitted URL exceeds 2,048 bytes, message text exceeds 10,000 characters, or string contains invalid UTF-8 sequences.
- **Internal Handling**: Clamps input to maximum byte boundary; replaces invalid sequences with replacement character (`U+FFFD`).
- **User-Facing Presentation**: "Input was too long or contained unrecognized characters. Analyzing the safe portion."
- **Fallback / Verdict**: Evaluates truncated input. If completely unparseable, awards `CAUTION` with `INVALID_STRUCTURE` token.

---

### Category 2: `UNSUPPORTED_CONTENT` (`ERR-200`)
- **Root Cause**: Scanned file has unknown magic bytes; URL uses unrecognized custom URI scheme (e.g., `customapp://`).
- **Internal Handling**: Emits `CONTENT_UNSUPPORTED` event.
- **User-Facing Presentation**: "This item uses an uncommon format that cannot be fully verified. Proceed with caution."
- **Fallback / Verdict**: Awards `INFORM` / `CAUTION`.

---

### Category 3: `DETECTOR_FAILURE` (`ERR-300`)
- **Root Cause**: An isolated analyzer encounters an unhandled exception or regular expression fault.
- **Internal Handling**: Catches fault at the subsystem boundary; records error code; continues execution of remaining detectors.
- **User-Facing Presentation**: "Partial scan completed. Some checks could not run."
- **Fallback / Verdict**: Deducts $0.20$ from Confidence score ($C_{\text{final}}$); sets verdict to minimum `CAUTION` (Score $\ge 50$). Never returns `ALLOW`.

---

### Category 4: `TIMEOUT` (`ERR-400`)
- **Root Cause**: Overall scan exceeds $100\text{ ms}$ SLA, or ML inference exceeds $30\text{ ms}$.
- **Internal Handling**: Aborts running worker isolate; aggregates all evidence gathered up to the timeout boundary.
- **User-Facing Presentation**: "Analysis timed out. Showing preliminary safety results."
- **Fallback / Verdict**: If ML times out, transparently activates Deterministic Template Engine; completes explanation in $< 0.1\text{ ms}$.

---

### Category 5: `MODEL_FAILURE` (`ERR-500`)
- **Root Cause**: On-device ONNX runtime fails to initialize, model file is missing, or SHA-256 integrity check fails.
- **Internal Handling**: Marks `MLInferenceProvider` as degraded; routes all narrative generation to Deterministic Template Engine.
- **User-Facing Presentation**: "Standard security templates active." (Zero disruption to user).
- **Fallback / Verdict**: 100% template fallback. Zero impact on detection accuracy or risk scores.

---

### Category 6: `STORAGE_FAILURE` (`ERR-600`)
- **Root Cause**: Host disk is full (`SQLITE_FULL`), database file is locked, or OS Keystore returns authentication error.
- **Internal Handling**: Switches local storage to volatile in-memory ring buffer; disables persistent event history logging.
- **User-Facing Presentation**: "Warning: Device storage is full. Real-time protection is still active, but scan history cannot be saved."
- **Fallback / Verdict**: Core detection continues uninterrupted.

---

### Category 7: `PERMISSION_FAILURE` (`ERR-700`)
- **Root Cause**: User denied camera permission on mobile or file access on desktop.
- **Internal Handling**: Gracefully handles OS permission denial callback without crashing.
- **User-Facing Presentation**: "Permission required to scan QR codes with your camera. Tap here to open Settings."
- **Fallback / Verdict**: Disables corresponding scanning vector; leaves all other vectors active.

---

### Category 8: `NETWORK_FAILURE` (`ERR-800`)
- **Root Cause**: No internet connection, DNS failure, or CDN timeout during background update check.
- **Internal Handling**: Logs network state; applies exponential backoff ($30\text{s}, 60\text{s}, 300\text{s}, 1800\text{s}$) with $\pm 20\%$ jitter.
- **User-Facing Presentation**: Silent background handling. If threat database exceeds 30 days old, shows non-intrusive staleness notice.
- **Fallback / Verdict**: Continues running on cached threat intelligence.

---

### Category 9: `UPDATE_FAILURE` (`ERR-900`)
- **Root Cause**: Cryptographic Ed25519 signature verification fails, patch SHA-256 mismatches, or monotonic version downgrade detected.
- **Internal Handling**: Deletes downloaded patch from staging immediately; preserves live database intact; isolates corrupt archive.
- **User-Facing Presentation**: "Security update check failed cryptographic verification. Current protection remains active."
- **Fallback / Verdict**: Retains current active database version. If active database is damaged, restores immutable Factory Seed.

---

### Category 10: `SECURITY_VIOLATION` (`ERR-999`)
- **Root Cause**: Analyzed message contains active indirect prompt injection patterns (e.g. `Ignore all previous instructions...`), or local binary checksum tampering is detected.
- **Internal Handling**: Isolates payload; flags `PROMPT_INJECTION_ATTEMPT` evidence token with maximum severity ($s = 95$); halts model execution.
- **User-Facing Presentation**: "High Risk: This message contains hidden commands attempting to manipulate security software."
- **Fallback / Verdict**: Immediate `DANGEROUS` verdict with high friction gate.
