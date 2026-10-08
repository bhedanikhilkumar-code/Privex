# ONLINE_ARCHITECTURE.md — Connected Services, Privacy Guarantees & Fallbacks

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVEX ONLINE ARCHITECTURE**  
> This document specifies the optional, value-add online capabilities of PRIVEX. It provides an exhaustive accounting of every network interaction, detailing data minimization, cryptographic privacy mechanisms, explicit consent gates, and offline fallbacks.

---

## 1. THE FOUNDATIONAL ZERO-CLOUD MANDATE

> **ONLINE CONSTITUTIONAL INVARIANT**: Online connectivity is an **OPTIONAL ENHANCEMENT**, never a runtime prerequisite. Disabling all network entitlements must leave core endpoint threat protection 100% operational.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ENDPOINT BOUNDARY                                                      INTERNET / CLOUD EDGE           │
│                                                                                                        │
│   ┌───────────────────────────────┐     HTTPS GET (Static Binary)        ┌─────────────────────────┐   │
│   │ Local Threat Intel Updater    │────────────────────────────────────►│ Stateless CDN Edge       │   │
│   │ • No User ID • No Device ID   │◄────────────────────────────────────│ (Cloudflare/Fastly)     │   │
│   └───────────────────────────────┘     Ed25519 Signed Patch (<500 KB)   │ • Public static assets  │   │
│                                                                          └─────────────────────────┘   │
│                                                                                                        │
│   ┌───────────────────────────────┐     HPKE Encrypted Blob              ┌─────────────────────────┐   │
│   │ Opt-In Telemetry Sanitizer    │────────────────────────────────────►│ Oblivious HTTP Relay    │   │
│   │ • Laplace Noise (epsilon=1.0) │     (Relay sees IP, NOT payload)     │ (RFC 9458)              │   │
│   │ • k-Anonymity (k >= 1,000)    │                                      └────────────┬────────────┘   │
│   └───────────────────────────────┘                                                   │                │
│                                                                                       ▼ Forward Blob   │
│                                                                          ┌─────────────────────────┐   │
│                                                                          │ Telemetry Aggregator    │   │
│                                                                          │ (Sees payload, NOT IP)  │   │
│                                                                          └─────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. COMPREHENSIVE ONLINE FEATURE MATRIX

Every online capability is audited against five mandatory security criteria:

---

### Feature 1: Threat Intelligence Bloom Filter Delta Updates
- **Purpose**: Distributes daily binary delta patches (`.bf.patch`) to keep local Bloom filters updated against newly discovered phishing and malware domains.
- **Why It Needs Network**: Threat actors register thousands of malicious domains daily; local databases need fresh hash indicators.
- **Data Leaving Device**: **ZERO USER DATA**. Client sends a standard HTTP GET request with `If-None-Match` HTTP header containing the currently installed version integer (e.g. `104`). No user identifiers, device tokens, or URLs are sent.
- **Consent Gate**: **Enabled by Default** (Essential security maintenance). User can disable in Settings (`Automatic Threat Database Updates: OFF`).
- **Can It Be Disabled?**: **YES**. Fully configurable in client preferences.
- **Offline Fallback**: Uses existing cached local Bloom filter with staleness degradation protocol (as defined in `docs/OFFLINE_ARCHITECTURE.md`).

---

### Feature 2: Rule Engine & Detection Logic Updates
- **Purpose**: Distributes updated deterministic regex patterns, brand dictionary entries, and heuristic weights.
- **Why It Needs Network**: To rapidly counter novel scam message templates and emerging brand typosquatting variations without requiring full app store releases.
- **Data Leaving Device**: **ZERO USER DATA**. Static HTTPS GET for signed JSON bundle (`rules-v{N}.json.enc`).
- **Consent Gate**: Enabled by Default.
- **Can It Be Disabled?**: **YES**. User can lock rule version in advanced settings.
- **Offline Fallback**: Uses factory-bundled immutable ruleset.

---

### Feature 3: On-Device Model Weight Refresh (ONNX INT8)
- **Purpose**: Periodically distributes retrained INT8 quantized model weights for improved intent classification.
- **Why It Needs Network**: Downloads updated 20MB model artifact.
- **Data Leaving Device**: **ZERO USER DATA**. Static file download.
- **Consent Gate**: Enabled by Default (Constrained to Wi-Fi only to conserve mobile cellular data).
- **Can It Be Disabled?**: **YES**. User can toggle `Download Models Over Cellular` or disable model updates completely.
- **Offline Fallback**: Uses previous model weights or deterministic template engine.

---

### Feature 4: $k$-Anonymity Reputation Lookup (Optional Second Opinion)
- **Purpose**: Allows an optional real-time cloud reputation check for rare, ambiguous domains that score borderline (50-69) on local heuristics.
- **Why It Needs Network**: Queries the global reputation database for newly registered domain age.
- **Data Leaving Device**: **TRUNCATED HASH PREFIX ONLY**. Client computes SHA-256 of the domain, truncates the hash to the first **20 bits** (leaving 236 bits unknown), and sends only the 20-bit prefix.
- **Mathematical Privacy Guarantee**: $k$-anonymity where $k \ge 1,000$. The server responds with a list of all known malicious hashes matching that 20-bit prefix. The client performs the final exact match locally in RAM. The cloud server **never learns** which specific domain was visited.
- **Consent Gate**: **STRICTLY OPT-IN**. Disabled by default. User must explicitly enable "Cloud-Assisted Ambiguity Resolution" in Security Settings.
- **Can It Be Disabled?**: **YES** (Default is OFF).
- **Offline Fallback**: Borderline domains receive a `CAUTION` warning with transparent uncertainty disclosure; no network call attempted.

---

### Feature 5: End-to-End Encrypted User Allowlist Synchronization (Optional)
- **Purpose**: Synchronizes user-defined custom trusted allowlists across their personal mobile, desktop, and browser instances.
- **Why It Needs Network**: Replicates allowlist state across user devices.
- **Data Leaving Device**: **ZERO PLAINTEXT**. Encrypted client-side using user-derived Master Key (Argon2id + AES-256-GCM) before transmission. Server stores opaque binary blobs.
- **Consent Gate**: **STRICTLY OPT-IN**. Requires user to generate and link sync keys.
- **Can It Be Disabled?**: **YES** (Default is local-only storage).
- **Offline Fallback**: All allowlists reside in local SQLCipher database.

---

### Feature 6: Differential Privacy Anonymous Telemetry Relay (Optional)
- **Purpose**: Collects aggregate statistics on triggered rule IDs to help researchers track emerging cybercrime campaigns.
- **Why It Needs Network**: Transmits anonymized threat occurrence counts.
- **Data Leaving Device**:
  - Triggered Rule ID (e.g., `rule-brand-spoof-amazon`).
  - Engine Version (e.g., `104`).
  - Truncated 16-bit domain hash prefix.
  - Injected Laplace noise ($\varepsilon = 1.0$).
  - **ABSOLUTELY NO**: URLs, message text, user IDs, device IDs, or IP addresses.
- **Privacy Architecture**: Routed through an **Oblivious HTTP Relay (RFC 9458)**. The relay terminates the IP connection and forwards an opaque HPKE-encrypted blob to the aggregator.
- **Consent Gate**: **STRICTLY OPT-IN**. Explicit toggle during initial onboarding with clear privacy disclosure.
- **Can It Be Disabled?**: **YES** (Default is OFF).
- **Offline Fallback**: Zero telemetry recorded; events remain strictly in local user audit logs.

---

## 3. NETWORK PROTOCOL & TRANSPORT SECURITY REQUIREMENTS

1. **Mandatory TLS 1.3**: All outbound connections enforce TLS 1.3 with modern cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
2. **Strict Certificate Pinning**: Mobile and desktop clients pin the Subject Public Key Info (SPKI) hashes of the CDN and update authority certificates.
3. **DNS-over-HTTPS (DoH)**: Where platform networking allows, update lookups use encrypted DoH (Cloudflare / Quad9) to prevent local ISP eavesdropping.
4. **No Third-Party Trackers**: Zero third-party analytics libraries (Google Analytics, Firebase Analytics, Sentry, Mixpanel, Adjust, AppsFlyer) are permitted anywhere in the codebase.
