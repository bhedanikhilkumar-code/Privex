# TRUST_BOUNDARIES.md — Trust Boundary Model & Component Isolation

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION TRUST BOUNDARIES**  
> This document defines the zero-trust boundary model of PRIVATE PROTECTION, detailing the separation between untrusted inputs, privileged host components, the trusted core, and external network services.

---

## 1. TRUST BOUNDARY ARCHITECTURE OVERVIEW

PRIVATE PROTECTION operates under the principle that **all inputs are potentially malicious payloads attempting to compromise the security tool itself**. The architecture enforces five strict trust boundaries:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ UNTRUSTED ZONE 0: EXTERNAL THREAT UNIVERSE                                                            │
│ • Attacker-controlled phishing URLs, deceptive Punycode domains, zero-width spoofing strings           │
│ • Scam SMS, extortion messages, impersonation emails, social engineering text                         │
│ • Malicious executables, polyglot files, weaponized office documents, malformed QR code bitmaps        │
│ ASSUMPTION: ACTIVE MALICE • EXPLOIT ATTEMPTS • HOSTILE PAYLOADS                                        │
└───────────────────────────────────────────────┬────────────────────────────────────────────────────────┘
                                                │
                                  TRUST BOUNDARY 1: INGESTION PERIMETER
                                  (Size Clamping, Input Normalization, Memory Sandboxing)
                                                │
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ SEMI-TRUSTED ZONE 1: HOST OS INTERACTION & CLIENT RUNTIMES                                            │
│ • Flutter Mobile App / Tauri Desktop Shell / Browser Extension Background Service Worker / Next.js PWA │
│ • Native OS Hooks: Android NotificationListener, iOS IdentityLookup, Windows ReadDirectoryChangesW     │
│ ASSUMPTION: COOPERATIVE BUT UNTRUSTED • PRONE TO PROCESS MEMORY INSPECTION IF OS COMPROMISED           │
└───────────────────────────────────────────┬────────────────────────────────────────────────────────────┘
                                            │
                              TRUST BOUNDARY 2: IPC & ENGINE API CONTRACT
                              (Immutable ScanRequest DTOs, Memory Zeroing Protocol, Zero OS Entitlements)
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ FULLY TRUSTED ZONE 2: LOCAL DETECTION CORE (@private-protection/core)                                  │
│ • Canonical Normalizer, Deterministic Rule Engine, Lexical & Entropy Analyzers                        │
│ • Binary Scalable Bloom Filter (Read-Only in RAM), Multi-Factor Risk Scorer                            │
│ ASSUMPTION: FULLY AUDITED • PURE COMPUTATION • ZERO NETWORK ACCESS • ZERO PERSISTENT OS ACCESS         │
└──────────────────────┬─────────────────────────────────────────────────┬───────────────────────────────┘
                       │                                                 │
         TRUST BOUNDARY 3: AI BOUNDARY                     TRUST BOUNDARY 4: STORAGE BOUNDARY
         (Strict JSON Tokens, Read-Only, No Overrides)      (AES-256-GCM, OS Keystore, Crypto-Shred)
                       │                                                 │
                       ▼                                                 ▼
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────────────┐
│ RESTRICTED ZONE 3: AI ASSISTANT RUNTIME      │ │ PROTECTED ZONE 4: ENCRYPTED LOCAL STATE              │
│ • Local ONNX INT8 SLM / Template Synthesizer │ │ • SQLite with SQLCipher / Web Crypto IndexedDB       │
│ • Generates user-facing threat narrative     │ │ • Custom user allowlists, local event counters       │
│ ASSUMPTION: UNTRUSTED FOR DECISION-MAKING    │ │ ASSUMPTION: ENCRYPTED AT REST • PURGEABLE AT WILL    │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────────────┘
                                                                         │
                                                           TRUST BOUNDARY 5: NETWORK RELAY
                                                           (OHTTP RFC 9458, Ed25519 Verified Only)
                                                                         │
                                                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ RESTRICTED ZONE 5: OPTIONAL BACKEND & STATELESS CDN                                                    │
│ • Cloudflare/Fastly Edge CDN (Signed Bloom filter delta patches)                                       │
│ • Oblivious HTTP Relay (IP-scrubbed anonymous telemetry aggregator)                                    │
│ ASSUMPTION: ZERO-KNOWLEDGE • SERVER NEVER SEES RAW URLS, MESSAGES, FILES, OR CLIENT IP/PAYLOAD PAIR     │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. DETAILED BOUNDARY DEFINITIONS & DEFENSE PROTOCOLS

### 2.1 Trust Boundary 1: Ingestion Perimeter (Untrusted External $\rightarrow$ Host Client)
- **Border Separation**: The boundary between raw, unvalidated external data (web traffic, SMS text, downloaded files) and the client application process.
- **Threat Vector**: Denial of Service (ReDoS) via catastrophically long URLs, memory exhaustion via multi-gigabyte file buffers, or buffer overflow via malformed binary headers.
- **Defensive Controls**:
  1. *Hard Truncation*: URLs are clamped to 2,048 bytes; text strings are clamped to 10,000 characters; file streams are processed in bounded 64 KB memory chunks.
  2. *Unicode Canonicalization*: Stripping of unassigned Unicode code points, zero-width spaces, and control characters before passing into analyzers.
  3. *Type Validation*: Strict runtime parsing using immutable schema validators (Zod / TypeBox).

### 2.2 Trust Boundary 2: Core Engine Contract (Host Client $\rightarrow$ Core Detection Engine)
- **Border Separation**: The boundary between the OS-level application shell (Tauri/Flutter/Extension) and the pure computational detection engine (`@private-protection/core`).
- **Threat Vector**: Host privilege escalation, memory leaks across scans, side-channel timing attacks, or malicious process tampering.
- **Defensive Controls**:
  1. *Zero OS Entitlements*: `@private-protection/core` has zero filesystem access, zero network sockets, zero child process spawning, and zero environment variable access.
  2. *Pure Function Interface*: All interaction occurs via immutable `ScanRequest` objects and returns frozen `ScanResult` structs.
  3. *Memory Zeroing Protocol*: Any buffer containing Tier 1 sensitive data is overwritten with zeroes immediately following scan evaluation before garbage collection.

### 2.3 Trust Boundary 3: AI Security Boundary (Core Engine $\rightarrow$ AI Assistant)
- **Border Separation**: The boundary between technical threat telemetry and the AI synthesis runtime (ONNX / SLM).
- **Threat Vector**: Indirect Prompt Injection, model jailbreaking, hallucinated safety verdicts, model-driven security downgrades, or sensitive data leakage in explanations.
- **Defensive Controls**:
  1. *Data vs. Instruction Separation*: Untrusted user text is **NEVER** concatenated into prompt instruction templates.
  2. *Structured Evidence Ingestion*: The AI receives only verified, tokenized evidence tags (e.g., `["BRAND_SPOOFING", "ENTROPY_HIGH", "SUSPICIOUS_TLD"]`).
  3. *Zero Authority Invariant*: The AI model has **zero architectural authority** to modify, lower, or reverse the risk score, severity level, or recommended action established by Plane 3.
  4. *Rigid Grammar Enforcement*: AI output is forced into a strict JSON grammar conforming to `docs/AI_ASSISTANT_CONTRACT.md`. Any output failing validation is dropped in favor of deterministic fallback templates.

### 2.4 Trust Boundary 4: Local Storage Perimeter (Core Engine $\rightarrow$ Persistence)
- **Border Separation**: The boundary between volatile execution RAM and non-volatile persistent storage (disk).
- **Threat Vector**: Unauthorized local file reads by co-located apps, forensics recovery of browsing history, offline disk theft, or database tampering.
- **Defensive Controls**:
  1. *Full Page Encryption*: SQLCipher AES-256-GCM page encryption.
  2. *Hardware-Backed Key Hierarchy*: Encryption keys are derived from the OS hardware enclave and never persisted in plaintext.
  3. *Zero-Knowledge Tier 1 Policy*: Visited URLs, raw message bodies, and file payloads are **never written to disk**. Only anonymized event counters and user allowlists reside in storage.
  4. *Crypto-Shredding*: Instant deletion of local history by zeroing the Master Encryption Key in the hardware keystore.

### 2.5 Trust Boundary 5: Network Perimeter (Local Endpoint $\rightarrow$ External Backend)
- **Border Separation**: The boundary between the user's physical device and the internet.
- **Threat Vector**: User tracking, URL surveillance, man-in-the-middle updates, supply chain malware injection, or IP-based correlation.
- **Defensive Controls**:
  1. *Default Air-Gap*: The core detection engine functions 100% offline. Disconnecting network interfaces produces zero functional degradation in real-time threat detection.
  2. *Ed25519 Binary Signatures*: All update packages (Bloom filter diffs, rule updates) must be verified against an embedded, immutable Root Public Key. Unsigned or improperly signed updates are immediately rejected.
  3. *Monotonic Anti-Downgrade Versioning*: Client firmware/database updates reject any payload with a version integer $\le$ current installed version.
  4. *Oblivious HTTP Telemetry*: Opt-in metrics are stripped of client IP addresses via an independent third-party OHTTP relay (RFC 9458) and locally blurred with Laplace differential privacy noise ($\varepsilon = 1.0$).

---

## 3. TRUSTED VS. UNTRUSTED COMPONENT MATRIX

| Component | Trust Level | Justification & Safeguards |
|---|---|---|
| **Raw Inbound URL / Text / File** | **UNTRUSTED (Hostile)** | Untrusted external input. Treated as an active exploit payload. |
| **Input Sanitizer & Normalizer** | **TRUSTED** | Audited, bounded regex and string transformations; zero-allocation algorithms. |
| **Rule & Heuristic Engines** | **TRUSTED** | Pure mathematical deterministic functions; zero external state; tested against 100+ edge cases. |
| **Threat Intel Bloom Filter** | **TRUSTED (Read-Only)** | Static in-memory binary array; cryptographic hash lookups; zero dynamic execution. |
| **Risk Aggregator** | **TRUSTED** | Pure Bayesian weighted math; strictly bounded output between 0 and 100. |
| **AI / SLM Runtime** | **RESTRICTED** | Constrained to narrative synthesis; zero decision authority; strictly validated output schemas. |
| **Encrypted Local Storage** | **TRUSTED** | Authenticated AES-256-GCM; access gated by OS user credentials. |
| **Host OS Notification / Services** | **SEMI-TRUSTED** | Platform-provided daemon; restricted to registered IPC channels. |
| **External Update CDN** | **UNTRUSTED (Untrusted Host)** | Public cloud server; contents verified cryptographically via offline Ed25519 signatures. |
| **OHTTP Telemetry Relay** | **UNTRUSTED (Zero-Knowledge)** | Relay routes blind encrypted blobs; cannot read content; collector cannot see IP. |
