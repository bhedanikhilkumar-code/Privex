# DATA_FLOW_ARCHITECTURE.md — Comprehensive Data Flows & Processing Pipelines

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVEX DATA FLOWS**  
> This document specifies the exact, step-by-step data flows across all eight primary operations in the PRIVEX ecosystem. Each flow documents input, normalization, processing stages, detectors, AI involvement, threat intelligence, risk aggregation, output, storage, network transmission, and privacy boundaries.

---

## 1. FLOW TAXONOMY & OVERVIEW

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    DATA FLOW DIRECTORY                                       │
│                                                                                              │
│   FLOW A: Manual User URL Check (Web / Extension / Desktop / Mobile Form)                    │
│   FLOW B: Inbound Scam Message Analysis (SMS / Chat / Email / Clipboard)                     │
│   FLOW C: Real-Time Browser Pre-Navigation Intercept (Extension WebNavigation)               │
│   FLOW D: Local Desktop Download / File Inspection (Tauri Filesystem Watcher)                │
│   FLOW E: Mobile Screenshot / Live Camera QR Code Scan (Flutter Camera / Gallery Share)      │
│   FLOW F: Air-Gapped Offline Threat Detection (100% Disconnected Core Pipeline)              │
│   FLOW G: Differential Threat Intelligence & OTA Update Ingestion                            │
│   FLOW H: Privacy-Preserving Cloud Telemetry Relay (Opt-In OHTTP Telemetry)                  │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. DETAILED FLOW SPECIFICATIONS

---

### FLOW A: Manual Suspicious URL Analysis
*User submits a suspicious URL via manual input field in Web App, Mobile App, or Desktop UI.*

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as Client UI Surface
    participant Adapter as Input Adapter
    participant Core as Core Detection Pipeline
    participant Bloom as Threat Intel Bloom Filter
    participant Scorer as Risk Aggregator
    participant AI as AI Security Assistant
    participant Vault as Local Encrypted Vault

    User->>UI: Pastes URL ("http://login.pаypal.com-auth.xyz/verify")
    UI->>Adapter: Submit raw URL string
    Adapter->>Adapter: Truncate <= 2,048 bytes & validate format
    Adapter->>Core: ScanRequest(type: URL, payload: rawUrl)
    Core->>Core: Unicode NFKD normalization & Punycode decoding
    Core->>Core: Extract lexical features (Entropy, Brand Distance, Subdomain Depth)
    Core->>Bloom: O(1) Bitwise lookup on domain hash ("paypal.com-auth.xyz")
    Bloom-->>Core: Match result (e.g., negative or hit)
    Core->>Core: Evaluate deterministic rules (e.g., IP host, deceptive brand match)
    Core->>Scorer: Aggregate Evidence tokens
    Scorer-->>UI: Return Verdict: WARN / BLOCK (Score: 92/100) [< 1.0 ms]
    UI->>UI: Render Instant Warning Modal with Friction Shield [< 50 ms]
    Core->>AI: Synthesize Explanation(Evidence list)
    AI-->>UI: Async update modal with plain-language threat narrative [< 25 ms]
    UI->>Vault: Store anonymized event record in encrypted SQLite/IndexedDB
```

- **Input**: Raw URL string from user clipboard or text field (max 2,048 bytes).
- **Normalization**: Unicode NFKD canonicalization; lowercase scheme and host; Punycode homoglyph resolution (`pаypal` Cyrillic `а` resolved to `a`); path stripping for domain checks.
- **Processing**: Extraction of lexical metrics (Shannon entropy, Levenshtein edit distance against 100 top protected brands, subdomain count, suspicious TLD flag).
- **Detectors**: `DeterministicRuleEngine` + `LexicalAnalyzer` + `PunycodeAnalyzer`.
- **AI Involvement**: **Read-Only Narrative Synthesis**. The AI engine receives the structured `Evidence` list (e.g., `["BRAND_SPOOF_PAYPAL", "SUSPICIOUS_TLD_XYZ", "HIGH_ENTROPY"]`) and generates the user explanation.
- **Threat Intelligence**: Local memory-mapped binary Bloom filter lookup ($O(1)$) on host hash prefix.
- **Risk Aggregation**: Multi-factor non-linear Bayesian scorer yields Score: 92, Confidence: 0.95, Action: `BLOCK`.
- **Output**: Warning modal rendered in $< 50\text{ ms}$; detailed explanation rendered in $< 25\text{ ms}$.
- **Storage**: Event metadata (timestamp, rule IDs, risk score) persisted to SQLCipher/IndexedDB. Raw URL is **not** persisted unless user explicitly whitelists it.
- **Network Transmission**: **ZERO**. Entire execution occurs in local volatile RAM.
- **Privacy Boundary**: Tier 1 data processed strictly inside local process memory.

---

### FLOW B: Inbound Scam Message Analysis
*Inbound SMS, chat message, or email text is analyzed for social engineering, urgency extortion, or financial scam indicators.*

```mermaid
sequenceDiagram
    autonumber
    actor Sender
    participant OS as OS Notification / SMS Filter
    participant Adapter as Mobile/Desktop Adapter
    participant Parser as Heuristic Message Parser
    participant Rules as Deterministic Keyword Engine
    participant Scorer as Risk Aggregator
    participant AI as AI Security Assistant
    participant UI as User Notification Surface

    Sender->>OS: Inbound message ("URGENT: Bank account suspended! Send $500 crypto...")
    OS->>Adapter: Event received (text <= 10,000 chars)
    Adapter->>Parser: Parse Message Tokens in Volatile RAM
    Parser->>Rules: Match extortion keywords & payment demands (Crypto, gift card, wire)
    Parser->>Parser: Compute urgency score & authority impersonation markers
    Parser->>Scorer: Emit Evidence tokens (e.g. URGENCY_PRESSURE, CRYPTO_DEMAND)
    Scorer-->>Adapter: Final Risk Score: 88 (DANGEROUS)
    Adapter->>AI: Request Plain-Language Explanation(Evidence)
    AI-->>Adapter: Narrative: "This message uses fake urgency to pressure you into paying."
    Adapter->>UI: Dispatch Instant High-Priority Warning Notification [< 50 ms]
    Adapter->>Adapter: Zero raw message text from RAM buffer
```

- **Input**: Raw text message string (max 10,000 characters).
- **Normalization**: Unicode NFKD normalization; leetspeak and zero-width character de-obfuscation; regex-based tokenization into sentences and entities.
- **Processing**: Extraction of urgency markers (time pressure indicators), financial demands (cryptocurrency wallet regexes, wire transfers, gift cards), and authority impersonation cues (IRS, Bank, Police).
- **Detectors**: `MessageAnalyzer` + `UrgencyHeuristicEngine` + `FinancialExtortionDetector`.
- **AI Involvement**: Translates matched scam patterns into cognitive Grade 6 explanations explaining *why* the message is fraudulent and instructing the user *never* to reply or click links.
- **Threat Intelligence**: Checks extracted URLs/cryptocurrency addresses against local blocklist caches.
- **Risk Aggregation**: Weighted multi-factor aggregation computes overall scam probability score (0-100).
- **Output**: High-priority push notification / warning banner with clear "Do Not Reply" recommendation.
- **Storage**: Zero-knowledge logging: increments local scam category counter; raw message text is zeroed from RAM immediately upon scan completion.
- **Network Transmission**: **ZERO**. 100% on-device processing.
- **Privacy Boundary**: Tier 1 raw message content strictly isolated to volatile memory.

---

### FLOW C: Real-Time Browser Pre-Navigation Intercept
*User clicks a link or enters a URL in the browser address bar. The browser extension intercepts navigation before network transmission.*

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser as Browser Navigation Engine
    participant Ext as MV3 Background Service Worker
    participant Core as WASM Detection Pipeline
    participant Shadow as Content Script Shadow DOM
    participant Webpage as Destination Server

    User->>Browser: Clicks link or enters address
    Browser->>Ext: webNavigation.onBeforeNavigate(details)
    Ext->>Core: Evaluate target URL via WebAssembly
    Core->>Core: Normalization -> Bloom Filter -> Lexical Rules (< 0.8 ms)
    alt Safe URL (Score < 30)
        Core-->>Ext: Verdict: ALLOW
        Ext-->>Browser: Proceed with navigation
        Browser->>Webpage: Standard HTTP GET request
    else Malicious URL (Score >= 70)
        Core-->>Ext: Verdict: BLOCK / WARN
        Ext->>Browser: Cancel or redirect navigation to interstitial
        Ext->>Shadow: Inject Full-Page Warning Overlay into tab
        Shadow->>User: Display red warning screen with friction gate ("Take me back")
    end
```

- **Input**: Navigation URL intercepted via `webNavigation.onBeforeNavigate` or `declarativeNetRequest`.
- **Normalization**: Canonical normalization and Punycode resolution via compiled WebAssembly module.
- **Processing**: High-speed pre-flight check in background Service Worker.
- **Detectors**: `WASMBloomFilter` + `WASMLexicalAnalyzer`.
- **AI Involvement**: Deterministic templates provide instant headline; local ONNX-Web/Template generates full breakdown on warning overlay.
- **Threat Intelligence**: In-memory Bloom filter lookup completed in $< 0.05\text{ ms}$.
- **Risk Aggregation**: Immediate threshold evaluation against pre-set security policies.
- **Output**: Navigation cancellation and injection of un-bypassable Shadow DOM interstitial warning.
- **Storage**: Temporary session cache of blocked domain in `chrome.storage.local`.
- **Network Transmission**: **ZERO outbound calls** prior to user decision. If blocked, zero network packets reach the destination server.
- **Privacy Boundary**: Full browsing history never leaves the local browser extension sandbox.

---

### FLOW D: Desktop Local File & Download Inspection
*User downloads a file or requests a scan of a local executable/document.*

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant FS as Host Filesystem / Download Folder
    participant Watcher as Tauri Background File Watcher
    participant Core as File Analyzer Engine
    participant Vault as Quarantine Vault
    participant UI as Desktop System Tray / Window

    FS->>Watcher: ReadDirectoryChangesW / FSEvents notification (New file created)
    Watcher->>Core: Stream file header & compute SHA-256 (64 KB chunks)
    Core->>Core: Inspect Magic Bytes & PE/Mach-O/ELF header structure
    Core->>Core: Compute Shannon Entropy of file sections (Packed/Encrypted payload check)
    Core->>Core: Check against known malicious file signatures & heuristics
    alt Malicious File Detected
        Core->>Vault: Move file to AES-256 encrypted Quarantine Vault (.vault container)
        Core->>UI: Trigger OS Warning Notification & Desktop Modal
        UI->>User: "Malicious file detected and quarantined. Explaining threat..."
    else Safe File
        Core->>Watcher: Release file lock
    end
```

- **Input**: Local file path or streamed byte chunks from download directory watcher.
- **Normalization**: Path sanitization, symlink resolution, magic byte header identification.
- **Processing**: Extraction of file metadata, magic bytes vs. file extension consistency, Shannon entropy across sections, and PE/Mach-O header anomaly parsing.
- **Detectors**: `FileHeaderAnalyzer` + `EntropyCalculator` + `SignatureMatchEngine`.
- **AI Involvement**: Synthesizes explanation of executable anomalies (e.g., "This file pretends to be a PDF but is actually an executable with suspicious packed code").
- **Threat Intelligence**: Hash prefix comparison against local threat intelligence database.
- **Risk Aggregation**: Evaluates structural indicators into aggregate risk score.
- **Output**: System tray alert, window popup, and atomic file move into local encrypted quarantine vault.
- **Storage**: Quarantine metadata saved in encrypted SQLite. File contents encrypted with AES-256-GCM.
- **Network Transmission**: **ZERO**. Pure offline desktop processing.
- **Privacy Boundary**: File bytes and file paths remain strictly on the local machine.

---

### FLOW E: Mobile Screenshot & Live Camera QR Code Scan
*User scans a QR code with the device camera or shares a screenshot to PRIVEX.*

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as Mobile App (Flutter)
    participant MLKit as Local On-Device Vision / ZXing
    participant Core as Detection Engine (dart:ffi)
    participant Scorer as Risk Aggregator
    participant UI as Camera Overlay UI

    User->>App: Points camera at QR code or shares screenshot
    App->>MLKit: Process frame/image strictly in RAM
    MLKit-->>App: Extracted text/URL payload
    App->>Core: ScanRequest(type: URL/TEXT, payload)
    Core->>Core: Normalization -> Bloom Filter -> Heuristics (< 1.0 ms)
    Core->>Scorer: Risk Score calculated
    Scorer-->>App: Verdict: DANGEROUS (Score: 95)
    App->>UI: Flash Red Border on Camera Frame & Haptic Warning Vibrate [< 50 ms]
    App->>UI: Show Warning Drawer with AI Explanation before user clicks
    App->>App: Zero camera frame buffer from memory
```

- **Input**: Camera bitmap buffer or shared screenshot image from gallery.
- **Normalization**: On-device barcode/QR decoding (ZXing / Google ML Kit local barcode API) or on-device OCR.
- **Processing**: Decoded string payload passed directly into `@private-protection/core`.
- **Detectors**: Vision decoder + full URL/Message detection pipeline.
- **AI Involvement**: Read-only explanation of detected QR payload deception.
- **Threat Intelligence**: In-memory Bloom filter query.
- **Risk Aggregation**: Standard core risk scoring.
- **Output**: Real-time camera viewfinder bounding box colored red, haptic vibration feedback, and warning modal.
- **Storage**: Zero persistence of camera frames or image pixels.
- **Network Transmission**: **ZERO**.
- **Privacy Boundary**: Raw visual frames processed entirely in ephemeral GPU/CPU memory and immediately released.

---

### FLOW F: Air-Gapped Offline Threat Detection
*Device is in Airplane Mode or operating within a physically air-gapped secure environment.*

- **Input**: Any supported payload (URL, text, file, QR).
- **Processing**: 100% identical to normal operation. All rules, lexical models, heuristics, Bloom filters, and explanation templates are hosted locally on disk and loaded in RAM.
- **Threat Intelligence**: Uses cached local Bloom filter with staleness indicator. If cache is $> 30\text{ days}$ old, system applies a mild conservative penalty to borderline scores while maintaining full deterministic and heuristic protection.
- **AI Involvement**: Deterministic parameterized template engine or local quantized ONNX model executes with zero cloud dependency.
- **Network Transmission**: **ABSOLUTELY ZERO**. Network sockets are never opened.
- **Privacy Boundary**: Physically and logically contained within the device endpoint.

---

### FLOW G: Differential Threat Intelligence & OTA Update
*Background daemon queries the static update CDN for signed delta patches.*

```mermaid
sequenceDiagram
    autonumber
    participant Client as Local Update Manager
    participant CDN as Stateless Edge CDN
    participant HSM as Offline Build Authority (Hardware Key)

    Note over HSM,CDN: Build Authority generates & signs delta patch (Ed25519)
    Client->>CDN: HTTPS GET /manifest.json (No user ID, No device ID)
    CDN-->>Client: Manifest { version: 104, sha256, signature, patchUrl }
    Client->>Client: Check monotonic version (Reject version <= current)
    Client->>Client: Verify Ed25519 signature against hardcoded Root Public Key
    Client->>CDN: HTTPS GET /patches/diff_103_to_104.bf.patch
    CDN-->>Client: Binary delta patch (< 500 KB)
    Client->>Client: Verify patch SHA-256 hash
    Client->>Client: Apply bsdiff patch to local Bloom filter in atomic staging area
    Client->>Client: Verify reconstructed filter Merkle root & Ed25519 signature
    Client->>Client: Atomic rename staging -> live active filter
```

- **Input**: Outbound HTTP GET request to CDN for public update manifest.
- **Normalization**: Cryptographic verification of update manifest and delta binary.
- **Security Check**: Verification of monotonic version counter (anti-downgrade) and Ed25519 cryptographic signature.
- **Storage**: Atomic write to temporary staging directory followed by atomic file swap.
- **Network Transmission**: Standard HTTPS GET for static binary blobs. **Zero user payload transmitted**.
- **Privacy Boundary**: Request contains only standard HTTP cache headers; zero tracking cookies, user IDs, or device identifiers.

---

### FLOW H: Privacy-Preserving Cloud Telemetry Relay (Opt-In Only)
*User has explicitly opted into anonymous threat telemetry to help improve global detection feeds.*

```mermaid
sequenceDiagram
    autonumber
    participant Core as Local Risk Scorer
    participant Telemetry as Telemetry Sanitizer
    participant OHTTP as Oblivious HTTP Relay (Cloudflare)
    participant Collector as Telemetry Aggregation Server

    Core->>Telemetry: Detection Event (Rule: "url-brand-spoof", Score: 85)
    Telemetry->>Telemetry: Check Opt-In flag (If false, abort immediately)
    Telemetry->>Telemetry: Strip all URLs, IPs, user IDs, and timestamps
    Telemetry->>Telemetry: Truncate domain hash to 16-bit prefix (k-anonymity >= 1,000)
    Telemetry->>Telemetry: Inject Laplace differential privacy noise (epsilon = 1.0)
    Telemetry->>Telemetry: Encrypt payload with Collector Public Key (HPKE)
    Telemetry->>OHTTP: Transmit Encrypted Blob to OHTTP Relay (Relay sees IP, not payload)
    OHTTP->>Collector: Forward Decoupled Blob (Collector sees payload, not IP)
    Collector->>Collector: Aggregate statistical counters
```

- **Input**: Detection event telemetry struct.
- **Sanitization & Differential Privacy**: Complete removal of Tier 1 user data; truncation of domain hashes to 16-bit prefixes ensuring $k\ge 1,000$; addition of Laplace differential privacy noise ($\varepsilon = 1.0$).
- **Cryptographic Oblivious Relay**: Hybrid Public Key Encryption (HPKE RFC 9180) payload transmitted via Oblivious HTTP (RFC 9458) relay.
- **Network Transmission**: Relay sees Client IP but cannot decrypt payload; Collector receives decrypted payload but has zero visibility into Client IP.
- **Privacy Boundary**: Mathematically prevents re-identification and tracking of individual users.
