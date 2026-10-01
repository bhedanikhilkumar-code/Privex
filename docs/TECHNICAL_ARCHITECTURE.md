# TECHNICAL_ARCHITECTURE.md — System Topology & Technical Architecture

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION TECHNICAL ARCHITECTURE**  
> This document specifies the comprehensive technical topology, process boundaries, execution threads, and subsystem interactions of the PRIVATE PROTECTION ecosystem.

---

## 1. COMPREHENSIVE SYSTEM TOPOLOGY

PRIVATE PROTECTION is structured into six strictly demarcated execution planes:

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ PLANE 1: CLIENT RUNTIMES & INTERACTION SURFACES                                                      │
│                                                                                                       │
│   ┌─────────────────────┐   ┌─────────────────────┐   ┌────────────────────┐   ┌──────────────────┐   │
│   │   Mobile Client     │   │   Desktop Client    │   │  Browser Extension │   │  Web App (PWA)   │   │
│   │  (Flutter UI + OS   │   │  (Tauri Webview +   │   │  (MV3 Background + │   │  (Next.js SSG +  │   │
│   │   Native Services)  │   │   Rust Core Daemon) │   │   Shadow DOM UI)   │   │   Web Workers)   │   │
│   └──────────┬──────────┘   └──────────┬──────────┘   └─────────┬──────────┘   └────────┬─────────┘   │
└──────────────┼─────────────────────────┼────────────────────────┼───────────────────────┼─────────────┘
               │                         │                        │                       │
               ▼                         ▼                        ▼                       ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ PLANE 2: PLATFORM ADAPTER & IPC LAYER (ZERO-TRUST SANITIZATION BOUNDARY)                               │
│  • Enforces memory limits (URLs <= 2,048 bytes; Text <= 10,000 bytes; Files <= 100MB stream)          │
│  • Normalizes raw OS platform events into standardized ScanRequest structs                           │
│  • Marshals platform thread contexts (Main UI thread -> Dedicated background worker thread)           │
└──────────────────────────────────────────┬────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ PLANE 3: SHARED CORE DETECTION PIPELINE (@private-protection/core)                                    │
│                                                                                                       │
│   ┌───────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ STAGE 1: Canonical Normalizer (NFKD, Punycode, Unescape, Canonical Scheme/Host)               │   │
│   └──────────────────────────────────────┬────────────────────────────────────────────────────────┘   │
│                                          │                                                            │
│       ┌──────────────────────────────────┴────────────────────────────────────┐                       │
│       ▼                                  ▼                                    ▼                       │
│   ┌───────────────────────┐   ┌────────────────────────┐   ┌──────────────────────────────────────┐   │
│   │ Deterministic Rules   │   │ Lexical & Heuristics   │   │ Reputation & Threat Intelligence     │   │
│   │ • Scheme checks       │   │ • Shannon Entropy      │   │ • Binary Bloom Filter (<3.5MB)       │   │
│   │ • IP-in-hostname      │   │ • Brand Distance       │   │ • Custom User Allowlist/Blocklist    │   │
│   │ • Urgent extortion kw │   │ • Subdomain stacking   │   │ • In-Memory O(1) Bitwise Evaluation  │   │
│   └───────────┬───────────┘   └───────────┬────────────┘   └──────────────────┬───────────────────┘   │
│               │                           │                                   │                       │
│               └───────────────────────────┼───────────────────────────────────┘                       │
│                                           ▼                                                           │
│   ┌───────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ STAGE 2: Multi-Factor Risk Scorer (Weighted Mathematical Aggregation: 0-100 Score, Severity)  │   │
│   └──────────────────────────────────────┬────────────────────────────────────────────────────────┘   │
│                                          │                                                            │
│                                          ▼                                                            │
│   ┌───────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ STAGE 3: Policy Decision Engine (ALLOW, INFORM, CAUTION, SUSPICIOUS, DANGEROUS)               │   │
│   └───────────────────────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────┬────────────────────────────────────────────────────────────┘
                                           │
              ┌────────────────────────────┴─────────────────────────────┐
              ▼                                                          ▼
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────────────┐
│ PLANE 4: LOCAL AI & SYNTHESIS RUNTIME        │ │ PLANE 5: ENCRYPTED PERSISTENCE & VAULT               │
│ • ONNX Runtime INT8 / Deterministic Template │ │ • SQLCipher / IndexedDB (AES-256-GCM)                │
│ • Synthesizes user-friendly explanations     │ │ • Hardware-backed Key Derivation (Enclave/DPAPI)     │
│ • STRICT CONSTITUTION: Zero override rights  │ │ • Zero-knowledge scan history & quarantine metadata  │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────────────┘
                                                 ▲
                                                 │ (Cryptographically Signed OTA Diffs Only)
┌────────────────────────────────────────────────┴──────────────────────────────────────────────────────┐
│ PLANE 6: OPTIONAL STATELESS CLOUD EDGE & TELEMETRY RELAY                                              │
│ • Ed25519-Signed Differential Bloom Filter Updates (`.bf.patch`) via Cloudflare/Fastly CDN             │
│ • Oblivious HTTP (OHTTP RFC 9458) Relay: IP scrubbing for opt-in epsilon-differentially private stats │
│ • STRICT RULE: Zero user URLs, Zero messages, Zero file data received by cloud services              │
└───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. SUBSYSTEM RESPONSIBILITIES & BOUNDARIES

### 2.1 Plane 1: Client Runtimes
Each client runtime provides the human-facing experience and interfaces with OS-specific event sources:
- **Mobile Client**: Runs on Android and iOS. Hosts the Flutter presentation layer, handles user friction confirmation dialogs, and coordinates with platform background daemons.
- **Desktop Client**: Runs on Windows and macOS. Hosts the Tauri frontend UI, controls the system tray, and drives desktop notification popups.
- **Browser Extension**: Runs in Chromium and Gecko browsers. Manages `webNavigation` lifecycle, injects pre-navigation Shadow DOM warning overlays, and shields password inputs.
- **Web App (PWA)**: Pure client-side security portal. Executes analysis completely within the user's browser without sending payloads to any server.

### 2.2 Plane 2: Platform Adapter & IPC Layer
Acts as the defensive perimeter between untrusted OS inputs and the core detection engine:
- **Size Clamping**: Enforces hard truncation bounds:
  - URL strings: strictly limited to $2,048$ bytes.
  - Message texts: strictly limited to $10,000$ characters.
  - File streams: chunked at $64\text{ KB}$ buffers up to $100\text{ MB}$ scanning ceiling.
- **Memory Boundary**: Guarantees that payloads are loaded into isolated memory segments and zeroed upon completion.
- **Thread Marshaling**: Offloads heavy parsing from UI threads into background Web Workers (Web/Extension), Tokio tasks (Desktop Rust), or background isolates/threads (Mobile Flutter/Kotlin).

### 2.3 Plane 3: Shared Core Detection Pipeline (`@private-protection/core`)
The mathematical heart of PRIVATE PROTECTION. Pure, deterministic, memory-safe, and self-contained:
- **Stage 1 (Normalizer)**: Strips obfuscation, decodes Punycode/IDN homographs, canonicalizes URL components, and strips zero-width spaces.
- **Stage 2 (Parallel Detectors)**:
  - *Rule Engine*: Evaluates pre-compiled regex and deterministic boolean rules.
  - *Lexical & Heuristic Engine*: Computes Shannon entropy, brand typosquatting Levenshtein distances, and structural token counts.
  - *Threat Intelligence*: Performs $O(1)$ bitwise checks against the binary Bloom filter and checks local custom allowlists.
- **Stage 3 (Risk Aggregation)**: Combines weighted detector evidence using non-linear Bayesian aggregation, producing a deterministic risk score ($0$ to $100$), confidence ($0.0$ to $1.0$), and recommended action.

### 2.4 Plane 4: Local AI & Synthesis Runtime
Responsible for translating technical evidence into clear, jargon-free explanations:
- **Constitutional Constraint**: The AI assistant receives only structured `Evidence` tokens generated by Plane 3. It **never** receives executable prompts or unvalidated text instructions.
- **Authority Boundary**: The AI assistant has **zero authority** to alter, downgrade, or elevate the risk score or action determined by Plane 3.
- **Fallback Engine**: If ONNX runtime is unavailable, uninitialized, or fails schema validation, the system automatically falls back to deterministic parameterized string templates with zero latency penalty.

### 2.5 Plane 5: Encrypted Persistence & Local Vault
Manages all persistent state on the endpoint:
- **SQLCipher Engine**: Relational storage encrypted at rest using AES-256-GCM.
- **Key Derivation**: Cryptographic keys are derived from the device's hardware-backed keystore (Android Keystore, iOS Keychain, macOS Keychain, Windows DPAPI/Credential Guard) via Argon2id (salt: 16 bytes, iterations: 3, memory: 64MB).
- **Crypto-Shredding**: When the user requests a history wipe, the database encryption key is destroyed, rendering all stored ciphertext permanently irrecoverable.

### 2.6 Plane 6: Stateless Cloud Edge & Telemetry Relay
An optional, privacy-preserving infrastructure layer:
- **Threat Intelligence CDN**: Serves pre-compiled binary Bloom filter diffs signed with Ed25519.
- **OHTTP Relay**: RFC 9458 Oblivious HTTP relay. Separates client IP from telemetry payload, ensuring that the backend collector cannot correlate an IP address with anonymized detection metrics.

---

## 3. THREADING, CONCURRENCY & ASYNCHRONOUS BOUNDARIES

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ APPLICATION PROCESS (e.g. Tauri Desktop / Flutter Mobile / Extension Worker)    │
│                                                                                 │
│   ┌────────────────────────────────┐       ┌────────────────────────────────┐   │
│   │          MAIN UI THREAD        │       │   BACKGROUND SCANNER WORKER    │   │
│   │ • User interaction & gestures  │       │ • Normalization & Tokenization │   │
│   │ • 60/120 fps render loop       │       │ • Deterministic Rule Matching  │   │
│   │ • Instant warning modal render │       │ • Bloom filter bitwise lookup  │   │
│   │ • Friction bypass button logic │       │ • Weighted Risk Scoring        │   │
│   └───────────────┬────────────────┘       └───────────────┬────────────────┘   │
│                   │                                        │                    │
│     Fast Path     │ PostMessage / IPC Request              │ Detection Verdict  │
│     Verdict       │ (ScanRequest payload)                  │ (< 1.0 ms)         │
│     (< 1.0 ms)    ▼                                        │                    │
│   ┌────────────────────────────────┐                       │                    │
│   │       ACTION DISPATCHER        │◄──────────────────────┘                    │
│   └───────────────┬────────────────┘                                            │
│                   │                                                             │
│                   ▼ Dispatch Slow Path Async (If Verdict != ALLOW)              │
│   ┌────────────────────────────────┐                                            │
│   │   ASYNC EXPLANATION THREAD     │                                            │
│   │ • ONNX INT8 / Template engine  │                                            │
│   │ • Reads structured Evidence    │                                            │
│   │ • Returns plain English copy   │                                            │
│   │ • Completes in < 25.0 ms       │                                            │
│   └────────────────────────────────┘                                            │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Fast-Path vs. Slow-Path Concurrency Separation
To satisfy the sub-millisecond detection requirement while still providing rich AI explanations:
1. **The Fast Path ($< 1.0\text{ ms}$)**:
   - Input is received on the background scanner worker.
   - Normalizer, Rules, Heuristics, and Bloom filter execute synchronously in volatile memory.
   - RiskScorer computes the numeric score and maps the verdict (`ALLOW`, `WARN`, `BLOCK`).
   - The verdict is immediately returned to the Action Dispatcher on the Main UI Thread.
   - If the verdict is `WARN` or `BLOCK`, the warning modal is rendered **immediately** ($< 50\text{ ms}$) with a deterministic summary headline.
2. **The Slow Path ($< 25.0\text{ ms}$)**:
   - Concurrently, the structured `Evidence` list is handed to the Async Explanation Thread.
   - The ONNX SLM or Template Synthesizer generates the detailed paragraph explanation and action steps.
   - When ready, the detailed copy populates the already-visible warning modal smoothly without blocking the user interface.

---

## 4. FAILURE ISOLATION & FAULT TOLERANCE

1. **Parser Crash Isolation**:
   - If an input string triggers an unhandled parsing exception or regular expression catastrophe, the isolate/worker catches the fault, logs an internal error event, and fails safely to `CAUTION` with an `UNPARSED_INPUT` evidence token. It **never fails open** to silent `ALLOW`.
2. **AI Inference Timeout**:
   - The `MLInferenceProvider` has a strict $50\text{ ms}$ hard timeout. If inference does not return within $50\text{ ms}$, the explanation layer cancels the execution and defaults to the deterministic template engine.
3. **Storage Failure Tolerance**:
   - If local SQLite or IndexedDB fails to initialize or experiences a disk-full condition, detection processing continues unimpeded in volatile RAM. Persistence is non-critical for real-time protection.
