# Data Boundaries & Trust Architecture: PRIVATE PROTECTION

## 1. Architectural Trust Topology

The PRIVATE PROTECTION architecture enforces strict, non-bypassable **Trust Boundaries** between components. Data crossing any boundary must undergo explicit sanitization, schema validation, and authorization checks.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 UNTRUSTED ZONE                                  │
│  • Public Webpages (Hostile DOM, Malicious Scripts)                             │
│  • Inbound Communications (Phishing SMS, Social Engineering Emails)             │
│  • Untrusted Downloads (Ransomware Executables, Obfuscated Scripts)             │
│  • Camera Viewfinder (Malicious QR Codes)                                       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                        [BOUNDARY 1: INPUT SANITIZATION GATE]
                        (Byte length limits, Unicode NFKD, De-obfuscation)
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            CLIENT USER INTERFACE ZONE                           │
│  • Browser Extension (Shadow DOM Overlay)                                       │
│  • Mobile App View (Jetpack Compose / SwiftUI)                                  │
│  • Desktop App UI (Tauri Webview)                                               │
│  • Web Application Dashboard (Next.js Client)                                   │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                        [BOUNDARY 2: LOCAL IPC / FFI ISOLATION GATE]
                        (Authenticated Named Pipes, JNI, C-FFI, Ephemeral Tokens)
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          LOCAL DETECTION ENGINE (ISOLATED)                      │
│  • Deterministic Rule Engine                                                    │
│  • Lexical & Structural Analyzers                                               │
│  • Risk Scoring Engine                                                          │
│  • Memory-Mapped Bloom Filter Threat Cache                                      │
└───────────────────┬─────────────────────────────────────────┬───────────────────┘
                    │                                         │
 [BOUNDARY 3: AI SECURITY BARRIER]              [BOUNDARY 4: ENCRYPTED STORAGE GATE]
 (Structured Evidence ONLY;                     (AES-256-GCM, OS Keystore Binding)
  Read-only, Constrained JSON Grammar)                        │
                    │                                         ▼
                    ▼                          ┌──────────────────────────────────┐
┌─────────────────────────────────────────┐    │     LOCAL PERSISTENT STORAGE     │
│       ON-DEVICE AI ASSISTANT ZONE       │    │  • Local User Allowlists         │
│  • Quantized Local SLM Runtime          │    │  • Scan History Ring Buffer      │
│  • Template-Based Explanation Fallback  │    │  • Encrypted Quarantine Vault    │
└─────────────────────────────────────────┘    └──────────────────────────────────┘
                    │
 [BOUNDARY 5: ZERO-KNOWLEDGE NETWORK EGRESS GATE]
 (No User Payloads; Outbound Delta Pulls ONLY;
  OHTTP Privacy Relay Stripping IP Addresses)
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    OPTIONAL BACKEND & CDN DISTRIBUTION SERVICES                 │
│  • Stateless OTA Delta Patch Servers (Ed25519 Signed)                           │
│  • Anonymous Aggregated Telemetry Sink (OHTTP Decapsulator)                     │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Trust Boundary Profiles

### Boundary 1: Untrusted Zone ➔ Client Ingestion
- **Trust Level**: Low (Attacker-Controlled) ➔ Medium (Client App).
- **Untrusted Elements**: Raw URLs, inbound SMS text, downloaded binary files, DOM nodes.
- **Enforcement Mechanisms**:
  - Byte-length ceilings: URLs $\le 2,048$ bytes; Text $\le 10,000$ bytes; QR frames $\le 4,296$ bytes.
  - Memory isolation: buffers allocated in volatile heap, never committed to disk unencrypted.
  - Unicode NFKD normalization strips homoglyphs and hidden zero-width spaces before inspection.

### Boundary 2: Client UI ➔ Local Detection Engine (IPC / FFI)
- **Trust Level**: Medium (Unprivileged User UI) ➔ High (Core Engine & System Daemons).
- **Privileged Operations**: File quarantine, DNS proxying, system notifications.
- **Enforcement Mechanisms**:
  - Windows / macOS: Named Pipes and Unix Domain Sockets require mutual ephemeral token authentication generated during service spawn.
  - OS Security Descriptor Access Control Lists (ACLs) restrict socket binding to the current user SID and `NT AUTHORITY\SYSTEM`.
  - RPC calls strictly restricted to predefined, typed command schemas (e.g. `scan_file(path)`). Arbitrary code execution or shell commands are architecturally impossible.

### Boundary 3: Detection Engine ➔ AI Security Assistant
- **Trust Level**: High (Verified Threat Metrics) ➔ Medium (Stochastic Generative Model).
- **Attack Surface**: Direct and indirect prompt injection attempts embedded in analyzed content.
- **Enforcement Mechanisms**:
  - Raw user text is **NEVER** passed into LLM prompt templates.
  - Only structured, immutable `EvidenceItem` arrays generated by deterministic layers are supplied.
  - Model outputs are validated against a rigid JSON schema; invalid outputs immediately trigger deterministic template fallbacks.
  - The AI Assistant possesses **ZERO AUTHORITY** to alter threat severity, risk score, or action recommendations.

### Boundary 4: Local Engine ➔ Local Persistent Storage
- **Trust Level**: High (Engine) ➔ High (Encrypted Disk Vault).
- **Sensitive Data**: Custom user allowlists, quarantined files, scan metadata.
- **Enforcement Mechanisms**:
  - All data at rest encrypted via AES-256-GCM.
  - Encryption keys stored in hardware-backed secure elements (Apple Secure Enclave, Android Keystore, Windows DPAPI).
  - Quarantined files have OS execution permissions stripped (`chmod 000`) and file headers scrambled.

### Boundary 5: Client Endpoint ➔ Cloud Backend (Network Egress)
- **Trust Level**: High (Client Endpoint) ➔ Untrusted / External Network.
- **Prohibited Data**: Tier 1 data (messages, visited URLs, screenshots, file contents) is **100% BLOCKED**.
- **Enforcement Mechanisms**:
  - Inbound updates use pull-only architecture via global CDN.
  - Outbound telemetry is opt-in, aggregated, and routed through Oblivious HTTP (OHTTP) relays that strip client IP addresses.
  - Updates require Ed25519 cryptographic signatures verified against an immutable root public key compiled directly into the client binary.

---

## 3. Attack Surface Inventory & Defenses

| Attack Surface ID | Component | Potential Attack Vector | Architectural Mitigation |
|---|---|---|---|
| **AS-01** | URL Parser | ReDoS / Heap Overflow via malformed URLs | 2KB input length ceiling; memory-safe Rust/strict TS parser; regular expressions audited for linear complexity ($O(N)$). |
| **AS-02** | Local Desktop IPC | Local Privilege Escalation (LPE) via malicious Named Pipe connection | Mutual ephemeral token handshake; OS ACL restricted to local user SID; strictly typed RPCs with zero arbitrary execution commands. |
| **AS-03** | Browser Content Script | Malicious host page compromising extension background script | Content Script runs in isolated execution world; communicates with background worker via typed `runtime.sendMessage`; Shadow DOM isolation. |
| **AS-04** | AI Explanation Model | Prompt Injection / Jailbreak to declare malware "Safe" | Unidirectional air-gap: AI model receives only tokenized evidence structs; zero power to alter risk score or block decision. |
| **AS-05** | Update Mechanism | Man-in-the-Middle (MITM) / CDN compromise delivering poisoned rules | Ed25519 offline dual-key signatures; monotonic sequence counter preventing rollback; SHA-256 Merkle root verification. |
| **AS-06** | Telemetry Ingress | Eavesdropping / Traffic correlation de-anonymizing users | Oblivious HTTP (OHTTP) relay architecture; client-side ε-Differential Privacy noise injection; batching and temporal jitter. |
