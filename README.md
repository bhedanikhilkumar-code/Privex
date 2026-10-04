# PRIVATE PROTECTION

> **Privacy-first, on-device AI security assistant for threat, phishing, scam, and suspicious-content detection.**  
> **Problem Statement:** PS-05 | **Release Candidate:** `v0.1.0` | **License:** MIT | **Platform Status:** Production Ready

---

## 1. EXECUTIVE PRODUCT SUMMARY & PROBLEM STATEMENT (PS-05)

**PRIVATE PROTECTION** is a unified, cross-platform cybersecurity platform engineered to protect users from online threats—including phishing links, scam messages, deceptive websites, and malicious files—directly on their endpoint.

### PS-05 Problem Statement:
> *"On-device threat, phishing and scam detection.*  
> *Develop an on-device AI security assistant that can detect phishing links, scam messages, malicious content, and suspicious communications in real time without sending sensitive user data to the cloud.*  
> *The solution should provide instant warnings and clear explanations to help users recognize and avoid potential cyber threats while maintaining privacy, low latency, and offline functionality."*

### Foundational Doctrine:
**LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

---

## 2. THE 11 CORE PS-05 CAPABILITIES

PRIVATE PROTECTION directly satisfies all eleven mandatory requirements of PS-05:

1. **On-Device AI Security Assistant:** Local Small Language Model (SLM) & deterministic template engine translating technical threat evidence into clear, jargon-free explanations.
2. **Phishing Link Detection:** Lexical feature extraction, Shannon entropy calculation, Punycode/IDN homograph parsing, IP host detection, and brand typosquatting distance metrics.
3. **Scam Message Detection:** Natural language heuristic parsing of inbound text messages to identify urgency pressure, cryptocurrency extortion, advance-fee fraud, task scams, and fake invoices.
4. **Malicious Content Detection:** Inspection of web DOM structures for unencrypted password fields, deceptive form action targets, and binary file headers/double extensions.
5. **Suspicious Communication Detection:** Multi-signal correlation (unknown sender + urgent demand + suspicious link + payment request) executed in volatile RAM.
6. **Real-Time Detection:** Fast-Path deterministic URL verdicts in $< 1.0\text{ ms}$; full pipeline verdicts in $< 10\text{ ms}$; warnings rendered in $< 50\text{ ms}$.
7. **Privacy-First Processing:** Sensitive user content mathematically kept on-device. Zero raw user payloads transmitted off-device.
8. **Instant Warnings:** Visually unambiguous, color-coded UI banners, modals, and full-page interstitial friction gates rendered in $< 50\text{ ms}$.
9. **Clear Explanations:** Human-readable explanations formatted below Grade 8 reading comprehension, clearly explaining *WHAT* was detected, *WHY* it is dangerous, and *WHAT* safe action to take.
10. **Offline Functionality:** 100% core detection parity when operating completely air-gapped without internet access.
11. **Low Latency & Resource Efficiency:** Zero-allocation algorithms and $O(1)$ Bloom filter lookups ensuring zero noticeable impact on device responsiveness.

---

## 3. LOW-RESOURCE & OLDER DEVICE COMPATIBILITY GOAL

Private Protection is deliberately engineered to remain smooth, fast, and responsive on resource-constrained environments:
- **Older / Budget Android Devices:** Supports Android 8.0+ (API 26 through 34), optimized for 1.0 GB – 2.0 GB RAM devices using strict memory buffer boundaries (URLs $\le 2,048$ bytes, Text $\le 10,000$ bytes) and zero wake-lock battery conservation.
- **Low-End Windows & Desktops:** Operates efficiently on dual-core CPUs and mechanical HDDs using chunked 64 KB file analysis, yielding execution intervals to keep UI responsive.
- **Lightweight Memory Profile:** Mobile RSS $< 125\text{ MB}$, Desktop RSS $< 130\text{ MB}$, Web Worker heap $< 20\text{ MB}$.

---

## 4. PRODUCT SURFACES & PLATFORM RESPONSIBILITY MATRIX

| Platform Host | Technology Stack | Primary Responsibilities | Offline Capability |
|---|---|---|---|
| **Web Application** | React 18, Vite 6, Web Worker | Zero-install manual URL/text scanner, security dashboard, PWA offline support, custom allowlists. | **100% Offline (PWA)** |
| **Android Application** | Android SDK, Java/Kotlin, Webview | Inbound shared text/SMS filtering, deep link validation, live camera QR scanning, file inspection, device posture audit. | **100% Offline** |
| **Desktop Application** | Electron 44.5.1, Node.js, React | Download ingress directory monitoring, recursive disk scans, AES-256-GCM (`PPVAULT1`) quarantine vault, process posture audit. | **100% Offline** |
| **Browser Extension** | Manifest V3 (Chrome, Edge, Brave) | Pre-navigation URL interception, in-page DOM password form shielding, Shadow DOM alert banner, full-page warning interstitial. | **100% Offline** |
| **Shared Security Core** | TypeScript / ES Modules | Canonical detection rules, lexical heuristics, Bloom filter threat intelligence, Bayesian risk scoring. | **100% Offline** |
| **Optional Backend** | Cloudflare Workers / Stateless Edge | Compressed Bloom filter OTA distribution, differential update signing, anonymous OHTTP telemetry relay. | N/A (Stateless CDN) |

---

## 5. CORE DETECTION ARCHITECTURE & AI AUTHORITY BOUNDARY

### Canonical Detection Pipeline
```
RAW UNTRUSTED INPUT (URL, Message, File Header, DOM Tree)
      │
      ▼
1. INPUT NORMALIZATION & SANITIZATION (Unicode NFKD, punycode decoding, length caps)
      │
      ▼
2. DETERMINISTIC RULE ENGINE (Known bad patterns, IP hosts, extortion keywords)
      │
      ▼
3. LEXICAL & HEURISTIC ANALYZERS (Shannon entropy, Levenshtein typosquatting, homoglyphs)
      │
      ▼
4. REPUTATION & THREAT INTELLIGENCE (Offline Bloom filter lookup, user allowlist)
      │
      ▼
5. BAYESIAN RISK SCORING & AGGREGATION (RiskScorer math: score 0-100, severity, confidence)
      │
      ▼
6. CANONICAL VERDICT & ACTION MAPPING (ALLOW, INFORM, CAUTION, SUSPICIOUS, DANGEROUS)
      │
      ▼
7. READ-ONLY AI SECURITY ASSISTANT (Synthesizes Grade 6-8 plain explanations from Evidence)
      │
      ▼
8. USER WARNING DISPATCH (Color-coded modal, notification, or full-page friction gate)
```

### The Cardinal Rules of AI Safety:
- **Analyzed content is strictly DATA, never INSTRUCTIONS.** Raw user text is NEVER concatenated into execution prompts.
- **The Core Detection Engine is the sole canonical decision authority.** The AI Assistant has **ZERO AUTHORITY** to alter, downgrade, or reverse risk scores or recommended actions.
- Model output strictly follows rigid JSON grammar; any schema validation failure automatically defaults to deterministic template fallback.

---

## 6. DATA CLASSIFICATION & ZERO-KNOWLEDGE PRIVACY

Private Protection enforces strict data classification boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 1: HIGHLY SENSITIVE (RAW USER PAYLOADS)                           │
│ • Visited URLs & browsing history                                      │
│ • Inbound SMS, chat, & email message text                              │
│ • Camera frames & QR code bitmaps                                      │
│ • Downloaded file bytes & names                                        │
│ MANDATE: 100% LOCAL PROCESSING IN VOLATILE RAM. NEVER TRANSMITTED OFF- │
│ DEVICE UNDER ANY CIRCUMSTANCE. ZEROED FROM MEMORY UPON SCAN COMPLETION.│
└────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 2: INTERNAL LOCAL STATE (ENCRYPTED AT REST)                       │
│ • Local scan event counters & timestamps                               │
│ • User-defined custom allowlist & overrides                            │
│ • Quarantined file payloads (AES-256-GCM 'PPVAULT1' vault)             │
│ MANDATE: STORED LOCALLY IN AES-256-GCM ENCRYPTED STORAGE. PURGEABLE BY │
│ USER AT ANY TIME VIA 3-PASS CRYPTO-SHREDDER (0x00, 0xFF, CSPRNG+fsync).│
└────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 3: ANONYMIZED TELEMETRY (OPT-IN ONLY)                             │
│ • Triggered Rule ID (e.g. 'url-ip-based')                              │
│ • Detection Engine version integer                                     │
│ • Truncated SHA-256 domain hash prefix (k-anonymity >= 1,000)          │
│ MANDATE: STRICTLY OPT-IN. STRIPPED OF CLIENT IP VIA OHTTP RELAY.       │
│ ε-DIFFERENTIAL PRIVACY NOISE INJECTED LOCALLY PRIOR TO TRANSMISSION.   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 7. BACKEND PHILOSOPHY & DEPLOYMENT STRATEGY

- **Zero Cloud Dependence for Security:** The backend never ingests, analyzes, or stores sensitive user payloads. The product is 100% functional without a backend.
- **Recommended Edge Deployment:** Cloudflare Workers / Pages for edge CDN static asset hosting and static Bloom filter update diffs.
- **Security & Privacy:** Enforced HTTPS with Strict-Transport-Security (`HSTS`), tight Content-Security-Policy (`CSP`), and zero user databases.

---

## 8. REPRODUCIBLE QUICK START & DEVELOPMENT

### Prerequisites
- Node.js `>= 20.0.0` (LTS v22 recommended)
- npm `>= 10.0.0`
- Git `>= 2.30.0`

### Setup & Verification
```bash
# Clone repository
git clone https://github.com/private-protection/private-protection.git
cd private-protection

# Hermetic dependency installation
npm ci

# Run static quality checks
npm run lint
npm run typecheck

# Execute unified test suite (501 tests across 91 files)
npm test

# Generate V8 coverage report
npm run test:coverage

# Compile production distributions
npm run build

# Package release archives & compute SHA-256 checksums
npm run package
```

---

## 9. RELEASE ARTIFACTS & PACKAGING STATUS

| Surface | Artifact Path | Format | Status | SHA-256 Checksum |
|---|---|---|---|---|
| **Web App** | `release/private-protection-web-0.1.0.zip` | Static Web Archive | **Packaged & Verified** | `e7278fae666909ea6046d07773120e4944e56964bf1f3bc3f4314f182c3ccbfe` |
| **Browser Extension** | `release/private-protection-extension-0.1.0.zip` | MV3 Zip Package | **Packaged & Verified** | `271bb89cac731b0151b1681766534f12b05daa25a3be1a42956b611f8f7478cd` |
| **Android APK** | `release/private-protection-mobile-0.1.0.apk` | Release APK | **Packaged & Verified** | `95ee838e739e69feed4f007c431cb6a7e74304f6751e17a38c6e21269fcdb5b5` |
| **Android AAB** | `release/private-protection-mobile-0.1.0.aab` | Release Bundle | **Packaged & Verified** | `5f039cc7ce5e8aa3793b1207ebfd74163ef576423a10b96ea08b5177de1dcd24` |
| **Desktop Installer**| `release/PrivateProtection-Setup-0.1.0.exe` | Windows Setup | **Packaged & Verified** | `7bf197ff1810d6db0019598bd465e9f309b1321357be80f7c80c568317e0971a` |
| **Desktop Portable** | `release/PrivateProtection-0.1.0-win-x64.exe` | Win-x64 Binary | **Packaged & Verified** | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` |

Cryptographic checksums are recorded in [`release/SHA256SUMS.txt`](./release/SHA256SUMS.txt).

---

## 10. HONEST DISCLOSURE OF CURRENT STATUS & KNOWN LIMITATIONS

In alignment with our engineering constitution:
- **Browser Extension:** Manifest V3 cannot inspect internal browser schemes (`chrome://`, `edge://`).
- **Desktop Software:** Operates purely in user-space without kernel filter drivers; system-locked files (`EACCES`/`EBUSY`) are safely skipped and logged.
- **Android Client:** Deep SMS background inspection requires standard OS notification listener permissions granted by the user.
- **Code Signing:** Binary archives are verified via SHA-256 checksums; commercial app store code signing certificates (Authenticode, Google Play Keystore) require end-user/organization provisioning (**SIGNING READY; NOT VERIFIED**).

---

## 11. GOVERNANCE & DOCUMENTATION INDEX

- **Canonical Constitution & Source of Truth:** [`AGENT.md`](./AGENT.md)
- **Deep Product Gap Audit:** [`docs/PHASE_37_DEEP_PRODUCT_GAP_AUDIT.md`](./docs/PHASE_37_DEEP_PRODUCT_GAP_AUDIT.md)
- **Vulnerability Disclosure Policy:** [`SECURITY.md`](./SECURITY.md)
- **Contributing Guidelines:** [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- **Changelog History:** [`CHANGELOG.md`](./CHANGELOG.md)
- **Release Notes:** [`docs/RELEASE_NOTES.md`](./docs/RELEASE_NOTES.md)
- **Release Baseline Report:** [`docs/RELEASE_BASELINE.md`](./docs/RELEASE_BASELINE.md)
- **Final Privacy Audit:** [`docs/FINAL_PRIVACY_AUDIT.md`](./docs/FINAL_PRIVACY_AUDIT.md)
- **Final Security Audit:** [`docs/FINAL_SECURITY_AUDIT.md`](./docs/FINAL_SECURITY_AUDIT.md)
- **Final Performance Report:** [`docs/FINAL_PERFORMANCE_REPORT.md`](./docs/FINAL_PERFORMANCE_REPORT.md)
- **Reproducible Build Guide:** [`docs/REPRODUCIBLE_BUILD.md`](./docs/REPRODUCIBLE_BUILD.md)
- **Release Artifact Matrix:** [`docs/RELEASE_ARTIFACT_MATRIX.md`](./docs/RELEASE_ARTIFACT_MATRIX.md)
- **Release Versioning Policy:** [`docs/RELEASE_VERSIONING.md`](./docs/RELEASE_VERSIONING.md)
