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

## 8. USER GUIDE & DIRECT DOWNLOADS (HOW REAL USERS GET & USE IT)

Private Protection is engineered for normal, non-technical users. You do not need developer tools or technical knowledge to install and use it.

### Direct Download Matrix

| Product Surface | Target Platform | Download Package | Format & Size | Cryptographic SHA-256 Checksum |
|---|---|---|---|---|
| **Web App** | Modern Browsers | [Launch Live Web App](https://private-protection.pages.dev) | Zero-Install PWA | Same-origin edge verified |
| **Android Mobile** | Android 8.0+ (API 26–34) | [`private-protection-mobile-0.1.0.apk`](./release/private-protection-mobile-0.1.0.apk) | Direct APK (1.03 MB) | `95ee838e739e69feed4f007c431cb6a7e74304f6751e17a38c6e21269fcdb5b5` |
| **Windows Desktop (Setup)** | Windows 10/11 x64 | [`PrivateProtection-Setup-0.1.0.exe`](./release/PrivateProtection-Setup-0.1.0.exe) | Single-File Installer (150.7 MB) | `529bee4bc50bb73a0a282575f088099ef264bd0e8a5004be7eba3275eca9e569` |
| **Windows Desktop (Portable)** | Windows 10/11 x64 | [`PrivateProtection-0.1.0-win-x64.exe`](./release/PrivateProtection-0.1.0-win-x64.exe) | Standalone Portable (234.3 MB) | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` |
| **Browser Extension** | Chrome, Edge, Brave | [`private-protection-extension-0.1.0.zip`](./release/private-protection-extension-0.1.0.zip) | Manifest V3 Zip (100.1 KB) | `d0f42ab50db530b752cffd3b6e39a6f3a1e23f888e145375fe4b8cc5c67b25dc` |

All checksums are authoritatively recorded in [`release/SHA256SUMS.txt`](./release/SHA256SUMS.txt).

---

### Step-by-Step Installation Guides

#### 🌐 1. Web Application (Zero Install)
1. **Open:** Visit [`https://private-protection.pages.dev`](https://private-protection.pages.dev) in any web browser.
2. **Use:** Click the **URL Scanner** or **Message Scanner** tab to inspect suspicious links or text.
3. **Offline PWA:** Click **"Install Web App"** in your browser's address bar to install it as an offline-capable Progressive Web App.

#### 📱 2. Android Mobile (Direct APK Sideload)
> *Note: Private Protection is distributed via direct APK download. It is **not** published to the Google Play Store.*
1. **Download:** Save [`private-protection-mobile-0.1.0.apk`](./release/private-protection-mobile-0.1.0.apk) to your Android device.
2. **Install:** Tap the downloaded file in your browser downloads or Files app. If prompted with *"Install unknown apps"*, toggle **"Allow from this source"**.
3. **Open:** Tap **Open** or tap the **Private Protection** shield icon on your home screen.
4. **Permissions:** The app requests standard user-level permissions (`CAMERA` for QR scanning, `NOTIFICATION_LISTENER` for inbound SMS warnings). Dangerous permissions (`READ_SMS`, `READ_CONTACTS`, `LOCATION`) are strictly never requested.

#### 💻 3. Windows Desktop (Installer or Portable)
1. **Download:** Download [`PrivateProtection-Setup-0.1.0.exe`](./release/PrivateProtection-Setup-0.1.0.exe) (or portable version).
2. **Install:** Double-click the setup executable. Installation completes in seconds into `%LOCALAPPDATA%\Programs\Private Protection\` without requiring administrator privileges or UAC prompts.
3. **Launch:** Launch **Private Protection** from your Start Menu or Desktop.
4. **Real-Time Shield:** The application automatically monitors your Downloads directory and safely moves dangerous executable files into the AES-256-GCM encrypted quarantine vault.

#### 🧩 4. Browser Extension (Chromium: Chrome, Edge, Brave)
> *Note: Private Protection is distributed as a self-contained unpacked package. It is **not** published to the Chrome Web Store.*
1. **Download & Extract:** Download [`private-protection-extension-0.1.0.zip`](./release/private-protection-extension-0.1.0.zip) and unzip it into a folder.
2. **Open Extensions Page:** In your browser, open `chrome://extensions` (or `edge://extensions` / `brave://extensions`).
3. **Enable Developer Mode:** Turn on the **"Developer mode"** toggle in the top-right corner.
4. **Load Extension:** Click **"Load unpacked"** in the top-left corner and select the extracted folder.
5. **Protection Active:** The Private Protection shield will appear in your browser toolbar, automatically blocking deceptive links before pages load.

---

## 9. INTERACTIVE DEMO SCENARIOS (TRY IT YOURSELF)

You can safely test Private Protection using these non-sensitive synthetic test cases:

### Scenario 1: Safe Web Destination
- **Input:** `https://en.wikipedia.org/wiki/Computer_security`
- **Expected Verdict:** `SAFE / ALLOWED` (Risk Score: `0 / 100`, Green Badge)
- **Explanation:** *"Safe web address. No deceptive patterns or spoofed characters detected."*

### Scenario 2: Deceptive Phishing Link (IP-Based Banking Phish)
- **Input:** `http://192.168.1.100/secure-banking/login`
- **Expected Verdict:** `DANGEROUS / BLOCK` (Risk Score: `95 / 100`, Red Banner)
- **Warning:** High-contrast warning banner with 5-second safety friction gate (`Wait 5s (Safety Gate)` $\rightarrow$ `I Understand the Risks`).
- **AI Briefing:** Plain-language explanation below Grade 8 reading comprehension detailing that the site uses an unencrypted numerical IP address disguised as a banking service.

### Scenario 3: 100% Offline Air-Gapped Test
- **Action:** Disconnect your device from Wi-Fi and Ethernet (or turn on Airplane Mode).
- **Input:** `http://paypal-verification-alert.xyz/account`
- **Expected Verdict:** `DANGEROUS / BLOCK` (Risk Score: `85 / 100`)
- **Observation:** Full detection, scoring, and explanation execute instantaneously on your device with zero network connection.

---

## 10. PLAIN-LANGUAGE PRIVACY & BACKEND QUESTIONS

- **Does Private Protection require a backend server?**  
  **NO.** The core security decision engine, Bayesian risk scoring, and AI explanation assistant run 100% locally on your computer or phone.
- **Does Private Protection require the cloud?**  
  **NO.** All scanning occurs in volatile device RAM. An optional cloud edge CDN (Cloudflare Pages) is used only to host the zero-install web page and distribute release files.
- **Does my browsing history, messages, or files ever leave my device?**  
  **NO.** Raw user payloads never cross the device boundary. Zero user data is transmitted to the cloud, logged on remote servers, or sold.
- **Can I delete my local scan data?**  
  **YES.** You can clear all local settings, allowlists, and logs at any time in Settings. The desktop application uses a 3-pass cryptographic shredder (`0x00`, `0xFF`, CSPRNG + `fsync`) to permanently purge quarantined threats.

---

## 11. REPRODUCIBLE QUICK START & DEVELOPMENT

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

# Execute unified test suite (506 tests across 92 files)
npm test

# Generate V8 coverage report
npm run test:coverage

# Compile production distributions
npm run build

# Package release archives & compute SHA-256 checksums
npm run package
```

---

## 12. RELEASE ARTIFACTS & PACKAGING STATUS

| Surface | Artifact Path | Format | Status | SHA-256 Checksum |
|---|---|---|---|---|
| **Web App** | `release/private-protection-web-0.1.0.zip` | Static Web Archive | **Packaged & Verified** | `18d4c35762d0a41d3908aa2f7b8a72420615d67817e70af76cac93757c705b1d` |
| **Browser Extension** | `release/private-protection-extension-0.1.0.zip` | MV3 Zip Package | **Packaged & Verified** | `d0f42ab50db530b752cffd3b6e39a6f3a1e23f888e145375fe4b8cc5c67b25dc` |
| **Android APK** | `release/private-protection-mobile-0.1.0.apk` | Release APK | **Packaged & Verified** | `95ee838e739e69feed4f007c431cb6a7e74304f6751e17a38c6e21269fcdb5b5` |
| **Android AAB** | `release/private-protection-mobile-0.1.0.aab` | Release Bundle | **Packaged & Verified** | `5f039cc7ce5e8aa3793b1207ebfd74163ef576423a10b96ea08b5177de1dcd24` |
| **Desktop Installer**| `release/PrivateProtection-Setup-0.1.0.exe` | Windows Setup | **Packaged & Verified** | `529bee4bc50bb73a0a282575f088099ef264bd0e8a5004be7eba3275eca9e569` |
| **Desktop Portable** | `release/PrivateProtection-0.1.0-win-x64.exe` | Win-x64 Binary | **Packaged & Verified** | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` |

Cryptographic checksums are recorded in [`release/SHA256SUMS.txt`](./release/SHA256SUMS.txt).

---

## 13. HONEST DISCLOSURE OF CURRENT STATUS & KNOWN LIMITATIONS

In alignment with our engineering constitution:
- **Browser Extension:** Manifest V3 cannot inspect internal browser schemes (`chrome://`, `edge://`).
- **Desktop Software:** Operates purely in user-space without kernel filter drivers; system-locked files (`EACCES`/`EBUSY`) are safely skipped and logged.
- **Android Client:** Deep SMS background inspection requires standard OS notification listener permissions granted by the user. Physical low-end/legacy Android hardware (`1.0 GB RAM` / API 26 physical device) was not attached during automated CI/local validation (`NOT TESTED` on physical legacy handset; validated under simulated memory/CPU throttling and API 26 static bytecode targets).
- **Code Signing:** Binary archives are verified via SHA-256 checksums; commercial app store code signing certificates (Authenticode, Google Play Keystore) require end-user/organization provisioning (**SIGNING READY; NOT VERIFIED**).

---

## 14. GOVERNANCE & DOCUMENTATION INDEX

- **Canonical Constitution & Source of Truth:** [`AGENT.md`](./AGENT.md)
- **Final Human Acceptance & Distribution UX Audit:** [`docs/PHASE_R12_FINAL_HUMAN_ACCEPTANCE.md`](./docs/PHASE_R12_FINAL_HUMAN_ACCEPTANCE.md)
- **Final Release Candidate Matrix:** [`docs/PHASE_R11_RELEASE_CANDIDATE_MATRIX.md`](./docs/PHASE_R11_RELEASE_CANDIDATE_MATRIX.md)
- **Final Release Hardening & Security Audit:** [`docs/PHASE_R10_FINAL_SECURITY_RELEASE_HARDENING.md`](./docs/PHASE_R10_FINAL_SECURITY_RELEASE_HARDENING.md)
- **Final End-to-End Product Acceptance:** [`docs/PHASE_R9_FINAL_END_TO_END_ACCEPTANCE.md`](./docs/PHASE_R9_FINAL_END_TO_END_ACCEPTANCE.md)
- **Performance, Low-End Device & Offline Deep Validation:** [`docs/PHASE_R8_PERFORMANCE_LOW_END_VALIDATION.md`](./docs/PHASE_R8_PERFORMANCE_LOW_END_VALIDATION.md)
- **Backend Necessity & Cloud Boundary Architecture:** [`docs/PHASE_R7_BACKEND_CLOUD_ARCHITECTURE.md`](./docs/PHASE_R7_BACKEND_CLOUD_ARCHITECTURE.md)
- **Cross-Product Consistency & Gap Audit:** [`docs/PHASE_R6_CROSS_PRODUCT_DEEP_VALIDATION.md`](./docs/PHASE_R6_CROSS_PRODUCT_DEEP_VALIDATION.md)
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
