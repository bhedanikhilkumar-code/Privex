# PRIVEX

> **Privacy-first, on-device AI security assistant for threat, phishing, scam, and suspicious-content detection.**  
> **Problem Statement Code:** PS-05 | **Authoritative Version:** `v0.1.0` | **License:** MIT | **Platform Status:** Production Ready & Verified

---

## TABLE OF CONTENTS

1. [WHAT IS PRIVEX?](#1-what-is-private-protection)
2. [HOW DOES IT WORK?](#2-how-does-it-work)
3. [PRIVACY](#3-privacy)
4. [OFFLINE MODE](#4-offline-mode)
5. [WEB](#5-web)
6. [ANDROID](#6-android)
7. [WINDOWS DESKTOP](#7-windows-desktop)
8. [BROWSER EXTENSION](#8-browser-extension)
9. [DOWNLOADS](#9-downloads)
10. [INSTALLATION](#10-installation)
11. [DEMO](#11-demo)
12. [BACKEND / CLOUD](#12-backend--cloud)
13. [SECURITY](#13-security)
14. [SUPPORTED PLATFORMS](#14-supported-platforms)
15. [KNOWN LIMITATIONS](#15-known-limitations)
16. [VERSION](#16-version)

---

## 1. WHAT IS PRIVEX?

**PRIVEX** is a unified, cross-platform cybersecurity platform engineered to protect users from online digital threats—including phishing links, scam messages, deceptive websites, and malicious files—directly on their personal devices.

### PS-05 Problem Statement:
> *"On-device threat, phishing and scam detection.*  
> *Develop an on-device AI security assistant that can detect phishing links, scam messages, malicious content, and suspicious communications in real time without sending sensitive user data to the cloud.*  
> *The solution should provide instant warnings and clear explanations to help users recognize and avoid potential cyber threats while maintaining privacy, low latency, and offline functionality."*

### Foundational Doctrine:
**LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

### The 11 Core Capabilities:
1. **On-Device AI Security Assistant:** Local deterministic template engine and quantized SLM providing plain-language explanations below Grade 8 reading level directly on the endpoint.
2. **Phishing Link Detection:** Lexical analysis, Shannon entropy, brand typosquatting distance (Levenshtein), Punycode/IDN homographs, and local Bloom filter lookups.
3. **Scam Message Detection:** Natural language and heuristic parsing of inbound text messages to identify urgency pressure, cryptocurrency extortion, advance-fee fraud, and fake invoices.
4. **Malicious Content Detection:** Inspection of web DOM structures (unencrypted password fields, deceptive form action targets) and binary file headers/double extensions.
5. **Suspicious Communication Detection:** Multi-signal correlation (unknown sender + urgent demand + suspicious link + payment request) executed in volatile RAM.
6. **Real-Time Detection:** Fast-path execution providing detection verdicts in under $1.0\text{ ms}$ on local rules and $< 100\text{ ms}$ on full heuristic pipelines.
7. **Privacy-First Processing:** Sensitive user content mathematically kept on-device. Zero raw user payloads are ever transmitted off-device.
8. **Instant Warnings:** Visually unambiguous, color-coded UI banners, modals, and full-page interstitial friction gates rendered in $< 50\text{ ms}$.
9. **Clear Explanations:** Human-readable explanations formatted below Grade 8 reading comprehension, clearly explaining *what* was detected, *why* it is dangerous, and *what* action to take.
10. **Offline Functionality:** 100% core detection parity when operating completely air-gapped without an active internet connection.
11. **Low Latency & Zero Allocation:** $O(1)$ Bloom filter lookups, zero-allocation algorithms, and compiled WebAssembly/native execution ensuring zero noticeable impact on device responsiveness.

---

## 2. HOW DOES IT WORK?

Privex employs a defense-in-depth, multi-layer detection architecture where deterministic rules and mathematics govern threat decisions, and the AI Security Assistant synthesizes plain-language explanations:

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
7. READ-ONLY AI SECURITY ASSISTANT (Synthesizes Grade 6 plain explanations from Evidence)
      │
      ▼
8. USER WARNING DISPATCH (Color-coded modal, notification, or full-page friction gate)
```

### The Cardinal Rules of AI Safety:
- **Analyzed content is strictly DATA, never INSTRUCTIONS.** Untrusted input is never concatenated into prompt templates.
- **The Core Detection Engine is the sole canonical decision authority.** The AI Assistant has **ZERO AUTHORITY** to alter, downgrade, or reverse risk scores or recommended actions.
- Model output strictly adheres to a rigid JSON grammar; any schema validation failure automatically defaults to deterministic template fallback.

---

## 3. PRIVACY

Privex operates under a strict 3-tier zero-knowledge data classification model:

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

- **Zero Cloud Persistence:** We have no user databases, no session recording, and no user tracking.
- **Zero Third-Party Trackers:** No Google Analytics, no Facebook Pixels, and no telemetry SDKs exist in any release package.
- **Instant Data Purge:** Users can wipe scan history and allowlists at any time with a single click.

---

## 4. OFFLINE MODE

- **100% Core Threat Detection Parity:** The full detection pipeline operates identically whether you are connected to the internet or completely air-gapped.
- **Pre-Compiled Threat Intelligence:** Fast $O(1)$ Bloom filter databases and lexical rule matrices are packaged directly into the client applications.
- **No Network Egress:** Disconnecting your Wi-Fi, Ethernet, or mobile data does not degrade Privex's ability to identify phishing links, scam messages, or deceptive domains.

---

## 5. WEB

- **Zero-Install Client PWA:** Access the fully functional web dashboard at [`https://privex.pages.dev`](https://privex.pages.dev).
- **Client-Side Execution:** The web application downloads static assets from the edge CDN and executes all threat analysis locally inside a dedicated Web Worker sandbox in your browser's volatile RAM.
- **Installable PWA:** Can be installed directly to your desktop or mobile home screen as a standalone Progressive Web App with full offline caching via Service Worker.
- **Password Security & Network Protection Module:**
  - **Password Security Checker:** Real-time client-side password entropy, sequential walk, and common breach dictionary analysis with visual strength meter and criteria checklist. 100% volatile memory evaluation with zero server transmission or storage.
  - **Strong Password Generator:** Cryptographically secure credential generation using `crypto.getRandomValues()` (no `Math.random()`), length selection (8-48 chars), character set toggles, and ambiguous/similar character exclusions.
  - **URL / Request Security Monitor:** Background application network request telemetry monitoring first-party, third-party, and unknown/suspicious destinations.
  - **Request Overload Detection:** Real-time sliding window frequency analyzer that identifies sudden request bursts (e.g., >50 requests in 10s) and alerts users to potential traffic anomalies.
  - **Suspicious Third-Party Detection:** Identifies unverified external endpoints, numeric IP destinations, and high-abuse TLDs without misclassifying benign CDNs.
  - **Security Alerts & Password Notifications:** Dismissible security banners with prompt actions to review activity or update account credentials when suspicious traffic is detected.
  - **Privacy Protections:** Strict client-side sanitization automatically redacts all query credentials, tokens, session IDs, and API keys before logging or display.
  - **Browser Limitations:** Network monitoring operates non-intrusively on application-level fetch/XHR traffic within the browser security sandbox; cross-origin requests adhere to standard CORS policies.

---

## 6. ANDROID

- **Direct Standalone APK:** Distributed as a verified release APK (`private-protection-mobile-0.1.0.apk`, 1.03 MB).
- **Core Mobile Features:** Inbound SMS notification filtering, deep link validation, live camera QR scanning, and local device posture audits.
- **Supported Android Versions:** Android 8.0+ (API Level 26 through 34).
- **Privacy Permissions:** Requests standard user permissions (`CAMERA`, `NOTIFICATION_LISTENER`). Never requests dangerous or unnecessary permissions (`READ_SMS`, `READ_CONTACTS`, `LOCATION`).
- **No Google Play Store Dependence:** Free from proprietary Google Play Services dependencies or store tracking.

---

## 7. WINDOWS DESKTOP

- **Standalone Binaries:** Available as both a standard Windows setup installer (`PrivateProtection-Setup-0.1.0.exe`, 158 MB) and a standalone zero-install portable executable (`PrivateProtection-0.1.0-win-x64.exe`, 245 MB).
- **Supported Environments:** 64-bit Windows 10 and Windows 11.
- **Real-Time Downloads Monitor:** Watches your local Downloads folder and automatically quarantines dangerous double-extension executables or malware into an AES-256-GCM encrypted vault (`PPVAULT1`).
- **Zero Developer Dependencies:** Bundled standalone Electron 44.5.1 runtime. No Node.js, Python, or Git required on client.

---

## 8. BROWSER EXTENSION

- **Chromium Manifest V3 Extension:** Distributed as an unpacked extension package (`private-protection-extension-0.1.0.zip`, 100 KB).
- **Supported Browsers:** Google Chrome (v110+), Microsoft Edge (v110+), Brave, Opera, Vivaldi.
- **Real-Time Protection:** Pre-navigation URL interceptor blocks deceptive domains before requests resolve; in-page DOM scanner shields unencrypted password fields; full-page interstitial warning alerts users before visiting blocked sites.
- **Direct Sideloading:** Loaded via standard Chromium Developer Mode (`Load unpacked`).

---

## 9. DOWNLOADS

All release packages are independently verified and available from both production edge mirrors and the official GitHub release:

| Platform / Artifact | File Name | Size | Cryptographic SHA-256 Checksum | Direct Public Download Link |
|---|---|---|---|---|
| **Web PWA** | Web Application | Hosted | Same-origin edge verified | [Launch Web App](https://privex.pages.dev) |
| **Android APK** | `private-protection-mobile-0.1.0.apk` | 1.03 MB | `95ee838e739e69feed4f007c431cb6a7e74304f6751e17a38c6e21269fcdb5b5` | [Direct APK](https://privex.pages.dev/downloads/private-protection-mobile-0.1.0.apk) |
| **Windows Setup** | `PrivateProtection-Setup-0.1.0.exe` | 158 MB | `529bee4bc50bb73a0a282575f088099ef264bd0e8a5004be7eba3275eca9e569` | [GitHub Release v0.1.0](https://github.com/bhedanikhilkumar-code/Private-Protection/releases/tag/v0.1.0) |
| **Windows Portable** | `PrivateProtection-0.1.0-win-x64.exe` | 245 MB | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` | [GitHub Release v0.1.0](https://github.com/bhedanikhilkumar-code/Private-Protection/releases/tag/v0.1.0) |
| **Browser Extension** | `private-protection-extension-0.1.0.zip` | 100 KB | `d0f42ab50db530b752cffd3b6e39a6f3a1e23f888e145375fe4b8cc5c67b25dc` | [Direct ZIP](https://privex.pages.dev/downloads/private-protection-extension-0.1.0.zip) |
| **Integrity Manifest**| `SHA256SUMS.txt` | 610 B | Authoritative | [Direct Manifest](https://privex.pages.dev/downloads/SHA256SUMS.txt) |

All release checksums are authoritatively recorded in [`release/SHA256SUMS.txt`](./release/SHA256SUMS.txt).

---

## 10. INSTALLATION

### 🌐 1. Web Application (Zero Install)
1. Navigate to [`https://privex.pages.dev`](https://privex.pages.dev).
2. Click the **URL Scanner** or **Message Scanner** tab to inspect suspicious content immediately.
3. (Optional) Click **Install Web App** in your browser's address bar for offline home-screen usage.

### 📱 2. Android Mobile (Direct APK Sideload)
1. Download [`private-protection-mobile-0.1.0.apk`](https://privex.pages.dev/downloads/private-protection-mobile-0.1.0.apk).
2. Open your device's **Files** or **Downloads** app and tap the APK.
3. If prompted with *"Install unknown apps"*, enable **"Allow from this source"**.
4. Tap **Install**, then tap **Open**.
5. Grant Notification Listener permissions when prompted to enable inbound scam message protection.

### 💻 3. Windows Desktop (Installer or Portable)
1. Download [`PrivateProtection-Setup-0.1.0.exe`](https://github.com/bhedanikhilkumar-code/Private-Protection/releases/tag/v0.1.0) (or portable executable).
2. Double-click the file. (If Windows SmartScreen appears on this self-signed binary, click *More info* $\rightarrow$ *Run anyway*).
3. The application opens immediately into your local desktop threat scanner.

### 🧩 4. Browser Extension (Chromium: Chrome, Edge, Brave)
1. Download [`private-protection-extension-0.1.0.zip`](https://privex.pages.dev/downloads/private-protection-extension-0.1.0.zip) and extract it to a local folder.
2. In your browser, open `chrome://extensions` (or `edge://extensions`).
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked** and select the extracted folder.
5. The Privex shield will appear in your browser toolbar.

---

## 11. DEMO

Test Privex safely using these non-sensitive synthetic test cases:

### Scenario A: Legitimate Safe Website
- **Input:** `https://en.wikipedia.org/wiki/Computer_security`
- **Expected Verdict:** `SAFE / ALLOWED` (Risk Score: `0 / 100`, Green Badge)
- **Explanation:** *"Safe web address. No deceptive patterns or spoofed characters detected."*

### Scenario B: Deceptive Phishing Link (IP-Based Banking Phish)
- **Input:** `http://192.168.1.100/secure-banking/login?auth=immediate`
- **Expected Verdict:** `DANGEROUS / BLOCK` (Risk Score: `100 / 100`, Crimson Alert Banner)
- **Warning:** High-contrast alert identifying unencrypted numerical IP host and credential harvesting keywords.
- **AI Briefing:** Plain-language explanation detailing why raw IP addresses and urgent banking demands represent deception.

### Scenario C: 100% Offline Air-Gapped Test
- **Action:** Disconnect your device from Wi-Fi and Ethernet (or enable Airplane Mode).
- **Input:** `http://paypal-verification-alert.xyz/account`
- **Expected Verdict:** `DANGEROUS / BLOCK` (Risk Score: `85 / 100`)
- **Observation:** Full detection, scoring, and explanation execute instantaneously on your device with zero network connection.

---

## 12. BACKEND / CLOUD

- **Does Privex require a backend server?**  
  **NO.** The Core Detection Engine, Bayesian scoring, and AI explanation assistant run 100% locally on your computer or phone.
- **Does Privex require the cloud?**  
  **NO.** All scanning occurs in volatile device RAM. An optional cloud edge CDN (Cloudflare Pages) is used only to host static web assets and distribute release files.
- **Does my browsing history, messages, or files ever leave my device?**  
  **NO.** Raw user payloads never cross the device boundary. Zero user data is transmitted to the cloud, logged on remote servers, or sold.
- **What runs locally?**  
  100% of detection rules, lexical analyzers, Bloom filter reputation checks, Bayesian risk scoring, and AI explanation synthesis.
- **What optional cloud services exist?**  
  Future cryptographically signed OTA Bloom filter delta updates (< 5 MB) downloaded like static files, and an optional RFC 9458 Oblivious HTTP (OHTTP) relay for anonymized threat telemetry.
- **What happens offline?**  
  Full threat detection capabilities operate without degradation. Threat verdicts are returned with identical mathematical precision.

---

## 13. SECURITY

- **Fail-Closed Principle:** If an input parser encounters malformed data or syntax errors, it safely escalates to `CAUTION` or `SUSPICIOUS`, never to a silent `ALLOW`.
- **Zero Hardcoded Secrets:** No API keys, private credentials, or developer tokens exist in the codebase.
- **Memory Safety & Length Caps:** Inputs are strictly bounded (URLs $\le 2,048$ bytes, Text $\le 10,000$ bytes) and sanitized via Unicode NFKD normalization to prevent buffer overruns or ReDoS attacks.
- **Cryptographic Shredder:** Local quarantined threats can be permanently purged using a 3-pass DoD 5220.22-M compliant crypto-shredder (`0x00`, `0xFF`, CSPRNG + `fsync`).

---

## 14. SUPPORTED PLATFORMS

| Platform | Supported OS / Environment | Architecture | Memory Footprint | Privilege Level |
|---|---|---|---|---|
| **Web App** | Modern Browsers (Chrome, Firefox, Safari, Edge) | WebAssembly / JS | $< 35\text{ MB}$ Heap | Zero OS Privileges (Sandbox) |
| **Android App** | Android 8.0 through Android 14 (API 26–34) | ARM64 / ARMv7 / x86_64 | $< 125\text{ MB}$ RSS | Standard User Permissions (`CAMERA`, `NOTIFICATION`) |
| **Windows Desktop** | Windows 10, Windows 11 (Setup & Portable) | x86_64 (64-bit) | $< 130\text{ MB}$ RSS | Standard User Rights (No UAC required) |
| **Browser Extension**| Chromium Browsers (Chrome, Edge, Brave, Opera) | Manifest V3 | $< 25\text{ MB}$ RSS | Standard WebExtension Permissions |

- **Older / Budget Android Devices:** Supports Android 8.0+ (API 26 through 34) with strict memory buffer boundaries (URLs $\le 2,048$ bytes, Text $\le 10,000$ bytes) and zero wake-lock battery conservation.

---

## 15. KNOWN LIMITATIONS

In strict adherence to our engineering transparency doctrine:
1. **Direct Sideloading Required:** Android requires users to enable "Allow from this source"; Chromium browsers require enabling "Developer mode" to load unpacked extensions.
2. **Self-Signed Windows Binaries:** Windows SmartScreen may display an initial "Unknown Publisher" advisory because release binaries are self-signed rather than signed with an enterprise EV code-signing certificate.
3. **No Background SMS Interception on Web/Desktop:** Automated inbound SMS filtering is architecturally exclusive to Android via native notification listeners. On Web and Desktop, message analysis requires user copy-paste.
4. **Legacy Low-End Hardware:** Software unit benchmarks confirm bounded memory allocations (< 125 MB RSS), but physical testing on legacy Android handsets manufactured before 2018 with $\le 1.0\text{ GB}$ RAM has not been conducted.
5. **Browser Internal Schemes:** Browser extensions cannot inspect internal configuration URLs (e.g., `chrome://`, `edge://`).

---

## 16. VERSION

- **Authoritative Product Version:** `v0.1.0` (Release Candidate)
- **Release Date:** October 4, 2026
- **Git Commit:** [`cc14dc1`](https://github.com/bhedanikhilkumar-code/Private-Protection/commit/cc14dc1)
- **Test Baseline:** 92 test files passed (100%), 506 unit/integration tests passed (100%), 0 failures, 0 skips.
- **Verification Suites:**
  - R13 Launch Verification: 37/37 passed (100%)
  - WCAG AA Accessibility: 5/5 passed (100%)

### Documentation & Audit Index:
- **Project Constitution:** [`AGENTS.md`](./AGENTS.md)
- **Final Launch Packaging Report:** [`docs/FINAL_LAUNCH_COMPLETION.md`](./docs/FINAL_LAUNCH_COMPLETION.md)
- **Phase R13 Public Launch Verification:** [`docs/PHASE_R13_PUBLIC_LAUNCH_VERIFICATION.md`](./docs/PHASE_R13_PUBLIC_LAUNCH_VERIFICATION.md)
- **Phase R12 Final Human Acceptance:** [`docs/PHASE_R12_FINAL_HUMAN_ACCEPTANCE.md`](./docs/PHASE_R12_FINAL_HUMAN_ACCEPTANCE.md)
- **Phase R11 Release Candidate Matrix:** [`docs/PHASE_R11_RELEASE_CANDIDATE_MATRIX.md`](./docs/PHASE_R11_RELEASE_CANDIDATE_MATRIX.md)
- **Phase R10 Security Hardening Report:** [`docs/PHASE_R10_FINAL_SECURITY_RELEASE_HARDENING.md`](./docs/PHASE_R10_FINAL_SECURITY_RELEASE_HARDENING.md)
- **Vulnerability Disclosure Policy:** [`SECURITY.md`](./SECURITY.md)
- **Changelog History:** [`CHANGELOG.md`](./CHANGELOG.md)
- **Release Checksums:** [`release/SHA256SUMS.txt`](./release/SHA256SUMS.txt) 
