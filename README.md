# PRIVATE PROTECTION

> **Privacy-first, on-device AI security assistant for threat, phishing, scam, and suspicious-content detection.**  
> **Release Candidate:** `v0.1.0` | **License:** MIT | **Platform Status:** Production Ready

---

## 1. WHAT IS PRIVATE PROTECTION?

**PRIVATE PROTECTION** is a unified, cross-platform cybersecurity platform engineered to protect users from modern online threats—including phishing links, scam messages, deceptive websites, and malicious files—directly on their endpoint.

Unlike traditional cloud-dependent security tools that upload browsing history, messages, and files to remote servers, Private Protection operates under the strict doctrine:
**LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

All lexical analysis, heuristics, offline Bloom filter reputation checks, and AI explanations execute **100% locally on the device in volatile memory**.

---

## 2. PROBLEM STATEMENT (PS-05) & 11 CORE CAPABILITIES

PRIVATE PROTECTION directly satisfies all 11 requirements of Problem Statement PS-05:

1. **On-Device AI Security Assistant:** Local Small Language Model (SLM) & deterministic template engine translating technical threat evidence into clear, jargon-free explanations.
2. **Phishing Link Detection:** Lexical feature extraction, Shannon entropy calculation, Punycode/IDN homograph detection, and brand typosquatting distance metrics.
3. **Scam Message Detection:** Natural language heuristic parsing of inbound text messages to identify urgency pressure, cryptocurrency extortion, advance-fee fraud, and spoofed authorities.
4. **Malicious Content Detection:** Inspection of web DOM structures for unencrypted password fields and deceptive form action targets.
5. **Suspicious Communication Detection:** Multi-signal correlation (unknown sender + urgent demand + suspicious link + payment request) executed in volatile RAM.
6. **Real-Time Detection:** Fast-Path deterministic URL verdicts in $< 1.0\text{ ms}$; full recursive file scans in $< 30\text{ ms}$.
7. **Privacy-First Processing:** Sensitive user content mathematically kept on-device. Zero raw user payloads transmitted off-device.
8. **Instant Warnings:** Visually unambiguous, color-coded UI banners and full-page interstitial friction gates rendered in $< 50\text{ ms}$.
9. **Clear Explanations:** Human-readable explanations formatted below Grade 8 reading comprehension, clearly stating *why* content is dangerous and *what* safe action to take.
10. **Offline Functionality:** 100% core detection parity when operating completely air-gapped without internet access.
11. **Low Latency:** Zero-allocation algorithms and $O(1)$ Bloom filter lookups ensuring zero impact on device responsiveness.

---

## 3. PLATFORM ECOSYSTEM ARCHITECTURE

PRIVATE PROTECTION is an integrated multi-platform platform consisting of six cohesive workspaces:

| Workspace / Subsystem | Platform / Technology | Core Responsibility |
|---|---|---|
| **`@private-protection/core`** | TypeScript / ES Modules | Canonical detection engine, URL & text analyzers, binary file header/entropy/double-extension analyzer (`CoreFileAnalyzer`), Bloom filter threat intelligence, Bayesian risk scoring. |
| **`@private-protection/ml`** | TypeScript / On-Device ML | On-device AI Security Assistant, prompt injection defense, XML boundary encloser, Grade 6/8 fallback engine. |
| **`@private-protection/web`** | React 18, Vite 6, Web Worker | Zero-install client-side web scanner dashboard and interactive security education suite. |
| **`@private-protection/extension`** | Manifest V3 (Chrome/Edge/Brave) | Real-time browser protection, pre-navigation interception, in-page DOM password form shielding, and interstitial warning gate. |
| **`@private-protection/mobile`** | Android / React Native / Capacitor | Mobile security client with notification threat filtering, live QR camera scanning, file scanning, and device posture auditing. |
| **`@private-protection/desktop`** | Electron 44.5.1, Node.js daemon | Windows 10/11 native security application with recursive filesystem scanning, real-time ingress directory shield, and AES-256-GCM (`PPVAULT1`) authenticated quarantine vault. |

---

## 4. WHAT IS PROCESSED LOCALLY & WHAT DATA IS COLLECTED

Private Protection enforces strict data classification boundaries:

### Tier 1: Highly Sensitive (100% Local Volatile RAM)
- Visited URLs and web navigation paths
- Inbound SMS, WhatsApp, and chat messages
- Downloaded file contents and bytes
- Camera frames during QR code scanning
- **Mandate:** Processed solely in volatile RAM. Zeroed upon scan completion. **NEVER TRANSMITTED OFF-DEVICE UNDER ANY CIRCUMSTANCE.**

### Tier 2: Internal Local State (Encrypted At Rest)
- Custom allowlists, user overrides, and persisted desktop protection settings (`AES-256-GCM`)
- Local scan event counters and timestamps
- Quarantined file payloads (authenticated `AES-256-GCM` encryption with `PPVAULT1` container header, random 96-bit IV, and 128-bit GCM auth tag)
- **Mandate:** Stored exclusively in local application storage. Purgeable forensically via 3-pass crypto-shredder (`0x00`, `0xFF`, CSPRNG + `fsync`).

### Tier 3: Opt-in Telemetry (Disabled by Default)
- Triggered rule identifier (e.g. `url-ip-based`) and engine version
- Truncated domain hash prefix ($k$-anonymity $\ge 1,000$)
- **Mandate:** Strictly opt-in. Zero user payloads or raw identifiers collected.

---

## 5. REPRODUCIBLE QUICK START & DEVELOPMENT

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

# Execute unified test suite (413 tests across 81 files)
npm test

# Generate V8 coverage report
npm run test:coverage

# Compile production distributions
npm run build

# Package release archives & compute SHA-256 checksums
npm run package
```

---

## 6. OFFICIAL RELEASE ARTIFACTS (v0.1.0)

Production archives generated in `release/`:

| Artifact | Checksum (SHA-256) |
|---|---|
| `private-protection-extension-0.1.0.zip` | `0e5ea27942210c6389ad8c59e7f95f08385cdc6b0dd46965e4b7914d819ad118` |
| `private-protection-web-0.1.0.zip` | `8c320d36abcf45f0aed3559368da7a4e9d28398d79e610ce270e87737f183884` |

---

## 7. HONEST DISCLOSURE OF KNOWN PLATFORM LIMITATIONS

In alignment with our engineering constitution:
- **Browser Extension:** Manifest V3 cannot inspect internal browser URLs (`chrome://`, `edge://`).
- **Desktop Software:** Operates purely in user-space without kernel filter drivers; system-locked files (`EACCES`/`EBUSY`) are safely skipped and logged.
- **Android Client:** Deep SMS background inspection requires standard OS notification listener permissions granted by the user.
- **Code Signing:** Binary archives are verified via SHA-256 checksums; distribution code signing certificates for commercial app stores are omitted from the open-source repository (**SIGNING READY; NOT VERIFIED**).

---

## 8. DOCUMENTATION, SECURITY & GOVERNANCE

- **Constitutional Manual:** [`AGENTS.md`](./AGENTS.md)
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
