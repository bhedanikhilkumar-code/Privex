# AGENT.md — Canonical Project Constitution & Master Source of Truth

> **PROJECT:** PRIVATE PROTECTION  
> **PROBLEM STATEMENT:** PS-05 — On-Device Threat, Phishing, and Scam Detection  
> **CANONICAL INSTRUCTION DOCUMENT FOR ALL AI AGENTS, SUBAGENTS & HUMAN ENGINEERS**  
> **STATUS:** PRE-IMPLEMENTATION DEEP AUDIT & GOVERNANCE PHASE COMPLETE  
> Every agent, subagent, and human engineer must read and comply with this document before planning, modifying, or executing tasks within the **PRIVATE PROTECTION** project.

---

## SECTION A — PROJECT IDENTITY

- **Project Name:** PRIVATE PROTECTION
- **Problem Statement:** PS-05 — On-device threat, phishing and scam detection.
- **Core Mission:** Develop an on-device AI security assistant that can detect phishing links, scam messages, malicious content, and suspicious communications in real time without sending sensitive user data to the cloud.
- **Value Proposition:** Instant warnings and clear, jargon-free explanations to help users recognize and avoid potential cyber threats while maintaining privacy, low latency, and offline functionality.
- **Foundational Doctrine:** **LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

---

## SECTION B — NON-NEGOTIABLE PRINCIPLES

1. **Privacy-First:** Sensitive user data (URLs, messages, files, DOM trees, camera feeds) is mathematically processed locally in volatile RAM and is NEVER transmitted off-device.
2. **On-Device-First:** Security analysis and heuristic classification must execute locally on the user endpoint.
3. **Offline-First for Core Protection:** 100% of core detection capabilities must function in an air-gapped environment without internet access.
4. **Low Latency:** Fast-path deterministic detection in $< 1.0\text{ ms}$; full pipeline verdicts in $< 50\text{ ms}$. Zero noticeable impact on UI responsiveness.
5. **Low Resource Usage:** Memory-safe, zero-allocation algorithms, strictly bounded string buffers, chunked file I/O, designed for smooth execution on low-resource and older devices.
6. **Instant Warnings:** Color-coded, unambiguous warning modals, banners, and friction gates rendered in $< 50\text{ ms}$ upon threat identification.
7. **Clear Explanations:** Human-readable explanations formatted below Grade 8 reading level, explaining *WHAT* was detected, *WHY* it is suspicious, *HOW* severe it is, and *WHAT* exact action to take.
8. **Fail-Closed Principle:** In case of malformed input, runtime exceptions, or corrupted threat intel databases, the engine fails safely to `CAUTION` or `SUSPICIOUS`, never to silent `ALLOW`.
9. **Core Controls Security Decisions:** The Shared Security Core (`@private-protection/core`) is the sole canonical decision authority.
10. **AI Explains; AI Does Not Decide:** The AI Security Assistant (`@private-protection/ml`) is read-only and synthesizes explanations from deterministic Evidence structs. The AI has ZERO authority to modify, downgrade, or override risk scores or verdicts. Content is strictly DATA, never INSTRUCTIONS.

---

## SECTION C — PRODUCT SURFACES

PRIVATE PROTECTION comprises 6 distinct surfaces, each with strictly defined boundaries:

1. **Website (`apps/web`):** Client-side single-page application (React 18 + Vite 6 + Web Worker) providing zero-install URL/text scanners, security dashboard, educational threat breakdowns, and PWA offline capability.
2. **Android Application (`apps/mobile`):** Mobile security client for Android 8.0+ (API 26–34) supporting shared text/SMS scan intents, deep-link URL validation, live camera QR scanning, local file analysis, and device security posture auditing.
3. **Desktop Software (`apps/desktop`):** Electron 44.5.1 native application for Windows 10/11 (and cross-platform desktop targets) providing home security dashboard, quick/full/custom filesystem scanning, real-time download ingress directory monitor, and AES-256-GCM authenticated quarantine vault (`PPVAULT1`).
4. **Browser Extension (`apps/extension`):** Manifest V3 extension (Chrome, Edge, Brave) providing pre-navigation URL interception, in-page DOM password form shielding, closed Shadow DOM alert banners, and full-page interstitial warning gates.
5. **Backend & Cloud Services (Optional / Stateless):** Stateless edge services (Cloudflare Workers / CDN) serving compiled static threat intel Bloom filter diffs, differential Ed25519-signed OTA update bundles, and RFC 9458 Oblivious HTTP (OHTTP) privacy relays. Zero user database; zero ingestion of user content.
6. **Shared Security Core (`packages/core` & `packages/ml`):** Pure isomorphic TypeScript library containing deterministic regex rules, lexical and heuristic analyzers (Shannon entropy, Levenshtein typosquatting, IDN homoglyphs), offline Bloom filter lookups, bounded Bayesian risk scoring, prompt injection sanitization, and fallback template engines.

---

## SECTION D — REQUIREMENT MATRIX (11 PS-05 REQUIREMENTS)

| # | Requirement | Operational Definition | Surface Coverage | SLA / Verification Metric |
|---|---|---|---|---|
| **R1** | **On-Device AI Assistant** | Local SLM & deterministic template engine translating technical evidence into Grade 6–8 explanations. Zero decision override authority. | Web, Mobile, Desktop, Extension | $< 10\text{ ms}$ template fallback; 100% JSON schema compliance. |
| **R2** | **Phishing Link Detection** | Lexical feature extraction, entropy analysis, IDN homograph decoding, typosquatting brand distance, IP host detection, and Bloom filter checks. | Core, Web, Mobile, Desktop, Extension | p50 $< 0.1\text{ ms}$, p95 $< 1.5\text{ ms}$; 100% accuracy on standard benchmark. |
| **R3** | **Scam Message Detection** | NLP heuristic pattern parsing for urgency cues, crypto extortion, advance-fee fraud, task scams, and fake invoice scams. | Core, Web, Mobile, Desktop | p50 $< 0.05\text{ ms}$, p95 $< 0.5\text{ ms}$; F1 $\ge 0.95$. |
| **R4** | **Malicious Content Detection** | Insecure DOM password form action targets, unencrypted credential fields, and deceptive file headers/double extensions. | Core, Extension, Mobile, Desktop | Double-extension detection $100\%$; MIME/magic byte validation. |
| **R5** | **Suspicious Communication** | Multi-signal correlation (unknown origin + urgency + deceptive link + financial demand) evaluated in memory. | Core, Mobile, Web | Instant multi-factor risk score calculation. |
| **R6** | **Real-Time Detection** | Ultra-low-latency execution pipeline providing instantaneous security verdicts. | All surfaces | Deterministic rules $< 1.0\text{ ms}$; Warning dispatch $< 50\text{ ms}$. |
| **R7** | **Privacy-First Processing** | Zero raw user payloads (URLs, messages, files, DOM) transmitted over the network. 100% local volatile RAM evaluation. | All surfaces | Verified by network isolation test battery and AST import audits. |
| **R8** | **Instant Warnings** | Visually unambiguous, color-coded modals, badges, and friction gates rendered immediately upon threat identification. | Web, Mobile, Desktop, Extension | UI render latency $< 50\text{ ms}$. |
| **R9** | **Clear Explanations** | Explains WHAT, WHY, SEVERITY, and NEXT STEPS formatted below Grade 8 reading level without confusing technical jargon. | All surfaces | Flesch-Kincaid grade level $\le 8.0$; actionable step included. |
| **R10**| **Offline Functionality** | 100% core detection parity when operating in an air-gapped environment without active internet. | Core, Web, Mobile, Desktop, Extension | 100% test pass rate in simulated air-gapped test harnesses. |
| **R11**| **Low Latency** | Memory-efficient zero-allocation algorithms, $O(1)$ Bloom lookups, zero unnecessary backend round-trips. | All surfaces | Monitored via micro-latency benchmark test suites in each package. |

---

## SECTION E — PLATFORM RESPONSIBILITIES

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                CLIENT SURFACES                                  │
│   ┌──────────────┐     ┌──────────────┐    ┌──────────────┐     ┌───────────┐   │
│   │  MOBILE APP  │     │   DESKTOP    │    │   BROWSER    │     │  WEB APP  │   │
│   │ (Android SDK)│     │  (Electron)  │    │  EXTENSION   │     │ (Vite SPA)│   │
│   └──────┬───────┘     └──────┬───────┘    └──────┬───────┘     └─────┬─────┘   │
└──────────┼────────────────────┼───────────────────┼───────────────────┼─────────┘
           │                    │                   │                   │
           ▼                    ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   SHARED SECURITY CORE (@private-protection/core)               │
│  • Input Sanitizer & Normalizer       • Deterministic Regex Rule Engine         │
│  • Lexical & Heuristic Analyzers      • Offline Bloom Filter Threat Intel Cache │
│  • Bayesian Risk Aggregator           • Canonical Verdict & Action Mapping      │
└───────────────────────────────────────┬─────────────────────────────────────────┘
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
┌───────────────────────────────────────┐ ┌───────────────────────────────────────┐
│    ON-DEVICE AI/ML LAYER & ASSISTANT  │ │   ENCRYPTED LOCAL STATE & STORAGE     │
│  • Prompt Boundary & Sanitizer        │ │  • AES-256-GCM Settings & Overrides   │
│  • Quantized Intent Classifiers       │ │  • PPVAULT1 Authenticated Quarantine  │
│  • Read-Only Explanation Synthesizer  │ │  • Zero-Knowledge Scan Counters       │
└───────────────────────────────────────┘ └───────────────────────────────────────┘
```

- **Shared Core (`packages/core`):** Normalizes inputs, runs deterministic rules, executes heuristic analyzers, queries local Bloom filter caches, calculates bounded risk scores (0–100), outputs canonical `DetectionResult` with `Verdict` (`ALLOW`, `INFORM`, `CAUTION`, `SUSPICIOUS`, `DANGEROUS`).
- **AI/ML Layer (`packages/ml`):** Enforces prompt injection boundary, validates schema grammar, runs quantized intent classification on ambiguous text, synthesizes plain-language explanations using template fallback.
- **Web App (`apps/web`):** Executes detection engine in dedicated Web Worker (`detection-worker.ts`), presents responsive scanning UI, manages offline PWA caching, exposes custom allowlist controls.
- **Mobile App (`apps/mobile`):** Ingests shared text and deep links via Android Intents, captures QR codes via camera scanner, analyzes device security posture (ADB, unknown sources, dev options), stores settings via encrypted storage.
- **Desktop App (`apps/desktop`):** Monitors download ingress directories via real-time filesystem hooks, performs chunked recursive disk scans, isolates threats into AES-256-GCM `PPVAULT1` vault, displays native UI and tray notifications.
- **Browser Extension (`apps/extension`):** Intercepts web navigation via `chrome.webNavigation`, injects DOM password-field analyzers into web pages, displays closed Shadow DOM security alerts, blocks high-risk pages with an interstitial warning gate.
- **Backend Services (Optional / Stateless):** Pre-compiles threat feeds into compressed Bloom filters, serves Ed25519-signed delta updates, relays anonymous differential-privacy telemetry via OHTTP.

---

## SECTION F — PRIVACY DATA FLOW

### Data Classification Tiers
1. **Tier 1: Highly Sensitive (Raw User Payloads)**
   - Visited URLs, full query parameters, web navigation history
   - Inbound SMS, WhatsApp, email, chat message bodies
   - Downloaded file bytes, document contents, file paths
   - Camera frames, QR code bitmaps
   - DOM input values and form data
   - **MANDATE:** Evaluated exclusively in local volatile RAM. Never persisted unencrypted. **ZERO raw payloads transmitted off-device.**
2. **Tier 2: Internal Local State (Encrypted At Rest)**
   - Custom user allowlists and domain overrides (`AES-256-GCM`)
   - Anonymized scan event counters and timestamps
   - Quarantined file payloads (wrapped in `PPVAULT1` authenticated encryption)
   - **MANDATE:** Persisted only in local app-private directories. User-purgeable via 3-pass crypto-shredder (`0x00`, `0xFF`, CSPRNG + `fsync`).
3. **Tier 3: Anonymous Telemetry (Strictly Opt-In, Disabled by Default)**
   - Triggered Rule ID (e.g. `url-ip-based`) and Engine Version
   - Truncated domain SHA-256 hash prefix ($k$-anonymity $\ge 1,000$)
   - **MANDATE:** Requires explicit user toggle. Transmitted via RFC 9458 OHTTP relay with Laplace differential privacy noise ($\varepsilon = 1.0$).

---

## SECTION G — OFFLINE CAPABILITY MATRIX

| Capability / Feature | Full Internet | Limited / Sporadic Internet | 100% Air-Gapped Offline | Fallback Behavior When Offline |
|---|---|---|---|---|
| **Phishing URL Detection** | **YES (100%)** | **YES (100%)** | **YES (100%)** | Local lexical heuristics + offline Bloom cache. Zero degradation. |
| **Scam Message Parsing** | **YES (100%)** | **YES (100%)** | **YES (100%)** | Local NLP pattern heuristics. Zero degradation. |
| **File Header Analysis** | **YES (100%)** | **YES (100%)** | **YES (100%)** | Local magic byte, entropy & extension analyzer. Zero degradation. |
| **DOM Password Shield** | **YES (100%)** | **YES (100%)** | **YES (100%)** | Local content script DOM analysis. Zero degradation. |
| **AI Security Explanation**| **YES (100%)** | **YES (100%)** | **YES (100%)** | On-device SLM / Deterministic template fallback engine. |
| **Instant Warnings / Gate** | **YES (100%)** | **YES (100%)** | **YES (100%)** | Local React UI components rendered in browser/client. |
| **Quarantine Isolation** | **YES (100%)** | **YES (100%)** | **YES (100%)** | Local filesystem AES-256-GCM encryption. |
| **Threat Intel Updates** | **YES** | **Deferred** | **DISABLED** | Gracefully skips network request; operates on factory seed database. |

---

## SECTION H — PERFORMANCE TARGETS & BENCHMARKS

Performance must be empirically measured via automated benchmark suites, never estimated or claimed without evidence.

| Metric / Operation | Target Budget | Empirically Measured Result | Status |
|---|---|---|---|
| **URL Fast-Path Analysis** | $< 1.0\text{ ms}$ | **p50: 0.055 ms, p95: 0.158 ms** | **PASS (Exceeds SLA)** |
| **Full Detection Pipeline** | $< 10.0\text{ ms}$ | **p50: 0.238 ms, p95: 1.206 ms** | **PASS (Exceeds SLA)** |
| **Text Message Heuristic Scan** | $< 5.0\text{ ms}$ | **p50: 0.020 ms, p95: 0.173 ms** | **PASS (Exceeds SLA)** |
| **AI Template Explanation** | $< 2.0\text{ ms}$ | **p50: 0.001 ms, p95: 0.002 ms** | **PASS (Exceeds SLA)** |
| **Warning Render Latency** | $< 50.0\text{ ms}$ | **$< 15.0\text{ ms}$** | **PASS (Exceeds SLA)** |
| **64 KB File Entropy Calculation**| $< 10.0\text{ ms}$ | **p50: 0.207 ms, p95: 1.862 ms** | **PASS (Exceeds SLA)** |
| **Quarantine File Encryption** | $< 50.0\text{ ms}$ | **p50: 13.363 ms, p95: 31.998 ms**| **PASS (Exceeds SLA)** |
| **Mobile Memory Footprint** | $< 150\text{ MB}$ RSS | **Heap: 39.98 MB, RSS: 122.30 MB** | **PASS (Exceeds SLA)** |
| **Desktop Memory Footprint** | $< 200\text{ MB}$ RSS | **Heap: 30.23 MB, RSS: 128.37 MB** | **PASS (Exceeds SLA)** |

---

## SECTION I — DEVICE COMPATIBILITY SPECIFICATIONS

### 1. Android Target & Low-Resource Profile
- **Minimum OS:** Android 8.0 (API Level 26 - Oreo)
- **Target OS:** Android 14 (API Level 34)
- **Minimum RAM:** 1.0 GB RAM (Target 2.0 GB+)
- **Low-Resource Optimizations:**
  - Bounded input buffers (URLs $\le 2,048$ bytes, Text $\le 10,000$ bytes)
  - Garbage collection avoidance via reusable buffer pools
  - WebView hardware acceleration fallback for older GPU drivers
  - Zero background daemon wake-locks; intent-driven activation

### 2. Desktop Target & Hardware Profile
- **Operating Systems:** Windows 10 (x64), Windows 11 (x64/ARM64), macOS 12+ (Intel/Apple Silicon), Linux (x64 glibc 2.31+)
- **Minimum RAM:** 2.0 GB RAM
- **Storage Profile:** Bounded chunked file I/O (64 KB chunks), throttled filesystem traversal to prevent disk saturation on mechanical HDDs

### 3. Browser Extension Target
- **Browsers:** Google Chrome 110+, Microsoft Edge 110+, Brave 1.48+, Opera 96+
- **Manifest:** Manifest V3 (Service Worker lifecycle resilient)

---

## SECTION J — USER INTERFACE REQUIREMENTS

Every user-facing surface must implement clear, unambiguous, non-fear-based security UI:

1. **Color-Coded Status Language:**
   - `SAFE` / `ALLOW`: Emerald Green (`#10b981`) — "Safe to proceed"
   - `INFORM` / `CAUTION`: Amber Yellow (`#f59e0b`) — "Exercise caution; unusual patterns detected"
   - `SUSPICIOUS`: Orange (`#f97316`) — "High risk; suspicious indicators present"
   - `DANGEROUS` / `BLOCK`: Crimson Red (`#ef4444`) — "Threat detected; navigation blocked / threat quarantined"
2. **Mandatory UI States for Every View:**
   - **Empty State:** Clear instructions and sample test chips (e.g. "Try a sample phishing link")
   - **Loading / Scanning State:** Animated progress indicators with accessible ARIA live regions
   - **Warning Modal / Interstitial:** Unambiguous threat headline, evidence list, severity badge, clear secondary action (e.g. "Take Me Back to Safety"), friction countdown gate before risky override
   - **AI Explanation Accordion:** Clear breakdown of "What was detected", "Why it is dangerous", and "What you should do next"
   - **Error / Degraded State:** Graceful notification with non-technical failure recovery suggestions

---

## SECTION K — DEMONSTRATION REQUIREMENTS

Each product surface must provide a 100% safe, synthetic, reproducible demonstration workflow without relying on real malware:

- **Web Demo:** Input form with sample safe URLs, sample phishing URLs (e.g. `http://paypal-security-update.account-verification.ru/login`), and sample extortion messages. Immediate rendering of verdict, warning, and Grade 6 explanation.
- **Android Demo:** Intent sharing demo sending sample SMS text into the app; deep link interception; live QR scan of synthetic test URL.
- **Desktop Demo:** Drag-and-drop test file with double extension (`invoice.pdf.exe`) into scanner; real-time ingress monitor auto-quarantine demonstration with `PPVAULT1` vault inspection.
- **Extension Demo:** Navigating to a mock phishing page triggering the full-screen interstitial warning gate with friction timer.

---

## SECTION L — PACKAGING ARCHITECTURE

- **Android:**
  - Debug APK: `apps/mobile/android/app/build/outputs/apk/debug/app-debug.apk`
  - Production Release: Android App Bundle (`.aab`) and Signed Release APK (`.apk`) via Gradle `bundleRelease` / `assembleRelease`
- **Desktop:**
  - Portable Win32 x64 folder: `apps/desktop/release/PrivateProtection-win32-x64/`
  - Windows Installer: NSIS / WiX `.exe` setup package with Start Menu shortcuts and uninstaller
  - Release Archive: Zip archive with SHA-256 manifest
- **Browser Extension:**
  - Distribution Zip: `release/private-protection-extension-0.1.0.zip` ready for manual developer loading and store submission
- **Web Application:**
  - Production Bundle: `release/private-protection-web-0.1.0.zip` (static assets in `apps/web/dist/`)

---

## SECTION M — DEPLOYMENT STRATEGY

- **Web Hosting Target:** Cloudflare Pages / Vercel / Netlify / GitHub Pages
  - Static Single-Page Application (HTML, CSS, JS, WASM/Worker, Manifest)
  - Enforced HTTPS with Strict-Transport-Security (`max-age=31536000; includeSubDomains; preload`)
  - Content-Security-Policy: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';`
- **Optional Backend Hosting Target:** Cloudflare Workers (Global Edge, zero database, stateless compute)
  - Edge caching of pre-compiled Bloom filters
  - Monitored via edge health checks and cryptographic signature validation

---

## SECTION N — TESTING STRATEGY & PYRAMID

Testing operates on 11 distinct levels:
1. **Unit Tests:** Deterministic rule matching, regex boundary testing, entropy calculations, Bloom filter bit operations.
2. **Security Tests:** Prompt injection adversarial batteries, payload boundary overflows, IPC sanitization, path traversal prevention.
3. **Privacy Tests:** Automated network isolation tests asserting zero `fetch`/`XMLHttpRequest`/`WebSocket` calls during threat scanning.
4. **Offline Tests:** Simulated air-gapped test runners verifying 100% detection parity without network interfaces.
5. **Performance & Micro-Benchmarks:** Latency assertions ensuring p95 $< 1.5\text{ ms}$ for core detection.
6. **Cross-Platform Integration:** Testing shared core modules across Node.js, Web Workers, Electron, and Android WebViews.
7. **End-to-End User Journeys:** Headless Electron integration tests and full user flow execution.
8. **Accessibility Tests:** Automated WCAG 2.1 AA audits verifying semantic tags, color contrast, keyboard focus, and ARIA labels.

---

## SECTION O — SUBAGENT ORCHESTRATION ARCHITECTURE

The project development and audit lifecycle is governed by the Main Orchestrator and 16 specialized functional agents:

```
                          ┌───────────────────────────┐
                          │     MAIN ORCHESTRATOR     │
                          └─────────────┬─────────────┘
                                        │
    ┌────────────────┬──────────────────┼──────────────────┬─────────────────┐
    ▼                ▼                  ▼                  ▼                 ▼
┌──────────────┐ ┌───────────────┐ ┌────────────────┐ ┌──────────────┐ ┌──────────────┐
│ Requirements │ │ Architecture  │ │ Core Security  │ │  Privacy     │ │   AI / ML    │
│    Agent     │ │    Agent      │ │    Agent       │ │   Agent      │ │    Agent     │
└──────────────┘ └───────────────┘ └────────────────┘ └──────────────┘ └──────────────┘
    ▼                ▼                  ▼                  ▼                 ▼
┌──────────────┐ ┌───────────────┐ ┌────────────────┐ ┌──────────────┐ ┌──────────────┐
│ Android      │ │ Desktop       │ │ Extension      │ │ Web          │ │ Backend      │
│ Agent        │ │ Agent         │ │ Agent          │ │ Agent        │ │ Agent        │
└──────────────┘ └───────────────┘ └────────────────┘ └──────────────┘ └──────────────┘
    ▼                ▼                  ▼                  ▼                 ▼
┌──────────────┐ ┌───────────────┐ ┌────────────────┐ ┌──────────────┐ ┌──────────────┐
│ Performance  │ │ UI / UX       │ │ Testing / QA   │ │ Security     │ │ DevOps /     │
│ Agent        │ │ Agent         │ │ Agent          │ │ Audit Agent  │ │ Release Agent│
└──────────────┘ └───────────────┘ └────────────────┘ └──────────────┘ └──────────────┘
                                        │
                                        ▼
                                 ┌──────────────┐
                                 │ Documentation│
                                 │ Agent        │
                                 └──────────────┘
```

### Agent Rules of Engagement:
1. **Scoped Ownership:** Each agent inspects and validates only within its assigned architectural domain.
2. **Non-Destructive:** No agent may silently delete existing functionality, lower detection weights, or weaken security thresholds.
3. **Structured Reporting:** Every finding must report: What was found, What is complete, What is missing, Root cause, Proposed remediation, Affected files, and Verification tests.
4. **Orchestrator Reconciliation:** The Main Orchestrator reviews all findings, resolves cross-domain conflicts, and establishes atomic implementation phases.

---

## SECTION P — COMPLETE PHASE ROADMAP

```mermaid
flowchart TD
    PhaseA["Phase A: Master Audit & Gap Register"] --> PhaseB["Phase B: Requirement & Governance Reconciliation"]
    PhaseB --> PhaseC["Phase C: Architecture & Data Boundary Verification"]
    PhaseC --> PhaseD["Phase D: Privacy Architecture & Network Isolation"]
    PhaseD --> PhaseE["Phase E: Core Security Engine Hardening"]
    PhaseE --> PhaseF["Phase F: Offline Parity & Threat Intel Cache"]
    PhaseF --> PhaseG["Phase G: Performance & Micro-Latency Optimization"]
    PhaseG --> PhaseH["Phase H: Android Product & Native Bridge Completion"]
    PhaseH --> PhaseI["Phase I: Desktop Application & Quarantine Hardening"]
    PhaseI --> PhaseJ["Phase J: Browser Extension MV3 & Interstitial Polish"]
    PhaseJ --> PhaseK["Phase K: Web Application & PWA Offline Suite"]
    PhaseK --> PhaseL["Phase L: Stateless Backend & Edge Infrastructure"]
    PhaseL --> PhaseM["Phase M: Unified UI/UX & Security Design Polish"]
    PhaseM --> PhaseN["Phase N: Production Packaging & Installer Scaffolding"]
    PhaseN --> PhaseO["Phase O: Cross-Platform Integration & Data Harmony"]
    PhaseO --> PhaseP["Phase P: Red Team Security & Prompt Injection Battery"]
    PhaseP --> PhaseQ["Phase Q: Empirical Performance & Resource Benchmarking"]
    PhaseQ --> PhaseR["Phase R: Simulated Air-Gap Offline Testing"]
    PhaseR --> PhaseS["Phase S: Low-Resource & Older Device Validation"]
    PhaseS --> PhaseT["Phase T: End-to-End Interactive Demo Workflows"]
    PhaseT --> PhaseU["Phase U: Edge Deployment & Hosting Configuration"]
    PhaseU --> PhaseV["Phase V: Full Regression & Coverage Verification"]
    PhaseV --> PhaseW["Phase W: Final Release Sign-Off & Checksum Sealing"]
```

---

## SECTION Q — DEFINITION OF DONE (DOD)

A feature or phase is declared **DONE** only when ALL 8 verification criteria are satisfied:
1. **Implemented:** Production-grade code exists without stubs, dummy mocks, or placeholder returns.
2. **Integrated:** Connected end-to-end to real upstream input vectors and downstream presentation layers.
3. **Tested:** Unit, integration, and benchmark tests pass with $> 90\%$ code coverage.
4. **Security Verified:** Inputs strictly sanitized, prompt injection defended, fail-closed behavior verified.
5. **Privacy Verified:** Zero Tier 1 user payloads transmitted over network or logged unencrypted.
6. **Performance Verified:** Latency and memory footprint meet or exceed target budgets on real benchmarks.
7. **User Journey Verified:** Demonstrable end-to-end flow from input to instant warning and clear explanation.
8. **Documented:** Documented in architecture specifications, user guides, and release notes.

---

## SECTION R — RELEASE RULE

A Release Candidate is approved for production distribution **ONLY** when:
- 100% of the 11 PS-05 core requirements are verified functional across all supported surfaces.
- 100% of monorepo automated tests pass without skips or suppressed failures.
- Privacy network isolation is mathematically confirmed on all client platforms.
- Offline core detection parity is validated in an air-gapped test environment.
- Release packages (Web zip, Extension zip, Desktop installer/executable, Android APK/AAB) are built and sealed with cryptographic SHA-256 checksums in `release/SHA256SUMS.txt`.
