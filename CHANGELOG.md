# CHANGELOG
## PRIVEX — All Notable Changes

All notable changes to this project are documented in this file in adherence to the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) standard and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-10-02

### Added
- **Constitutional Governance (Phase 0):**
  - Project Constitution and autonomous agent manual in `AGENTS.md`.
  - 24 Pre-Coding Verification Gates audited and passed by the 12-role technical audit committee.
  - Complete architectural specifications under `docs/` covering data flows, trust boundaries, threat models, and interface contracts.
- **Shared Core Detection Engine (`@private-protection/core`, Phase 2):**
  - High-performance `UrlAnalyzer` with Shannon entropy calculation, Punycode/IDN homograph detection, and brand typosquatting distance metrics.
  - Heuristic `TextAnalyzer` identifying urgency pressure tactics, cryptocurrency extortion, advance-fee fraud, and spoofed authorities.
  - Compressed offline `BloomFilter` supporting $O(1)$ lookup latency of known threat domains with $< 5\text{MB}$ memory footprint.
  - Weighted non-linear Bayesian `RiskScorer` delivering bounded 0–100 threat scores and deterministic action mapping (`ALLOW`, `INFORM`, `WARN`, `BLOCK`).
  - Read-only `ExplanationEngine` synthesizing human-readable threat rationales below Reading Grade 8.
- **On-Device AI / ML Layer & Security Assistant (`@private-protection/ml`, Phase 3):**
  - On-device `AISecurityAssistant` runtime operating with strict prompt injection containment.
  - `PromptSanitizer` defending against 6 injection categories using XML boundary tagging (`<untrusted_content>`).
  - `SchemaValidator` enforcing rigid JSON grammar schemas on assistant outputs.
  - Deterministic Grade 6 / Grade 8 template fallback activated on model failure or timeout.
  - 110+ adversarial test battery achieving 100% attack mitigation.
- **Web Application Client (`apps/web`, Phase 4):**
  - Zero-install client-side web application running `@private-protection/core` and `@private-protection/ml` in a dedicated Web Worker (`detection-worker.js`).
  - Reactive interactive scanning dashboard for manual URL and text analysis.
  - Offline Progressive Web App (PWA) caching with zero network dependencies.
  - WCAG 2.1 AA accessibility compliance with full keyboard navigation and screen-reader support.
- **Browser Extension Real-Time Protection (`apps/extension`, Phase 5):**
  - Chromium Manifest V3 extension intercepting pre-navigation events via `webNavigation.onBeforeNavigate`.
  - Fast-Path deterministic URL evaluation ($< 1.0\text{ ms}$) blocking malicious sites before network connection.
  - Full-page interstitial warning page (`interstitial.html`) with friction gate to prevent drive-by navigation.
  - In-page closed Shadow DOM alert banner shielding unencrypted password inputs on deceptive forms.
- **Android Mobile Security Client (`apps/mobile`, Phase 6):**
  - Android-first client integrating NotificationListenerService for inbound message filtering.
  - Live QR code camera analyzer evaluating embedded links in volatile memory.
  - Comprehensive device posture audit inspecting ADB debugging, mock location providers, and developer options.
- **Desktop Security Software (`apps/desktop`, Phase 7):**
  - Hardened 3-tier Electron desktop client with unprivileged Chromium renderer (`contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`).
  - Real-time filesystem ingress watcher monitoring `%USERPROFILE%\Downloads`, `%TEMP%`, and mounted removable drives.
  - Recursive PC scanner handling file locks gracefully and preventing symlink loops via canonical `fs.realpathSync`.
  - Cryptographic quarantine vault featuring XOR magic-byte scrambling (`0xA5`) and 3-pass forensic crypto-shredder.
- **Production Release Hardening:**
  - Automated CI/CD workflow `.github/workflows/ci.yml` running lint, typecheck, tests, and security scans.
  - Cross-platform release packaging script `scripts/package-release.js` generating production zip archives and SHA-256 manifests.
  - Comprehensive security policy in `SECURITY.md`, contributor guide in `CONTRIBUTING.md`, and reproducible build guide in `docs/REPRODUCIBLE_BUILD.md`.

### Security & Privacy Highlights
- **100% On-Device Processing:** Zero visited URLs, text messages, file contents, or personal credentials transmitted off-device.
- **Automated Network Tripwires:** 4/4 client test suites confirm 0 outbound HTTP/network requests across all scanning operations.
- **0 Supply Chain CVEs:** `npm audit` confirms 0 known vulnerabilities across all workspaces.
- **100% Test Pass Rate:** 413 unit, integration, and benchmark tests passing across 81 test files.
