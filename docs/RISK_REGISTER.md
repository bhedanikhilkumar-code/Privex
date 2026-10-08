# Risk Register: PRIVEX

This register documents identified risks for the PRIVEX project, their mitigation strategies, and ownership.

---

## RR-001: On-Device Model Accuracy Insufficient for Novel Threats

| Field | Value |
|---|---|
| **Risk** | Quantized on-device models (INT4/INT8) may have significantly lower accuracy than cloud-scale models, causing high false-negative rates for novel/zero-day phishing campaigns. |
| **Probability** | Medium |
| **Impact** | High — users exposed to undetected threats, eroding trust. |
| **Mitigation** | Layered detection (rules + heuristics catch known patterns even if ML misses). Frequent model updates via differential patches. Aggressive synthetic data augmentation during training. Optional cloud fallback for low-confidence cases. |
| **Owner** | AI/ML Architect |
| **Detection Method** | Continuous evaluation against labeled benchmark datasets. Monitor false-negative rate via opt-in telemetry. |
| **Status** | **Open — requires Phase 2 benchmarking to quantify actual gap** |

---

## RR-002: False Positive Rate Causes User Fatigue

| Field | Value |
|---|---|
| **Risk** | Overly aggressive detection causes legitimate content to be flagged, leading users to disable or ignore warnings ("alert fatigue"). |
| **Probability** | Medium |
| **Impact** | High — users disable protection entirely, defeating the product's purpose. |
| **Mitigation** | Target FPR <0.01%. Graduated warning severity (informational vs blocking). User feedback loop for false positives. Automated regression testing against Alexa Top 1000 sites. Customizable strictness levels. |
| **Owner** | Detection Architect |
| **Detection Method** | FP regression suite in CI/CD. Opt-in telemetry tracking warning dismissal rates. |
| **Status** | **Open — critical acceptance criteria for Phase 1** |

---

## RR-003: Prompt Injection via Untrusted Content

| Field | Value |
|---|---|
| **Risk** | Attackers embed adversarial text in messages or web pages that manipulates the local AI assistant into classifying malicious content as safe. |
| **Probability** | Medium |
| **Impact** | Medium — could bypass AI layer (but deterministic rules still provide a safety net). |
| **Mitigation** | Strict system/user prompt separation. Input pre-filtering for injection patterns. AI assistant is read-only — cannot modify detection decisions. Deterministic rules override AI classifications. Output schema validation. |
| **Owner** | AI/ML Architect + Security Architect |
| **Detection Method** | Adversarial testing suite with known injection payloads. Red team exercises. |
| **Status** | **Open — requires dedicated adversarial test suite in Phase 2** |

---

## RR-004: Model Theft / Reverse Engineering

| Field | Value |
|---|---|
| **Risk** | Competitors or attackers extract on-device ML models from application binaries to steal IP or discover evasion techniques. |
| **Probability** | High |
| **Impact** | Medium — business risk (IP loss) and security risk (attackers can craft model-evading inputs). |
| **Mitigation** | Model encryption at rest (decrypted only in memory during inference). Code obfuscation. **Accepted residual risk**: any model deployed to user devices is ultimately extractable by a determined attacker. Defense-in-depth (rules + heuristics) limits the impact of model compromise. |
| **Owner** | Security Architect |
| **Detection Method** | None at runtime (accepted). |
| **Status** | **Accepted Risk** |

---

## RR-005: Platform API Restrictions (Mobile)

| Field | Value |
|---|---|
| **Risk** | Apple and Google restrict background processing, SMS access, and notification interception capabilities. iOS severely limits SMS scanning. Android's accessibility service requirements may trigger Play Store rejections. |
| **Probability** | High |
| **Impact** | High — core mobile functionality may be impossible or require significant workarounds on iOS. |
| **Mitigation** | iOS: Use Safari Web Extension for browser protection, Notification Content Extension for push analysis, and manual submission as primary workflow. Android: Use SMS permission (with Play Store declaration) or Notification Listener service. Design mobile app to degrade gracefully when permissions are restricted. |
| **Owner** | Mobile Platform Architect |
| **Detection Method** | Platform API audit during Phase 4. App Store review guidelines monitoring. |
| **Status** | **Open — critical constraint for mobile architecture** |

---

## RR-006: SLM Size Impact on Mobile Storage and Performance

| Field | Value |
|---|---|
| **Risk** | The AI Assistant SLM (1.5-3GB) is too large for many mobile devices, causing storage pressure and slow inference on older hardware. |
| **Probability** | Medium |
| **Impact** | Medium — users with limited storage cannot install, or experience unacceptable latency. |
| **Mitigation** | Make SLM download optional (core detection works without it). Offer template-based explanations as fallback. Use smallest viable model (Gemma 2B INT4 ≈ 1.5GB). Desktop uses larger models. Browser uses no SLM (template explanations only). |
| **Owner** | AI/ML Architect |
| **Detection Method** | Storage budget monitoring. User telemetry on SLM adoption rate. |
| **Status** | **Open — architecture supports graceful degradation** |

---

## RR-007: Supply Chain Attack on Dependencies

| Field | Value |
|---|---|
| **Risk** | A compromised npm/crates.io/PyPI package introduces malicious code into the build. |
| **Probability** | Low-Medium |
| **Impact** | Critical — could compromise every user's device. |
| **Mitigation** | Strict dependency pinning. Automated vulnerability scanning (Dependabot/Snyk). SBOM generation. Minimal dependency footprint. Reproducible builds. Code review for dependency updates. |
| **Owner** | DevSecOps Architect |
| **Detection Method** | CI/CD vulnerability scanners. SBOM diffing between releases. |
| **Status** | **Mitigated — ongoing monitoring required** |

---

## RR-008: Stale Threat Intelligence Degrades Protection

| Field | Value |
|---|---|
| **Risk** | Users who remain offline for extended periods have outdated threat intelligence, missing new phishing campaigns and malware signatures. |
| **Probability** | Medium |
| **Impact** | Medium — reduced detection for new threats, but ML/heuristic layers still function. |
| **Mitigation** | Visual staleness indicators (yellow at >7 days, red at >30 days). ML models trained on behavioral patterns (not just signatures) remain effective. Automatic priority sync on reconnection. |
| **Owner** | Platform Architect |
| **Detection Method** | Staleness age tracking with UI warnings. |
| **Status** | **Mitigated — architecture handles graceful degradation** |

---

## RR-009: Scope Explosion Beyond MVP

| Field | Value |
|---|---|
| **Risk** | Attempting to build all 4 client platforms (mobile, desktop, browser extension, web dashboard) simultaneously causes resource spread and delays core detection engine quality. |
| **Probability** | High |
| **Impact** | High — nothing ships if everything is built at once. |
| **Mitigation** | Strict phased development roadmap. Phase 1-2 focus exclusively on the shared detection engine. Phase 3-6 deliver one platform at a time. Web dashboard is deferred. Each phase has clear exit criteria. |
| **Owner** | Lead Architect |
| **Detection Method** | Phase gate reviews. Exit criteria enforcement. |
| **Status** | **Mitigated — roadmap enforces sequencing** |

---

## RR-010: Browser Extension MV3 Execution Limits

| Field | Value |
|---|---|
| **Risk** | Manifest V3 Service Workers have a 5-minute execution limit. Complex ML inference or large WASM module loading may be interrupted. |
| **Probability** | Medium |
| **Impact** | Medium — extension may fail to complete analysis for complex pages. |
| **Mitigation** | Keep WASM models small (<10MB). Use persistent WASM module caching via IndexedDB. Implement fast-path rule analysis that completes in <100ms. Offload heavy analysis to native messaging with desktop app (if installed). Fast-path WASM (<0.85ms) and session rehydration (<8ms) formalized in `docs/BROWSER_TECHNICAL_ARCHITECTURE.md`. |
| **Owner** | Browser Extension Architect |
| **Detection Method** | Service Worker lifecycle testing. Cold-start benchmarking. |
| **Status** | **Mitigated — architecture formalized in BROWSER_TECHNICAL_ARCHITECTURE.md** |

---

## RR-011: Privacy Compliance Across Jurisdictions

| Field | Value |
|---|---|
| **Risk** | GDPR, CCPA, and emerging privacy regulations may impose requirements that conflict with product features (e.g., data retention, right to explanation). |
| **Probability** | Low |
| **Impact** | Medium — legal liability if non-compliant. |
| **Mitigation** | Privacy-by-design architecture (no user data on servers). Local-only processing satisfies most regulations by default. Transparent privacy policy. "Clear All Data" feature. Legal review before each market launch. |
| **Owner** | Privacy Architect |
| **Detection Method** | Privacy impact assessment per jurisdiction. |
| **Status** | **Mitigated — architecture is inherently privacy-compliant** |

---

## RR-012: Adversarial ML Evasion

| Field | Value |
|---|---|
| **Risk** | Attackers study the detection models and craft adversarial inputs (e.g., slightly modified phishing pages, obfuscated URLs) that evade ML classifiers. |
| **Probability** | Medium |
| **Impact** | Medium — specific attacks may bypass ML layer. |
| **Mitigation** | Ensemble models (multiple classifiers must agree). Adversarial training during model development. Deterministic rules as backstop. Frequent model updates to stay ahead of evasion techniques. |
| **Owner** | AI/ML Architect |
| **Detection Method** | Adversarial robustness benchmarks. Red team exercises with ML evasion tools. |
| **Status** | **Open — ongoing arms race; deterministic rules serve as immutable backstop** |

---

## RR-013: Latency Budget Exceeded on Low-End Devices

| Field | Value |
|---|---|
| **Risk** | On-device ML inference exceeds latency targets on older or budget mobile devices, causing visible delays in warnings. |
| **Probability** | Medium |
| **Impact** | Low-Medium — degraded user experience, but functionality preserved. |
| **Mitigation** | Graceful degradation: fall back to rules+heuristics only on slow hardware. Detect device capability at startup and adjust pipeline. Skip SLM explanation generation on slow devices (use templates). |
| **Owner** | Performance Architect |
| **Detection Method** | Device-class benchmarking matrix. Opt-in latency telemetry. |
| **Status** | **Mitigated — degradation strategy defined** |

---

## RR-014: Factory Seed Bloom Filter Staleness

| Field | Value |
|---|---|
| **Risk** | Newly installed air-gapped devices running factory seed Bloom filters older than 90 days incur excessive false positive penalties. |
| **Probability** | Low |
| **Impact** | Medium — user alert fatigue. |
| **Mitigation** | Factory seed filters do not apply staleness penalties until 30 days post-installation epoch. Deterministic structural rules and brand Levenshtein analyzers remain at 100% sensitivity regardless of filter age. |
| **Owner** | Threat Intel Engineer |
| **Detection Method** | Air-gapped offline test suite (Tier 5). |
| **Status** | **Mitigated — resolved in docs/OFFLINE_ARCHITECTURE.md** |

---

## RR-015: Indirect Prompt Injection via Analyzed Target Content

| Field | Value |
|---|---|
| **Risk** | Adversary injects malicious instructions inside scam text or HTML trying to force the local AI Assistant to declare the threat safe. |
| **Probability** | High |
| **Impact** | Critical if unmitigated. |
| **Mitigation** | Raw content treated strictly as passive data. AI Assistant receives only tokenized Evidence structs generated by deterministic layers. AI has zero authority to alter risk score. Grammar-Constrained Decoding (CFG) restricts output strictly to JSON schema. |
| **Owner** | AI/ML Security Engineer |
| **Detection Method** | Adversarial jailbreak corpus (Tier 9 tests: 500 prompts; 0% bypass). |
| **Status** | **Mitigated — verified in docs/AI_ASSISTANT_CONTRACT.md and RED_TEAM_AUDIT_REPORT.md** |

