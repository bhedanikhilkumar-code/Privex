# PHASE_2_EXISTING_CORE_INVENTORY.md — Packages/Core Component Inventory

> **SYSTEM STATUS: PHASE 2 IMPLEMENTATION**  
> **CANONICAL INVENTORY — EXISTING SHARED DETECTION ENGINE**  
> Monitored directory: `packages/core/src/`  
> Baseline Date: 2026-10-02  
> Baseline Test Status: 69/69 passing tests, 97.49% statement coverage, 100% benchmark accuracy.

---

## 1. INVENTORY OVERVIEW

| Component Name | File Path | Core Responsibility | Public Interface | Dependencies | Test File | Phase 2 Action |
|---|---|---|---|---|---|---|
| **Domain Models & Enums** | `src/types.ts` | Type definitions for risk categories, severities, evidence, requests, results | `RiskCategory`, `Severity`, `Confidence`, `InputType`, `ActionRecommendation`, `Evidence`, `DetectionResult`, `ScanRequest` | None | Implicit across all tests | **KEEP & EXPAND**: Reconcile with canonical contracts in `docs/DOMAIN_MODELS.md` and `docs/INTERFACE_CONTRACTS.md` |
| **Detection Pipeline** | `src/pipeline/detection-pipeline.ts` | Multi-stage scan orchestration, input validation, analyzer coordination | `DetectionPipeline`, `scan(request: ScanRequest): Promise<DetectionResult>` | `RuleEngine`, `URLAnalyzer`, `TextAnalyzer`, `RiskScorer`, `ExplanationEngine`, `ThreatIntel`, `uuidv4` | `src/__tests__/pipeline/detection-pipeline.test.ts` | **KEEP & HARDEN**: Add AnalysisContext, timing, error resilience, fail-closed handling, allowlist precedence |
| **Rule Engine** | `src/rules/rule-engine.ts` | Fast-path deterministic regex and structural rule evaluation | `RuleEngine`, `Rule`, `RuleMatch`, `RuleEvaluationResult`, `evaluateAll`, `evaluateUrl`, `evaluateText` | `types` | `src/__tests__/rules/rule-engine.test.ts` | **KEEP & HARDEN**: Expand structural indicators, enforce linear-time regexes (ReDoS safe), input byte limits |
| **URL Analyzer** | `src/analyzers/url-analyzer.ts` | Lexical parsing, entropy, Levenshtein typosquatting, TLD checks, IP checks | `URLAnalyzer`, `UrlAnalyzer`, `URLFeatures`, `URLAnalysisResult`, `analyze(urlInput)` | `calculateEntropy`, `levenshteinDistance` | `src/__tests__/analyzers/url-analyzer.test.ts` | **KEEP & HARDEN**: IPv6/octal/hex IP evasion, private IP ranges/SSRF, homoglyph parsing, dangerous ports, length clamping |
| **Text Analyzer** | `src/analyzers/text-analyzer.ts` | Natural language heuristic parsing, scam patterns, extortion, impersonation | `TextAnalyzer`, `TextAnalysisResult`, `analyze(text)` | `types` | `src/__tests__/analyzers/text-analyzer.test.ts` | **KEEP & HARDEN**: Expand scam categories (delivery, tech support invoice, crypto recovery), false positive shields, zero-width stripping |
| **Risk Scorer / Aggregator** | `src/scoring/risk-scorer.ts` | Evidence weighting, risk score aggregation, severity and action mapping | `RiskScorer`, `ScoreResult`, `calculate(evidence)`, `calculateScore(evidence)` | `types` | `src/__tests__/scoring/risk-scorer.test.ts` | **KEEP & HARDEN**: Implement canonical Bounded Non-Linear Diminishing-Returns model, staleness penalty, conflict resolution rules |
| **Explanation Engine** | `src/explanation/explanation-engine.ts` | Plain-language, evidence-based synthesis for user warnings | `ExplanationEngine`, `ExplanationResult`, `generate(...)`, `generateExplanation(...)` | `types` | `src/__tests__/explanation/explanation-engine.test.ts` | **KEEP & EXPAND**: Structure output to conform to `Explanation` contract (`headline`, `plainTextSummary`, `technicalDetails`, `recommendedSteps`, `confidenceLabel`) |
| **Threat Intelligence** | `src/threat-intel/threat-intel.ts` | Local-first hash lookup, domain allowlist/blocklist, TTL expiry, staleness | `ThreatIntel`, `ThreatIntelEntry`, `ThreatIntelResult`, `addMaliciousDomain`, `addAllowedDomain`, `checkHash`, `checkDomain`, `getStalenessDays` | `sha256`, `types` | `src/__tests__/threat-intel/threat-intel.test.ts` | **KEEP & HARDEN**: URL hash lookup, IP lookup, threat metadata, record versioning, Bloom filter support, updater validation integration |
| **Cryptographic Utilities** | `src/utils/crypto.ts` | SHA-256 hashing, UUIDv4 generation, Shannon entropy, Levenshtein distance | `uuidv4`, `isValidUUID`, `sha256`, `calculateEntropy`, `levenshteinDistance`, `CryptoUtils` | `node:crypto` | `src/__tests__/utils/crypto.test.ts` | **KEEP & EXPAND**: Add Ed25519 signature verification support for OTA update manifest verification |
| **Package Exports** | `src/index.ts` | Public API surface re-exports | All exported members from modules | All internal modules | Build & type tests | **KEEP & EXPAND**: Export new canonical interfaces and classes |

---

## 2. DETAILED COMPONENT AUDIT

### 2.1 `packages/core/src/types.ts`
- **Current Interfaces**: `RiskCategory`, `Severity`, `Confidence`, `InputType`, `ActionRecommendation`, `Evidence`, `DetectionResult`, `ScanRequest`.
- **Existing Tests**: Tested across all 9 test suites.
- **Contract Reference**: `docs/DOMAIN_MODELS.md` Models 1-11; `docs/INTERFACE_CONTRACTS.md`.
- **Phase 2 Status**: Validated baseline. Needs enrichment with canonical models (`DetectionRequest`, `Threat`, `RiskAssessment`, `Recommendation`, `AnalysisContext`, `SecurityEvent`, `ThreatIntelRecord`, `UpdateMetadata`, `Explanation`) while preserving all legacy fields for backwards compatibility.

### 2.2 `packages/core/src/rules/rule-engine.ts`
- **Current Implementation**: Implements default URL rules (`url-ip-based`, `url-suspicious-tld`, `url-data-uri`, `url-javascript-uri`, `url-excessive-subdomains`, `url-shortener`, `url-at-symbol`) and text rules (`text-urgency`, `text-financial-scam`, `text-threat`, `text-prize`, `text-advance-fee`).
- **Phase 2 Status**: Correct deterministic fast-path architecture. Needs input byte bounds, additional security indicators (e.g. dangerous schemes like `vbscript:`, `blob:`, credential obfuscation), and protection against regex backtracking.

### 2.3 `packages/core/src/analyzers/url-analyzer.ts`
- **Current Implementation**: Extracts 9 lexical features: domainLength, pathLength, subdomainCount, isHttps, isIpAddress, entropy, levenshteinScores, dotsCount, digitsToLettersRatio.
- **Phase 2 Status**: Needs enhancement for IPv6, octal/hex IP encodings, localhost / RFC1918 / link-local metadata addresses (SSRF), IDN homoglyphs beyond ASCII punycode, non-standard and dangerous port numbers, and URL length clamping to 2,048 bytes.

### 2.4 `packages/core/src/analyzers/text-analyzer.ts`
- **Current Implementation**: Tests for urgency, extortion, tech support scareware, legal threats, cryptocurrency, family impersonation, account verification, brand impersonation, lottery scam.
- **Phase 2 Status**: Needs input length clamping (10,000 chars), zero-width character stripping, delivery scam detection, tech support invoice scams, and false positive protection for legitimate bank and shipping alerts.

### 2.5 `packages/core/src/scoring/risk-scorer.ts`
- **Current Implementation**: Simple weighted maximum with linear bonus (`Math.min(100, Math.round(maxWeight + bonus))`).
- **Phase 2 Status**: Must be updated to implement the canonical Bounded Non-Linear Diminishing-Returns Aggregation Model specified in `docs/RISK_ENGINE_ARCHITECTURE.md`, while maintaining deterministic output and compatibility with existing tests.

### 2.6 `packages/core/src/explanation/explanation-engine.ts`
- **Current Implementation**: Generates readable string explanation and action recommendation.
- **Phase 2 Status**: Must return full `Explanation` structured record conforming to `docs/INTERFACE_CONTRACTS.md` Subsystem 11, while preserving `toString()` and string returns for backwards compatibility.

### 2.7 `packages/core/src/threat-intel/threat-intel.ts`
- **Current Implementation**: In-memory SHA-256 hash lookup of domains with TTL and staleness tracking.
- **Phase 2 Status**: Needs full URL hash lookups, IP address lookups, rich threat metadata, threat database versioning, allowlist vs blocklist precedence, and pairing with `ThreatIntelUpdater` for atomic signed updates.

### 2.8 `packages/core/src/utils/crypto.ts`
- **Current Implementation**: `uuidv4`, `isValidUUID`, `sha256`, `calculateEntropy`, `levenshteinDistance`.
- **Phase 2 Status**: Add Ed25519 signature verification utility using native `crypto.verify` (Node.js/Web Crypto compatible) to enable cryptographic OTA update validation.

---

## 3. DECISION SUMMARY

- **Keep and Harden**: All 9 existing components are foundational, well-architected, and have passing tests.
- **No Deletions**: No component is deprecated or deleted.
- **Additive Expansion**: All canonical domain models and contracts from Phase 0 are incorporated via additive, non-breaking interfaces.
