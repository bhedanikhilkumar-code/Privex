# PRIVATE PROTECTION

> Privacy-First, On-Device AI Security Assistant for Threat, Phishing, and Scam Detection.

PRIVATE PROTECTION delivers real-time, on-device threat detection without transmitting sensitive user data to the cloud.

---

## Architecture Documentation

Comprehensive Phase 0 architecture documentation is available in [`docs/`](./docs/):

- [`PROJECT_REQUIREMENTS.md`](./docs/PROJECT_REQUIREMENTS.md) — Requirements specification
- [`PRODUCT_SCOPE.md`](./docs/PRODUCT_SCOPE.md) — Product boundaries and platform scope
- [`PLATFORM_RESPONSIBILITY_MATRIX.md`](./docs/PLATFORM_RESPONSIBILITY_MATRIX.md) — Responsibility matrix
- [`SYSTEM_ARCHITECTURE.md`](./docs/SYSTEM_ARCHITECTURE.md) — High-level system architecture
- [`DETECTION_ARCHITECTURE.md`](./docs/DETECTION_ARCHITECTURE.md) — 7-layer detection engine & risk scoring
- [`AI_ML_ARCHITECTURE.md`](./docs/AI_ML_ARCHITECTURE.md) — On-device AI/ML models & prompt injection defense
- [`PRIVACY_ARCHITECTURE.md`](./docs/PRIVACY_ARCHITECTURE.md) — 3-tier data classification & encryption
- [`SECURITY_ARCHITECTURE.md`](./docs/SECURITY_ARCHITECTURE.md) — Product self-defense & code signing
- [`THREAT_MODEL.md`](./docs/THREAT_MODEL.md) — STRIDE threat model (15 modeled threats)
- [`DATA_ARCHITECTURE.md`](./docs/DATA_ARCHITECTURE.md) — Schemas & data separation
- [`BACKEND_ARCHITECTURE.md`](./docs/BACKEND_ARCHITECTURE.md) — Optional cloud backend
- [`USER_FLOW_SPECIFICATION.md`](./docs/USER_FLOW_SPECIFICATION.md) — 10 user interaction flows
- [`OFFLINE_FIRST_ARCHITECTURE.md`](./docs/OFFLINE_FIRST_ARCHITECTURE.md) — Offline-first capabilities
- [`PERFORMANCE_REQUIREMENTS.md`](./docs/PERFORMANCE_REQUIREMENTS.md) — Real-time performance targets
- [`TESTING_STRATEGY.md`](./docs/TESTING_STRATEGY.md) — Multi-tier QA strategy
- [`DEVELOPMENT_ROADMAP.md`](./docs/DEVELOPMENT_ROADMAP.md) — 10-phase roadmap
- [`REPOSITORY_ARCHITECTURE.md`](./docs/REPOSITORY_ARCHITECTURE.md) — Monorepo structure
- [`SUBAGENT_ORCHESTRATION.md`](./docs/SUBAGENT_ORCHESTRATION.md) — Subsystem ownership & delegation
- [`DECISION_REGISTER.md`](./docs/DECISION_REGISTER.md) — 12 architectural decisions
- [`RISK_REGISTER.md`](./docs/RISK_REGISTER.md) — 13 identified risks & mitigations
- [`ARCHITECTURE_REVIEW.md`](./docs/ARCHITECTURE_REVIEW.md) — Consolidation & review

---

## Phase 1: Core Detection Engine (`packages/core`)

The shared detection engine is implemented in `@private-protection/core`:

- **Deterministic Rule Engine** (`src/rules/rule-engine.ts`): URL patterns, suspicious TLDs, IP hosts, scheme misuse, urgent scam cues, financial fraud keywords.
- **URL Analyzer** (`src/analyzers/url-analyzer.ts`): Lexical feature extraction, Shannon entropy, Levenshtein distance brand typosquatting, subdomain brand spoofing, punycode/IDN detection, credential masking.
- **Text / Message Analyzer** (`src/analyzers/text-analyzer.ts`): Urgent pressure tactics, crypto extortion / ransomware, law enforcement impersonation, lottery fees, family emergency scams.
- **Weighted Risk Scorer** (`src/scoring/risk-scorer.ts`): Multi-factor risk aggregation, confidence calculation, severity mapping, layer disagreement resolution.
- **Explanation Engine** (`src/explanation/explanation-engine.ts`): Jargon-free, human-readable explanations with actionable recommendations.
- **Threat Intelligence Cache** (`src/threat-intel/threat-intel.ts`): In-memory SHA-256 hash lookup with allowlist precedence and TTL staleness tracking.
- **Detection Pipeline Orchestrator** (`src/pipeline/detection-pipeline.ts`): End-to-end multi-modal analysis returning structured `DetectionResult`.

---

## Verification & Metrics

```bash
# Build TypeScript packages
npm run build

# Run Vitest test suite
npm test

# Run test suite with V8 coverage report
npm run test:coverage --workspace=@private-protection/core
```

### Benchmark Results (100 Curated Real-World Samples)
- **Total Samples Evaluated:** 100 (50 Malicious, 50 Benign)
- **Detection Accuracy:** 100.00%
- **False Positive Rate:** 0.00% (0 false positives on legitimate sites)
- **Precision:** 100.00%
- **Recall:** 100.00%
- **F1 Score:** 1.0000
- **Latency p50:** 0.13 ms (130 microseconds)
- **Latency p95:** 0.72 ms (720 microseconds)

### Code Coverage
- **Statements:** 97.49%
- **Lines:** 98.5%
- **Branches:** 94.05%
- **Functions:** 94.87%
- **Unit Tests:** 69 / 69 Passed across 9 test files
