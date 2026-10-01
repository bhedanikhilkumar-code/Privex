# PRIVATE PROTECTION

> Privacy-first, on-device AI security assistant for threat, phishing, scam, and suspicious-content detection.

PRIVATE PROTECTION is a unified security platform intended to provide local-first protection across mobile, desktop, browser, and web experiences while minimizing sensitive-data transmission.

> **Project memory:** This README keeps the core project context in one place so future agents do not need the same requirements repeated. `AGENTS.md` remains the canonical engineering/governance instruction file.

---

## 1. Original PS-05 Problem Statement

**On-device threat, phishing and scam detection**

Develop an on-device AI security assistant that can detect phishing links, scam messages, malicious content, and suspicious communications in real time without sending sensitive user data to the cloud. The solution should provide instant warnings and clear explanations to help users recognize and avoid potential cyber threats while maintaining privacy, low latency, and offline functionality.

### The 11 direct requirements

1. **On-device AI security assistant** — the security assistant and core detection should operate locally wherever technically feasible.
2. **Phishing link detection** — identify suspicious or malicious URLs and links.
3. **Scam message detection** — detect scam, fraud, impersonation, and social-engineering messages.
4. **Malicious content detection** — identify harmful or suspicious content.
5. **Suspicious communication detection** — analyze suspicious communications using layered detection.
6. **Real-time detection** — provide detection quickly enough for real-time protection flows.
7. **Privacy** — sensitive user data must not be sent to cloud/server by default.
8. **Instant warning** — warn the user when a credible threat is detected.
9. **Clear explanation** — explain why something was considered suspicious and what the user can safely do next.
10. **Offline functionality** — core detection must continue to work without internet connectivity.
11. **Low latency** — critical detection paths must have measurable, low latency.

---

## 2. Complete Product Vision

PRIVATE PROTECTION is **not only a website and not only an AI chatbot**. The intended product is a coordinated security platform containing:

- **Mobile App** — Android first in the practical implementation path, with iOS architecture considered where platform capabilities permit.
- **Desktop Security Software** — Windows/macOS security client for local scanning and desktop protection capabilities.
- **Browser Extension** — phishing/URL protection and browser-side warnings.
- **Web Application** — zero-install analysis, dashboard/education, and user-facing security workflows that can operate client-side where possible.
- **Shared Detection Engine** — common local detection contracts, analyzers, rules, risk aggregation, evidence, and explanations.
- **AI/ML Layer** — on-device models and AI assistant runtime, used as one layer rather than the sole security authority.
- **Optional Backend** — only for capabilities that genuinely require remote infrastructure, such as privacy-preserving updates or selected threat-intelligence services.
- **Threat Intelligence Layer** — locally usable threat data, updates, reputation information, and verified allowlists.
- **Secure Update System** — authenticated, integrity-checked, versioned updates for application components, rules, threat intelligence, and models.

### Platform responsibility at a glance

| Platform | Main responsibility |
|---|---|
| **Android/Mobile** | Local threat analysis, supported message/content workflows, QR/link scanning, notifications, security assistant, local history/settings |
| **Windows/macOS Desktop** | Local file/download scanning, desktop monitoring capabilities supported by the OS, security events, offline protection |
| **Browser Extension** | URL/page signals, phishing detection, pre-navigation warnings where technically supported, local browser protection |
| **Web App** | Manual URL/content analysis, dashboard, explanations, education, client-side/offline capabilities where technically supported |
| **Shared Core** | Normalization, rules, analyzers, evidence, risk aggregation, detection contracts, explanations |
| **AI/ML** | Local classification/assistant capabilities, evidence-based explanations, prompt-injection-resistant assistance |
| **Backend** | Optional privacy-preserving services and updates; never the default dumping ground for sensitive user content |

Platform limitations must always be respected. The project must not claim OS/browser capabilities that the target platform does not actually provide.

---

## 3. Core Detection Flow

The intended security flow is:

```text
User / Browser / App / Desktop Input
                ↓
        Input Normalization
                ↓
      Deterministic Analysis
                ↓
       Heuristic / Rule Layer
                ↓
     Reputation / Threat Intel
                ↓
          ML / AI Layer
                ↓
        Risk Aggregation
                ↓
       Evidence + Confidence
                ↓
        Decision / Assessment
                ↓
      Alert + Clear Explanation
                ↓
       Safe User Next Action
```

The AI assistant is **not** the sole detector. Security decisions must be based on layered evidence and deterministic controls where appropriate.

---

## 4. Questions That Must Always Be Answered

Every implementation that affects detection or privacy must be traceable to these questions:

- **Kya detect karenge?** — What exact threat/content class is being detected?
- **Kahan detect karenge?** — Which platform/component performs the detection?
- **Kaise detect karenge?** — Which rules, heuristics, reputation data, models, and evidence are involved?
- **Kaunsa data device se bahar kabhi nahi jayega?** — Which data is strictly local and prohibited from transmission?
- **Threat detect hone par exactly kya hoga?** — What warning, explanation, evidence, and safe action are shown?
- **False positive kaise handle hoga?** — How are uncertain/incorrect detections handled, tested, and corrected?
- **Offline mode mein kya chalega?** — Which detection and safety functions remain operational without internet?
- **Internet available hone par kya additional capability milegi?** — What genuinely requires connectivity and what data, if any, leaves the device?
- **Android/Windows/browser ki limitations kya hain?** — What can each platform actually permit, and what fallback is used when a capability is unavailable?

These questions are project-wide acceptance criteria, not optional documentation questions.

---

## 5. Architecture / Development Order

The project follows this dependency-aware order:

```text
1. Problem Requirements
        ↓
2. Feature Specification
        ↓
3. Threat Model
        ↓
4. Platform Strategy
        ↓
5. System Architecture
        ↓
6. AI/ML Architecture
        ↓
7. Privacy & Security Architecture
        ↓
8. Database / API Architecture
        ↓
9. UI/UX Flow
        ↓
10. Testing Strategy
        ↓
11. Development Plan
        ↓
12. CODING
```

The architecture/pre-coding work is represented by `AGENTS.md`, `agents/`, and the authoritative documents under `docs/`.

---

## 6. Subagent / Agent Model

The project uses a **Master Orchestrator + specialist subagents** model.

The Master Agent owns planning, dependency management, scope control, integration, verification, and final completion decisions. Specialist agents work within explicit responsibilities and file ownership boundaries.

Important specialist responsibilities include:

| Agent | Main responsibility |
|---|---|
| Product/Requirements | Exact product requirements and acceptance criteria |
| Threat Intelligence | Phishing/scam/malware threat intelligence |
| Cybersecurity Architect | Overall security architecture |
| AI/ML | On-device detection models and AI runtime |
| Privacy | Local processing and data minimization |
| Platform | Android, Windows/macOS, browser, and platform constraints |
| Backend/API | APIs and optional cloud services |
| Frontend/UI | User flows, dashboard, warnings |
| Detection Engine | Shared detection engine and risk pipeline |
| QA/Test | Detection, integration, security, privacy, regression testing |
| DevSecOps | Packaging, CI/CD, supply-chain controls |
| Performance | Latency, memory, battery, and performance regression |
| Security Auditor | Independent security/red-team verification |
| Integration/Release | Cross-platform integration and release verification |

The agent count is **dynamic**. Do not blindly run every specialist in parallel. Parallel work is allowed only when file ownership and dependencies make it safe.

---

## 7. Non-Negotiable Privacy & Security Rules

- Local-first and privacy-first by default.
- Sensitive user content must not leave the device unless an explicitly justified, documented, user-aware architecture requires it.
- Treat URLs, messages, webpages, files, and external API responses as untrusted data.
- Never allow analyzed content to silently become instructions for the AI assistant.
- AI cannot arbitrarily override security policy.
- Never hardcode secrets or API keys.
- Never disable security controls just to make tests pass.
- Never swallow security-critical errors.
- Never claim protection that the platform cannot technically provide.
- Detection results must represent uncertainty where appropriate.
- Updates must be authenticated and integrity-checked.
- Logs/telemetry must be scrubbed so they do not become an accidental data-exfiltration channel.

---

## 8. Coding Governance

Production coding must follow the repository's architecture, contracts, ownership, tests, and dependency graph.

A feature is **not done** merely because a file exists or code compiles. Completion requires implementation evidence, relevant tests, security/privacy review where applicable, documentation updates, and successful verification.

No fake success:

- no skipped tests presented as passing,
- no weakened tests merely to obtain green CI,
- no mocks presented as production capability,
- no swallowed failures,
- no hardcoded demo behavior presented as a real detector.

---

## 9. Current Implementation Status

The repository is **already beyond pure pre-coding documentation**.

The current `main` branch contains an implemented shared detection package at `packages/core`, including deterministic rules, URL analysis, text/message analysis, risk scoring, explanations, threat-intelligence caching, and a detection pipeline, with an accompanying Vitest test suite and benchmark dataset.

The repository history records the shared core implementation before the later architecture/red-team audit commits. Therefore, the old wording in the readiness checklist that says “zero production application code has been written in this phase” describes the architecture-audit phase, not the current repository state.

### Current practical position

```text
PHASE 0 — Architecture / contracts / governance     COMPLETE
                 ↓
PHASE 1 — Shared Detection Foundation               IMPLEMENTED
                 ↓
NEXT     — Phase 2 reconciliation + implementation
                 ↓
PHASE 3 — AI/ML inference + assistant runtime
                 ↓
PHASE 4 — Web application
                 ↓
PHASE 5 — Browser extension
                 ↓
PHASE 6 — Mobile application
                 ↓
PHASE 7 — Desktop security software
                 ↓
PHASE 8 — Cross-platform integration
                 ↓
PHASE 9 — Security hardening
                 ↓
PHASE 10 — Performance optimization
                 ↓
PHASE 11 — Full verification / release
```

**Important:** Before starting the next implementation phase, reconcile the existing `packages/core` implementation with the Phase 2 contracts/roadmap. Some Phase 2 concepts (rules and a threat-intelligence cache) already exist in the current core, so the next agent must extend or harden the existing implementation rather than blindly duplicate it.

---

## 10. Authoritative Documentation

- [`AGENTS.md`](./AGENTS.md) — canonical project-wide agent and engineering rules
- [`docs/PROJECT_REQUIREMENTS.md`](./docs/PROJECT_REQUIREMENTS.md) — requirements
- [`docs/PRODUCT_SCOPE.md`](./docs/PRODUCT_SCOPE.md) — product boundaries
- [`docs/PLATFORM_RESPONSIBILITY_MATRIX.md`](./docs/PLATFORM_RESPONSIBILITY_MATRIX.md) — platform responsibilities
- [`docs/SYSTEM_ARCHITECTURE.md`](./docs/SYSTEM_ARCHITECTURE.md) — system architecture
- [`docs/TECHNICAL_ARCHITECTURE.md`](./docs/TECHNICAL_ARCHITECTURE.md) — detailed technical architecture
- [`docs/DETECTION_ARCHITECTURE.md`](./docs/DETECTION_ARCHITECTURE.md) — detection engine
- [`docs/AI_ML_ARCHITECTURE.md`](./docs/AI_ML_ARCHITECTURE.md) — AI/ML architecture
- [`docs/AI_ASSISTANT_CONTRACT.md`](./docs/AI_ASSISTANT_CONTRACT.md) — AI assistant contract
- [`docs/PRIVACY_ARCHITECTURE.md`](./docs/PRIVACY_ARCHITECTURE.md) — privacy architecture
- [`docs/SECURITY_ARCHITECTURE.md`](./docs/SECURITY_ARCHITECTURE.md) — security architecture
- [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) — threat model
- [`docs/DATA_ARCHITECTURE.md`](./docs/DATA_ARCHITECTURE.md) — data architecture
- [`docs/DATA_BOUNDARIES.md`](./docs/DATA_BOUNDARIES.md) — data boundaries
- [`docs/USER_FLOW_SPECIFICATION.md`](./docs/USER_FLOW_SPECIFICATION.md) — user flows
- [`docs/OFFLINE_ARCHITECTURE.md`](./docs/OFFLINE_ARCHITECTURE.md) — offline behavior
- [`docs/ONLINE_ARCHITECTURE.md`](./docs/ONLINE_ARCHITECTURE.md) — online behavior
- [`docs/UPDATE_SECURITY_ARCHITECTURE.md`](./docs/UPDATE_SECURITY_ARCHITECTURE.md) — secure updates
- [`docs/TEST_ARCHITECTURE.md`](./docs/TEST_ARCHITECTURE.md) — testing architecture
- [`docs/DEVELOPMENT_ROADMAP.md`](./docs/DEVELOPMENT_ROADMAP.md) — implementation phases
- [`docs/IMPLEMENTATION_DEPENDENCY_GRAPH.md`](./docs/IMPLEMENTATION_DEPENDENCY_GRAPH.md) — dependency graph
- [`docs/SUBAGENT_ORCHESTRATION.md`](./docs/SUBAGENT_ORCHESTRATION.md) — subagent governance
- [`docs/MASTER_TRACEABILITY_MATRIX.md`](./docs/MASTER_TRACEABILITY_MATRIX.md) — requirement-to-test traceability
- [`docs/CODING_READINESS_CHECKLIST.md`](./docs/CODING_READINESS_CHECKLIST.md) — readiness audit
- [`docs/RED_TEAM_AUDIT_REPORT.md`](./docs/RED_TEAM_AUDIT_REPORT.md) — red-team audit
- [`docs/FINAL_ARCHITECTURE_SCORECARD.md`](./docs/FINAL_ARCHITECTURE_SCORECARD.md) — architecture scorecard

---

## 11. Existing Shared Detection Core

The shared detection engine is implemented in `@private-protection/core`:

- **Deterministic Rule Engine** (`src/rules/rule-engine.ts`): URL patterns, suspicious TLDs, IP hosts, scheme misuse, urgent scam cues, and financial-fraud indicators.
- **URL Analyzer** (`src/analyzers/url-analyzer.ts`): lexical feature extraction, Shannon entropy, Levenshtein brand-typosquatting detection, subdomain brand spoofing, punycode/IDN detection, and credential masking.
- **Text / Message Analyzer** (`src/analyzers/text-analyzer.ts`): urgent pressure tactics, crypto extortion/ransomware, law-enforcement impersonation, lottery-fee scams, and family-emergency scams.
- **Weighted Risk Scorer** (`src/scoring/risk-scorer.ts`): multi-factor risk aggregation, confidence calculation, severity mapping, and layer disagreement handling.
- **Explanation Engine** (`src/explanation/explanation-engine.ts`): human-readable explanations and actionable recommendations.
- **Threat Intelligence Cache** (`src/threat-intel/threat-intel.ts`): in-memory SHA-256 hash lookup with allowlist precedence and TTL staleness tracking.
- **Detection Pipeline Orchestrator** (`src/pipeline/detection-pipeline.ts`): end-to-end multi-modal analysis returning structured detection results.

---

## 12. Verification & Metrics Currently Documented in the Repository

```bash
# Build TypeScript packages
npm run build

# Run Vitest test suite
npm test

# Run test suite with V8 coverage report
npm run test:coverage --workspace=@private-protection/core
```

The existing README/Phase 1 benchmark reports 100 curated samples and 69/69 unit tests passing. These are **repository-reported measurements**, not a guarantee for future versions; every subsequent change must rerun the relevant tests and benchmarks.

---

## 13. Rule for Future Agents

Before changing code, every agent must:

1. Read `AGENTS.md`.
2. Read the relevant architecture and contract documents.
3. Inspect the existing implementation instead of duplicating it.
4. Identify the exact phase/task being executed.
5. Respect file ownership and dependency boundaries.
6. Add regression tests with implementation changes.
7. Run relevant tests and report actual evidence.
8. Update documentation when architecture/contracts change.
9. Never claim completion without verification.
10. Ask the Master Orchestrator to resolve cross-cutting architectural conflicts.

**This README is the persistent project-context summary. `AGENTS.md` is the canonical rulebook. The architecture documents are the authoritative technical sources.**
