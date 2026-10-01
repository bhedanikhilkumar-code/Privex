# AGENTS.md — The Project Constitution & Autonomous Agent Operating Manual

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL INSTRUCTION DOCUMENT FOR ALL AI AGENTS & SUBAGENTS**  
> Every agent, subagent, and human engineer must read and comply with this document before planning, modifying, or executing tasks within the **PRIVATE PROTECTION** project.

---

## 1. PROJECT IDENTITY

- **Project Name:** PRIVATE PROTECTION
- **Project Category:** Privacy-First Cybersecurity & Digital-Threat Protection Platform
- **Problem Statement Code:** PS-05
- **Primary Goal:** Detect and help users understand phishing links, scam messages, malicious content, and suspicious communications in real time with local/on-device processing wherever technically feasible.
- **Foundational Doctrine:** **LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

---

## 2. ORIGINAL PROBLEM STATEMENT (PS-05)

> *"On-device threat, phishing and scam detection.*
>
> *Develop an on-device AI security assistant that can detect phishing links, scam messages, malicious content, and suspicious communications in real time without sending sensitive user data to the cloud.*
>
> *The solution should provide instant warnings and clear explanations to help users recognize and avoid potential cyber threats while maintaining privacy, low latency, and offline functionality."*

---

## 3. THE 11 CORE REQUIREMENTS

Every subsystem, interface, and test in PRIVATE PROTECTION must directly serve and trace back to these eleven mandatory capabilities:

1. **On-Device AI Security Assistant:** A local Small Language Model (SLM) or deterministic template engine that translates technical threat telemetry into actionable, jargon-free explanations directly on the user's endpoint.
2. **Phishing Link Detection:** Lexical feature analysis, Shannon entropy, brand typosquatting distance, Punycode/IDN homograph parsing, and local Bloom filter lookups to detect deceptive URLs before interaction.
3. **Scam Message Detection:** Natural language and heuristic parsing of inbound text messages to identify urgency pressure tactics, cryptocurrency extortion, advance-fee fraud, and impersonation.
4. **Malicious Content Detection:** Inspection of web DOM structures (insecure password fields, deceptive form action targets) and local file headers/executables.
5. **Suspicious Communication Detection:** Multi-signal correlation (unknown sender + urgent demand + suspicious link + payment request) executed in volatile RAM.
6. **Real-Time Detection:** Fast-path execution providing detection verdicts in under $1.0\text{ ms}$ on local rules and $<100\text{ ms}$ on full heuristic pipelines.
7. **Privacy-First Processing:** Sensitive user content (URLs, messages, files) is mathematically kept on-device. No telemetry containing raw user payloads is ever transmitted off-device.
8. **Instant Warnings:** Visually unambiguous, color-coded modal and notification warnings rendered in $<50\text{ ms}$ upon threat identification.
9. **Clear Explanations:** Human-readable explanations formatted at a cognitive reading grade below Grade 8, clearly explaining *why* something is dangerous and *what* action to take.
10. **Offline Functionality:** 100% core detection parity when operating completely air-gapped without an active internet connection.
11. **Low Latency:** Zero-allocation algorithms, $O(1)$ hash table lookups, and compiled WebAssembly/native execution ensuring zero noticeable impact on user device responsiveness.

---

## 4. COMPLETE PRODUCT VISION & ARCHITECTURE TOPOLOGY

PRIVATE PROTECTION is an integrated, multi-platform cybersecurity platform—not a single website or isolated script. The ecosystem consists of:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                CLIENT PLATFORMS                                 │
│                                                                                 │
│   ┌──────────────┐     ┌──────────────┐    ┌──────────────┐     ┌───────────┐   │
│   │  MOBILE APP  │     │   DESKTOP    │    │   BROWSER    │     │  WEB APP  │   │
│   │ (iOS/Android)│     │(Windows/macOS│    │  EXTENSION   │     │ (Next.js) │   │
│   └──────┬───────┘     └──────┬───────┘    └──────┬───────┘     └─────┬─────┘   │
└──────────┼────────────────────┼───────────────────┼───────────────────┼─────────┘
           │                    │                   │                   │
           └────────────────────┼───────────────────┴───────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                  SHARED CORE DETECTION ENGINE (@private-protection/core)        │
│                                                                                 │
│   ┌────────────────────┐   ┌─────────────────────┐   ┌──────────────────────┐   │
│   │ Deterministic Rule │   │ Lexical & Heuristic │   │   Hash-Based Threat  │   │
│   │   Engine (Regex)   │   │ Analyzers (URL/Text)│   │  Intelligence Cache  │   │
│   └─────────┬──────────┘   └──────────┬──────────┘   └──────────┬───────────┘   │
│             │                         │                         │               │
│             └─────────────────────────┼─────────────────────────┘               │
│                                       ▼                                         │
│                      ┌─────────────────────────────────┐                        │
│                      │   Risk Scoring & Aggregation    │                        │
│                      │     (Weighted Math Engine)      │                        │
│                      └────────────────┬────────────────┘                        │
└───────────────────────────────────────┼─────────────────────────────────────────┘
                                        │
           ┌────────────────────────────┴────────────────────────────┐
           ▼                                                         ▼
┌───────────────────────────────────────┐ ┌───────────────────────────────────────┐
│    ON-DEVICE AI/ML LAYER & ASSISTANT  │ │   ENCRYPTED LOCAL STORAGE & STATE     │
│  • Quantized Intent Classifiers       │ │  • SQLite with SQLCipher / Web Crypto │
│  • Read-Only Explanation Synthesizer  │ │  • Local Custom Allowlists            │
│  • Strict Prompt Injection Containment│ │  • Zero-Knowledge Scan History        │
└───────────────────────────────────────┘ └───────────────────────────────────────┘
                                        ▲
                                        │ (Cryptographically Signed OTA Diffs)
┌───────────────────────────────────────┴─────────────────────────────────────────┐
│                 OPTIONAL BACKEND & CLOUD SERVICES (Stateless CDN)               │
│  • Threat Feed Aggregator (Compiles public blocklists into <5MB Bloom filters)  │
│  • Differential OTA Update Server (Ed25519-signed bsdiff delta patches)         │
│  • Oblivious HTTP (OHTTP) Privacy Relay (IP-scrubbed aggregated telemetry)      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. PLATFORM RESPONSIBILITY MATRIX

| Platform Host | Primary Responsibilities | Data Ingestion Vector | Offline Capability | Privilege Level |
|---|---|---|---|---|
| **Mobile App (Android/iOS)** | Inbound SMS/notification threat filtering, live camera QR scanning, screenshot analysis, push notifications, local SLM explanations. | OS Notification Listener, SMS Filter Extension, Share Target intent. | **100% Offline** | Standard user permissions (`CAMERA`, `NOTIFICATION_LISTENER`). |
| **Desktop Software (Win/Mac)** | Background download directory monitoring, local file header/entropy analysis, secure quarantine vault, tray UI. | Filesystem hooks (`ReadDirectoryChangesW`, `FSEvents`), manual drag-and-drop. | **100% Offline** | Standard user filesystem access. Authenticated local IPC daemon. |
| **Browser Extension (MV3)** | Pre-navigation URL interceptor, malicious redirect blocking, DOM password input shielding, full-page warning interstitial. | WebNavigation API, DeclarativeNetRequest, Content Script Shadow DOM injection. | **100% Offline** | Browser WebExtension permissions (`webNavigation`, `storage`). |
| **Web Application Dashboard** | Zero-install manual URL/text scanner, educational threat breakdowns, security self-assessment, local report viewer. | Client-side web input form evaluated locally in browser via WebAssembly. | **Client PWA Offline** | Zero OS privileges (standard browser sandbox). |
| **Shared Detection Engine** | Multi-modal parsing, deterministic rules, lexical heuristics, Bloom filter queries, multi-factor risk scoring, evidence generation. | Pure function input (`ScanRequest`). | **100% Offline** | Pure computational library (Zero OS entitlements). |
| **Optional Backend** | Threat feed compilation, differential OTA binary update distribution, anonymous OHTTP telemetry relay. | Outbound client poll for delta updates (no user payloads ingested). | N/A (Server infrastructure). | Standard cloud container hosting. |

---

## 6. LAYERED DETECTION ARCHITECTURE & AI ASSISTANT CONSTITUTION

### The Cardinal Rule of Security Detection
> **DETECTION CONSTITUTIONAL INVARIANT 1**: The AI Security Assistant is **NOT** the sole security detector. Detection is strictly layered, deterministic, and defense-in-depth.

```
RAW UNTRUSTED INPUT (URL, Message, File, DOM)
      │
      ▼
1. INPUT NORMALIZATION & SANITIZATION (Unicode NFKD, punycode decoding, de-obfuscation)
      │
      ▼
2. DETERMINISTIC RULE ENGINE (Known bad schemes, IP hosts, urgent extortion keywords)
      │
      ▼
3. LEXICAL & HEURISTIC ANALYZERS (Entropy, Levenshtein distance, spoofed subdomains)
      │
      ▼
4. REPUTATION & THREAT INTELLIGENCE (Offline Bloom filter check, verified allowlist)
      │
      ▼
5. ON-DEVICE AI/ML CLASSIFIERS (Quantized intent classification for ambiguous text)
      │
      ▼
6. MULTI-FACTOR RISK AGGREGATION (RiskScorer weighted math: score 0-100, confidence, severity)
      │
      ▼
7. DECISION & ACTION MAPPING (ALLOW, INFORM, WARN, BLOCK - FINALIZED HERE)
      │
      ▼
8. AI SECURITY ASSISTANT (Read-only synthesis: translates evidence into plain language)
      │
      ▼
9. USER WARNING & ACTION DISPATCH (UI warning modal, recommended action, friction gate)
```

### The Cardinal Rule of AI Security
> **DETECTION CONSTITUTIONAL INVARIANT 2**: Analyzed content is treated strictly as **DATA**, never as **INSTRUCTIONS**.
>
> 1. Raw user text is NEVER directly concatenated into an LLM prompt as executable instructions.
> 2. The AI Security Assistant receives only sanitized, tokenized `Evidence` structs generated by the deterministic layers.
> 3. The AI Assistant has **ZERO AUTHORITY** to alter, downgrade, or reverse the risk score or recommended action.
> 4. Model output must strictly adhere to a rigid JSON schema. Output failing schema validation defaults to deterministic template copy.

---

## 7. PRIVACY RULES & DATA CLASSIFICATION

PRIVATE PROTECTION operates under strict data classification boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 1: HIGHLY SENSITIVE (RAW USER PAYLOADS)                           │
│ • Visited URLs & browsing history                                      │
│ • Inbound SMS, chat, & email message text                              │
│ • Camera frames & photo screenshots                                    │
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
│ • Cached Bloom filter threat intelligence databases                    │
│ MANDATE: STORED LOCALLY IN AES-256-GCM / SQLCIPHER ENCRYPTED STORAGE. │
│ KEYS DERIVED FROM OS-NATIVE KEYSTORE. PURGEABLE BY USER AT ANY TIME.   │
└────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 3: ANONYMIZED TELEMETRY (OPT-IN ONLY)                             │
│ • Triggered Rule ID (e.g. `url-ip-based`)                              │
│ • Detection Engine version integer                                     │
│ • Truncated SHA-256 domain hash prefix (k-anonymity >= 1,000)          │
│ MANDATE: STRICTLY OPT-IN. STRIPPED OF CLIENT IP VIA OHTTP RELAY.       │
│ ε-DIFFERENTIAL PRIVACY NOISE INJECTED LOCALLY PRIOR TO TRANSMISSION.   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 8. ABSOLUTE SECURITY CONSTRAINTS

1. **Zero Trust for Inputs**: Every input (URL string, SMS text, QR bitmap, file header) is treated as an active exploit payload. Parsers must enforce strict byte limits (URLs $\le 2,048$ bytes; text $\le 10,000$ bytes) and use memory-safe runtimes.
2. **Zero Hardcoded Secrets**: No private keys, cloud tokens, or developer credentials may exist in the codebase.
3. **No Weakened Detection**: Never lower detection weights, weaken regex rules, or broaden allowlists merely to make a failing test pass.
4. **Fail-Closed Principle**: If a parser crashes, an input is malformed, or an update signature fails verification, the system must fail safely to `CAUTION` or `SUSPICIOUS`, never to silent `ALLOW`.
5. **No Claiming Impossible Capabilities**: Never promise background interception on iOS that Apple sandboxing forbids; use explicit, supported platform extension points (`IdentityLookup`, Safari Web Extensions).

---

## 9. THE 24 MANDATORY PRE-CODING VERIFICATION GATES

> **CRITICAL DIRECTIVE**: Production coding MUST NOT start until all verification gates are verified complete with concrete architectural evidence. All 24 gates have been audited by the 12-role technical audit committee and verified as **PASS**:

- [x] **GATE 01 — Requirements Complete**: All 11 core requirements defined with inputs, outputs, SLAs, and acceptance criteria in `docs/PROJECT_REQUIREMENTS.md` and traced in `docs/MASTER_TRACEABILITY_MATRIX.md`.
- [x] **GATE 02 — Product Scope Complete**: Boundary matrix distinguishing Must-Have, Should-Have, Optional, and Future capabilities in `docs/PRODUCT_SCOPE.md`.
- [x] **GATE 03 — Platform Responsibilities Complete**: Detailed boundary matrix establishing what runs on Mobile, Desktop, Extension, Web, Core, and Backend in `docs/PLATFORM_RESPONSIBILITY_MATRIX.md` and `docs/PLATFORM_VALIDATION.md`.
- [x] **GATE 04 — System Architecture Complete**: 6-plane execution topology, threading models, and platform adapters specified in `docs/TECHNICAL_ARCHITECTURE.md` and `docs/SYSTEM_ARCHITECTURE.md`.
- [x] **GATE 05 — Technology Stack Selected**: 13 technical areas evaluated with alternatives, trade-offs, security, and privacy impacts in `docs/TECHNOLOGY_STACK.md`.
- [x] **GATE 06 — Complete Data Flows Defined**: Step-by-step specifications for Flows A through H with zero undocumented data paths in `docs/DATA_FLOW_ARCHITECTURE.md`.
- [x] **GATE 07 — Trust Boundaries Defined**: 5-tier zero-trust boundary model, threat vectors, and defense protocols documented in `docs/TRUST_BOUNDARIES.md` and `docs/DATA_BOUNDARIES.md`.
- [x] **GATE 08 — Domain Models Standardized**: 11 canonical implementation-independent domain models with strict typing and validation in `docs/DOMAIN_MODELS.md`.
- [x] **GATE 09 — Technical Contracts Complete**: Implementation-independent contracts for all 18 core subsystems documented in `docs/INTERFACE_CONTRACTS.md` and `docs/TECHNICAL_CONTRACTS.md`.
- [x] **GATE 10 — Risk Engine Mathematics Defined**: Non-linear bounded Bayesian aggregation, detector reliability weights, and conflict resolution rules in `docs/RISK_ENGINE_ARCHITECTURE.md`.
- [x] **GATE 11 — AI Assistant Contract & Boundary Defined**: Rigid JSON grammar schemas, prompt injection containment, zero decision authority, and template fallback in `docs/AI_ASSISTANT_CONTRACT.md` and `docs/AI_SECURITY_BOUNDARY.md`.
- [x] **GATE 12 — Offline Parity Architecture Complete**: 100% core detection parity air-gapped, staleness degradation protocol, and factory seed fallback in `docs/OFFLINE_ARCHITECTURE.md` and `docs/OFFLINE_FIRST_ARCHITECTURE.md`.
- [x] **GATE 13 — Online Architecture & OHTTP Defined**: Value-add online capabilities, $k$-anonymity domain prefix checks, and RFC 9458 Oblivious HTTP relay in `docs/ONLINE_ARCHITECTURE.md`.
- [x] **GATE 14 — Update Security Architecture Defined**: Air-gapped Ed25519 hardware signing, embedded Root Public Key, monotonic anti-downgrade counters, and atomic staging in `docs/UPDATE_SECURITY_ARCHITECTURE.md` and `docs/UPDATE_ARCHITECTURE.md`.
- [x] **GATE 15 — Local Storage & Crypto-Shredding Defined**: SQLCipher/IndexedDB schemas, hardware key derivation, zero Tier 1 disk persistence, and crypto-shredding in `docs/LOCAL_STORAGE_ARCHITECTURE.md` and `docs/DATA_ARCHITECTURE.md`.
- [x] **GATE 16 — Backend Stateless Architecture Defined**: Stateless edge CDN, RFC 9458 OHTTP relay, zero user databases, and constitutional PII prohibitions in `docs/BACKEND_TECHNICAL_ARCHITECTURE.md`.
- [x] **GATE 17 — Browser Extension Architecture Defined**: Manifest V3 Service Worker rehydration, WebAssembly fast path, and closed Shadow DOM overlay in `docs/BROWSER_TECHNICAL_ARCHITECTURE.md`.
- [x] **GATE 18 — Mobile Architecture Defined**: Flutter UI, Android NotificationListenerService, iOS IdentityLookup, and live camera QR HUD in `docs/MOBILE_TECHNICAL_ARCHITECTURE.md`.
- [x] **GATE 19 — Desktop Security Architecture Defined**: Tauri 2.x, Rust download watcher, file header analysis, and encrypted quarantine vault in `docs/DESKTOP_TECHNICAL_ARCHITECTURE.md`.
- [x] **GATE 20 — Web Application Architecture Defined**: Next.js SSG, client-side WASM Web Worker, PWA offline caching, and strict CSP in `docs/WEB_TECHNICAL_ARCHITECTURE.md`.
- [x] **GATE 21 — Unified Error Taxonomy Defined**: 10 canonical error codes, fail-closed safety policy, and sanitized error presentations in `docs/ERROR_ARCHITECTURE.md` and `docs/FAILURE_MODE_ARCHITECTURE.md`.
- [x] **GATE 22 — Privacy Observability Defined**: Local metrics, scrubbed crash reports, Laplace differential privacy ($\varepsilon=1.0$), and $k\ge 1,000$ anonymity in `docs/OBSERVABILITY_ARCHITECTURE.md`.
- [x] **GATE 23 — Testing Architecture Defined**: 11-tier testing pyramid, 90% branch coverage threshold, adversarial prompt injection corpus, and agent test ownership in `docs/TEST_ARCHITECTURE.md` and `docs/TEST_CONTRACT.md`.
- [x] **GATE 24 — Build & Dependency DAG Defined**: Multi-platform build toolchains, SLSA Level 3 SBOM, and strict 12-phase dependency DAG in `docs/BUILD_ARCHITECTURE.md`, `docs/IMPLEMENTATION_DEPENDENCY_GRAPH.md`, and `docs/FINAL_ARCHITECTURE_SCORECARD.md`.

---

## 10. DEFINITION OF DONE (DOD)

> *"Code exists" does NOT mean "Feature is done."*

A task or feature in PRIVATE PROTECTION is declared **DONE** only when all 11 criteria are met:
1. **Implementation Complete**: Production-quality implementation exists without stubs, dummy returns, or TODOs.
2. **Behavioral Correctness**: Intended threat detection, warning, or explanation behavior operates accurately.
3. **Automated Tests Exist**: Comprehensive unit, integration, or benchmark tests are committed.
4. **All Tests Pass**: 100% test pass rate across the monorepo test suite.
5. **Code Coverage Met**: Code coverage exceeds **90%** on statements, lines, and branches.
6. **Security Review Signed Off**: STRIDE threat impact verified; input sanitization and privilege minimization confirmed.
7. **Privacy Review Signed Off**: Verified that zero Tier 1 user content is logged, persisted unencrypted, or transmitted.
8. **Error & Failure Handling Complete**: Graceful degradation handles low memory, malformed input, and network loss.
9. **Offline Behavior Verified**: Feature functions with zero degradation when all network interfaces are disabled.
10. **Platform Constraints Respected**: Code adheres to OS sandboxing, memory ceilings, and store policy rules.
11. **Documentation Synchronized**: All relevant architectural documents and technical contracts are updated.

---

## 11. NO FAKE SUCCESS POLICY

Agents and engineers must **NEVER** report task success based on superficial indicators:
- ❌ Do NOT claim success because a file was written.
- ❌ Do NOT claim success because code compiles if logic is unverified.
- ❌ Do NOT claim success because an endpoint returns HTTP 200 with dummy data.
- ❌ Do NOT claim success by skipping, commenting out, or weakening failing tests.
- ❌ Do NOT claim success by using fake mocks in place of real functional logic.
- ❌ Do NOT swallow exceptions or return empty arrays to mask detection errors.
- ❌ Do NOT claim protection that the underlying OS platform cannot technically provide.

**Every completion claim must be substantiated by concrete execution evidence, test logs, and metric data.**

---

## 12. SUBAGENT GOVERNANCE & 15-STEP EXECUTION LOOP

When the Master Orchestrator delegates a task to a specialist subagent, the following 15-step execution lifecycle must be strictly observed:

```
 1. Master Agent defines task scope, target directory, and acceptance criteria.
 2. Master Agent checks dependencies and ensures non-overlapping file ownership.
 3. Master Agent invokes the designated Specialist Subagent.
 4. Specialist Subagent reads AGENTS.md.
 5. Specialist Subagent reads relevant docs/ specifications.
 6. Specialist Subagent reads relevant docs/TECHNICAL_CONTRACTS.md schemas.
 7. Specialist Subagent implements changes strictly within its permitted directory domain.
 8. Specialist Subagent authors comprehensive unit and regression tests.
 9. Specialist Subagent executes tests locally (`npm test`, `npx vitest run ...`).
10. Specialist Subagent records concrete metrics (coverage, pass count, latency).
11. Specialist Subagent compiles the mandatory 16-field Handoff Report.
12. Master Agent inspects modified files (verifying zero out-of-bounds writes).
13. Master Agent reviews security and privacy implications.
14. Master Agent runs full monorepo regression test suite.
15. Master Agent integrates changes atomically and updates tracking registers.
```

---

## 13. MANDATORY 16-FIELD SUBAGENT HANDOFF SCHEMA

Every subagent completing an assignment must return its completion report adhering to this exact format:

```markdown
### 1. Task Definition
- **Task ID**: [e.g. TASK-CORE-005]
- **Assigned Role**: [Agent role name]
- **Target Objective**: [Summary of assigned work]

### 2. Objective Status
- [COMPLETE / BLOCKED / PARTIAL]

### 3. Files Modified / Created
- `path/to/file1` (Created / Modified / Deleted)
- `path/to/file2`

### 4. Files Intentionally NOT Modified
- [Confirmation that out-of-bounds files were untouched]

### 5. Implementation Summary
- [Technical explanation of logic, algorithms, and design decisions applied]

### 6. Tests Added / Updated
- [List of new unit, integration, or benchmark test files]

### 7. Tests Executed
- [Exact terminal commands run, e.g. `npx vitest run ...`]

### 8. Verification Results
- **Pass / Fail**: [X passed, 0 failed]
- **Coverage**: [Statements % | Lines % | Branches %]
- **Key Metrics**: [Latency p95, Memory MB, Accuracy %]

### 9. Security Impact
- [STRIDE threat mitigations verified; sanitization confirmed]

### 10. Privacy Impact
- [Verification of zero Tier 1 data transmission; local RAM zeroing confirmed]

### 11. Performance Impact
- [Latency measurements against SLA budgets]

### 12. Assumptions
- [Technical assumptions made during implementation]

### 13. Identified Risks
- [Residual risks or external failure points]

### 14. Known Limitations
- [Platform boundaries or deliberate scope omissions]

### 15. Remaining Work
- [Items deferred to subsequent phases]

### 16. Recommended Next Step
- [Actionable recommendation for Master Orchestrator]
```

---

## 14. AUTHORITATIVE DOCUMENTATION REGISTRY

In the event of ambiguity or conflicting information, documentation authority is governed by this strict precedence hierarchy:

1. **`AGENTS.md`** ➔ Project Constitution, Core Invariants, Pre-Coding Gates, & Agent Rules (*Highest Authority*).
2. **`docs/TECHNICAL_CONTRACTS.md`** ➔ Authoritative subsystem interfaces, input/output schemas, and error contracts.
3. **`docs/PROJECT_REQUIREMENTS.md` & `docs/PRODUCT_SCOPE.md`** ➔ Scope boundaries and functional requirements.
4. **`docs/SECURITY_ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/AI_SECURITY_BOUNDARY.md`** ➔ Security and threat defense controls.
5. **`docs/PRIVACY_ARCHITECTURE.md` & `docs/DATA_CLASSIFICATION.md`** ➔ Zero-knowledge and data handling rules.
6. **`docs/DETECTION_ARCHITECTURE.md` & `docs/AI_ML_ARCHITECTURE.md`** ➔ Detection pipeline and ML inference design.
7. **`docs/DEVELOPMENT_ROADMAP.md` & `docs/CODING_READINESS_CHECKLIST.md`** ➔ Phasing, dependencies, and readiness gates.
8. **`agents/**`** ➔ Specialist agent role definitions and write boundaries.
