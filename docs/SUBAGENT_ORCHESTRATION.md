# Subagent Orchestration Plan: PRIVEX

This document defines how future implementation work should be delegated to specialist agents, their responsibilities, file ownership, and coordination rules.

---

## 1. Subsystem Ownership Map

### 1.1 Core Detection Engine (`packages/core/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Detection Engine Developer |
| **Inputs** | Detection Architecture doc, Risk Scoring spec, Threat Intelligence format spec |
| **Outputs** | Compiled core library (Rust → native + WASM), rule engine, analyzers, scoring engine, explanation templates |
| **Dependencies** | None (foundational — all other subsystems depend on this) |
| **Files/Directories Owned** | `packages/core/**` |
| **Tests Owned** | `packages/core/tests/**`, detection accuracy benchmarks |
| **Integration Points** | Exports a stable API consumed by all `apps/*` |

### 1.2 AI/ML Layer (`packages/ml/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | AI/ML Engineer |
| **Inputs** | AI/ML Architecture doc, training datasets, model format specs |
| **Outputs** | Trained + quantized models (TFLite, ONNX, CoreML), inference wrapper library, model verification module |
| **Dependencies** | Phase 1 (Core Engine must define feature extraction interfaces) |
| **Files/Directories Owned** | `packages/ml/**`, `threat-data/training/**` |
| **Tests Owned** | `packages/ml/tests/**`, accuracy evaluation suite, adversarial robustness tests |
| **Integration Points** | Models loaded by `packages/core` inference layer. Explanation engine consumes evidence chain. |

### 1.3 Browser Extension (`apps/extension/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Extension Developer |
| **Inputs** | Platform Responsibility Matrix, System Architecture, User Flow Specification |
| **Outputs** | Manifest V3 extension (Chrome, Firefox, Edge) with content scripts, service worker, warning UI overlay |
| **Dependencies** | Phase 1 + 2 (Core Engine compiled to WASM) |
| **Files/Directories Owned** | `apps/extension/**` |
| **Tests Owned** | `apps/extension/tests/**`, Playwright browser tests |
| **Integration Points** | Imports `packages/core` as WASM module. Uses `packages/ml` ONNX models via WebNN/WASM. |

### 1.4 Mobile Application (`apps/mobile/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Mobile Developer(s) — Android + iOS |
| **Inputs** | Platform Responsibility Matrix, User Flow Specification, Privacy Architecture |
| **Outputs** | Android (Kotlin) and iOS (Swift) applications with SMS scanning, QR analysis, notifications |
| **Dependencies** | Phase 1 + 2 (Core Engine as native library via JNI/C-Interop) |
| **Files/Directories Owned** | `apps/mobile/**` |
| **Tests Owned** | `apps/mobile/tests/**`, Appium/Maestro E2E tests, battery/memory profiling |
| **Integration Points** | Links `packages/core` via FFI. Loads `packages/ml` models via TFLite/CoreML. |

### 1.5 Desktop Application (`apps/desktop/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Desktop Developer |
| **Inputs** | Platform Responsibility Matrix, System Architecture, Security Architecture |
| **Outputs** | Tauri application (Windows + macOS) with file scanning, system monitoring, tray integration |
| **Dependencies** | Phase 1 + 2 (Core Engine as native Rust library — direct linking) |
| **Files/Directories Owned** | `apps/desktop/**` |
| **Tests Owned** | `apps/desktop/tests/**`, file scanning benchmarks, system integration tests |
| **Integration Points** | Directly links `packages/core` Rust library. Loads `packages/ml` ONNX models. |

### 1.6 Web Application (`apps/web/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Web Developer |
| **Inputs** | Backend Architecture, User Flow Specification, Data Architecture |
| **Outputs** | Next.js dashboard with manual scanning, security history, account management |
| **Dependencies** | Phase 6 (Backend API must be available) |
| **Files/Directories Owned** | `apps/web/**` |
| **Tests Owned** | `apps/web/tests/**`, Cypress/Playwright E2E tests |
| **Integration Points** | Calls `apps/backend` REST API. May use `packages/core` WASM for client-side pre-analysis. |

### 1.7 Backend Services (`apps/backend/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Backend Developer |
| **Inputs** | Backend Architecture, Data Architecture, Security Architecture |
| **Outputs** | API gateway, threat feed aggregator, telemetry collector, model/rule distribution service |
| **Dependencies** | Phase 1 (Core Engine defines rule/model formats that backend must distribute) |
| **Files/Directories Owned** | `apps/backend/**` |
| **Tests Owned** | `apps/backend/tests/**`, API integration tests, load tests |
| **Integration Points** | Distributes artifacts consumed by all clients. Receives opt-in telemetry. |

### 1.8 Threat Intelligence (`threat-data/`)

| Field | Value |
|---|---|
| **Responsible Specialist** | Threat Intelligence Analyst |
| **Inputs** | Public feeds (PhishTank, OpenPhish, etc.), Detection Architecture |
| **Outputs** | Curated seed data, Bloom filter generation scripts, rule definition files |
| **Dependencies** | Phase 1 (must align with Core Engine's data format) |
| **Files/Directories Owned** | `threat-data/**` |
| **Tests Owned** | Threat feed validation tests, Bloom filter accuracy tests |
| **Integration Points** | Consumed by `packages/core/threat-intel`. Distributed by `apps/backend`. |

---

## 2. Parallel Work Rules

### 2.1 What Can Run in Parallel
- **Phase 3, 4, 5** (Browser Extension, Mobile, Desktop) can be developed in parallel after Phases 1+2 complete — they share `packages/core` but own separate `apps/` directories.
- **Phase 6** (Web + Backend) can begin backend API development in parallel with Phase 3-5, but the web frontend depends on the backend API.
- **AI/ML training** (Phase 2) can begin in parallel with Phase 1 rule engine development — they have separate directories.

### 2.2 What Must Be Sequential
- **Phase 1 → Phase 2**: ML layer depends on core engine's feature extraction interfaces.
- **Phase 1+2 → Phase 3-6**: All platform apps depend on the compiled detection engine.
- **Phase 7 (Integration) → Phase 8 (Security Hardening)**: Must integrate before hardening.
- **Phase 8 → Phase 9 (Optimization)**: Harden before optimizing.

---

## 3. File Ownership and Conflict Rules

| Rule | Description |
|---|---|
| **Exclusive Ownership** | Each `apps/*` directory is owned by exactly one specialist. No cross-app file edits without owner approval. |
| **Shared Library Changes** | Any change to `packages/core/**` or `packages/ml/**` requires regression testing across ALL dependent platforms before merge. |
| **Interface Stability** | The `packages/core` public API is treated as a versioned contract. Breaking changes require RFC and approval from all platform owners. |
| **Branch Strategy** | Feature branches per subsystem. `main` is always buildable. Platform branches merge into `main` only after CI passes. |
| **Conflict Resolution** | Lead Architect arbitrates any cross-subsystem conflicts. Platform-specific workarounds are preferred over core engine changes. |

---

## 4. Code Review Rules

| Scope | Reviewers Required |
|---|---|
| `packages/core/**` | Detection Architect + 1 platform owner |
| `packages/ml/**` | AI/ML Architect + Detection Architect |
| `apps/extension/**` | Extension Developer + Security Architect |
| `apps/mobile/**` | Mobile Developer + Privacy Architect |
| `apps/desktop/**` | Desktop Developer + Security Architect |
| `apps/backend/**` | Backend Developer + Privacy Architect + Security Architect |
| `threat-data/**` | Threat Intel Analyst + Detection Architect |
| Security-sensitive changes (any) | Security Architect (mandatory) |
| Privacy-impacting changes (any) | Privacy Architect (mandatory) |

---

## 5. Integration and Rollback

| Process | Description |
|---|---|
| **Integration Testing** | After each platform app reaches feature completion, run cross-platform integration test suite (`tests/integration/`). |
| **Rollback** | Each deployment includes the previous version's artifacts. Model/rule rollback is supported via version pinning. App rollback via app store versioning. |
| **Hotfix Process** | Critical security fixes to `packages/core` bypass normal review cycle — require Security Architect + Lead Architect approval, with retroactive full review within 24 hours. |
