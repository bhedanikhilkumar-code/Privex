# Autonomous Agent Organization Directory: PRIVEX

## 1. Directory Mission & Purpose

This `agents/` directory establishes the permanent, hierarchical autonomous agent orchestration structure for the PRIVEX cybersecurity project.

It defines:
- The 20 specialized agent roles required across discovery, architecture, core engine engineering, platform applications, security auditing, and release engineering.
- Strict operational boundaries, permitted file write paths, prohibited areas, and test mandates for every role.
- Dynamic invocation triggers and termination conditions to prevent redundant or uncontrolled agent execution.
- Standardized handoff schemas and conflict resolution protocols to ensure safe parallelism and deterministic integration.

> **CRITICAL DIRECTIVE**: This directory contains agent role specifications, coordination contracts, and orchestration instructions. It must NEVER contain production application logic or dummy code.

---

## 2. Hierarchical Agent Organization

```
                          ┌───────────────────────────────┐
                          │   01. MASTER ORCHESTRATOR     │
                          │   (Lead Director & Gate)      │
                          └───────────────┬───────────────┘
                                          │
    ┌─────────────────────────────────────┼─────────────────────────────────────┐
    │                                     │                                     │
┌───▼──────────────────────────┐  ┌───────▼──────────────────────┐  ┌───────────▼───────────────────┐
│ FOUNDATIONAL ARCHITECTURE     │  │ PLATFORM & PRODUCT           │  │ VERIFICATION & DEPLOYMENT     │
├──────────────────────────────┤  ├──────────────────────────────┤  ├───────────────────────────────┤
│ 02. Requirements Architect   │  │ 10. Mobile Specialist        │  │ 16. QA / Test Specialist      │
│ 03. System Architect         │  │ 11. Desktop Security Spec.   │  │ 17. Performance Specialist    │
│ 04. Cybersecurity Architect  │  │ 12. Browser Extension Spec.  │  │ 18. DevSecOps Specialist      │
│ 05. Threat Intelligence Spec │  │ 13. Web Application Spec.    │  │ 19. Security Auditor          │
│ 06. Detection Engine Spec.   │  │ 14. Backend / API Specialist │  │ 20. Integration / Release Spec│
│ 07. AI / ML Specialist       │  │ 15. UX / Warning Specialist  │  └───────────────────────────────┘
│ 08. Privacy Specialist       │  └──────────────────────────────┘
│ 09. Data Architect           │
└──────────────────────────────┘
```

---

## 3. Directory Index of Agent Role Definitions

| Role ID | Specification Document | Primary Domain | Permitted File Domain |
|:---:|---|---|---|
| **01** | [`MASTER_ORCHESTRATOR.md`](./MASTER_ORCHESTRATOR.md) | Central Coordination & Gatekeeping | Workspace root, `agents/**`, `docs/` |
| **02** | [`requirements_architect.md`](./requirements_architect.md) | Requirement Traceability & Scope | `docs/PROJECT_REQUIREMENTS.md`, `PRODUCT_SCOPE.md` |
| **03** | [`system_architect.md`](./system_architect.md) | Cross-Platform Systems Architecture | `tsconfig.base.json`, `packages/core/src/types.ts` |
| **04** | [`cybersecurity_architect.md`](./cybersecurity_architect.md) | STRIDE Threat Modeling & Self-Defense | `docs/SECURITY_ARCHITECTURE.md`, `THREAT_MODEL.md` |
| **05** | [`threat_intelligence_specialist.md`](./threat_intelligence_specialist.md) | Feeds, Bloom Filters, & Signatures | `packages/core/src/threat-intel/**`, `threat-data/**` |
| **06** | [`detection_engine_specialist.md`](./detection_engine_specialist.md) | Rules, Analyzers, Scoring, & Pipeline | `packages/core/src/rules/**`, `analyzers/**`, `scoring/**` |
| **07** | [`ai_ml_specialist.md`](./ai_ml_specialist.md) | On-Device Quantized SLMs & Embeddings | `packages/ml/**`, `packages/core/src/explanation/**` |
| **08** | [`privacy_specialist.md`](./privacy_specialist.md) | Data Tiers, Zeroing, & OHTTP Relays | `docs/PRIVACY_ARCHITECTURE.md`, Privacy Policies |
| **09** | [`data_architect.md`](./data_architect.md) | Schemas, Local Storage, & Serialization | `packages/core/src/data/**`, SQLite Schemas |
| **10** | [`mobile_specialist.md`](./mobile_specialist.md) | Android / iOS OS Sandboxed Extensions | `apps/mobile/**` |
| **11** | [`desktop_security_specialist.md`](./desktop_security_specialist.md) | Tauri/Rust Desktop Daemon & File Hooks | `apps/desktop/**` |
| **12** | [`browser_extension_specialist.md`](./browser_extension_specialist.md) | Manifest V3 Extensions & Navigation | `apps/extension/**` |
| **13** | [`web_application_specialist.md`](./web_application_specialist.md) | Next.js Dashboard & PWA Sandbox | `apps/web/**` |
| **14** | [`backend_api_specialist.md`](./backend_api_specialist.md) | Cloud Delta Feed & Distribution APIs | `apps/backend/**` |
| **15** | [`ux_security_warning_specialist.md`](./ux_security_warning_specialist.md) | Threat Warning UX, Hierarchy & Copy | `docs/USER_FLOW_SPECIFICATION.md`, UI Warning Templates |
| **16** | [`qa_test_specialist.md`](./qa_test_specialist.md) | Multi-Tier Test Suites & Benchmarks | `**/__tests__/**`, `threat-data/benchmark-dataset.json` |
| **17** | [`performance_specialist.md`](./performance_specialist.md) | Real-Time Latency & Memory Profiling | Performance benchmark harnesses, profiling configs |
| **18** | [`devsecops_specialist.md`](./devsecops_specialist.md) | CI/CD, SBOM, Signing & Tooling | `.github/workflows/**`, `scripts/**`, Build Configs |
| **19** | [`security_auditor.md`](./security_auditor.md) | Red Teaming, Injections, & SAST Audits | Security Audit Reports, Fuzzing Test Cases |
| **20** | [`integration_release_specialist.md`](./integration_release_specialist.md) | Packaging, Monotonic Bumps & Signing | Release manifests, packaging build scripts |

---

## 4. Invocation & Orchestration Rules

- **Ephemeral Spawning**: The Master Orchestrator creates specialist agents dynamically as needed.
- **Contract Freezes**: When a shared interface in `packages/core/src/types.ts` is modified, dependent platform specialists are paused until the new library is compiled.
- **Standard Handoff**: Every agent must submit the standard 11-field handoff markdown before its output can be integrated.
