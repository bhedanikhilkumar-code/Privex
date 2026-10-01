# Implementation & Documentation Governance: PRIVATE PROTECTION

## 1. Governance Principles & Authority Hierarchy

To prevent documentation rot, technical debt, and architectural drift, all engineering activities in PRIVATE PROTECTION are governed by strict documentation authority rules.

```
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 1: THE PROJECT CONSTITUTION                                      │
│ • AGENTS.md                                                            │
│ BINDING AUTHORITY: Project identity, non-negotiable core invariants,    │
│ pre-coding gates, Definition of Done, and "No Fake Success" policy.     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 2: AUTHORITATIVE TECHNICAL CONTRACTS                             │
│ • docs/TECHNICAL_CONTRACTS.md                                          │
│ • docs/DATA_CLASSIFICATION.md & docs/DATA_BOUNDARIES.md                │
│ BINDING AUTHORITY: Typed subsystem schemas, data types, error states,  │
│ and trust boundaries. Code MUST conform to these contracts.            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 3: DOMAIN SPECIFICATION DOCUMENTS                                │
│ • docs/PROJECT_REQUIREMENTS.md & docs/PRODUCT_SCOPE.md                 │
│ • docs/SYSTEM_ARCHITECTURE.md & docs/PLATFORM_VALIDATION.md            │
│ • docs/SECURITY_ARCHITECTURE.md & docs/THREAT_MODEL.md                 │
│ • docs/PRIVACY_ARCHITECTURE.md                                         │
│ • docs/DETECTION_ARCHITECTURE.md & docs/AI_ML_ARCHITECTURE.md          │
│ • docs/UPDATE_ARCHITECTURE.md & docs/FAILURE_MODE_ARCHITECTURE.md      │
│ • docs/PERFORMANCE_CONTRACT.md & docs/TEST_CONTRACT.md                 │
│ BINDING AUTHORITY: System design, algorithms, hardware targets,        │
│ threat mitigations, and verification methodologies.                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 4: OPERATIONAL ORCHESTRATION & ROADMAP                           │
│ • docs/DEVELOPMENT_ROADMAP.md & docs/CODING_READINESS_CHECKLIST.md     │
│ • docs/AGENT_ORCHESTRATION_ARCHITECTURE.md & docs/AGENT_FILE_OWNERSHIP.md│
│ • agents/** (Role Definitions)                                         │
│ BINDING AUTHORITY: Execution phasing, role boundaries, and handoffs.  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Change Synchronization & Contract Amendment Protocol

Whenever code implementation or technical discovery necessitates altering a contract, the following mandatory **Contract Synchronization Protocol** must be executed:

1. **RFC Submission**: The implementing specialist identifies the necessity to alter an interface or data structure and drafts a contract amendment RFC.
2. **Authority Review**: The System Architect and Master Orchestrator review the proposed amendment against all downstream dependencies.
3. **Documentation Update Prior to Merge**: The authoritative contract in `docs/TECHNICAL_CONTRACTS.md` or domain specification is updated **BEFORE** the implementation code is merged.
4. **Downstream Notice**: The Master Orchestrator pauses dependent specialist agents, applies the contract change, updates types in `packages/core/src/types.ts`, and verifies clean monorepo compilation.
5. **Atomic Commit**: Code changes and contract updates are committed together in a single atomic git revision.

> **CRITICAL DIRECTIVE**: Code changes that drift from `docs/TECHNICAL_CONTRACTS.md` without an approved documentation update are considered architectural defects and will be rejected at the merge gate.
