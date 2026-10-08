# Agent File Ownership Model: PRIVEX

## 1. Core Ownership Principles

To guarantee deterministic, conflict-free autonomous agent collaboration:
1. **Exclusive Write Domains**: Every file and directory in the monorepo has exactly ONE primary owner role. No agent may modify files outside its assigned domain without explicit Master authorization.
2. **Read-Anywhere, Write-Restricted**: All agents have unrestricted read permissions to understand system interfaces, schemas, and contracts.
3. **Contract-Driven Changes**: Modifying shared interfaces in `packages/core/src/types.ts` requires a formal RFC approved by the System Architect and Master Orchestrator before downstream consumers adapt.
4. **Master-Only Root Configuration**: Monorepo root files (`package.json`, `tsconfig.base.json`, `.gitignore`, root CI workflows) may only be altered by the Master Orchestrator, DevSecOps Specialist, or System Architect.

---

## 2. Master File Ownership Map

| Directory / File Path | Primary Owner Role | Permitted Secondary Roles (Review/Test) | Prohibited Roles |
|---|---|---|---|
| **Root Level Configuration** | | | |
| `package.json`, `tsconfig.base.json` | System Architect | Master Orchestrator, DevSecOps | All other specialist agents |
| `README.md`, `LICENSE` | Master Orchestrator | Requirements Architect | All other specialist agents |
| `.gitignore`, `.editorconfig` | DevSecOps Specialist | Master Orchestrator | All other specialist agents |
| **Documentation (`docs/`)** | | | |
| `docs/PROJECT_REQUIREMENTS.md`, `PRODUCT_SCOPE.md` | Requirements Architect | Master Orchestrator | Platform & Implementation Agents |
| `docs/SYSTEM_ARCHITECTURE.md`, `REPOSITORY_ARCHITECTURE.md` | System Architect | Master Orchestrator | Platform & Implementation Agents |
| `docs/SECURITY_ARCHITECTURE.md`, `THREAT_MODEL.md` | Cybersecurity Architect | Security Auditor | Platform & Implementation Agents |
| `docs/PRIVACY_ARCHITECTURE.md` | Privacy Specialist | Security Auditor | Platform & Implementation Agents |
| `docs/DETECTION_ARCHITECTURE.md` | Detection Engine Specialist | Cybersecurity Architect | Platform & Implementation Agents |
| `docs/AI_ML_ARCHITECTURE.md`, `AI_SECURITY_BOUNDARY.md` | AI/ML Specialist | Cybersecurity Architect | Platform & Implementation Agents |
| `docs/PLATFORM_RESPONSIBILITY_MATRIX.md`, `PLATFORM_VALIDATION.md` | System Architect | Mobile, Desktop, Extension Specialists | Backend, QA Specialists |
| `docs/USER_FLOW_SPECIFICATION.md` | UX / Warning Specialist | Requirements Architect | Implementation Agents |
| `docs/PERFORMANCE_REQUIREMENTS.md` | Performance Specialist | System Architect | Implementation Agents |
| `docs/TESTING_STRATEGY.md` | QA / Test Specialist | Integration/Release Specialist | Implementation Agents |
| `docs/DEVELOPMENT_ROADMAP.md`, `DECISION_REGISTER.md` | Master Orchestrator | System Architect | Implementation Agents |
| `docs/AGENT_*.md` | Master Orchestrator | System Architect | Implementation Agents |
| **Agent Definitions (`agents/`)** | | | |
| `agents/**` | Master Orchestrator | System Architect | All specialist task agents |
| **Core Shared Detection Engine (`packages/core/`)** | | | |
| `packages/core/src/types.ts` | System Architect (Contract Authority) | Detection Engine Specialist | Platform agents |
| `packages/core/src/rules/**` | Detection Engine Specialist | Threat Intel Specialist | Platform agents |
| `packages/core/src/analyzers/**` | Detection Engine Specialist | AI/ML Specialist | Platform agents |
| `packages/core/src/scoring/**` | Detection Engine Specialist | Cybersecurity Architect | Platform agents |
| `packages/core/src/explanation/**` | AI/ML Specialist | UX / Warning Specialist | Platform agents |
| `packages/core/src/threat-intel/**` | Threat Intelligence Specialist | Detection Engine Specialist | Platform agents |
| `packages/core/src/pipeline/**` | Detection Engine Specialist | System Architect | Platform agents |
| `packages/core/src/utils/**` | Detection Engine Specialist | Cybersecurity Architect | Platform agents |
| `packages/core/src/__tests__/**` | QA / Test Specialist | Detection Engine Specialist | Platform agents |
| `packages/core/package.json`, `tsconfig.json` | System Architect | DevSecOps Specialist | Platform agents |
| **On-Device AI/ML Packages (`packages/ml/`)** | | | |
| `packages/ml/src/**` | AI/ML Specialist | Performance Specialist | Platform agents, Web agents |
| `packages/ml/models/**` | AI/ML Specialist | Security Auditor (Model Signatures) | Platform agents |
| `packages/ml/tests/**` | QA / Test Specialist | AI/ML Specialist | Platform agents |
| **Threat Intelligence Seed Data (`threat-data/`)** | | | |
| `threat-data/benchmark-dataset.json` | QA / Test Specialist | Threat Intel Specialist | Platform agents |
| `threat-data/feeds/**`, `bloom-filters/**` | Threat Intelligence Specialist | DevSecOps Specialist | Platform agents |
| **Mobile Application (`apps/mobile/`)** | | | |
| `apps/mobile/android/**` | Mobile Specialist (Android) | UX / Warning Specialist | Browser, Desktop, Backend |
| `apps/mobile/ios/**` | Mobile Specialist (iOS) | UX / Warning Specialist | Browser, Desktop, Backend |
| `apps/mobile/tests/**` | QA / Test Specialist | Mobile Specialist | Browser, Desktop, Backend |
| **Desktop Application (`apps/desktop/`)** | | | |
| `apps/desktop/src-tauri/**` | Desktop Security Specialist | Cybersecurity Architect (IPC) | Mobile, Browser, Web |
| `apps/desktop/ui/**` | Desktop Security Specialist | UX / Warning Specialist | Mobile, Browser, Web |
| `apps/desktop/tests/**` | QA / Test Specialist | Desktop Security Specialist | Mobile, Browser, Web |
| **Browser Extension (`apps/extension/`)** | | | |
| `apps/extension/src/background/**` | Browser Extension Specialist | Detection Engine Specialist | Mobile, Desktop, Backend |
| `apps/extension/src/content/**` | Browser Extension Specialist | UX / Warning Specialist | Mobile, Desktop, Backend |
| `apps/extension/manifest.json` | Browser Extension Specialist | DevSecOps Specialist | Mobile, Desktop, Backend |
| `apps/extension/tests/**` | QA / Test Specialist | Browser Extension Specialist | Mobile, Desktop, Backend |
| **Web Application (`apps/web/`)** | | | |
| `apps/web/src/**` | Web Application Specialist | UX / Warning Specialist | Mobile, Desktop, Extension |
| `apps/web/tests/**` | QA / Test Specialist | Web Application Specialist | Mobile, Desktop, Extension |
| **Backend & Cloud Services (`apps/backend/`)** | | | |
| `apps/backend/src/services/**` | Backend / API Specialist | Threat Intel Specialist | Mobile, Desktop, Extension |
| `apps/backend/src/api/**` | Backend / API Specialist | DevSecOps Specialist | Mobile, Desktop, Extension |
| `apps/backend/tests/**` | QA / Test Specialist | Backend / API Specialist | Mobile, Desktop, Extension |
| **CI/CD & Infrastructure (`.github/`, `scripts/`)** | | | |
| `.github/workflows/**`, `scripts/**` | DevSecOps Specialist | Integration/Release Specialist | All feature specialists |

---

## 3. Enforcement & Conflict Prevention

1. **Pre-Commit Verification**: Agent task execution tools check the modified file list against the agent's defined permitted write directory before accepting results.
2. **No Overwrite Rule**: An agent attempt to write to another domain's path produces an immediate task halt and requires escalation to the Master Orchestrator.
3. **Interface Staging**: Downstream consumers (e.g., Extension or Mobile) may not modify `packages/core` to fit client-specific needs; they must request an interface enhancement from the Detection Engine Specialist.
