# CONTRIBUTING TO PRIVEX
## Autonomous Agent & Developer Contribution Guidelines

Thank you for your interest in contributing to **PRIVEX**!  
Before submitting code or proposing architectural changes, please read this document and the canonical project constitution in [`AGENTS.md`](./AGENTS.md).

---

## 1. FOUNDATIONAL CONSTITUTIONAL PRINCIPLES

Every contribution must honor the core doctrine:
**LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

1. **Constitutional Invariant 1 (Defense-in-Depth):** The AI Security Assistant is **NOT** the primary detector. Security decisions are governed deterministically by layered rules, heuristics, and Bloom filter threat intelligence.
2. **Constitutional Invariant 2 (Data, Not Instructions):** Raw untrusted user text is **NEVER** concatenated into LLM prompts as instructions. The AI assistant receives only tokenized `Evidence` structs.
3. **No Weakening of Controls:** Never lower detection thresholds or loosen validation schemas merely to make a test pass.

---

## 2. DEVELOPMENT SETUP

### Prerequisites
- **Node.js:** `>= 20.0.0` (LTS v22 recommended)
- **npm:** `>= 10.0.0`
- **Git:** `>= 2.30.0`

### Initializing the Workspace
```bash
git clone https://github.com/private-protection/private-protection.git
cd private-protection
npm ci
```

### Essential Development Commands
```bash
# Run full unit and integration tests
npm test

# Run tests with V8 code coverage report
npm run test:coverage

# Perform static lint analysis
npm run lint

# Validate TypeScript compilation across all 6 workspaces
npm run typecheck

# Build all production bundles
npm run build

# Package release archives and generate SHA-256 checksums
npm run package
```

---

## 3. MONOREPO STRUCTURE

Contributions are organized across npm workspaces:
- `packages/core`: Canonical detection pipeline, analyzers (URL/Text), rule engine, Bloom filter, Bayesian risk scorer.
- `packages/ml`: On-device AI assistant runtime, model loaders, prompt injection filters, response grammar schemas.
- `apps/web`: Client-side Next.js/Vite Web Worker scanner and security dashboard.
- `apps/extension`: Manifest V3 browser extension for pre-navigation threat interception.
- `apps/mobile`: Android client with notification listeners, QR code scanners, and device posture audits.
- `apps/desktop`: Electron 3-tier desktop security software with file scanning and cryptographic quarantine vault.

---

## 4. CODING & SECURITY STANDARDS

- **TypeScript Strict Mode:** All code must be strictly typed. Avoid `any`; use validated domain models defined in `@private-protection/core`.
- **Fail-Closed Design:** In the event of an unhandled exception, parsers must default to `CAUTION` or `SUSPICIOUS`, never silent `ALLOW`.
- **Zero Hardcoded Secrets:** Never commit API keys, tokens, private keys, or credentials.
- **Memory Safety:** Process user payloads in volatile RAM and clear buffers upon scan completion. Never persist raw Tier 1 content to disk unencrypted.
- **Test Coverage SLA:** New features must achieve code coverage exceeding **90%** on statements, lines, and branches.

---

## 5. COMMIT MESSAGE CONVENTIONS

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat(scope): add new URL homograph detection rule`
- `fix(desktop): resolve race condition in file scanner cancellation`
- `docs(api): update interface contracts for detection pipeline`
- `test(ml): expand adversarial prompt injection test battery`
- `chore(deps): bump patch dependency for vitest`

---

## 6. PULL REQUEST PROCESS

1. Fork the repository and create a feature branch (`feat/your-feature-name`).
2. Implement your changes along with comprehensive unit, integration, and security tests.
3. Verify that all 413+ tests pass and coverage exceeds thresholds (`npm run test:coverage`).
4. Ensure clean static lint and typecheck (`npm run lint && npm run typecheck`).
5. Submit your PR with a detailed description linking relevant requirements in [`docs/MASTER_TRACEABILITY_MATRIX.md`](./docs/MASTER_TRACEABILITY_MATRIX.md).
