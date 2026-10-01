# Repository Architecture: Private Protection

We use a Monorepo approach (managed via Turborepo or Nx) to maximize code sharing and ensure version consistency across all client platforms and backend services.

## 1. Directory Structure

```text
private-protection/
├── docs/                          # Architecture, API specs, diagrams
├── packages/
│   ├── core/                      # Shared detection engine (TS/Rust)
│   │   ├── rules/                 # Deterministic regex & logic rules
│   │   ├── heuristics/            # Entropy, typosquatting analyzers
│   │   ├── analyzers/             # URL, message, content parsers
│   │   ├── scoring/               # Weighted risk scoring
│   │   ├── explanation/           # ML explanation string generator
│   │   └── threat-intel/          # Local cache DB management
│   └── ml/                        # ML inference wrappers, ONNX models
├── apps/
│   ├── web/                       # Web dashboard (Next.js/React)
│   ├── extension/                 # Browser extension (Plasmo/Manifest V3)
│   ├── mobile/                    # React Native / Expo application
│   ├── desktop/                   # Tauri / Electron application
│   └── backend/                   # Optional Node/Go backend services
├── tests/                         # Cross-platform E2E test suites
├── tools/                         # Build scripts, CI helpers
├── threat-data/                   # Seed files for threat intelligence
└── .github/                       # GitHub Actions workflows
```

## 2. Dependency Graph
- `apps/*` (except backend) depend strictly on `packages/core` and `packages/ml`.
- `apps/backend` depends on `packages/core` (for the manual deep-scan API).
- `packages/ml` operates independently but feeds outputs into `packages/core/scoring`.

## 3. File Ownership & Rules
- **Core Engine:** Changes to `packages/core` require rigorous regression testing and approval from the Core Security team.
- **No Platform-Specific Code in Core:** Core modules must rely on interfaces (e.g., generic Storage Interface) injected by the host app (Mobile/Desktop/Web) to ensure true portability.
- **ML Models:** Binary `.onnx` or `.tflite` models are tracked via Git LFS.

## 4. Build System & CI/CD
- **Build Tool:** Turborepo for aggressive caching of TypeScript and Rust compilation.
- **CI Pipeline:**
  1. Linting & Formatting.
  2. Unit Tests (`packages/*`).
  3. Integration Tests (`apps/*` integrating `packages/*`).
  4. Platform Builds (Webpack, Metro, Tauri Build).
  5. Artifact generation and automated privacy audits (network traffic simulation).
