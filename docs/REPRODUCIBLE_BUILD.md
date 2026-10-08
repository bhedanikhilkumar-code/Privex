# REPRODUCIBLE BUILD SPECIFICATION
## PRIVEX — Production Release v0.1.0

> **DOCUMENT ID:** `docs/REPRODUCIBLE_BUILD.md`  
> **STANDARD:** Reproducible Builds Initiative, SLSA Level 3 Alignment  
> **DATE:** 2026-10-02  
> **CANONICAL VERSION:** `v0.1.0`  

---

## 1. PURPOSE & PRINCIPLES

A build is reproducible if given the exact same source code, environment, and build instructions, any engineer or automated system generates byte-for-byte identical distribution artifacts.

Privex guarantees:
1. **Zero Secret Requirements:** The build requires no external credentials, API keys, or cloud access tokens.
2. **Deterministic Lockfiles:** Every dependency version is cryptographically locked via `package-lock.json`.
3. **Air-Gapped Compilation:** Once dependencies are installed, compilation and test execution can proceed in a 100% network-disabled environment.

---

## 2. BUILD PREREQUISITES

| Component | Minimum Version | Certified / Tested Version | Notes |
|---|---|---|---|
| **Operating System** | Windows 10 / Ubuntu 22.04 / macOS 12 | Windows 11 x64 / Linux x64 | Cross-platform Node.js runtime |
| **Node.js** | `>= 20.0.0` (LTS) | `v22.13.0` | Active LTS release recommended |
| **npm** | `>= 10.0.0` | `10.9.2` | Supports npm workspaces |
| **Git** | `>= 2.30.0` | `2.45.0+` | Source control |
| **Python / C++ Toolchain** | Not required | None | Zero native node-gyp bindings needed for core runtime |

---

## 3. STEP-BY-STEP REPRODUCIBLE BUILD PROCEDURE

### Step 1: Clean Clone
```bash
git clone https://github.com/private-protection/private-protection.git
cd private-protection
git checkout v0.1.0
```

### Step 2: Hermetic Dependency Installation
Use `npm ci` rather than `npm install` to enforce strict compliance with `package-lock.json`:
```bash
npm ci
```

### Step 3: Static Verification Gate
Validate that source types and formatting are fully compliant before generating output:
```bash
npm run lint
npm run typecheck
```
*Expected output: Exit code 0, 0 compiler errors.*

### Step 4: Full Test Suite Execution
Execute the full 413-test regression suite across all workspaces:
```bash
npm run test:coverage
```
*Expected output: 81 test files passed, 413 tests passed, 0 failures.*

### Step 5: Production Compilation & Bundling
Compile TypeScript libraries and package client frontends:
```bash
npm run build
```
This step executes:
- `@private-protection/core`: Compiles `dist/` ES modules and type definitions via `tsc`.
- `@private-protection/ml`: Compiles `dist/` ES modules and type definitions via `tsc`.
- `@private-protection/web`: Builds client-side Vite distribution in `apps/web/dist/`.
- `@private-protection/extension`: Builds Manifest V3 extension bundle in `apps/extension/dist/`.
- `@private-protection/desktop`: Typechecks desktop security service and renderer components.
- `@private-protection/mobile`: Typechecks Android security adapter and React Native components.

### Step 6: Release Packaging & Checksum Generation
```bash
npm run package
```
Generates release archives in `release/`:
- `release/private-protection-web-0.1.0.zip`
- `release/private-protection-extension-0.1.0.zip`
- `release/SHA256SUMS.txt`

---

## 4. ARTIFACT VERIFICATION & CHECKSUMS

To verify that generated archives match official release signatures:

### On Windows (PowerShell):
```powershell
Get-FileHash -Algorithm SHA256 release\*.zip
```

### On Linux / macOS:
```bash
sha256sum -c release/SHA256SUMS.txt
```

---

## 5. ENVIRONMENT INDEPENDENCE GUARANTEES

- **Timestamp Normalization:** Build scripts avoid non-deterministic timestamp injection into bundle outputs where possible.
- **Path Neutrality:** All workspace aliases (`@/`, `buffer`, `crypto`) are resolved via relative Vite/TypeScript configs rather than absolute filesystem paths.
- **Fail-Closed Verification:** If any build step or test fails, the CI/CD pipeline immediately terminates and aborts artifact publication.
