# BUILD_ARCHITECTURE.md — Multi-Platform Build System, Packaging & Release Security

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION BUILD ARCHITECTURE**  
> This document specifies the multi-platform build toolchains, cross-compilation pipelines, reproducible builds, Software Bill of Materials (SBOM), code signing, and release channels across all deployment targets.

---

## 1. MULTI-PLATFORM BUILD PIPELINE TOPOLOGY

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ SOURCE REPOSITORY (MONOREPO ROOT: TURBOREPO + NPM WORKSPACES)                                         │
│                                                                                                        │
│   packages/core/ (TypeScript / AssemblyScript / C-ABI)                                                 │
│       ├── Node.js / ESM Bundle (tsc / esbuild) ──────────► packages/core/dist/esm                     │
│       ├── WebAssembly Bundle (asc / emcc) ──────────────► packages/core/dist/wasm/engine.wasm         │
│       └── Native C-ABI Static Lib (cargo / rustc) ───────► target/release/libprivate_protection.a      │
└───────────┬────────────────────────────┬─────────────────────────────┬─────────────────────────────────┘
            │                            │                             │
            ▼                            ▼                             ▼
┌───────────────────────┐    ┌───────────────────────┐    ┌────────────────────────┐    ┌────────────────┐
│ BROWSER EXTENSION     │    │ DESKTOP CLIENT        │    │ MOBILE CLIENT          │    │ WEB DASHBOARD  │
│ (Vite / TypeScript)   │    │ (Tauri 2.x / Rust)    │    │ (Flutter 3.x / Dart)   │    │ (Next.js SSG)  │
│                       │    │                       │    │                        │    │                │
│ Embeds:               │    │ Embeds:               │    │ Embeds:                │    │ Embeds:        │
│ • engine.wasm         │    │ • libprivate_prot.a   │    │ • libprivate_prot.so   │    │ • engine.wasm  │
│ • threats.bf          │    │ • threats.bf          │    │ • threats.bf           │    │ • threats.bf   │
└───────────┬───────────┘    └───────────┬───────────┘    └───────────┬────────────┘    └───────┬────────┘
            │                            │                             │                        │
            ▼ Packaging                  ▼ Packaging                   ▼ Packaging              ▼
┌───────────────────────┐    ┌───────────────────────┐    ┌────────────────────────┐    ┌────────────────┐
│ Chrome / Firefox Zip  │    │ Win .msi / Mac .dmg   │    │ Android .aab / iOS.ipa │    │ Static CDN     │
│ (Web Store Signing)   │    │ (EV Code Signing)     │    │ (Store App Signing)    │    │ (HTTPS Origin) │
└───────────────────────┘    └───────────────────────┘    └────────────────────────┘    └────────────────┘
```

---

## 2. BUILD TOOLCHAIN MATRIX

| Target Subsystem | Build Tool / Compiler | Target Output Artifact | Required Toolchain |
|---|---|---|---|
| **Core TypeScript Engine** | `tsc` + `tsup` / `esbuild` | CommonJS & ESM bundles (`.mjs`, `.d.ts`) | Node.js 18+ |
| **Core WebAssembly Engine**| `emcc` / `asc` (AssemblyScript)| `engine.wasm` (SIMD + Memory Bounds) | Emscripten / asc |
| **Browser Extension** | `vite build` | MV3 Zip (`chrome-mv3.zip`, `firefox-mv3.zip`) | Node.js 18+ |
| **Desktop (Windows)** | `cargo tauri build` | Signed `.msi` and `.exe` installers | Rust 1.75+, MSVC, WiX |
| **Desktop (macOS)** | `cargo tauri build` | Signed & Notarized `.dmg` / `.app` | Rust 1.75+, Xcode, clang |
| **Mobile (Android)** | `flutter build appbundle` | Android `.aab` / `.apk` | Flutter 3.x, Android SDK/NDK |
| **Mobile (iOS)** | `flutter build ipa` | iOS `.ipa` | Flutter 3.x, Xcode 15+ |
| **Web Dashboard** | `next build` (`output: 'export'`) | Static HTML/JS/CSS/WASM directory | Node.js 18+ |

---

## 3. REPRODUCIBLE BUILDS & SUPPLY CHAIN SECURITY (SLSA LEVEL 3)

To protect users against supply chain attacks, builds adhere to **Supply-chain Levels for Software Artifacts (SLSA) Level 3**:
1. **Hermetic & Isolated Builds**: CI workflows execute on ephemeral GitHub Actions runners without ambient network credentials.
2. **Pinned Dependency Trees**: All `package.json` dependencies use exact version pins. `npm ci` strictly validates against `package-lock.json`.
3. **Automated Software Bill of Materials (SBOM)**: Every release build automatically generates a cryptographically signed CycloneDX / SPDX JSON SBOM documenting every dependency and hash.
4. **Binary Reproducibility**: Build flags enforce deterministic output:
   - Clang/Rust: `-C link-arg=-Wl,--build-id=none` and zero timestamps in archive headers.
   - Any engineer building from the identical git commit hash produces byte-for-byte identical binaries.

---

## 4. CODE SIGNING & NOTARIZATION ARCHITECTURE

Every distributed client binary is signed with official cryptographic certificates:

### 4.1 Windows Desktop
- **Primitive**: Authenticode Extended Validation (EV) Code Signing.
- **Hardware Protection**: Private key stored on an air-gapped Cloud HSM token.
- **Timestamping**: RFC 3161 compliant timestamp server ensuring binary remains valid after certificate expiration.

### 4.2 macOS Desktop
- **Primitive**: Apple Developer ID Application Certificate.
- **Notarization**: Apple `notarytool` automated submission verifying binary passes Gatekeeper Hardened Runtime checks without warnings.

### 4.3 Mobile Platforms
- **Android**: Google Play App Signing with upload key rotation.
- **iOS**: Apple Distribution Certificate managed via Fastlane and Xcode.

### 4.4 In-Band Updates
- **Primitive**: Ed25519 signatures verified against the embedded Root Key (as specified in `docs/UPDATE_SECURITY_ARCHITECTURE.md`).

---

## 5. RELEASE CHANNELS & PROMOTION LIFECYCLE

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ RELEASE CHANNEL PROGRESSION                                                            │
│                                                                                        │
│   [NIGHTLY / ALPHA] ──────────► [BETA / STAGING] ──────────► [GENERAL AVAILABILITY]    │
│   • Internal CI builds          • Opt-in dogfooding          • Broad public rollout     │
│   • Automated synthetic tests   • 7-day canary bake period   • 100% test & audit signoff│
│   • Bleeding-edge rulesets      • Strict false positive audit • Zero known regressions   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
