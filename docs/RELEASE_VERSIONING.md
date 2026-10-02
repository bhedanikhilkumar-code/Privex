# RELEASE VERSIONING & SYNCHRONIZATION POLICY
## PRIVATE PROTECTION — Production Release v0.1.0

> **DOCUMENT ID:** `docs/RELEASE_VERSIONING.md`  
> **STANDARD:** Semantic Versioning 2.0.0 (SemVer)  
> **DATE:** 2026-10-02  
> **CANONICAL VERSION:** `0.1.0`  

---

## 1. CANONICAL RELEASE VERSION

Private Protection adopts a **unified lockstep versioning strategy** for all core engines, platform clients, and release documentation.

The canonical release version across the entire monorepo is:
```text
0.1.0
```

---

## 2. WORKSPACE COMPONENT VERSION MATRIX

Every package manifest and platform configuration has been normalized to the canonical version:

| Component | Manifest Path | Configured Version | Platform-Specific Identifiers | Synchronization Status |
|---|---|---|---|---|
| **Root Monorepo** | `package.json` | `0.1.0` | N/A | **SYNCHRONIZED** |
| **Detection Engine Core** | `packages/core/package.json` | `0.1.0` | Engine ABI: `1.0` | **SYNCHRONIZED** |
| **On-Device AI / ML** | `packages/ml/package.json` | `0.1.0` | Model Metadata: `1.0.0` | **SYNCHRONIZED** |
| **Web Application** | `apps/web/package.json` | `0.1.0` | PWA Cache: `v0.1.0` | **SYNCHRONIZED** |
| **Browser Extension** | `apps/extension/package.json` | `0.1.0` | `manifest.json`: `"version": "0.1.0"` | **SYNCHRONIZED** |
| **Mobile Android Client** | `apps/mobile/package.json` | `0.1.0` | `versionName: "0.1.0"`, `versionCode: 100` | **SYNCHRONIZED** |
| **Desktop Client** | `apps/desktop/package.json` | `0.1.0` | Win ProductVersion: `0.1.0.0` | **SYNCHRONIZED** |

---

## 3. SEMVER 2.0.0 SPECIFICATION ALIGNMENT

Releases adhere strictly to SemVer rules `MAJOR.MINOR.PATCH`:

1. **MAJOR (`X.y.z`):** Incremented when breaking changes occur in the `@private-protection/core` detection contract (`DetectionPipeline`, `ScanRequest`, `ScanResult`), changes to the local storage schema requiring irreversible migration, or updates to the cryptographic update verification protocol.
2. **MINOR (`x.Y.z`):** Incremented when new threat detection analyzers are added (e.g., new scam vectors, file format parsers), platform clients expand capability (e.g., desktop daemon additions), or backward-compatible API improvements occur.
3. **PATCH (`x.y.Z`):** Incremented for bug fixes, performance optimizations, memory leak mitigations, and regex heuristic refinements that do not alter the external interface contracts.

---

## 4. RELEASE TAGGING & GIT GOVERNANCE

Official Git tags must follow the pattern:
```text
v0.1.0
```
- Tags must be cryptographically signed via GPG or SSH where maintainer keys are configured.
- Release candidates for staging testing follow SemVer prerelease suffixes: `v0.1.0-rc.1`.

---

## 5. PLATFORM STORE COMPLIANCE & VERSION MAPPING

- **Google Play Store / Android (`apps/mobile`):**
  - `versionName`: `"0.1.0"` (Human-visible string)
  - `versionCode`: `100` (Monotonically increasing integer: `MAJOR * 10000 + MINOR * 100 + PATCH`)
- **Chrome Web Store / Edge Add-ons (`apps/extension`):**
  - `manifest.json`: `"version": "0.1.0"` (Strict 1-4 dot-separated integers required by Chrome MV3).
- **Windows / macOS Desktop (`apps/desktop`):**
  - Executable resource headers reflect `0.1.0.0`.
