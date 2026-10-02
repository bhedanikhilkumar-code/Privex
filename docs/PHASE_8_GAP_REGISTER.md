# PHASE 8 GAP REGISTER

> **Document Status:** CANONICAL PHASE 8 AUDIT ARTIFACT  
> **Evaluation Date:** 2026-10-02  
> **Audit Team:** Phase 8 Independent Red-Team & Validation Committee  
> **Taxonomy:** All entries represent empirically verified architectural, security, or implementation gaps.

---

## Gap Summary Table

| Gap ID | Severity | Category | Affected Component | Summary | Status |
|---|---|---|---|---|---|
| **GAP-01** | **CRITICAL** | Security / Vulnerability | `apps/desktop/src/services/update-verifier.service.ts` | Ed25519 signature verification bypassed; accepts arbitrary dummy bytes | **CLOSED (Remediated in Phase 9)** |
| **GAP-02** | **HIGH** | Architecture / ML | `packages/ml/src/models/onnx-provider.ts` | Zero ONNX models in repo; missing runtime dependencies; deceptive regex telemetry | **CLOSED (Remediated in Phase 9)** |
| **GAP-03** | **HIGH** | Completeness / Platform | `apps/mobile/` | Mobile native implementation: compiled APK missing web assets, unencrypted storage mismatch, missing QR frame decoder | **CLOSED (Remediated & Re-Audit Passed)** |
| **GAP-04** | **HIGH** | Completeness / Platform | `apps/desktop/` | Native Electron runtime, real filesystem scanning, real-time shield IPC/UI, settings enforcement, and safe quarantine verified | **CLOSED (Remediated in Phase 11)** |
| **GAP-05** | **HIGH** | Security / Cryptography | `apps/desktop/src/services/quarantine.service.ts` | Quarantine vault uses single-byte XOR `0xA5` obfuscation instead of AES-256-GCM | **CLOSED (Remediated in Phase 9)** |
| **GAP-06** | **MEDIUM** | Security / Storage | `apps/desktop/src/services/secure-storage.service.ts` | Desktop settings key derived from unsalted `hostname + username` without OS Keystore | **CLOSED (Remediated in Phase 9)** |
| **GAP-07** | **MEDIUM** | Consistency / Detection | Cross-Platform Client Adapters | Semantic verdict & threshold divergence (empty input, borderline scores) | **CLOSED (Remediated in Phase 9)** |
| **GAP-08** | **MEDIUM** | Domain Model / Contracts | Core, Desktop, Mobile | Canonical `CoreFileAnalyzer` implemented in `@private-protection/core` and consumed by Desktop and Mobile | **CLOSED (Remediated in Phase 11)** |
| **GAP-09** | **MEDIUM** | Detection Scoring | `packages/core/src/analyzers/text.analyzer.ts` | Extortion & urgent cryptocurrency scam scored as 69 (CAUTION) instead of DANGEROUS | **CLOSED (Remediated in Phase 9)** |
| **GAP-10** | **LOW** | Architecture / Backend | `apps/backend/` | OHTTP Privacy Relay & Stateless CDN backend not implemented | **DOCUMENTED OPTIONAL** |
| **GAP-11** | **MEDIUM** | Extension / Packaging | `apps/extension/` | Extension build script did not emit self-contained `dist/` unpacked bundle | **CLOSED (Remediated in Phase 9)** |
| **GAP-12** | **MEDIUM** | Build / Desktop Packaging | `apps/desktop/` | `npm run build` (`tsc --noEmit`) and `npm run package` (`PrivateProtection.exe`) both succeed with exit code `0` | **CLOSED (Remediated in Phase 11)** |
| **GAP-13** | **HIGH** | Build / TypeScript | `apps/desktop/src/ipc/ipc-channels.ts`, `electron-preload.ts` | Defined `REALTIME_THREAT_EVENT` and separated `IPC_INVOKE_CHANNELS` vs `IPC_EVENT_CHANNELS`; `tsc --noEmit` passes | **CLOSED (Remediated in Phase 11)** |
| **GAP-14** | **HIGH** | Runtime / Real-Time Shield | `apps/desktop/src/ipc/ipc-handler.ts`, `preload.ts`, `App.tsx` | Wired `RealtimeMonitorService` detections to IPC, UI alert banner, and conditional `autoQuarantineCritical` isolation | **CLOSED (Remediated in Phase 11)** |
| **GAP-15** | **MEDIUM** | Runtime / Settings | `apps/desktop/src/services/*` | Validated, persisted, and enforced all `DesktopSettings` at runtime across `ScannerService` and `RealtimeMonitorService` | **CLOSED (Remediated in Phase 11)** |
| **GAP-16** | **MEDIUM** | Security / IPC | `apps/desktop/src/ipc/ipc-handler.ts`, `quarantine.service.ts` | Enforced threat verdict/severity policy (`QUARANTINE_POLICY_REJECTED` for benign files), symlink defense, and OS path protection | **CLOSED (Remediated in Phase 11)** |
| **GAP-17** | **LOW** | Documentation Drift | `README.md`, `docs/PRODUCT_SCOPE.md`, `docs/MASTER_TRACEABILITY_MATRIX.md` | Synchronized documentation with `AES-256-GCM` (`PPVAULT1`), `CoreFileAnalyzer`, and Electron `44.5.1` | **CLOSED (Remediated in Phase 11)** |

---

## Detailed Gap Records

### GAP-01: UpdateVerifier Accepts Any Fake Signature (CRITICAL)
- **Requirement Tracing:** PP-020 (Cryptographically signed OTA updates).
- **File & Line:** `apps/desktop/src/services/update-verifier.service.ts` lines 48–56.
- **Empirical Evidence:**
  ```typescript
  // Actual Code in update-verifier.service.ts:
  public async verifyUpdate(manifest: UpdateManifest, _expectedRootKey: string): Promise<{ valid: boolean; reason?: string }> {
    if (!manifest.signature || manifest.signature.length < 32) {
      return { valid: false, reason: 'Invalid or missing signature format' };
    }
    // Signature verified against embedded root public key
    return { valid: true };
  }
  ```
- **Vulnerability Impact:** Remote code execution / binary substitution. Any attacker modifying the manifest or update payload with a 32-character dummy string (e.g. `'deadbeefdeadbeefdeadbeefdeadbeef'`) bypasses update verification completely.
- **Root Cause:** A placeholder stub was committed during Phase 6 and was never replaced with real calls to `packages/core/src/utils/crypto.ts:verifyEd25519Signature`.
- **Recommended Remediation:** Call `verifyEd25519Signature(manifest.packageHash, manifest.signature, expectedRootKey)` using `@noble/ed25519` or Node.js `crypto.verify`.

---

### GAP-02: Zero Trained ML Models & Deceptive Embedding Telemetry (HIGH)
- **Requirement Tracing:** PP-012, PP-013 (Quantized SLM & Neural Semantic Classifiers).
- **Files Affected:**
  - `packages/ml/src/models/onnx-provider.ts`
  - `packages/ml/src/classifiers/url-semantic.classifier.ts`
- **Empirical Evidence:**
  - File search across the entire repository reveals **zero `.onnx` files**.
  - `package.json` across all workspaces does not list `onnxruntime-node` or `onnxruntime-web`.
  - `OnnxModelProvider.load()` wraps dynamic imports in `catch()` and defaults to `isLoaded = false`.
  - `UrlSemanticClassifier.classify()` contains:
    ```typescript
    evidenceTokens.push({
      token: 'suspicious-semantic-path',
      description: 'Semantic embedding detected brand name combined with credential theft action path',
      weight: 35
    });
    ```
    This evidence token claims a "semantic embedding" was computed, when in fact it is purely evaluated via `RegExp.test()`.
- **Impact:** System relies 100% on regex heuristics while misinforming users and developers that neural embeddings are executing.
- **Recommended Remediation:** Either bundle genuine quantized mini-models (e.g. TinyBERT/MiniLM ONNX quantized < 5MB) or update the documentation and evidence tokens to honestly reflect deterministic lexical pattern matching.

---

### GAP-03: Mobile Native Implementation Blockers (HIGH) — CLOSED
- **Requirement Tracing:** PP-016 (Native Mobile App).
- **Files Affected:** `apps/mobile/`
- **Audit History:**
  - `AUDIT-PHASE-10-MOBILE-001` (October 2, 2026): **FAILED**. Identified missing web assets in APK, unencrypted `SharedPreferences` mismatch, missing camera QR frame decoder, bridge security exposure, and cold-start race conditions.
  - `REPORT-PHASE-10-REMEDIATION-001` (October 2, 2026): Remediated all 5 defects via Vite build/sync pipeline, `SecureStorageManager` with Android Keystore AES-256-GCM, ZXing 3.5.3 CV QR decoder, `WebViewAssetLoader` virtual host origin isolation, and atomic pending intent queue.
  - `AUDIT-PHASE-10-MOBILE-REAUDIT-002` (October 2, 2026): **PASSED**. Empirical on-device verification on Android 17 emulator (`Medium_Phone`, API 37 x86_64). APK contains web assets (`7.42 MB`, SHA-256 `99B8828E...`), storage XML confirmed Tink encrypted (`AesSivKey`/`AesGcmKey`, zero plaintext), ZXing decodes camera frames, 8 JVM unit tests + 2 on-device connected instrumentation tests + 56 Vitest tests passing.
- **Status:** **CLOSED (Remediated & Re-Audit Passed)**.

---

### GAP-04: Desktop Client Native Runtime & Real Filesystem Scanning (HIGH) — CLOSED
- **Requirement Tracing:** PP-017 (Native Desktop Client), PS-05.4 (Malicious Content & Filesystem Detection).
- **Files Affected:**
  - `apps/desktop/src/main/electron-main.ts`
  - `apps/desktop/src/preload/electron-preload.ts`, `preload.ts`
  - `apps/desktop/src/ipc/ipc-handler.ts`, `ipc-validator.ts`, `ipc-channels.ts`
  - `apps/desktop/src/renderer/App.tsx`, `FullScanScreen.tsx`, `QuickScanScreen.tsx`, `CustomScanScreen.tsx`, `SettingsScreen.tsx`
- **Audit & Remediation History:**
  - `PHASE-11-IMPLEMENTATION` (October 2, 2026): Implemented Electron `44.5.1` host (`electron-main.ts`), `contextBridge` preload (`electron-preload.ts`), `IpcValidator` path checks, live `SCAN_PROGRESS_EVENT` streaming, and packaged `PrivateProtection.exe`.
  - `PHASE-11-INDEPENDENT-REAUDIT` (`docs/PHASE_11_INDEPENDENT_DESKTOP_REAUDIT.md`, October 2, 2026): **FAILED**. Identified `GAP-13`..`GAP-17` and `GAP-08`.
  - `REPORT-PHASE-11-REMEDIATION-001` (`docs/PHASE_11_REMEDIATION_REPORT.md`, October 2, 2026): **PASSED**. Remediated all 6 defects (`GAP-13`..`GAP-17`, `GAP-08`), verified `79/79` Desktop tests + real Electron `--headless-verify` execution + `450/450` monorepo tests passing, and signed off by the independent read-only `FINAL VERIFICATION AGENT`.
- **Status:** **CLOSED (Remediated & Verified in Phase 11 Remediation)**.

---

### GAP-05: Quarantine Vault XOR 0xA5 Obfuscation vs AES-256-GCM (HIGH) — CLOSED
- **Requirement Tracing:** PP-019 (Hardware-Secured Quarantine Vault).
- **Files Affected:** `apps/desktop/src/services/quarantine.service.ts`.
- **Status:** **CLOSED (Remediated in Phase 9 — Authenticated AES-256-GCM with `PPVAULT1` header, 96-bit IV, and 128-bit auth tag)**.

---

### GAP-06: Insecure Desktop Key Derivation for Local Settings (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-022 (Secure Local Key Derivation).
- **Files Affected:** `apps/desktop/src/services/secure-storage.service.ts`.
- **Status:** **CLOSED (Remediated in Phase 9 — PBKDF2-HMAC-SHA256 with 100,000 iterations and persisted CSPRNG salt)**.

---

### GAP-07: Cross-Platform Verdict & Threshold Inconsistency (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-023 (Consistent Verdicts).
- **Files Affected:** Client adapters across Web, Extension, Mobile, Desktop.
- **Status:** **CLOSED (Remediated in Phase 9)**.

---

### GAP-08: Fragmented & Incompatible File Analyzer Models (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-018, PP-024 (File Analysis Domain Models).
- **Files Affected:** `packages/core/src/analyzers/file-analyzer.ts`, `packages/core/src/pipeline/detection-pipeline.ts`, `apps/desktop/src/core/file-analyzer.ts`, `apps/mobile/src/services/file-scanner.service.ts`.
- **Remediation Evidence (`docs/PHASE_11_REMEDIATION_REPORT.md`):**
  - Created canonical `CoreFileAnalyzer` in `packages/core/src/analyzers/file-analyzer.ts` and wired `DetectionPipeline.scanFile()` and `InputType.FILE`.
  - Refactored both Desktop (`apps/desktop/src/core/file-analyzer.ts`) and Mobile (`apps/mobile/src/services/file-scanner.service.ts`) to delegate all file header, double-extension, and Shannon byte entropy analysis and scoring to `CoreFileAnalyzer`.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.

---

### GAP-09: Extortion Message Scoring as CAUTION Instead of DANGEROUS (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-005 (Scam Message Detection).
- **Files Affected:** `packages/core/src/analyzers/text.analyzer.ts`.
- **Status:** **CLOSED (Remediated in Phase 9)**.

---

### GAP-10: Backend / OHTTP Relay Unimplemented (LOW) — DOCUMENTED OPTIONAL
- **Requirement Tracing:** PP-025 (Stateless Backend & OHTTP Relay).
- **Status:** **DOCUMENTED OPTIONAL (100% On-Device Offline Parity Verified)**.

---

### GAP-12: Desktop Build & Packaging Pipeline Incomplete Type Safety (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-017 (Desktop Build & Packaging).
- **Files Affected:** `apps/desktop/package.json`, `apps/desktop/scripts/build-desktop.js`, `apps/desktop/src/preload/electron-preload.ts`.
- **Remediation Evidence:** `npm --prefix apps/desktop run build` (`tsc --noEmit && node scripts/build-desktop.js`) and `npm --prefix apps/desktop run package` both succeed with exit code `0` and produce `PrivateProtection.exe`.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.

---

### GAP-13: Desktop TypeScript Build Failure (`TS2339: Property 'REALTIME_THREAT_EVENT' does not exist`) (HIGH) — CLOSED
- **Requirement Tracing:** PP-017, Gate 24 (Clean Build Verification).
- **Files Affected:** `apps/desktop/src/ipc/ipc-channels.ts`, `apps/desktop/src/preload/electron-preload.ts`, `apps/desktop/src/preload/preload.ts`.
- **Remediation Evidence:** Defined `REALTIME_THREAT_EVENT: 'desktop:realtime:threat-event'` in `IPC_CHANNELS`, separated `IPC_INVOKE_CHANNELS` and `IPC_EVENT_CHANNELS`, and added runtime schema validation in `preload.ts`. `tsc --noEmit` passes with zero errors.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.

---

### GAP-14: Real-Time Shield Detections Disconnected from IPC, UI, and Auto-Quarantine (HIGH) — CLOSED
- **Requirement Tracing:** PP-017, PS-05.4, PS-05.6, PS-05.8 (Real-Time Detection & Instant Warnings).
- **Files Affected:** `apps/desktop/src/ipc/ipc-handler.ts`, `apps/desktop/src/preload/preload.ts`, `apps/desktop/src/renderer/App.tsx`.
- **Remediation Evidence:** `IpcHandler` subscribes to `realtimeMonitor.on('threatDetected')`, automatically isolates critical `BLOCK` threats when `autoQuarantineCritical === true`, emits `REALTIME_THREAT_EVENT` to `webContents`, and `App.tsx` renders the real-time threat alert banner (`data-testid="realtime-threat-alert"`). Verified in real Electron `--headless-verify` runtime.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.

---

### GAP-15: Persisted Desktop Security Settings Ignored at Runtime (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-017 (Desktop User Configuration & Enforcement).
- **Files Affected:** `apps/desktop/src/ipc/ipc-validator.ts`, `apps/desktop/src/ipc/ipc-handler.ts`, `apps/desktop/src/services/scanner.service.ts`, `apps/desktop/src/services/realtime-monitor.service.ts`, `apps/desktop/src/renderer/screens/SettingsScreen.tsx`.
- **Remediation Evidence:** `IpcValidator.validateSettings()` validates all settings; `IpcHandler.applySettings()` enforces `realtimeShieldEnabled`, `monitorDownloads`, `monitorTemp`, `scanLargeFilesLimitMb`, `entropyDetectionEnabled`, `autoQuarantineCritical`, and `excludedPaths` at startup and on every save.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.

---

### GAP-16: Arbitrary Benign File Quarantine & Unlinking via IPC (MEDIUM) — CLOSED
- **Requirement Tracing:** PP-019, Gate 07 (IPC Trust Boundary & Fail-Safe Quarantine).
- **Files Affected:** `apps/desktop/src/ipc/ipc-handler.ts`, `apps/desktop/src/services/quarantine.service.ts`, `apps/desktop/src/ipc/ipc-validator.ts`.
- **Remediation Evidence:** Both `IpcHandler.handleIsolateFile()` and `QuarantineService.isolateFile()` reject symlinks (`lstat`), reject protected OS system paths (`isProtectedSystemPath`), and reject benign `ALLOW`/`INFORM` (`safe`/`low`) files with `QUARANTINE_POLICY_REJECTED`, leaving benign files untouched on disk.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.

---

### GAP-17: Documentation Drift in `README.md` & `docs/PRODUCT_SCOPE.md` (LOW) — CLOSED
- **Requirement Tracing:** Gate 02 & Gate 15 Documentation Integrity.
- **Files Affected:** `README.md`, `docs/PRODUCT_SCOPE.md`, `docs/MASTER_TRACEABILITY_MATRIX.md`.
- **Remediation Evidence:** Updated `README.md` to document `AES-256-GCM` (`PPVAULT1`) quarantine and `CoreFileAnalyzer`, updated `docs/PRODUCT_SCOPE.md` to clarify user-space desktop filesystem scanning is In-Scope, and updated `docs/MASTER_TRACEABILITY_MATRIX.md` to reference Electron `44.5.1`.
- **Status:** **CLOSED (Remediated in Phase 11 Remediation)**.
