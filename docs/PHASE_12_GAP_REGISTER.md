# PHASE 12 GAP REGISTER

> **Document Status:** CANONICAL PHASE 12 AUDIT ARTIFACT  
> **Evaluation Date:** 2026-10-02  
> **Audit Team:** Phase 12 Full Product Validation Committee (12 Independent Subagents)  
> **Taxonomy:** All entries represent empirically verified architectural, runtime, security, or implementation findings.

---

## 1. Complete Gap Register Summary Table

| Gap ID | Severity | Category | Affected Component | Summary | Status |
|---|---|---|---|---|---|
| **GAP-01** | **CRITICAL** | Security / Vulnerability | `apps/desktop/src/services/update-verifier.service.ts` | Ed25519 signature verification bypassed; accepted arbitrary dummy bytes | **CLOSED (Phase 9)** |
| **GAP-02** | **HIGH** | Architecture / ML | `packages/ml/src/models/onnx-provider.ts` | Deceptive embedding telemetry; missing runtime dependencies | **CLOSED (Phase 9)** |
| **GAP-03** | **HIGH** | Completeness / Platform | `apps/mobile/` | Mobile native implementation: missing web assets in APK, unencrypted storage mismatch, missing QR frame decoder | **CLOSED (Phase 10)** |
| **GAP-04** | **HIGH** | Completeness / Platform | `apps/desktop/` | Native Electron runtime, real filesystem scanning, real-time shield, settings, and safe quarantine | **CLOSED (Phase 11)** |
| **GAP-05** | **HIGH** | Security / Cryptography | `apps/desktop/src/services/quarantine.service.ts` | Quarantine vault single-byte XOR `0xA5` obfuscation replaced with `AES-256-GCM` (`PPVAULT1`) | **CLOSED (Phase 9)** |
| **GAP-06** | **MEDIUM** | Security / Storage | `apps/desktop/src/services/secure-storage.service.ts` | Desktop settings key derived without salt or PBKDF2; replaced with PBKDF2 100k rounds | **CLOSED (Phase 9)** |
| **GAP-07** | **MEDIUM** | Consistency / Detection | Cross-Platform Client Adapters | Semantic verdict & threshold divergence on borderline scores | **CLOSED (Phase 9)** |
| **GAP-08** | **MEDIUM** | Domain Model / Contracts | Core, Desktop, Mobile | Fragmented file analysis; unified in canonical `CoreFileAnalyzer` in `@private-protection/core` | **CLOSED (Phase 11)** |
| **GAP-09** | **MEDIUM** | Detection Scoring | `packages/core/src/analyzers/text.analyzer.ts` | Extortion & urgent crypto scam scored as 69 (CAUTION) instead of DANGEROUS | **CLOSED (Phase 9)** |
| **GAP-10** | **LOW** | Architecture / Backend | `apps/backend/` | OHTTP Privacy Relay & Stateless CDN backend not implemented | **DOCUMENTED OPTIONAL** |
| **GAP-11** | **MEDIUM** | Extension / Packaging | `apps/extension/` | Extension build script did not emit self-contained `dist/` unpacked bundle | **CLOSED (Phase 9)** |
| **GAP-12** | **MEDIUM** | Build / Desktop Packaging | `apps/desktop/` | `npm run build` (`tsc --noEmit`) and `npm run package` (`PrivateProtection.exe`) both exit 0 | **CLOSED (Phase 11)** |
| **GAP-13** | **HIGH** | Build / TypeScript | `apps/desktop/src/ipc/ipc-channels.ts`, `electron-preload.ts` | Defined `REALTIME_THREAT_EVENT` and separated `IPC_INVOKE_CHANNELS` vs `IPC_EVENT_CHANNELS` | **CLOSED (Phase 11)** |
| **GAP-14** | **HIGH** | Runtime / Real-Time Shield | `apps/desktop/src/ipc/ipc-handler.ts`, `preload.ts`, `App.tsx` | Wired `RealtimeMonitorService` detections to IPC, UI alert banner, and conditional `autoQuarantineCritical` | **CLOSED (Phase 11)** |
| **GAP-15** | **MEDIUM** | Runtime / Settings | `apps/desktop/src/services/*` | Validated, persisted, and enforced all `DesktopSettings` at runtime across scanning engines | **CLOSED (Phase 11)** |
| **GAP-16** | **MEDIUM** | Security / IPC | `apps/desktop/src/ipc/ipc-handler.ts`, `quarantine.service.ts` | Enforced threat verdict policy (`QUARANTINE_POLICY_REJECTED` for benign files), symlink and OS path protection | **CLOSED (Phase 11)** |
| **GAP-17** | **LOW** | Documentation Drift | `README.md`, `docs/PRODUCT_SCOPE.md`, `docs/MASTER_TRACEABILITY_MATRIX.md` | Synchronized documentation with `AES-256-GCM` (`PPVAULT1`), `CoreFileAnalyzer`, and Electron `44.5.1` | **CLOSED (Phase 11)** |
| **GAP-18** | **HIGH** | Completeness / False Success | `apps/mobile/src/screens/FileScannerScreen.tsx:15-95` | Mobile File Scanner uses 3 simulated buttons with hardcoded bytes; lacks real Android SAF document picker | **CLOSED (Remediated in Master Prompt #28)** |
| **GAP-19** | **LOW** | Integration / UI Telemetry | `apps/mobile/src/screens/HomeScreen.tsx:18-19` | Mobile device security posture card evaluates static un-connected baseline without native Android bridge | **CLOSED (Remediated in Master Prompt #28)** |
| **GAP-20** | **MEDIUM** | Architecture / ML Model | `packages/ml/src/models/providers/onnx-provider.ts:65-98` | On-device ML classifiers rely 100% on deterministic templates and regex rules; ONNX model weights absent | **OPEN (INHERITED GAP-02)** |
| **GAP-21** | **LOW** | Architecture / Cloud | `apps/backend/` | Stateless CDN and RFC 9458 OHTTP Privacy Relay absent from repo | **OPEN (INHERITED GAP-10)** |
| **GAP-22** | **CRITICAL** | Security / Core Risk Engine | `packages/core/src/scoring/risk-scorer.ts:82-142`, `pipeline/detection-pipeline.ts:116-153` | NaN score poisoning bypasses thresholds to `ALLOW`; malformed/empty input violates fail-closed doctrine | **CLOSED (Remediated in Master Prompt #28)** |
| **GAP-23** | **HIGH** | Security / Extension IPC | `apps/extension/src/background/message-router.ts:67-116` | Extension `MessageRouter` does not verify `sender`; untrusted web content scripts can call administrative handlers | **CLOSED (Remediated in Master Prompt #28)** |
| **GAP-24** | **MEDIUM** | Security / Desktop Quarantine | `apps/desktop/src/services/quarantine.service.ts:206-212` | Quarantine custom restore joins `item.fileName` without `path.basename()` normalization | **CLOSED (Remediated in Master Prompt #28)** |

---

## 2. Detailed New Gap Records (GAP-18 through GAP-24)

### GAP-18: Mobile File Scanner Uses Hardcoded Simulations Instead of Real Storage Access Framework (SAF)
- **Severity:** **HIGH** (Completeness / False Success)
- **Requirement Tracing:** PS-05.4 (Malicious Content Detection on Mobile), PP-016 (Native Mobile Application).
- **Files Affected:** `apps/mobile/src/screens/FileScannerScreen.tsx:15-95`, `apps/mobile/android/app/src/main/java/com/privateprotection/mobile/MainActivity.java`.
- **Empirical Evidence:**
  ```tsx
  // apps/mobile/src/screens/FileScannerScreen.tsx lines 15-23:
  const simulateFileScan = (fileName: string, mime: string, header: number[]) => {
    const inspection = scannerService.inspectFile({
      name: fileName,
      sizeBytes: header.length * 1024,
      mimeType: mime,
      headerBytes: header
    });
    setResult(inspection);
  };
  ```
  Lines 49, 65, and 81 render three static `<button>` elements passing static byte arrays (`invoice_document.pdf.exe`, `classes.dex`, `report.pdf`). Line 42 renders:
  `<span>Single-file scoped analysis via Android Storage Access Framework</span>`.
  In `MainActivity.java`, there are zero methods handling `Intent.ACTION_OPEN_DOCUMENT` or file picking.
- **Impact:** An end user holding an Android device cannot select, pick, or scan any real file from their storage. While `FileScannerService` correctly invokes `CoreFileAnalyzer`, the UI is purely an interactive demo benchmark.
- **Root Cause:** A test UI prototype was committed during Phase 6 and was never connected to an HTML5 `<input type="file">` or native SAF bridge.
- **Recommended Remediation:**
  1. Add an `<input type="file" accept="*/*" onChange={handleFileSelected} />` to `FileScannerScreen.tsx` that reads up to 8,192 header bytes via `FileReader.readAsArrayBuffer()`.
  2. Alternatively, expose `openDocumentPicker()` on `AndroidSecurityBridge` via `ActivityResultLauncher<Intent>`.

---

### GAP-19: Mobile Device Posture Security Audit Evaluates Static Unconnected Baseline
- **Severity:** **LOW** (UI Telemetry / Polish)
- **Requirement Tracing:** PP-016 (Native Mobile Application).
- **Files Affected:** `apps/mobile/src/screens/HomeScreen.tsx:18-19`, `apps/mobile/src/services/device-audit.service.ts:16-22`.
- **Empirical Evidence:**
  ```typescript
  // apps/mobile/src/screens/HomeScreen.tsx:
  const auditService = new DeviceAuditService();
  setPosture(auditService.auditSecurityPosture());
  ```
  `auditSecurityPosture()` accepts an optional `DeviceSystemSettings` parameter. When omitted, it defaults to `developerOptionsEnabled: false`, `adbDebuggingEnabled: false`, `screenLockConfigured: true`, `mockLocationsEnabled: false`, `unknownSourcesEnabled: false`. `AndroidSecurityBridge` lacks methods to query native Android `Settings.Global`.
- **Impact:** The mobile home screen posture card always displays a static "HEALTHY" baseline regardless of actual device settings.
- **Root Cause:** Native bridge telemetry was never connected between `MainActivity.java` and `HomeScreen.tsx`.
- **Recommended Remediation:** Implement `@JavascriptInterface public String getDeviceSecurityPosture()` in `MainActivity.java` querying `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`, `Settings.Global.ADB_ENABLED`, and `KeyguardManager.isDeviceSecure()`.

---

### GAP-20: ML Model Layer Relies Exclusively on Deterministic Lexical Fallback
- **Severity:** **MEDIUM** (Documented Platform Scope)
- **Requirement Tracing:** PP-012, PP-013 (Quantized SLM & Neural Classifiers).
- **Files Affected:** `packages/ml/src/models/providers/onnx-provider.ts:65-98`, `packages/ml/src/assistant/assistant-runtime.ts:141-152`.
- **Empirical Evidence:**
  No `.onnx` weight binaries exist in the monorepo. `OnnxModelProvider.load()` wraps dynamic imports in `catch()` and defaults to `loaded = false`. Classifiers and the assistant synthesize explanations via `TemplateFallback.generate()` with `inferenceStatus: 'DETERMINISTIC_FALLBACK'`.
- **Impact:** The system operates purely on deterministic rules and pre-compiled templates.
- **Status:** Satisfies low-latency ($<0.05\text{ ms}$) and 100% offline air-gapped parity, but neural weights are absent.

---

### GAP-21: Stateless Backend & OHTTP Privacy Relay Not Implemented
- **Severity:** **LOW** (Documented Optional Infrastructure)
- **Requirement Tracing:** PP-025 (Stateless CDN / OHTTP Relay).
- **Files Affected:** Repository root lacks `apps/backend/`.
- **Impact:** Client applications cannot poll remote OTA update feeds or transmit differential privacy telemetry via Oblivious HTTP.
- **Status:** All detection and security features operate 100% air-gapped locally on the endpoint.

---

### GAP-22: NaN Score Poisoning and Fail-Closed Violation in Core Risk Engine (SEC-01 / SEC-02)
- **Severity:** **CRITICAL** (Security / Constitutional Violation)
- **Requirement Tracing:** AGENTS.md Section 6 & 8.4 (Fail-Closed Principle), PS-05.6 (Risk Scoring).
- **Files Affected:** `packages/core/src/scoring/risk-scorer.ts:82-142, 241-251`, `packages/core/src/pipeline/detection-pipeline.ts:116-153`.
- **Empirical Evidence:**
  1. In `risk-scorer.ts:82`, `rawScore` is assigned with `typeof e.scoreContribution === 'number'`. In JavaScript, `typeof NaN === 'number'`. If a detector emits `NaN`, `calculatedScore` evaluates to `NaN`. All threshold checks (`>= 85`, `>= 70`, `>= 50`, `>= 20`) evaluate to `false`, causing execution to fall into the `else` block:
     ```typescript
     verdict = Verdict.ALLOW;
     category = RiskCategory.SAFE;
     recommendation = ActionRecommendation.ALLOW;
     ```
  2. In `detection-pipeline.ts:116-153`, empty or invalid `rawInput` returns `verdict: Verdict.ALLOW` with `score: 0`.
- **Vulnerability Impact:** A detector malfunction or crafted input producing `NaN` forces an unauthenticated `ALLOW` verdict on an active threat (fail-open). Empty or corrupted inputs fail to silent `ALLOW`.
- **Recommended Remediation:**
  1. Add `Number.isFinite()` checks in `risk-scorer.ts`:
     ```typescript
     if (Number.isNaN(calculatedScore) || !Number.isFinite(calculatedScore)) {
       calculatedScore = 75;
       verdict = Verdict.SUSPICIOUS;
       category = RiskCategory.SUSPICIOUS;
     }
     ```
  2. In `detection-pipeline.ts`, return `Verdict.CAUTION` (score: 50) on empty/malformed inputs.

---

### GAP-23: Unauthenticated IPC Privilege Abuse in Extension MessageRouter (SEC-03)
- **Severity:** **HIGH** (Security / Extension Boundary)
- **Requirement Tracing:** PP-018 (Browser Extension MV3 Security).
- **Files Affected:** `apps/extension/src/background/message-router.ts:67-116`.
- **Empirical Evidence:**
  `chrome.runtime.onMessage` handles messages from content scripts injected into `<all_urls>`. In `message-router.ts`, handlers for `UPDATE_SETTINGS`, `CLEAR_ALL_DATA`, and `REQUEST_OVERRIDE` do not inspect `sender`.
- **Vulnerability Impact:** Any malicious website running JavaScript in a tab can invoke:
  ```javascript
  chrome.runtime.sendMessage({ id: 'attack-1', type: 'CLEAR_ALL_DATA', payload: {}, timestamp: Date.now() });
  ```
  or `UPDATE_SETTINGS` to disable shields or add attacker domains to the extension allowlist.
- **Recommended Remediation:**
  Add sender authorization in `message-router.ts`:
  ```typescript
  const isPrivilegedSender = !sender.tab && sender.id === chrome.runtime.id;
  if (!isPrivilegedSender) {
    return { success: false, error: 'UNAUTHORIZED_SENDER: Privileged operation restricted to extension UI.' };
  }
  ```

---

### GAP-24: Quarantine Path Traversal on Custom Destination Restore (SEC-04)
- **Severity:** **MEDIUM** (Security / Desktop Filesystem)
- **Requirement Tracing:** PP-017 (Native Desktop Client / Quarantine Vault).
- **Files Affected:** `apps/desktop/src/services/quarantine.service.ts:206-212`, `apps/desktop/src/ipc/ipc-validator.ts:223`.
- **Empirical Evidence:**
  `quarantine.service.ts:211` joins `destinationPath = path.join(canonicalDestDir, item.fileName);`. `item.fileName` originates from `threat.fileName`, which is only length-truncated in `ipc-validator.ts:223` without `path.basename()`. Additionally, `canonicalDestDir.includes('..')` is a dead check because `path.resolve` strips relative segments.
- **Vulnerability Impact:** If a threat record contains relative directory components (`../../payload.exe`), custom destination restore could escape the target directory.
- **Recommended Remediation:**
  Enforce `destinationPath = path.join(canonicalDestDir, path.basename(item.fileName));` and assert `destinationPath.startsWith(canonicalDestDir + path.sep)`.
