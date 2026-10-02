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
| **GAP-04** | **HIGH** | Completeness / Platform | `apps/desktop/` | No Tauri/Electron runtime; UI mock screens return fake hardcoded scan metrics | **CLOSED (Remediated in Phase 11)** |
| **GAP-05** | **HIGH** | Security / Cryptography | `apps/desktop/src/services/quarantine.service.ts` | Quarantine vault uses single-byte XOR `0xA5` obfuscation instead of AES-256-GCM | **CLOSED (Remediated in Phase 9)** |
| **GAP-06** | **MEDIUM** | Security / Storage | `apps/desktop/src/services/secure-storage.service.ts` | Desktop settings key derived from unsalted `hostname + username` without OS Keystore | **CLOSED (Remediated in Phase 9)** |
| **GAP-07** | **MEDIUM** | Consistency / Detection | Cross-Platform Client Adapters | Semantic verdict & threshold divergence (empty input, borderline scores) | **CLOSED (Remediated in Phase 9)** |
| **GAP-08** | **MEDIUM** | Domain Model / Contracts | Core, Desktop, Mobile | File analysis models are incompatible and fragmented across packages | **CLOSED (Remediated in Phase 9)** |
| **GAP-09** | **MEDIUM** | Detection Scoring | `packages/core/src/analyzers/text.analyzer.ts` | Extortion & urgent cryptocurrency scam scored as 69 (CAUTION) instead of DANGEROUS | **CLOSED (Remediated in Phase 9)** |
| **GAP-10** | **LOW** | Architecture / Backend | `apps/backend/` | OHTTP Privacy Relay & Stateless CDN backend not implemented | **DOCUMENTED OPTIONAL** |

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
  - `apps/desktop/src/preload/electron-preload.ts`
  - `apps/desktop/src/ipc/ipc-handler.ts` & `ipc-validator.ts`
  - `apps/desktop/src/renderer/App.tsx`, `FullScanScreen.tsx`, `QuickScanScreen.tsx`, `CustomScanScreen.tsx`
- **Remediation Summary (Phase 11 — October 2, 2026):**
  - Implemented a hardened Electron `44.5.1` native host (`electron-main.ts`) with `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, strict CSP headers, and external navigation blocking.
  - Wired `electron-preload.ts` via `contextBridge.exposeInMainWorld('desktopSecurity', Object.freeze(api))` to all 19 canonical `IPC_CHANNELS`.
  - Hardened `IpcValidator` against `..` parent traversal, remote UNC shares (`\\server\share`), shell metacharacters, null bytes, and untrusted renderer origins.
  - Connected `ScannerService` live `'progress'` events to `SCAN_PROGRESS_EVENT` in the renderer and removed hardcoded `filesScannedTotal = 142` and fake quarantine fallbacks.
  - Built and packaged the standalone Windows x64 executable `PrivateProtection.exe` (`245,726,208` bytes, SHA-256 `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa`) and verified live filesystem scanning, threat detection, and AES-256-GCM quarantine/restore in `PrivateProtection.exe --headless-verify` and `desktop-runtime-e2e.test.ts` (`71/71` desktop tests passing).
- **Status:** **CLOSED (Remediated & Verified in Phase 11)**.

---

### GAP-05: Quarantine Vault XOR 0xA5 Obfuscation vs AES-256-GCM (HIGH)
- **Requirement Tracing:** PP-019 (Hardware-Secured Quarantine Vault).
- **Files Affected:** `apps/desktop/src/services/quarantine.service.ts` lines 86–92.
- **Empirical Evidence:**
  ```typescript
  private scrambleBytes(buffer: Buffer): Buffer {
    const scrambled = Buffer.alloc(buffer.length);
    for (let i = 0; i < buffer.length; i++) {
      scrambled[i] = buffer[i] ^ 0xa5;
    }
    return scrambled;
  }
  ```
- **Impact:** Architectural specification (`AGENTS.md` and `docs/TECHNICAL_CONTRACTS.md`) strictly mandates AES-256-GCM encryption with keys stored in the OS enclave. Single-byte XOR provides zero cryptographic confidentiality.
- **Recommended Remediation:** Upgrade `QuarantineService` to use `crypto.createCipheriv('aes-256-gcm', key, iv)` with authenticated auth tags.

---

### GAP-06: Insecure Desktop Key Derivation for Local Settings (MEDIUM)
- **Requirement Tracing:** PP-022 (Secure Local Key Derivation).
- **Files Affected:** `apps/desktop/src/services/secure-storage.service.ts` line 28.
- **Empirical Evidence:**
  ```typescript
  const rawKey = crypto.createHash('sha256').update(os.hostname() + os.userInfo().username).digest();
  ```
- **Impact:** The AES-256 key is derived from predictable system properties without salt, iterations (PBKDF2/Argon2), or DPAPI/Windows Credential Manager integration. Any unprivileged process running as the user can derive the exact same key.
- **Recommended Remediation:** Implement PBKDF2 with a randomly generated local salt or integrate platform credential managers (DPAPI via `node-keytar` or native bindings).

---

### GAP-07: Cross-Platform Verdict & Threshold Inconsistency (MEDIUM)
- **Requirement Tracing:** PP-023 (Consistent Verdicts).
- **Files Affected:** Client adapters across Web, Extension, Mobile, Desktop.
- **Empirical Evidence:**
  1. **Empty String Input:**
     - `Core.detectUrl('')` returns `Verdict.ALLOW, riskScore: 0`.
     - `Web.scanUrl('')` returns `Verdict.DANGEROUS, overallScore: 100, severity: CRITICAL`.
     - `Mobile.scanUrl('')` throws `Error('URL_REQUIRED')`.
     - `Desktop.scanUrl('')` throws `Error('URL_TOO_LONG_OR_INVALID')`.
  2. **Borderline Malicious Threshold:**
     - Web marks `DANGEROUS` when `riskScore >= 80`.
     - Extension & Mobile mark `DANGEROUS` when `riskScore >= 85`.
- **Impact:** The exact same URL or input yields conflicting verdicts depending on which platform the user is on.
- **Recommended Remediation:** Centralize all verdict decision rules, input validation, and score-to-verdict mapping strictly inside `@private-protection/core`. Client platforms must only format output.

---

### GAP-08: Fragmented & Incompatible File Analyzer Models (MEDIUM)
- **Requirement Tracing:** PP-018, PP-024 (File Analysis Domain Models).
- **Files Affected:** `apps/desktop/src/services/file-analyzer.service.ts`, `apps/mobile/src/services/file-analyzer.service.ts`.
- **Empirical Evidence:**
  - `packages/core` does not export a `FileAnalyzer` or canonical `FileScanResult`.
  - Desktop returns `{ riskScore, verdict: 'BLOCK' | 'WARN', isDeceptiveExtension }`.
  - Mobile returns `{ score, verdict: Verdict.DANGEROUS, shannonEntropy }`.
- **Impact:** Cross-platform shared core does not govern file analysis; desktop and mobile implement divergent file scoring logic.
- **Recommended Remediation:** Move `FileAnalyzer` into `@private-protection/core` alongside URL and Text analyzers with a single canonical `FileScanResult` interface.

---

### GAP-09: Extortion Message Scoring as CAUTION Instead of DANGEROUS (MEDIUM)
- **Requirement Tracing:** PP-005 (Scam Message Detection).
- **Files Affected:** `packages/core/src/analyzers/text.analyzer.ts`.
- **Empirical Evidence:**
  - Analyzing `"Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours or your private photos will be leaked"` yields:
    - Risk Score: **69**
    - Verdict: **CAUTION** (Severity: `MEDIUM`)
  - A blatant extortion attempt with a cryptocurrency wallet and urgency threat is not categorized as `DANGEROUS`.
- **Impact:** Users receiving extortion threats receive a yellow CAUTION banner instead of a high-friction BLOCK/DANGEROUS warning.
- **Recommended Remediation:** Add a synergistic heuristic rule in `TextAnalyzer`: when `extortion_demand` + `crypto_wallet` + `urgency` coincide, apply a +30 risk boost to push the score over 85 (DANGEROUS).

---

### GAP-10: Backend / OHTTP Relay Unimplemented (LOW)
- **Requirement Tracing:** PP-025 (Stateless Backend & OHTTP Relay).
- **Files Affected:** Monorepo root.
- **Empirical Evidence:** `apps/backend/` does not exist in the repository.
- **Impact:** No functional impact on on-device detection because the system is designed to be 100% offline. However, anonymous OHTTP telemetry relays and differential OTA update distribution servers described in architecture documents are absent.
- **Recommended Remediation:** Document backend as an external standalone service or stub a reference OHTTP relay server in `packages/backend`.
