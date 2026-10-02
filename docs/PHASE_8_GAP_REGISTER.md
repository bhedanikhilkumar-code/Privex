# PHASE 8 GAP REGISTER

> **Document Status:** CANONICAL PHASE 8 AUDIT ARTIFACT  
> **Evaluation Date:** 2026-10-02  
> **Audit Team:** Phase 8 Independent Red-Team & Validation Committee  
> **Taxonomy:** All entries represent empirically verified architectural, security, or implementation gaps.

---

## Gap Summary Table

| Gap ID | Severity | Category | Affected Component | Summary | Status |
|---|---|---|---|---|---|
| **GAP-01** | **CRITICAL** | Security / Vulnerability | `apps/desktop/src/services/update-verifier.service.ts` | Ed25519 signature verification bypassed; accepts arbitrary dummy bytes | **CONFIRMED** |
| **GAP-02** | **HIGH** | Architecture / ML | `packages/ml/src/models/onnx-provider.ts` | Zero ONNX models in repo; missing runtime dependencies; deceptive regex telemetry | **CONFIRMED** |
| **GAP-03** | **HIGH** | Completeness / Platform | `apps/mobile/` | Phantom mobile app: zero native Kotlin/Java/Swift code, missing camera QR scanner | **RESOLVED (Phase 10)** |
| **GAP-04** | **HIGH** | Completeness / Platform | `apps/desktop/` | No Tauri/Electron runtime; UI mock screens return fake hardcoded scan metrics | **CONFIRMED** |
| **GAP-05** | **HIGH** | Security / Cryptography | `apps/desktop/src/services/quarantine.service.ts` | Quarantine vault uses single-byte XOR `0xA5` obfuscation instead of AES-256-GCM | **CONFIRMED** |
| **GAP-06** | **MEDIUM** | Security / Storage | `apps/desktop/src/services/secure-storage.service.ts` | Desktop settings key derived from unsalted `hostname + username` without OS Keystore | **CONFIRMED** |
| **GAP-07** | **MEDIUM** | Consistency / Detection | Cross-Platform Client Adapters | Semantic verdict & threshold divergence (empty input, borderline scores) | **CONFIRMED** |
| **GAP-08** | **MEDIUM** | Domain Model / Contracts | Core, Desktop, Mobile | File analysis models are incompatible and fragmented across packages | **CONFIRMED** |
| **GAP-09** | **MEDIUM** | Detection Scoring | `packages/core/src/analyzers/text.analyzer.ts` | Extortion & urgent cryptocurrency scam scored as 69 (CAUTION) instead of DANGEROUS | **CONFIRMED** |
| **GAP-10** | **LOW** | Architecture / Backend | `apps/backend/` | OHTTP Privacy Relay & Stateless CDN backend not implemented | **CONFIRMED** |

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

### GAP-03: Phantom Mobile Client (Zero Native Code, Missing Camera QR) (HIGH) — RESOLVED
- **Requirement Tracing:** PP-016 (Native Mobile App).
- **Files Affected:** `apps/mobile/`
- **Pre-Phase 10 State:**
  - `apps/mobile/ios` directory was missing; `apps/mobile/android/app/src/main/java` contained no code.
  - Zero camera QR scanning or haptic integration; notifications and settings kept only in volatile JS structures.
- **Phase 10 Remediation Evidence:**
  - Authored concrete Android native application: `MainApplication.java` and `MainActivity.java` with `@JavascriptInterface` `AndroidSecurityBridge`.
  - Added on-device `CameraScannerService` with permission gating and deep link parsing.
  - Wired Android high-priority notification channel (`threat_alerts_channel`) and double-pulse warning haptics.
  - Connected app-private encrypted SharedPreferences storage with one-touch crypto-shredding.
  - Verified compilation via Gradle 8.11.1 against Android SDK 34.
  - All 53 unit/integration/benchmark tests passing across 12 suites in `apps/mobile`.
- **Status:** **CLOSED / RESOLVED in Phase 10**.

---

### GAP-04: Desktop Client Lacks Tauri/Electron Runtime & Uses Mock Fallbacks (HIGH)
- **Requirement Tracing:** PP-017 (Native Desktop Client).
- **Files Affected:**
  - `apps/desktop/src/renderer/screens/FullScanScreen.tsx`
  - `apps/desktop/src/renderer/screens/QuickScanScreen.tsx`
  - `apps/desktop/src/renderer/screens/CustomScanScreen.tsx`
- **Empirical Evidence:**
  - No `Cargo.toml` or Tauri configuration exists.
  - No `electron` dependency is installed in `apps/desktop/package.json`.
  - In `FullScanScreen.tsx` (lines 52–63):
    ```typescript
    const fallbackResults = {
      totalFilesScanned: 18450,
      totalBytesScanned: 1048576000,
      durationMs: 4210,
      skipped: ['C:\\Windows\\System32\\config'],
      threatsFound: []
    };
    ```
    When launched without an active IPC backend, the UI renders realistic-looking fake scan numbers (18,450 files scanned in 4.2s).
- **Impact:** Users are presented with simulated telemetry rather than actual filesystem scanning when the frontend runs standalone.
- **Recommended Remediation:** Integrate a native desktop runtime (Tauri 2.0 or Electron) and remove simulated mock telemetry fallbacks from production UI screens.

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
