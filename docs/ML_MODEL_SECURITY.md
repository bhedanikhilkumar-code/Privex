# ML_MODEL_SECURITY.md — Supply-Chain Integrity & Model Execution Security

> **CANONICAL SPECIFICATION — `@private-protection/ml`**  
> Governed by: `AGENTS.md`, `docs/SECURITY_ARCHITECTURE.md`, `docs/UPDATE_SECURITY_ARCHITECTURE.md`.

---

## 1. THREAT MODEL: ON-DEVICE AI AS AN ATTACK VECTOR

On-device machine learning models represent untrusted binary artifacts subject to sophisticated supply-chain and local file manipulation attacks:
1. **Model Weight Poisoning**: Tampering with weights to induce targeted false negatives on specific phishing domains.
2. **Buffer Overflow & Deserialization Exploits**: Malicious protobuf or flatbuffer structures designed to achieve arbitrary code execution during session initialization.
3. **Model Substitution / Downgrade Attacks**: Replacing a hardened v1.2 model with an older, vulnerable v0.1 model.
4. **Denial-of-Service / Memory Exhaustion**: Massive 500 MB model artifacts crafted to cause OS out-of-memory kernel panics.
5. **Adversarial Tensor Injections**: Crafting inputs of unexpected tensor shapes or infinite values to crash the native inference runtime.

---

## 2. THE 6 MANDATORY SUPPLY-CHAIN VERIFICATION GATES

Every model loaded into `@private-protection/ml` must pass six immutable verification gates before execution memory is allocated:

```
UNTRUSTED MODEL BINARY (.onnx / .tflite)
                  │
                  ▼
[GATE 1] STRICT BUFFER SIZE CEILING
  • Verify buffer length <= 50 MB (MAX_MODEL_SIZE_BYTES).
  • Verify buffer length matches expected metadata sizeBytes exactly.
  • Rejects oversized binaries before deserialization.
                  │
                  ▼
[GATE 2] CRYPTOGRAPHIC SHA-256 INTEGRITY
  • Calculate SHA-256 digest over raw byte array.
  • Compare constant-time against expected SHA-256 in signed ModelMetadata.
  • Mismatch immediately throws ModelChecksumMismatchError.
                  │
                  ▼
[GATE 3] MAGIC HEADER & FORMAT VERIFICATION
  • ONNX: Enforce valid protobuf header (> 8 bytes).
  • TFLite: Enforce 'TFL3' magic bytes at offset 4.
  • Rejects corrupt, truncated, or substituted binaries.
                  │
                  ▼
[GATE 4] MONOTONIC VERSION INTEGRITY
  • Reject model versions lower than currently active model version.
  • Prevent downgrade rollbacks.
                  │
                  ▼
[GATE 5] TENSOR SHAPE & RUNTIME COMPATIBILITY
  • Validate input dimensions against metadata.inputShape before execution.
  • Rejects dimensional mismatches (TensorShapeMismatchError).
                  │
                  ▼
[GATE 6] SANDBOXED ISOLATION & VOLATILE RAM LIFECYCLE
  • Loaded read-only in process memory.
  • Zero writeback to disk. Zero dynamic code generation (eval/dlopen).
```

---

## 3. IMPLEMENTATION IN CODEBASE

### 3.1 ModelIntegrityVerifier (`src/models/model-metadata.ts`)
- Enforces `MAX_MODEL_SIZE_BYTES = 50 * 1024 * 1024`.
- Constant-time SHA-256 comparison via Node `crypto.createHash('sha256')`.
- Magic byte inspection for ONNX and TFLite formats.

### 3.2 ModelLoader (`src/models/model-loader.ts`)
- Orchestrates cryptographic verification prior to calling provider factory.
- Implements lifecycle state machine (`registerProvider`, `activateProvider`, `unloadProvider`).
- Rejects unverified or corrupted model buffers with typed error codes.

### 3.3 OnnxModelProvider (`src/models/providers/onnx-provider.ts`)
- Validates tensor shape array counts against `metadata.inputShape`.
- Wraps inference execution in try/catch boundaries returning structured `status: 'ERROR'` on native exceptions.
- Provides zero-residue `unload()` freeing memory references.

---

## 4. FAILURE HANDLING & CORE DETECTOR PRECEDENCE

If any verification gate fails:
1. Model loading is aborted immediately.
2. Error is logged to internal volatile diagnostic state (no raw user data).
3. The system operates in **Deterministic Fallback Mode** (`TemplateFallbackEngine`).
4. Core security detection (`@private-protection/core`) remains 100% operational with zero degradation.
