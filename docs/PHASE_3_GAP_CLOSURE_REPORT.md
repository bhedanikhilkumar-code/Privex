# PHASE_3_GAP_CLOSURE_REPORT.md — Phase 3 Technical Gap Analysis & Action Plan

> **SYSTEM STATUS: PHASE 3 GAP CLOSURE ACTIVE (MASTER PROMPT #9)**  
> **CANONICAL GAP AUDIT — `@private-protection/ml`**  
> Governed by: `AGENTS.md`, Master Prompt #9, `docs/AI_SECURITY_ARCHITECTURE.md`.

---

## 1. COMPONENT-BY-COMPONENT REQUIREMENT CLASSIFICATION

| Area / Component | Current State | Required State | Classification | Action Plan |
|---|---|---|:---:|---|
| **ONNX Provider Feed Mapping** | Uses placeholder `session.run(feeds)` where `feeds` was empty or unmapped. | Real tensor mapping: input names, input tensor conversion, shapes, output tensor extraction, softmax calculation. | **INCORRECT** | Implement `TensorInputMapper`, `TextPreprocessor`, and real output tensor decoding in `OnnxModelProvider`. |
| **Input Preprocessing Boundary** | String-to-number mapping was handled ad-hoc. | Explicit `TextPreprocessor` / Tokenizer boundary converting text to token IDs and attention masks. | **MISSING** | Create `src/models/preprocessing/text-preprocessor.ts` with tokenization, padding, and truncation. |
| **Model Loader Validation** | Validated buffer size, SHA-256, and format header. | Validate complete metadata (version anti-downgrade, non-empty shapes, output classes $\ge 2$, quantization). | **PARTIAL** | Enhance `ModelLoader` and `ModelIntegrityVerifier` with monotonic versioning and schema sanity rules. |
| **Model Artifact Reality** | No `.onnx` binary present in repo; mock provider test-only. | Explicit status: No fake binary created. Document complete production model requirements specification. | **BLOCKED-BY-MODEL** | Author `docs/PRODUCTION_MODEL_REQUIREMENTS.md`. Expose clear `MODEL_UNAVAILABLE` status. |
| **Classifier Provenance & Labeling** | Handled both ML and heuristic paths. | Explicit `inferenceStatus`: `MODEL_INFERRED` vs `DETERMINISTIC_FALLBACK` vs `MODEL_UNAVAILABLE`. | **PARTIAL** | Update `ScamIntentClassifier` and `UrlSemanticClassifier` to strictly distinguish and label inference provenance. |
| **AI Authority Boundary Enforcement** | Enforced in `SchemaValidator` for DANGEROUS/SUSPICIOUS. | Dedicated comprehensive test suite explicitly asserting that Core Security Engine overrides ML and Assistant. | **PARTIAL** | Add `src/__tests__/security/authority-boundary.test.ts` testing all override, suppression, and bypass attempts. |
| **Inference Timeout Resource Leak** | Used `Promise.race()` without aborting in-flight execution. | Add `AbortController` / `AbortSignal` to cancel or isolate abandoned in-flight inference and prevent memory leaks. | **PARTIAL** | Integrate `AbortSignal` in `InferenceRequest` and handle clean abandonment in `AISecurityAssistant`. |
| **Model Evaluation Harness** | Tested in one benchmark test. | Formal reusable `ModelEvaluator` class computing Confusion Matrix, Macro/Micro F1, Precision, Recall per class. | **PARTIAL** | Create `src/evaluation/model-evaluator.ts` and test suite. |
| **Performance Benchmark Breadth** | Measured component micro-latencies. | Measure cold vs warm inference, repeated 1,000 runs, concurrent requests, memory footprint before/after. | **PARTIAL** | Expand `phase3-performance-benchmark.test.ts` to include concurrent inference and update baseline doc. |

---

## 2. SUMMARY OF ACTIONS

1. **Fix ONNX Provider & Preprocessing Boundary**:
   - Create `src/models/preprocessing/text-preprocessor.ts`.
   - Update `src/models/providers/onnx-provider.ts` to map real tensors (`input_ids`, `attention_mask`), validate shapes, and decode logits via softmax.
2. **Harden ModelLoader & Anti-Downgrade Versioning**:
   - Add semantic version comparison and anti-downgrade check in `ModelLoader`.
3. **Clarify Classifier Provenance**:
   - Add `inferenceStatus: 'MODEL_INFERRED' | 'DETERMINISTIC_FALLBACK' | 'MODEL_UNAVAILABLE'` to classifier results.
4. **Harden Inference Timeout & Resource Cancellation**:
   - Add `AbortSignal` support to `InferenceRequest` and pass abort signal from `AISecurityAssistant`.
5. **Implement Formal Model Evaluation Harness**:
   - Create `src/evaluation/model-evaluator.ts` supporting full multi-class confusion matrix, precision, recall, and F1 calculations.
6. **Author `docs/PRODUCTION_MODEL_REQUIREMENTS.md`**:
   - Specify the exact artifact requirements (MobileBERT / DistilBERT ONNX INT8).
7. **Dedicated Authority Boundary Test Suite**:
   - Create `src/__tests__/security/authority-boundary.test.ts`.
8. **Re-run Full Monorepo Test & Benchmark Suite**:
   - Ensure 100% green pass rate and coverage $> 90\%$.
