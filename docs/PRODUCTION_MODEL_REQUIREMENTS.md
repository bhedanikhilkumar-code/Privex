# PRODUCTION_MODEL_REQUIREMENTS.md — On-Device Neural Model Specification

> **STATUS: PHASE 3 GATE DOCUMENTATION**  
> **CLASSIFICATION: PRODUCTION ARTIFACT INTEGRATION SPECIFICATION**  
> This document specifies the exact technical requirements, tensor contracts, quantization targets, and cryptographic packaging standards required for a production-trained Small Language Model (SLM) / Neural Intent Classifier to be integrated into `@private-protection/ml`.

---

## 1. EXECUTIVE SUMMARY & CURRENT PHASE 3 STATUS

As governed by the project constitution (`AGENTS.md`) and non-negotiable engineering principles:
- **NO FAKE AI**: No heuristic rule may masquerade as a neural network.
- **NO HARDCODED PREDICTIONS**: Test mock providers (`DevelopmentMockModelProvider`) are strictly isolated to test fixtures.
- **ACCURACY PROVENANCE**: All benchmarks clearly report whether results are derived from the deterministic heuristic pipeline or a neural network artifact.

Because a trained production neural weight file (`.onnx` / `.tflite`) is not committed in this repository, **Phase 3 execution runtime is fully hardened and tested, with current status: `PHASE 3 BLOCKED — PRODUCTION MODEL ARTIFACT REQUIRED`.**

The deterministic fallback path (`TemplateFallbackEngine`, deterministic intent classification, and lexical analysis) provides **100% authoritative protection** until a compliant production artifact is supplied.

---

## 2. PRODUCTION MODEL ARCHITECTURE REQUIREMENTS

| Attribute | Specification | Rationale |
|---|---|---|
| **Base Architecture** | MobileBERT, DistilBERT, or MiniLM (Transformer Encoder) | Low parameter count ($\le 25\text{M}$ parameters), sub-millisecond on modern mobile NPUs/CPUs. |
| **Model Format** | **ONNX (Open Neural Network Exchange)** | Universal on-device execution across Node.js (`onnxruntime-node`), Browser/WASM (`onnxruntime-web`), and Desktop (`Tauri/Rust`). |
| **ONNX Opset Version** | **Opset 17 or 18** | Broad cross-platform runtime compatibility across WASM, iOS CoreML, and Android NNAPI execution providers. |
| **Quantization** | **INT8 (Static Quantization / QOperator)** | Reduces memory footprint by $4\times$, eliminates floating-point indeterminism, prevents heap exhaustion on constrained devices. |
| **Max Binary Size** | **$\le 35\text{ MB}$ (INT8)** | Strict memory budget; hard limit in `ModelIntegrityVerifier` is $50\text{ MB}$. |
| **Inference Latency SLA** | **$\le 30.0\text{ ms}$ (p95 CPU single thread)** | Fast enough to avoid user-perceived friction; deterministic fallback runs in $< 0.1\text{ ms}$. |
| **Peak Memory Budget** | **$\le 45\text{ MB}$ RSS in volatile RAM** | Conforms to Mobile and Browser Web Worker memory quotas. |

---

## 3. TENSOR INPUT CONTRACT

The ONNX model graph MUST expose the following input tensors:

```
Input 0: input_ids
  • Data Type:  INT64
  • Tensor Shape: [1, 128]  (Batch size 1, Sequence length 128)
  • Description: Token IDs mapped from vocabulary (including [CLS]=2 and [SEP]=3)

Input 1: attention_mask
  • Data Type:  INT64
  • Tensor Shape: [1, 128]
  • Description: Binary mask (1 for active tokens, 0 for padding [PAD]=0)
```

The model MUST NOT require raw strings or dynamically shaped input tensors that trigger runtime re-allocation.

---

## 4. TENSOR OUTPUT CONTRACT & CLASS MAPPING

The model MUST produce raw unnormalized logits for the canonical 7-class scam intent taxonomy:

```
Output 0: logits
  • Data Type:  FLOAT32
  • Tensor Shape: [1, 7]
  • Description: Unnormalized log-odds across the 7 canonical intent classes
```

### Class Index Mapping (Exact Order)

| Index | Label | Domain Description |
|---|---|---|
| `0` | `PHISHING_CREDENTIALS` | Credential theft, account lock impersonation, verify logins |
| `1` | `URGENCY_EXTORTION` | Extortion, ransomware threats, blackmail, cryptocurrency demands |
| `2` | `ADVANCE_FEE_FRAUD` | Lottery, inheritance, benefactor grants, advance fees |
| `3` | `EMPLOYMENT_TASK_SCAM` | Work-from-home tasks, deposit to unlock commissions, fake daily salary |
| `4` | `TECH_SUPPORT_INVOICE` | Fake subscription renewals (Geek Squad, Norton, McAfee invoices) |
| `5` | `POSTAL_DELIVERY_FRAUD` | USPS / FedEx package detained, customs fee payment requests |
| `6` | `BENIGN_COMMUNICATION` | Everyday non-malicious conversational messages |

### Probability Calibration Requirement
The runtime applies temperature-scaled numerically stable softmax:
$$P(y_i) = \frac{e^{z_i - \max(\mathbf{z})}}{\sum_j e^{z_j - \max(\mathbf{z})}}$$
The model training process must incorporate Platt scaling or temperature scaling so that predicted probability $P(y_i)$ represents a well-calibrated confidence score.

---

## 5. QUALITY & SAFETY BENCHMARKS (ACCEPTANCE CRITERIA)

Before any production artifact is accepted into `@private-protection/ml`, it must be evaluated using `ModelEvaluator` on the independent test split and meet:

1. **Overall Accuracy**: $\ge 92.0\%$ across all 7 classes.
2. **Binary Threat F1 Score**: $\ge 0.9500$.
3. **False Positive Rate (FPR)**: $\le 1.0\%$ on benign communications.
4. **Adversarial Robustness**: $0.0\%$ prompt injection breakout on the 110-sample adversarial attack battery (`injection-battery.test.ts`).
5. **No Hallucinated URLs or Overrides**: Zero ability to alter `Verdict` or downgrade `RiskAssessment`.

---

## 6. CRYPTOGRAPHIC INTEGRITY & PACKAGING SPECIFICATION

Every candidate model artifact must be accompanied by an immutable `ModelMetadata` manifest matching `packages/ml/src/types.ts`:

```json
{
  "modelId": "private-protection-intent-classifier-v1",
  "version": "1.0.0",
  "format": "ONNX",
  "task": "INTENT_CLASSIFICATION",
  "sha256": "4a7d...<64-hex-characters>...",
  "sizeBytes": 28450128,
  "inputShape": [1, 128],
  "inputNames": ["input_ids", "attention_mask"],
  "outputClasses": [
    "PHISHING_CREDENTIALS",
    "URGENCY_EXTORTION",
    "ADVANCE_FEE_FRAUD",
    "EMPLOYMENT_TASK_SCAM",
    "TECH_SUPPORT_INVOICE",
    "POSTAL_DELIVERY_FRAUD",
    "BENIGN_COMMUNICATION"
  ],
  "outputNames": ["logits"],
  "quantization": "INT8",
  "isProductionArtifact": true,
  "providerName": "OnnxModelProvider",
  "description": "Quantized MobileBERT 7-class on-device scam intent classifier"
}
```

The binary file must:
- Match `sha256` digest exactly.
- Have size $\le 50\text{ MB}$.
- Contain valid ONNX protobuf headers ($\ge 8$ bytes).
- Be signed with an Ed25519 signature verified by the update pipeline.

---

## 7. SUMMARY: TRANSITION PLAN TO COMPLETE PHASE 3

To lift the blocked status and complete Phase 3:
1. Export trained MobileBERT checkpoint to ONNX format with opset 17.
2. Quantize with ONNX Runtime Quantization tool (`quantize_dynamic` or `quantize_static` to INT8).
3. Compute SHA-256 hash and package with metadata manifest.
4. Run `ModelEvaluator.evaluate()` on the 70+ sample dataset and verify all acceptance thresholds pass.
5. Update Phase status to **PHASE 3 COMPLETE**.
