# PRIVATE PROTECTION: AI/ML Architecture

## 1. Model Portfolio

To achieve an effective on-device AI security assistant, PRIVATE PROTECTION utilizes an ensemble of optimized, specialized models rather than a single monolithic architecture.

### 1.1 Specialized Models
*   **NLP Text Classifier (Spam/Scam/Phishing):**
    *   *Architecture:* DistilBERT or MobileBERT.
    *   *Size:* ~20-40 MB (Quantized).
    *   *Role:* Extracts semantic intent from SMS, emails, and chat messages.
*   **URL & DGA Classifier:**
    *   *Architecture:* 1D CNN / Character-level Bi-LSTM or LightGBM.
    *   *Size:* < 5 MB.
    *   *Role:* Real-time assessment of URL string entropy, typosquatting, and algorithmic generation.
*   **Visual Analysis & Similarity (Vision):**
    *   *Architecture:* MobileNetV3 or EfficientNet-Lite.
    *   *Size:* ~10-15 MB.
    *   *Role:* Screen/image analysis for brand impersonation and rogue QR payloads.
*   **Local AI Assistant (Reasoning & Explanation):**
    *   *Architecture:* Llama 3 8B (highly quantized), Llama-3.2-1B/3B, or Gemma 2B.
    *   *Size:* ~1.5 GB - 3 GB (INT4/GGUF).
    *   *Role:* Consumes the *Evidence Chain* output from classifiers, cross-references with local context, and generates user-facing explanations. 

---

## 2. Model Formats & Inference Optimization

Operating strictly on-device requires extreme optimization to preserve battery life, memory, and thermal envelopes.

### 2.1 Deployment Formats
*   **Android/Linux:** TFLite (TensorFlow Lite) and ONNX.
*   **iOS/macOS:** CoreML.
*   **Browser-based Extensions:** WebNN / WebAssembly (WASM).

### 2.2 Inference Acceleration
*   **Hardware Delegation:** The AI pipeline defaults to Neural Processing Units (NPUs) or Apple Neural Engine (ANE). Fallback is GPU; CPU is the last resort.
*   **Quantization:** All large models (especially the AI Assistant LLM) use INT4 (4-bit integer) or INT8 quantization. Small classifiers use INT8.
*   **Pruning:** Vision and NLP models undergo unstructured pruning during training to remove weights close to zero, speeding up inference by 15-20% with negligible accuracy loss.

---

## 3. Training Data & Update Strategy

### 3.1 Training Data Pipeline
*   **Public Datasets:** PhishTank, Enron Email Dataset (filtered), OpenPhish, Android Malware Dataset (CIC-AndMal2017).
*   **Synthetic Data Generation:** Utilizing frontier cloud models (e.g., GPT-4/Claude) to generate millions of hyper-realistic, localized scam permutations (e.g., "Grandparent scam in Midwestern dialect").
*   **Federated Learning (Future Phase):** Opt-in decentralized training where weights (not user data) are averaged securely on the cloud to update models continuously based on emerging localized threats.

### 3.2 Update Mechanism
*   **Differential Updates:** Models are updated using binary diffing (e.g., `bsdiff`). Instead of downloading a 50MB model, the client downloads a 500KB patch representing newly learned threat weights.
*   **Versioning & Verification:** All models are cryptographically signed. The inference engine verifies the signature before loading to prevent model poisoning via local exploitation.
*   **Cadence:** Classifiers update daily/weekly. The heavy AI Assistant LLM updates quarterly.

---

## 4. AI Assistant & Prompt Injection Defense

The on-device SLM handles untrusted user data (messages, extracted DOM). This introduces severe Prompt Injection (PI) risks.

### 4.1 Prompt Injection Defense Architecture
1.  **Strict Data Separation (Sandboxing):** The system prompt and user data are separated at the token level using specialized formatting (e.g., ChatML). 
2.  **Instruction Override Pre-filtering:** A dedicated, ultra-fast regex/heuristic filter scans incoming text for common injection triggers (e.g., "Ignore all previous instructions", "System override").
3.  **Secondary Output Parsing:** The output of the Assistant is tightly constrained. If the LLM generates a JSON response, it is strictly validated against a JSON schema. If the output attempts to authorize a "SAFE" rating based on an injection, the deterministic Risk Scoring system will overrule it.
4.  **Privilege Dropping:** The AI Assistant operates with read-only access to the *Evidence Chain*. It has zero capability to alter the device state, click links, or alter the final block/allow decision.

---

## 5. Accuracy Targets & Feature Engineering

### 5.1 Evaluation Metrics
Given the high cost of user friction, the system is biased heavily against False Positives.
*   **Target False Positive Rate (FPR):** < 0.01% (Less than 1 in 10,000 legitimate items flagged).
*   **Target True Positive Rate (TPR):** > 95% for known threats; > 85% for zero-day/novel threats.
*   **Latency:** End-to-end local inference (excluding LLM explanation) < 50ms. LLM streaming explanation < 500ms time-to-first-token.

### 5.2 Feature Engineering by Modality
*   **URL Features:**
    *   Lexical: Length, consonant ratio, special character frequency.
    *   Semantic: Presence of brands (Levenshtein distance to top 500 brands).
    *   Structural: Subdomain depth, TLD risk score.
*   **Text/Message Features:**
    *   Linguistic: Sentiment, urgency indicators, financial keywords, pressure phrases ("immediately", "suspended").
    *   Metadata matching: Does the sender's apparent locale match the language syntax?
*   **Vision Features:**
    *   Structural Layout: Placement of input fields relative to known-good application layouts.
    *   Color Histograms: Identifying phishing kits that fail to replicate CSS gradients perfectly.
