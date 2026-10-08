# AI_SECURITY_ARCHITECTURE.md — Unified AI/ML Architecture & Safety Constitution

> **CANONICAL SPECIFICATION — `@private-protection/ml`**  
> Governed by: `AGENTS.md`, `docs/TECHNICAL_ARCHITECTURE.md`, `docs/AI_ML_ARCHITECTURE.md`.

---

## 1. THE CONSTITUTIONAL DOCTRINE OF ON-DEVICE AI

In PRIVEX, artificial intelligence is an **assistive, interpretative layer**, never the sovereign security authority:

1. **Security Engine Precedence**: The deterministic and heuristic engines in `@private-protection/core` (rules, lexical analysis, Bloom filter reputation, non-linear risk math) establish the canonical threat verdict (`ALLOW`, `INFORM`, `CAUTION`, `SUSPICIOUS`, `DANGEROUS`). The AI layer cannot overrule or downgrade this verdict.
2. **Data-Not-Instructions Invariant**: Untrusted inputs (URLs, SMS bodies, web DOM snapshots) are treated strictly as passive data. Direct concatenation into executable prompt context is architecturally prohibited.
3. **Local-Only Inference**: Inference executes strictly on-device in volatile RAM. Zero raw user payloads are transmitted off-device to cloud LLMs (OpenAI, Gemini, Claude).
4. **No Fake AI Invariant**: The repository does not present heuristic rule engines as neural network models, nor fabricate benchmark accuracy numbers. Where production neural artifacts are pending bundle integration, the system explicitly reports `DETERMINISTIC_FALLBACK` or `isModelBacked: false`.
5. **Fail-Closed and Air-Gapped Parity**: If local model initialization fails, times out (> 50 ms), or is missing, the system falls back seamlessly to deterministic parameterized template synthesis (< 0.1 ms) with 100% offline parity.

---

## 2. COMPONENT RESPONSIBILITY MATRIX

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 @private-protection/ml                          │
│                                                                                 │
│   ┌────────────────────┐   ┌─────────────────────┐   ┌──────────────────────┐   │
│   │   Model Security   │   │  Inference Runtime  │   │  Prompt Containment  │   │
│   │ (SHA-256 / Size /  │   │ (OnnxProvider /     │   │ (Sanitizer / Enclose │   │
│   │  Magic Header)     │   │  MockProvider)      │   │  XML / Authority)    │   │
│   └─────────┬──────────┘   └──────────┬──────────┘   └──────────┬───────────┘   │
│             │                         │                         │               │
│             └─────────────────────────┼─────────────────────────┘               │
│                                       ▼                                         │
│                      ┌─────────────────────────────────┐                        │
│                      │      Classifiers & Assistant    │                        │
│                      │ (ScamIntent / UrlSemantic /     │                        │
│                      │  AISecurityAssistant Runtime)   │                        │
│                      └────────────────┬────────────────┘                        │
└───────────────────────────────────────┼─────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      DOWNSTREAM CONSUMER / OUTPUT INTERFACE                     │
│  • Validated AssistantOutput (headline, summary, dangerFactors, recommended)    │
│  • Grade 6 cognitive reading level                                              │
│  • Friction Gate UI dispatch & clear user action instructions                   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. SUPPLY CHAIN & ARTIFACT LIFECYCLE

| Lifecycle Stage | Security Control | Code Location |
|---|---|---|
| **Storage / Delivery** | Cryptographic SHA-256 manifest + Ed25519 signing. | `docs/UPDATE_SECURITY_ARCHITECTURE.md` |
| **Ingestion** | Max 50 MB buffer ceiling + format header magic check. | `src/models/model-metadata.ts` |
| **Verification** | Cryptographic SHA-256 byte comparison before allocation. | `src/models/model-loader.ts` |
| **Instantiation** | Sandboxed execution provider (`cpu`, `wasm`, `npu`). | `src/models/providers/onnx-provider.ts` |
| **Execution** | Strict shape validation + 50 ms timeout race. | `src/assistant/assistant-runtime.ts` |
| **Output Parsing** | Strict JSON schema grammar validation. | `src/security/schema-validator.ts` |
| **Disposal** | Process memory unmapping via `unload()` hook. | `src/models/model-loader.ts` |
