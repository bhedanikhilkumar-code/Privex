# AI_ASSISTANT_RUNTIME.md — AI Security Assistant Runtime Architecture

> **CANONICAL SPECIFICATION — `@private-protection/ml`**  
> Governed by: `AGENTS.md`, `docs/AI_ASSISTANT_CONTRACT.md`, `docs/INTERFACE_CONTRACTS.md`.

---

## 1. RUNTIME ORCHESTRATION ARCHITECTURE

The `AISecurityAssistant` runtime provides a safe, low-latency execution façade for on-device natural language threat explanation:

```
AssistantInput
      │
      ▼
[STEP 1] ResponsePolicy.evaluateUserIntent()
  • Detects weaponization, evasion, or hacking assistance queries.
  • Short-circuits with safe educational refusal if prohibited.
      │
      ▼
[STEP 2] PromptSanitizer.sanitize()
  • Strips delimiters, invisible Unicode, and instruction overrides.
  • Flags injection attacks; short-circuits to educational warning if detected.
      │
      ▼
[STEP 3] ModelLoader / Provider Lookup
  • Inspects active provider registration and loaded state.
  • If unloaded: falls through directly to TemplateFallbackEngine.
      │
      ▼
[STEP 4] Sandboxed Execution with Timeout Race
  • Builds PromptBoundary (<untrusted_evidence_data> XML enclosure).
  • Executes provider.infer() bounded by Promise.race([inference, timeoutPromise(50ms)]).
      │
      ▼
[STEP 5] Strict Output Schema & Authority Validation
  • Validates character limits, item counts, and JSON structure via SchemaValidator.
  • Confirms model did not attempt to downgrade threat verdict to safe.
  • If valid: returns validated AssistantOutput (status: 'LOCAL_MODEL').
      │
      ▼ (On any error, timeout, or schema failure)
[STEP 6] Deterministic Template Fallback Parity
  • Synthesizes Grade 6 cognitive level explanation in < 0.1 ms via TemplateFallbackEngine.
  • Emits AssistantOutput (status: 'DETERMINISTIC_FALLBACK').
```

---

## 2. TIMEOUT PROTECTION & AIR-GAPPED PARITY

1. **Strict 50 ms Hard Timeout**: `Promise.race` enforces a 50 ms deadline on local SLM inference. If the hardware or thread pool stutters, the system falls back instantly.
2. **Deterministic Template Parity**: The template engine covers all 7 canonical threat categories (`BRAND_SPOOFING`, `URGENCY_EXTORTION`, `INSECURE_PASSWORD`, `SUSPICIOUS_FILE`, `EMPLOYMENT_SCAM`, `ALLOW`, `INFORM`).
3. **Cognitive Reading Grade**: All explanations are calibrated at or below Grade 6 reading level using short sentences, active voice, zero jargon, and concrete action steps.
