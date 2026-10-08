# INTERFACE_CONTRACTS.md — Concrete Subsystem Technical Interface Contracts

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVEX INTERFACE CONTRACTS**  
> This document defines the exact, typed technical contracts for all 18 core subsystems. These contracts are technology-agnostic and implementation-independent, serving as the binding specifications for all future implementations across TypeScript, Rust, Dart, Kotlin, and Swift.

---

## 1. SUBSYSTEM CONTRACT SPECIFICATIONS

---

### 1. `DetectionEngine`
- **Purpose**: The primary façade and orchestration entry point for all security scans across all platforms.
- **Input Structure**:
  ```typescript
  interface ScanRequest {
    readonly id: string; // UUIDv4
    readonly timestamp: number; // Unix epoch ms
    readonly type: 'URL' | 'MESSAGE' | 'FILE_HEADER' | 'DOM_STRUCTURE';
    readonly payload: string | Uint8Array;
    readonly context: AnalysisContext;
    readonly options?: {
      fastPathOnly?: boolean;
      skipThreatIntel?: boolean;
      timeoutMs?: number;
    };
  }
  ```
- **Output Structure**: `DetectionResult` (as defined in `docs/DOMAIN_MODELS.md`).
- **Errors**: `InvalidInputError`, `PayloadTooLargeError`, `EngineTimeoutError`, `SubsystemFailureError`.
- **Timeout Behavior**: Hard timeout at $100\text{ ms}$. If analyzers exceed timeout, returns partial results aggregated with `TIMEOUT_REACHED` caution flag.
- **Security Requirements**: Thread-isolated execution; strict input byte clamping; zero dynamic code evaluation.
- **Privacy Requirements**: Payload is processed strictly in volatile memory and zeroed immediately after scan.
- **Offline Behavior**: 100% operational air-gapped with zero degradation.
- **Versioning Strategy**: Monotonic interface semantic version `1.0.0`; breaking changes require major version bump.

---

### 2. `URLAnalyzer`
- **Purpose**: Lexical, structural, and cryptographic analysis of uniform resource locators.
- **Input Structure**: `{ readonly rawUrl: string; readonly context: AnalysisContext; }` (max 2,048 bytes).
- **Output Structure**:
  ```typescript
  interface URLAnalysisResult {
    readonly normalizedUrl: string;
    readonly canonicalHost: string;
    readonly punycodeDecodedHost: string;
    readonly entropy: number;
    readonly subdomainDepth: number;
    readonly suspiciousTld: boolean;
    readonly ipBasedHost: boolean;
    readonly brandSpoofDistance?: { brand: string; distance: number };
    readonly evidence: Array<Evidence>;
  }
  ```
- **Errors**: `MalformedURLError`, `NormalizationError`.
- **Timeout Behavior**: Synchronous execution; maximum SLA $2.0\text{ ms}$.
- **Security Requirements**: Bounded regex evaluation; protection against catastrophic polynomial backtracking.
- **Privacy Requirements**: URL is normalized in-place in RAM; never written to persistent logs.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 3. `MessageAnalyzer`
- **Purpose**: Heuristic, keyword, and entity parsing of inbound text messages for scam and extortion patterns.
- **Input Structure**: `{ readonly rawText: string; readonly context: AnalysisContext; }` (max 10,000 characters).
- **Output Structure**:
  ```typescript
  interface MessageAnalysisResult {
    readonly urgencyScore: number; // 0 to 100
    readonly paymentExtortionDetected: boolean;
    readonly cryptocurrencyAddresses: Array<string>;
    readonly extractedUrls: Array<string>;
    readonly authorityImpersonationMarkers: Array<string>;
    readonly evidence: Array<Evidence>;
  }
  ```
- **Errors**: `EmptyMessageError`, `TextClampingError`.
- **Timeout Behavior**: Synchronous execution; maximum SLA $5.0\text{ ms}$.
- **Security Requirements**: Protection against hidden zero-width character obfuscation and homoglyph exploits.
- **Privacy Requirements**: Entire raw string zeroed from RAM memory upon return.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 4. `ContentAnalyzer`
- **Purpose**: Inspection of web DOM structures (insecure password inputs, deceptive form actions, iframe overlays).
- **Input Structure**:
  ```typescript
  interface DOMSnapshot {
    readonly origin: string;
    readonly formActionUrls: Array<string>;
    readonly hasPasswordInput: boolean;
    readonly isInsecureHttp: boolean;
    readonly invisibleIframePresent: boolean;
  }
  ```
- **Output Structure**: `{ readonly suspiciousDOMSignals: Array<string>; readonly evidence: Array<Evidence>; }`
- **Errors**: `InvalidDOMSnapshotError`.
- **Timeout Behavior**: $< 1.0\text{ ms}$.
- **Security Requirements**: Operates on sanitized snapshot strings; no direct DOM manipulation.
- **Privacy Requirements**: Excludes all form input values (user passwords, keystrokes are never ingested).
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 5. `FileAnalyzer`
- **Purpose**: Static inspection of file magic bytes, PE/ELF/Mach-O headers, and structural section entropy.
- **Input Structure**: `{ readonly headerBytes: Uint8Array; readonly totalSizeBytes: number; readonly filename: string; }`
- **Output Structure**:
  ```typescript
  interface FileAnalysisResult {
    readonly detectedMimeType: string;
    readonly extensionMismatch: boolean;
    readonly headerEntropy: number;
    readonly suspiciousSections: Array<string>;
    readonly evidence: Array<Evidence>;
  }
  ```
- **Errors**: `BufferUnderflowError`, `FileReadError`.
- **Timeout Behavior**: $< 10.0\text{ ms}$ for header inspection.
- **Security Requirements**: Memory-safe parsing in Rust/WASM; no execution of parsed binary code.
- **Privacy Requirements**: File bytes never leave local memory.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 6. `ThreatIntelligenceProvider`
- **Purpose**: $O(1)$ in-memory bitwise queries against the local binary Bloom filter and custom user lists.
- **Input Structure**: `{ readonly targetHashPrefix: Uint8Array; readonly type: 'DOMAIN' | 'URL' | 'FILE_HASH'; }`
- **Output Structure**: `{ readonly matchFound: boolean; readonly filterVersion: number; readonly confidence: number; }`
- **Errors**: `FilterNotLoadedError`, `CorruptFilterError`.
- **Timeout Behavior**: $< 0.1\text{ ms}$ ($< 100\text{ microseconds}$).
- **Security Requirements**: Read-only memory-mapped access.
- **Privacy Requirements**: Zero network lookup; all queries resolved in RAM.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 7. `RuleEngine`
- **Purpose**: High-speed evaluation of deterministic pattern rules against normalized targets.
- **Input Structure**: `{ readonly target: NormalizedTarget; readonly context: AnalysisContext; }`
- **Output Structure**: `{ readonly matchedRules: Array<MatchedRule>; readonly evidence: Array<Evidence>; }`
- **Errors**: `RuleEvaluationError`.
- **Timeout Behavior**: Synchronous execution $< 0.5\text{ ms}$.
- **Security Requirements**: Rules compiled to immutable bytecode/regex objects at startup.
- **Privacy Requirements**: Pure computational function.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: Monotonic Rule Schema v1.

---

### 8. `MLInferenceProvider`
- **Purpose**: On-device quantized intent classification for ambiguous text payloads.
- **Input Structure**: `{ readonly tokenIds: Int32Array; readonly attentionMask: Int32Array; }`
- **Output Structure**: `{ readonly logits: Float32Array; readonly predictedClass: string; readonly confidence: number; }`
- **Errors**: `ModelNotLoadedError`, `InferenceTimeoutError`, `InferenceExecutionError`.
- **Timeout Behavior**: Strict hard timeout at $30\text{ ms}$; falls back to deterministic engine on timeout.
- **Security Requirements**: Sandboxed tensor memory; input tensors strictly numerical.
- **Privacy Requirements**: Weights and tensors kept in volatile RAM.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 9. `RiskAggregator`
- **Purpose**: Multi-factor mathematical aggregation of all evidence tokens into risk score and action.
- **Input Structure**: `{ readonly evidence: Array<Evidence>; readonly context: AnalysisContext; }`
- **Output Structure**: `RiskAssessment` (Score: 0-100, Confidence: 0.0-1.0, Severity: Enum).
- **Errors**: `AggregationCalculationError`.
- **Timeout Behavior**: Synchronous mathematical calculation $< 0.1\text{ ms}$.
- **Security Requirements**: Deterministic arithmetic; bounds checking $[0, 100]$.
- **Privacy Requirements**: Pure function.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: Math Engine v1.0.

---

### 10. `EvidenceProvider`
- **Purpose**: Centralized registry and builder for standardized, tamper-evident `Evidence` structs.
- **Input Structure**: `{ readonly ruleId: string; readonly detector: string; readonly score: number; readonly meta?: Record<string, string>; }`
- **Output Structure**: Validated `Evidence` token.
- **Errors**: `InvalidEvidenceMetadataError`.
- **Timeout Behavior**: Instantaneous ($O(1)$ object allocation).
- **Security Requirements**: Sanitizes metadata to prevent Tier 1 user payload leakage.
- **Privacy Requirements**: Enforces Tier 4 sensitivity on all metadata values.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 11. `ExplanationEngine`
- **Purpose**: Synthesizes human-readable, Grade-6 cognitive level threat explanations from evidence.
- **Input Structure**: `{ readonly evidence: Array<Evidence>; readonly riskAssessment: RiskAssessment; }`
- **Output Structure**:
  ```typescript
  interface Explanation {
    readonly headline: string; // "Warning: Deceptive Website Detected"
    readonly plainTextSummary: string; // Plain language paragraph
    readonly technicalDetails: Array<string>; // Jargon-free bullet points
    readonly recommendedSteps: Array<string>; // Immediate actionable instructions
    readonly confidenceLabel: 'HIGH' | 'MEDIUM' | 'LOW';
  }
  ```
- **Errors**: `TemplateRenderError`, `SynthesisTimeoutError`.
- **Timeout Behavior**: Asynchronous execution; SLA $< 25\text{ ms}$.
- **Security Requirements**: Read-only operation; zero authority to alter risk score.
- **Privacy Requirements**: Uses only tokenized evidence tags; never includes raw URLs or message texts.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 12. `SecurityAssistant`
- **Purpose**: High-level conversational and interaction façade for user threat inquiries.
- **Input Structure**: `{ readonly queryType: 'EXPLAIN_THREAT' | 'RECOMEND_ACTION'; readonly detectionResult: DetectionResult; }`
- **Output Structure**: `{ readonly assistantResponse: Explanation; readonly suggestedQuickReplies: Array<string>; }`
- **Errors**: `AssistantUnavailableError`.
- **Timeout Behavior**: $< 50\text{ ms}$.
- **Security Requirements**: Strict prompt injection isolation; constrained JSON grammar.
- **Privacy Requirements**: Local memory execution.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 13. `NotificationService`
- **Purpose**: Dispatches high-priority platform warnings to the user interface.
- **Input Structure**: `{ readonly title: string; readonly body: string; readonly severity: 'WARN' | 'DANGER'; readonly actionPayload: Recommendation; }`
- **Output Structure**: `{ readonly delivered: boolean; readonly notificationId: string; }`
- **Errors**: `PermissionDeniedError`, `NotificationDispatchError`.
- **Timeout Behavior**: Dispatched in $< 50\text{ ms}$.
- **Security Requirements**: Enforces friction gate; cannot be dismissed without user acknowledgment.
- **Privacy Requirements**: Notification text contains generic category warnings, not private user data.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 14. `LocalStorage`
- **Purpose**: Encrypted persistence of user allowlists, event counters, and model metadata.
- **Input Structure**: Standard CRUD queries (`get`, `put`, `delete`, `queryEvents`).
- **Output Structure**: Strongly typed entity records.
- **Errors**: `DatabaseLockedError`, `DecryptionError`, `DiskFullError`.
- **Timeout Behavior**: Disk I/O bounded $< 10\text{ ms}$.
- **Security Requirements**: AES-256-GCM full-page encryption; hardware enclave keys.
- **Privacy Requirements**: Prohibits storage of unencrypted Tier 1 user payloads.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: Schema migration v1.

---

### 15. `ModelManager`
- **Purpose**: Lifecycle, verification, and memory loading of on-device ONNX model artifacts.
- **Input Structure**: `{ readonly modelId: string; }`
- **Output Structure**: `{ readonly session: InferenceSession; readonly metadata: ModelMetadata; }`
- **Errors**: `ModelIntegrityMismatchError`, `InsufficientMemoryError`.
- **Timeout Behavior**: Cold start loading $< 200\text{ ms}$; cached session reuse.
- **Security Requirements**: Verifies SHA-256 hash before loading into memory.
- **Privacy Requirements**: Model weights loaded read-only in process memory.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 16. `ThreatIntelUpdater`
- **Purpose**: Manages background querying, verification, and atomic application of Bloom filter diffs.
- **Input Structure**: `{ readonly forceCheck?: boolean; }`
- **Output Structure**: `{ readonly updated: boolean; readonly newVersion: number; readonly bytesDownloaded: number; }`
- **Errors**: `SignatureVerificationFailedError`, `NetworkUnavailableError`, `DowngradeRejectedError`.
- **Timeout Behavior**: Background network timeout 30 seconds.
- **Security Requirements**: Ed25519 signature validation; monotonic version enforcement.
- **Privacy Requirements**: Requests contain zero device identifiers or tracking headers.
- **Offline Behavior**: Fails safely; returns `updated: false` without impacting detection.
- **Versioning Strategy**: v1.0.0.

---

### 17. `ConfigurationManager`
- **Purpose**: Thread-safe management of local security policies, sensitivity thresholds, and feature flags.
- **Input Structure**: `{ readonly key: string; }` / `{ readonly key: string; readonly value: any; }`
- **Output Structure**: Strongly typed configuration objects.
- **Errors**: `InvalidConfigurationValueError`.
- **Timeout Behavior**: Instantaneous in-memory reads.
- **Security Requirements**: Policy overrides require user authentication (biometrics/passcode).
- **Privacy Requirements**: Stored in encrypted local preferences.
- **Offline Behavior**: 100% operational offline.
- **Versioning Strategy**: v1.0.0.

---

### 18. `BackendClient`
- **Purpose**: Low-level client for fetching static signed update assets and routing OHTTP telemetry.
- **Input Structure**: `{ readonly endpoint: 'GET_MANIFEST' | 'GET_PATCH' | 'POST_OHTTP_TELEMETRY'; readonly payload?: Uint8Array; }`
- **Output Structure**: `{ readonly statusCode: number; readonly responseBytes: Uint8Array; }`
- **Errors**: `NetworkError`, `OHTTPRelayError`, `RateLimitExceededError`.
- **Timeout Behavior**: Network request timeout 10 seconds.
- **Security Requirements**: HTTPS TLS 1.3 with Certificate Transparency; HPKE payload encryption for telemetry.
- **Privacy Requirements**: Routes telemetry through independent OHTTP relay; scrubs Client IP.
- **Offline Behavior**: Short-circuits immediately if device is offline.
- **Versioning Strategy**: v1.0.0.
