# Technical Contracts Specification: PRIVATE PROTECTION

## 1. Executive Summary & Purpose

This document defines the implementation-independent, cross-platform technical contracts and data schemas for all seventeen core subsystems in the PRIVATE PROTECTION architecture. 

These contracts serve as the canonical contract boundary between the shared core library (`@private-protection/core`), on-device AI/ML layers (`@private-protection/ml`), client platforms (Mobile, Desktop, Extension, Web), and optional backend infrastructure.

---

## 2. Common Conceptual Detection Result Contract

To eliminate fragmented, incompatible representations across platforms, all scanners and analyzers map to a single, unified, immutable `DetectionResult` schema:

```typescript
export interface CommonDetectionResult {
  // Identification & Provenance
  scanId: string;                        // UUIDv4 unique scan identifier
  timestamp: string;                     // ISO-8601 UTC timestamp
  detectorVersion: string;               // Semantic version of detection engine (e.g. "1.0.0")
  rulesetVersion: string;                // Monotonic version integer of loaded ruleset (e.g. "2026100201")
  
  // Execution Context
  inputType: InputType;                  // URL | TEXT | FILE | DOM | QR
  isOffline: boolean;                    // True if evaluated with zero network roundtrips
  executionDurationMs: number;           // Wall-clock execution time in milliseconds
  
  // Decision & Scoring
  riskCategory: RiskCategory;            // SAFE | SUSPICIOUS | PHISHING | SCAM | MALWARE
  riskScore: number;                     // Normalized composite score: 0 to 100
  confidence: number;                    // Statistical confidence: 0.0 to 1.0
  uncertaintyScore: number;              // Epistemic uncertainty margin: 0.0 to 1.0
  severity: Severity;                    // SPAM(1) | PRIVACY_RISK(2) | FINANCIAL_FRAUD(3) | ACCOUNT_LOSS(4) | DEVICE_COMPROMISE(5)
  recommendedAction: ActionRecommendation;// ALLOW | INFORM | WARN | BLOCK
  
  // Detailed Evidence & User Explanation
  evidenceChain: EvidenceItem[];         // Ordered list of contributing risk indicators
  explanation: SafeExplanation;          // Plain-language summary and recommended user actions
  
  // Error & Degradation Telemetry
  degradedModeActive: boolean;           // True if heuristics operated without ML or threat intel
  warnings: string[];                    // Non-fatal execution warnings
}

export interface EvidenceItem {
  id: string;                            // Unique indicator identifier (e.g. "url-punycode-homograph")
  source: string;                        // RULE_ENGINE | URL_ANALYZER | TEXT_ANALYZER | THREAT_INTEL | ML_INTENT
  name: string;                          // Human-readable indicator title
  description: string;                  // Non-technical explanation of the risk indicator
  weight: number;                        // Indicator severity weight (0 to 100)
  confidence: number;                    // Individual indicator confidence (0.0 to 1.0)
  category: RiskCategory;                // Associated risk category
  metadata?: Record<string, string>;     // Anonymized technical attributes (e.g. { brand: "PayPal", distance: "1" })
}

export interface SafeExplanation {
  summary: string;                       // Plain-language executive summary (< Grade 8 reading level)
  keyRiskPoints: string[];               // 1 to 3 concise, bulleted risk points
  recommendedActionText: string;         // Plain-language directive ("Do not click link. Close tab.")
  educationalContext?: string;           // Optional brief cybersecurity lesson
}
```

---

## 3. The 17 Core Technical Subsystem Contracts

---

### Contract 01: Detection Engine Orchestrator
- **Purpose**: Unified entry point for multi-modal security analysis across all client applications.
- **Input**:
  ```typescript
  interface ScanRequest {
    input: string | Uint8Array;          // URL string, message text, or raw buffer
    inputType: InputType;                // URL | TEXT | FILE | DOM | QR
    metadata?: {
      sourceApp?: string;                // e.g. "SMS", "WhatsApp", "Safari"
      senderId?: string;                 // Obfuscated sender phone/email (if applicable)
      isUserInitiated?: boolean;         // True if user clicked "Scan Now"
    };
  }
  ```
- **Output**: `Promise<CommonDetectionResult>`
- **Errors**: `InvalidInputError`, `InputSizeLimitExceededError` (>2KB for URL, >10KB for Text), `EnginePanicError` (fails safe to `SUSPICIOUS`).
- **Security Constraints**: Wraps all modular operations in panic/exception catchers; enforces memory bounds.
- **Privacy Constraints**: Operates strictly in volatile memory. Discards input buffer upon return.
- **Offline Behavior**: 100% operational offline.
- **Performance**: Latency target: $p50 < 0.2\text{ms}$, $p95 < 1.0\text{ms}$ on rules/heuristics; $<50\text{ms}$ total.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Contracts 02, 03, 04, 05, 06, 07, 09.

---

### Contract 02: URL Analyzer
- **Purpose**: Extracts lexical, structural, brand typosquatting, and domain entropy indicators from URLs.
- **Input**: `urlInput: string`
- **Output**:
  ```typescript
  interface URLAnalysisOutput {
    evidence: EvidenceItem[];
    features: {
      domainLength: number;
      subdomainCount: number;
      isIpAddress: boolean;
      isHttps: boolean;
      entropy: number;
      levenshteinScores: Record<string, number>;
      hasPunycode: boolean;
      hasCredentialAtSign: boolean;
      isSuspiciousTLD: boolean;
    };
    isValid: boolean;
  }
  ```
- **Errors**: `MalformedURLError` (returns low-weight caution evidence, never crashes).
- **Security Constraints**: URL length capped at 2,048 characters to prevent ReDoS/parser buffer overflow.
- **Privacy Constraints**: Hostname split into hash tokens; no URL query parameters logged off-device.
- **Offline Behavior**: 100% offline via local Levenshtein dictionary and entropy math.
- **Performance**: $<0.2\text{ms}$ execution latency.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Crypto utilities (Entropy, Levenshtein).

---

### Contract 03: Message / Communication Analyzer
- **Purpose**: Analyzes inbound text messages and communications for social engineering, urgency, and fraud patterns.
- **Input**: `textInput: string`
- **Output**:
  ```typescript
  interface MessageAnalysisOutput {
    evidence: EvidenceItem[];
    extractedEntities: {
      hasEmbeddedLinks: boolean;
      hasPhoneNumbers: boolean;
      urgencyScore: number;
      isCryptoExtortion: boolean;
      isScareware: boolean;
      isLegalThreat: boolean;
      isFamilyImpersonation: boolean;
    };
  }
  ```
- **Errors**: `InvalidEncodingError` (sanitizes text via Unicode NFKD normalization).
- **Security Constraints**: Input capped at 10,000 characters; regex patterns audited for linear execution ($O(N)$).
- **Privacy Constraints**: Zero message persistence; volatile analysis only.
- **Offline Behavior**: 100% offline.
- **Performance**: $<0.3\text{ms}$ execution latency.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Unicode normalization utilities.

---

### Contract 04: Content & DOM Analyzer
- **Purpose**: Inspects webpage DOM trees for deceptive credential harvesting forms, unencrypted login fields, and brand spoofing.
- **Input**:
  ```typescript
  interface DOMInspectionInput {
    pageOrigin: string;
    formActionTargets: string[];
    hasPasswordInput: boolean;
    isPageHttps: boolean;
    pageTitle: string;
    embeddedIframeOrigins: string[];
  }
  ```
- **Output**: `EvidenceItem[]`
- **Errors**: `DOMAccessRestrictedError` (e.g. cross-origin iframe security restrictions).
- **Security Constraints**: Content Script operates in browser isolated worlds; no DOM mutation.
- **Privacy Constraints**: Analyzes structural tags only; does not read user-typed keystrokes or password values.
- **Offline Behavior**: 100% offline.
- **Performance**: $<5.0\text{ms}$ DOM traversal time.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Browser Extension Content Script host.

---

### Contract 05: File Analyzer
- **Purpose**: Inspects downloaded files and local executables via headers, magic numbers, entropy, and Yara signatures.
- **Input**:
  ```typescript
  interface FileInspectionInput {
    filePath: string;
    fileSizeBytes: number;
    headerBytes: Uint8Array;             // First 4,096 bytes
    fileSha256: string;
  }
  ```
- **Output**:
  ```typescript
  interface FileInspectionOutput {
    evidence: EvidenceItem[];
    fileType: string;                    // PE | Mach-O | ELF | ZIP | SCRIPT | UNKNOWN
    isExecutable: boolean;
    headerEntropy: number;
    isQuarantineRecommended: boolean;
  }
  ```
- **Errors**: `FileAccessDeniedError`, `FileLockedError`.
- **Security Constraints**: Header parsing runs in sandboxed worker thread with memory limit (64MB).
- **Privacy Constraints**: Local file names and paths remain on-device.
- **Offline Behavior**: 100% offline via local signature engine.
- **Performance**: $<15\text{ms}$ per file inspection.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Desktop Security Daemon.

---

### Contract 06: Threat Intelligence Provider
- **Purpose**: Fast $O(1)$ reputation lookups for domains, URLs, and file hashes using privacy-preserving Bloom filters.
- **Input**: `queryHash: string` (SHA-256 hex string)
- **Output**:
  ```typescript
  interface ThreatIntelMatch {
    isMatch: boolean;
    matchType: 'ALLOWLIST' | 'BLOCKLIST' | 'CLEAN';
    confidence: number;
    sourceFeed: string;
    lastUpdatedTimestamp: number;
    isStale: boolean;                    // True if cache age > 7 days
  }
  ```
- **Errors**: `DatabaseCorruptedError` (falls back to factory seed table).
- **Security Constraints**: Verified allowlists strictly override blocklist matches to prevent denial of service.
- **Privacy Constraints**: Queries accept SHA-256 hashes exclusively, never plaintext URLs.
- **Offline Behavior**: 100% offline against local memory-mapped Bloom filters.
- **Performance**: $<0.05\text{ms}$ ($50\mu\text{s}$) lookup latency.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Contract 13 (Threat Intel Updates).

---

### Contract 07: Risk Scoring Engine
- **Purpose**: Multi-factor mathematical aggregation of evidence items into a deterministic composite risk score and action recommendation.
- **Input**: `evidence: EvidenceItem[]`
- **Output**:
  ```typescript
  interface RiskScoreOutput {
    score: number;                       // 0 to 100
    category: RiskCategory;              // SAFE | SUSPICIOUS | PHISHING | SCAM | MALWARE
    severity: Severity;                  // 1 to 5
    confidence: number;                  // 0.0 to 1.0
    recommendation: ActionRecommendation;// ALLOW | INFORM | WARN | BLOCK
  }
  ```
- **Errors**: None (empty evidence defaults deterministically to score `0`, category `SAFE`, action `ALLOW`).
- **Security Constraints**: Critical deterministic rules (weight $\ge 90$, confidence $\ge 0.95$) trigger immediate `BLOCK` override.
- **Privacy Constraints**: Pure mathematical function; zero side-effects.
- **Offline Behavior**: 100% offline.
- **Performance**: $<0.01\text{ms}$ ($10\mu\text{s}$) calculation latency.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: None.

---

### Contract 08: Evidence Model Contract
- **Purpose**: Standardized immutable data structure representing discrete threat signals across all detection layers.
- **Schema**: `EvidenceItem` (as defined in Section 2).
- **Security Constraints**: Sanitized descriptions containing zero active executable script or injection delimiters.
- **Privacy Constraints**: Contains no raw user PII.
- **Versioning**: Contract v1.0.0.

---

### Contract 09: Explanation Engine
- **Purpose**: Synthesizes plain-language, non-jargon explanations from structured evidence chains using pre-compiled templates.
- **Input**:
  ```typescript
  interface ExplanationInput {
    riskCategory: RiskCategory;
    recommendation: ActionRecommendation;
    severity: Severity;
    evidence: EvidenceItem[];
  }
  ```
- **Output**: `SafeExplanation` (summary, bullet points, recommended action text).
- **Errors**: None (robust fallback to generic caution template).
- **Security Constraints**: Sanitizes technical terms (translates "Punycode IDN homograph" to "Deceptive lookalike characters").
- **Privacy Constraints**: Operates 100% on-device in memory.
- **Offline Behavior**: 100% offline.
- **Performance**: $<0.1\text{ms}$ execution latency.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: None.

---

### Contract 10: On-Device AI Security Assistant
- **Purpose**: Conversational explanation interface allowing users to ask interactive follow-up questions about detected threats.
- **Input**:
  ```typescript
  interface AssistantQueryInput {
    userQuestion: string;
    detectionContext: CommonDetectionResult;
  }
  ```
- **Output**:
  ```typescript
  interface AssistantResponseOutput {
    answerMarkdown: string;              // Plain-language conversational answer
    safetyWarningRepeated: boolean;      // Re-asserts warning if user asks to proceed
    suggestedFollowUpPrompts: string[];
  }
  ```
- **Errors**: `ModelInferenceError`, `PromptInjectionDetectedError` (falls back to template engine).
- **Security Constraints**: Enforces **AI Security Boundary**: user question and raw content treated strictly as untrusted data; read-only privileges; rigid JSON grammar constraint.
- **Privacy Constraints**: Inference executed locally via ONNX Runtime / CoreML / TFLite; zero cloud streaming.
- **Offline Behavior**: 100% offline.
- **Performance**: $<300\text{ms}$ time-to-first-token.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Contract 12 (Model Management).

---

### Contract 11: Local Encrypted Storage
- **Purpose**: Manages on-device persistent state (local allowlists, scan event counters, cached threat hashes).
- **Input**: Standard key-value or relational SQL queries (`get`, `put`, `query`, `delete`).
- **Output**: Decrypted data objects.
- **Errors**: `StorageFullError`, `EncryptionKeyUnavailableError`, `DatabaseCorruptionError`.
- **Security Constraints**: AES-256-GCM encryption at rest; encryption keys managed via OS Keystores.
- **Privacy Constraints**: No Tier 1 raw user content persisted; user can execute atomic wipe at any time.
- **Offline Behavior**: 100% offline.
- **Performance**: $<2\text{ms}$ read, $<10\text{ms}$ write.
- **Versioning**: Schema migration v1.
- **Dependencies**: OS Keychain / Keystore APIs.

---

### Contract 12: Model Management Runtime
- **Purpose**: Handles loading, integrity verification, memory mapping, and execution of quantized on-device ML models.
- **Input**: Model identifier (e.g. `intent-classifier-int8`, `explanation-slm-int4`).
- **Output**: Active inference session reference.
- **Errors**: `ModelNotFoundError`, `ModelSignatureMismatchError`, `OutOfMemoryError` (falls back to template engine).
- **Security Constraints**: Verifies Ed25519 digital signature and SHA-256 hash before loading any model file into RAM.
- **Privacy Constraints**: Models loaded locally from device filesystem.
- **Offline Behavior**: 100% offline.
- **Performance**: Initialization $<500\text{ms}$; warm inference session maintained in RAM.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: Local filesystem, OS NPU/GPU drivers.

---

### Contract 13: Threat Intelligence Delta Updater
- **Purpose**: Manages atomic differential updates for local Bloom filters and threat rule definitions.
- **Input**:
  ```typescript
  interface UpdateCheckRequest {
    currentRulesetVersion: number;
    currentBloomFilterVersion: number;
  }
  ```
- **Output**:
  ```typescript
  interface UpdateCheckResponse {
    isUpdateAvailable: boolean;
    latestVersion?: number;
    patchDownloadUrl?: string;
    patchSha256?: string;
    patchSignatureEd25519?: string;      // Base64 signed manifest
    patchSizeBytes?: number;
  }
  ```
- **Errors**: `NetworkUnavailableError` (silent backoff), `SignatureVerificationFailedError` (quarantine and reject).
- **Security Constraints**: Ed25519 signature verified against public key hardcoded in binary; monotonic sequence check prevents rollback.
- **Privacy Constraints**: Request contains version numbers only; zero device identifiers or IP telemetry transmitted.
- **Offline Behavior**: Suspends update check; operates on existing local cache.
- **Performance**: Delta patch size $<1\text{MB}$.
- **Versioning**: Manifest format v1.
- **Dependencies**: Contract 15 (Backend API).

---

### Contract 14: Notification & Warning System
- **Purpose**: Dispatches instantaneous, cross-platform user alerts upon detection of high-risk threats.
- **Input**:
  ```typescript
  interface WarningDispatchInput {
    result: CommonDetectionResult;
    displayMode: 'MODAL_OVERLAY' | 'SYSTEM_NOTIFICATION' | 'INLINE_BANNER';
  }
  ```
- **Output**: `Promise<{ userAction: 'BLOCKED' | 'PROCEEDED' | 'DISMISSED' }>`
- **Errors**: `NotificationPermissionDeniedError` (falls back to in-app modal).
- **Security Constraints**: High-risk warnings enforce deliberate friction (e.g. "Go Back" primary button; small "Advanced / Proceed" link).
- **Privacy Constraints**: Lock-screen notifications mask sensitive URLs and phone numbers.
- **Offline Behavior**: 100% offline.
- **Performance**: Dispatched and rendered within $<50\text{ms}$ of scan completion.
- **Versioning**: Contract v1.0.0.
- **Dependencies**: OS Notification APIs / Browser Shadow DOM.

---

### Contract 15: Stateless Backend API
- **Purpose**: Cloud distribution interface for differential updates, threat feed compilation, and anonymous telemetry.
- **Endpoints**:
  - `GET /v1/updates/manifest`: Returns latest version integers and patch URLs.
  - `GET /v1/updates/patches/{id}`: Serves binary delta patch files.
  - `POST /v1/telemetry/anonymized`: Ingests OHTTP relay encrypted threat telemetry.
- **Input**: Standard HTTP requests.
- **Output**: JSON manifests and binary patch streams.
- **Errors**: HTTP 400, 404, 429 (Rate Limited), 503 (Under Maintenance).
- **Security Constraints**: Strict rate limiting (10 req/min per IP); Cloudflare CDN DDoS shielding; TLS 1.3 only.
- **Privacy Constraints**: Telemetry endpoint accepts requests exclusively via Oblivious HTTP relays; client IP discarded.
- **Offline Behavior**: N/A (Server endpoint).
- **Performance**: $<50\text{ms}$ CDN edge response time.
- **Versioning**: API v1.
- **Dependencies**: Cloud CDN infrastructure.

---

### Contract 16: Authentication & Attestation
- **Purpose**: Anonymous client attestation for accessing update endpoints without persistent user accounts or trackable cookies.
- **Protocol**:
  - Web Crypto Anonymous Token / Apple App Attest / Android Play Integrity.
  - Verifies that the client binary is genuine, untampered, and official.
- **Output**: Ephemeral cryptographic access token valid for 60 seconds.
- **Security Constraints**: Cryptographically binds requests to genuine application binaries without storing user identity.
- **Privacy Constraints**: Zero user accounts; zero email/password credentials; zero advertising tracking.
- **Offline Behavior**: Unnecessary offline (updates require internet).
- **Versioning**: Protocol v1.
- **Dependencies**: OS Attestation Frameworks.

---

### Contract 17: Audit & Security Event Logging
- **Purpose**: Records localized, tamper-evident security audit logs (threats detected, rule updates applied, overrides chosen).
- **Input**:
  ```typescript
  interface SecurityAuditEvent {
    eventId: string;                     // UUIDv4
    timestamp: string;                   // ISO-8601
    eventType: 'THREAT_BLOCKED' | 'USER_OVERRIDE' | 'UPDATE_APPLIED' | 'CORRUPTION_RECOVERED';
    severity: 'INFO' | 'WARNING' | 'CRITICAL';
    details: Record<string, string>;     // Anonymized technical metadata
  }
  ```
- **Output**: Cryptographic append to local ring buffer.
- **Errors**: `DiskFullError`.
- **Security Constraints**: Local log records signed via local key; ring buffer capped at 5MB to prevent storage exhaustion.
- **Privacy Constraints**: Audit log stored in encrypted local storage; NEVER synced to cloud servers.
- **Offline Behavior**: 100% offline.
- **Performance**: $<1\text{ms}$ append latency.
- **Versioning**: Log schema v1.
- **Dependencies**: Contract 11 (Local Storage).
