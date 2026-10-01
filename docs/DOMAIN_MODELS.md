# DOMAIN_MODELS.md — Canonical Implementation-Independent Domain Models

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION DOMAIN MODELS**  
> This document defines the canonical domain models across the PRIVATE PROTECTION platform. These models are implementation-independent, technology-agnostic, and strictly typed. All platform implementations (Dart, Rust, TypeScript, Swift, Kotlin) must conform exactly to these structural contracts.

---

## 1. DATA SENSITIVITY CLASSIFICATION REFERENCE
Every field in every domain model is tagged with its data classification level:
- **[TIER 1 - HIGHLY SENSITIVE]**: Raw user payloads (URLs, message text, files, camera frames). Processed strictly in volatile RAM. Never persisted unencrypted; never transmitted over network.
- **[TIER 2 - INTERNAL STATE]**: Encrypted local state (user allowlists, scan event counters, quarantine metadata). Encrypted at rest using AES-256-GCM.
- **[TIER 3 - ANONYMIZED TELEMETRY]**: Anonymized metrics (rule IDs, truncated hash prefixes, engine versions). Transmitted only with explicit opt-in via OHTTP relay.
- **[TIER 4 - PUBLIC METADATA]**: Public threat feeds, signed update manifests, and system configurations. Safe for public transport.

---

## 2. THE 11 CORE DOMAIN MODELS

### 2.1 Model 1: `DetectionRequest`
Represents an incoming security evaluation request submitted by any platform adapter to the detection engine.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `id` | `UUIDv4` | **Required** | Valid RFC 4122 UUID | **Tier 4** | Unique identifier for tracing this scan request in memory. |
| `timestamp` | `Int64` (Unix ms) | **Required** | Positive integer $\le$ current epoch + 5000ms | **Tier 4** | Timestamp when the request was initiated. |
| `type` | `String` (Enum) | **Required** | One of: `URL`, `MESSAGE`, `FILE_HEADER`, `DOM_STRUCTURE` | **Tier 4** | Type of target being inspected. |
| `payload` | `String` \| `Binary` | **Required** | URLs $\le$ 2,048 B; Messages $\le$ 10,000 chars; File headers $\le$ 64 KB | **Tier 1** | Untrusted content to analyze. Must be zeroed from RAM after scan. |
| `context` | `AnalysisContext` | **Required** | Valid `AnalysisContext` struct | **Tier 2** | Operational context (platform, caller, network state). |
| `options` | `ScanOptions` | Optional | Default flags applied if null | **Tier 4** | Execution flags (e.g., `fastPathOnly`, `skipThreatIntel`). |

- **Serialization**: JSON for IPC/WASM; in-memory struct for native FFI.
- **Version Compatibility**: Backward-compatible with v1.x; unknown optional flags ignored.

---

### 2.2 Model 2: `DetectionResult`
The complete, consolidated detection verdict returned by the detection engine.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `requestId` | `UUIDv4` | **Required** | Matches corresponding `DetectionRequest.id` | **Tier 4** | Links the result to the initial request. |
| `verdict` | `String` (Enum) | **Required** | One of: `ALLOW`, `INFORM`, `CAUTION`, `SUSPICIOUS`, `DANGEROUS` | **Tier 4** | Final categorical security verdict. |
| `riskAssessment`| `RiskAssessment` | **Required** | Valid `RiskAssessment` struct | **Tier 4** | Numeric risk score, confidence, and severity breakdown. |
| `threats` | `Array<Threat>` | **Required** | Min items: 0. Max items: 20 | **Tier 4** | List of specific threats identified during evaluation. |
| `evidence` | `Array<Evidence>`| **Required** | Min items: 0. Max items: 50 | **Tier 4** | Granular technical evidence tokens supporting the verdict. |
| `recommendation`| `Recommendation`| **Required** | Valid `Recommendation` struct | **Tier 4** | Prescribed action and friction level for the user. |
| `explanation` | `Explanation` | Optional | Null on fast-path; populated when slow-path completes | **Tier 4** | User-friendly explanation synthesized by AI/Template. |
| `executionTimeMs`| `Float64` | **Required** | $\ge 0.0$. Must be $< 100.0\text{ ms}$ for full scan | **Tier 4** | Total wall-clock time spent in core engine. |

- **Serialization**: JSON / Protobuf / FlatBuffers for cross-platform zero-copy deserialization.
- **Version Compatibility**: Additive changes only; enum values are append-only.

---

### 2.3 Model 3: `Threat`
Represents an individual threat category identified within the analyzed target.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `id` | `String` | **Required** | Pattern: `^[a-z0-9\-]{3,32}$` (e.g., `brand-spoofing`) | **Tier 4** | Canonical threat category identifier. |
| `category` | `String` (Enum) | **Required** | One of: `PHISHING`, `SCAM`, `MALICIOUS_CONTENT`, `EXTORTION`, `MALWARE` | **Tier 4** | High-level taxonomy category. |
| `severity` | `String` (Enum) | **Required** | One of: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | **Tier 4** | Severity rating of this specific threat. |
| `confidence` | `Float64` | **Required** | Range: $[0.0, 1.0]$ | **Tier 4** | Detector confidence in this threat determination. |
| `description` | `String` | **Required** | Length: $10 \le \text{len} \le 256$ chars | **Tier 4** | Concise technical description of the threat. |

- **Serialization**: JSON.
- **Version Compatibility**: Additive enum values handled via fallback to `SUSPICIOUS`.

---

### 2.4 Model 4: `Evidence`
An atomic, tamper-evident token of technical telemetry produced by a detector.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `ruleId` | `String` | **Required** | Registered rule identifier (e.g., `rule-punycode-homoglyph`) | **Tier 4** | Specific detector rule or heuristic that triggered. |
| `detectorType` | `String` (Enum) | **Required** | One of: `RULE`, `HEURISTIC`, `THREAT_INTEL`, `ML_MODEL`, `REPUTATION` | **Tier 4** | Subsystem that produced the evidence. |
| `weight` | `Float64` | **Required** | Range: $[0.0, 1.0]$ | **Tier 4** | Configured contribution weight of this signal. |
| `scoreContribution`| `Int32` | **Required** | Range: $[0, 100]$ | **Tier 4** | Raw score points added by this evidence token. |
| `metadata` | `Map<String, String>`| Optional | Max 10 keys; values $\le 128$ chars; **NO TIER 1 DATA** | **Tier 4** | Sanitized parameters (e.g., `targetBrand: "PayPal"`, `entropy: "4.82"`). |

- **Sensitivity Invariant**: **MUST NEVER** contain raw user URLs, message strings, or file paths.
- **Serialization**: JSON.

---

### 2.5 Model 5: `RiskAssessment`
The aggregated risk calculation computed by the Multi-Factor Risk Engine.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `overallScore` | `Int32` | **Required** | Range: $[0, 100]$. Deterministic integer. | **Tier 4** | Scaled aggregate threat score ($0 = \text{Safe}, 100 = \text{Malicious}$). |
| `confidence` | `Float64` | **Required** | Range: $[0.0, 1.0]$. Bounded float. | **Tier 4** | Aggregate confidence in the score. |
| `severity` | `String` (Enum) | **Required** | One of: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | **Tier 4** | Mapped severity level based on score and evidence peaks. |
| `primaryThreatFactor`| `String` | **Required** | Must match one `Threat.id` or `"NONE"` | **Tier 4** | The single highest-weighted factor driving the score. |
| `detectorContributions`| `Map<String, Int32>`| **Required** | Sum of keys $\le$ overallScore | **Tier 4** | Breakdown of points by detector plane. |

- **Serialization**: JSON / Binary.

---

### 2.6 Model 6: `Recommendation`
The actionable advice prescribing how the client UI must gate user interaction.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `action` | `String` (Enum) | **Required** | One of: `PROCEED`, `WARN_USER`, `BLOCK_NAVIGATION`, `QUARANTINE_FILE` | **Tier 4** | Prescribed client action. |
| `frictionLevel` | `String` (Enum) | **Required** | One of: `NONE`, `LOW` (banner), `MEDIUM` (modal), `HIGH` (countdown gate) | **Tier 4** | Degree of friction required to proceed. |
| `suggestedAction`| `String` | **Required** | Length $\le 128$ chars (e.g., "Do not enter passwords") | **Tier 4** | Concise directive instructing the user. |
| `bypassPermitted`| `Boolean` | **Required** | True if user can override; False if strictly blocked | **Tier 4** | Policy flag governing manual bypass. |

---

### 2.7 Model 7: `AnalysisContext`
Operational context supplied by the platform adapter along with the scan request.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `platform` | `String` (Enum) | **Required** | One of: `ANDROID`, `IOS`, `WINDOWS`, `MACOS`, `BROWSER_EXT`, `WEB_PWA` | **Tier 4** | Target operating environment. |
| `appVersion` | `String` | **Required** | Semantic versioning format (e.g., `1.0.0`) | **Tier 4** | Current installed client application version. |
| `engineVersion` | `Int32` | **Required** | Monotonic integer (e.g., `104`) | **Tier 4** | Core detection engine rule/schema version. |
| `isOffline` | `Boolean` | **Required** | True if device has no network access | **Tier 4** | Connectivity state flag. |
| `sourceOrigin` | `String` | Optional | Sanitized origin domain (e.g., `web-form`, `sms-listener`) | **Tier 4** | Ingestion channel descriptor. |

---

### 2.8 Model 8: `SecurityEvent`
An encrypted audit log entry saved to local persistent storage for user review.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `eventId` | `UUIDv4` | **Required** | Valid RFC 4122 UUID | **Tier 2** | Unique persistent log record identifier. |
| `timestamp` | `Int64` (Unix ms) | **Required** | Positive integer | **Tier 2** | Epoch time of event. |
| `targetType` | `String` (Enum) | **Required** | One of: `URL`, `MESSAGE`, `FILE` | **Tier 2** | Category of analyzed artifact. |
| `targetIdentifierHash`| `String` (Hex SHA-256)| **Required** | Length: 64 hex characters | **Tier 2** | One-way cryptographic hash of target (Never plaintext). |
| `verdict` | `String` (Enum) | **Required** | Matches `DetectionResult.verdict` | **Tier 2** | Final verdict awarded. |
| `riskScore` | `Int32` | **Required** | Range: $[0, 100]$ | **Tier 2** | Risk score recorded. |
| `userActionTaken`| `String` (Enum) | Optional | One of: `BLOCKED`, `BYPASSED`, `IGNORED`, `WHITELISTED` | **Tier 2** | Action taken by user in response to warning. |

---

### 2.9 Model 9: `ModelMetadata`
Metadata tracking installed on-device AI/ML model artifacts.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `modelId` | `String` | **Required** | Identifier (e.g., `tinybert-scam-intent-v2`) | **Tier 4** | Unique name of the local model artifact. |
| `format` | `String` (Enum) | **Required** | One of: `ONNX_INT8`, `TFLITE_INT8`, `TEMPLATE_BUNDLE` | **Tier 4** | Binary execution format. |
| `sha256` | `String` (Hex) | **Required** | 64 hex characters | **Tier 4** | Cryptographic digest of model file on disk. |
| `sizeBytes` | `Int64` | **Required** | Range: $1 \le \text{size} \le 50,000,000$ ($< 50\text{ MB}$) | **Tier 4** | Total uncompressed model size in bytes. |
| `version` | `Int32` | **Required** | Monotonic integer | **Tier 4** | Model training/compilation revision. |

---

### 2.10 Model 10: `ThreatIntelRecord`
In-memory representation of local threat intelligence databases.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `databaseVersion`| `Int32` | **Required** | Monotonic integer | **Tier 4** | Current database schema and contents version. |
| `filterType` | `String` (Enum) | **Required** | One of: `BLOOM_FILTER_V1`, `RADIX_TRIE_V1` | **Tier 4** | Structural algorithm used for storage. |
| `capacity` | `Int64` | **Required** | Number of capacity slots (e.g., $1,000,000$) | **Tier 4** | Designed maximum element capacity. |
| `falsePositiveRate`| `Float64`| **Required** | Designed target FPR (e.g., $0.001$) | **Tier 4** | Mathematical false positive probability. |
| `generatedEpoch` | `Int64` | **Required** | Unix timestamp of build time | **Tier 4** | Build timestamp used for staleness calculation. |

---

### 2.11 Model 11: `UpdateMetadata`
Cryptographic manifest describing an available OTA differential patch.

| Field Name | Type | Required? | Validation Rules | Sensitivity | Description |
|---|---|---|---|---|---|
| `targetVersion` | `Int32` | **Required** | Must be strictly $>$ current installed version | **Tier 4** | Target update version. |
| `baseVersion` | `Int32` | **Required** | Base version required to apply patch (0 for full) | **Tier 4** | Pre-requisite base version. |
| `patchType` | `String` (Enum) | **Required** | One of: `BLOOM_DIFF`, `RULES_JSON`, `ENGINE_WASM` | **Tier 4** | Content type of the patch file. |
| `sha256` | `String` (Hex) | **Required** | 64 hex characters | **Tier 4** | SHA-256 hash of the binary patch file. |
| `ed25519Signature`| `String` (Hex) | **Required** | 128 hex characters (64 bytes Ed25519) | **Tier 4** | Cryptographic signature over `(targetVersion + sha256)`. |
| `downloadUrl` | `String` (URL) | **Required** | Valid HTTPS URL pointing to authorized CDN | **Tier 4** | Static CDN download URL. |
| `sizeBytes` | `Int64` | **Required** | Positive integer $< 10,000,000$ ($< 10\text{ MB}$) | **Tier 4** | Download payload size. |
