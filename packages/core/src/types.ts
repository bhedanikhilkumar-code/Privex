/**
 * Canonical Domain Models and Interfaces for @private-protection/core
 * Conforming to docs/DOMAIN_MODELS.md and docs/INTERFACE_CONTRACTS.md
 */

// ==========================================
// 1. CANONICAL ENUMS & TAXONOMIES
// ==========================================

export enum RiskCategory {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  PHISHING = 'PHISHING',
  SCAM = 'SCAM',
  MALWARE = 'MALWARE',
  EXTORTION = 'EXTORTION',
  MALICIOUS_CONTENT = 'MALICIOUS_CONTENT'
}

export enum Verdict {
  ALLOW = 'ALLOW',
  INFORM = 'INFORM',
  CAUTION = 'CAUTION',
  SUSPICIOUS = 'SUSPICIOUS',
  DANGEROUS = 'DANGEROUS'
}

export enum SeverityLevel {
  NONE = 'NONE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

/**
 * Legacy numeric severity mapping for backwards compatibility
 */
export enum Severity {
  SPAM = 1,
  PRIVACY_RISK = 2,
  FINANCIAL_FRAUD = 3,
  ACCOUNT_LOSS = 4,
  DEVICE_COMPROMISE = 5
}

export enum Confidence {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

export enum InputType {
  URL = 'URL',
  TEXT = 'TEXT',
  FILE = 'FILE',
  QR = 'QR',
  DOM = 'DOM'
}

export enum TargetType {
  URL = 'URL',
  MESSAGE = 'MESSAGE',
  FILE_HEADER = 'FILE_HEADER',
  DOM_STRUCTURE = 'DOM_STRUCTURE'
}

export enum ActionRecommendation {
  ALLOW = 'ALLOW',
  INFORM = 'INFORM',
  WARN = 'WARN',
  BLOCK = 'BLOCK'
}

export enum PrescribedAction {
  PROCEED = 'PROCEED',
  WARN_USER = 'WARN_USER',
  BLOCK_NAVIGATION = 'BLOCK_NAVIGATION',
  QUARANTINE_FILE = 'QUARANTINE_FILE'
}

export enum FrictionLevel {
  NONE = 'NONE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

export enum DetectorType {
  RULE = 'RULE',
  HEURISTIC = 'HEURISTIC',
  THREAT_INTEL = 'THREAT_INTEL',
  ML_MODEL = 'ML_MODEL',
  REPUTATION = 'REPUTATION'
}

export enum PlatformType {
  ANDROID = 'ANDROID',
  IOS = 'IOS',
  WINDOWS = 'WINDOWS',
  MACOS = 'MACOS',
  BROWSER_EXT = 'BROWSER_EXT',
  WEB_PWA = 'WEB_PWA'
}

// ==========================================
// 2. THE 11 CANONICAL DOMAIN MODELS
// ==========================================

/**
 * Model 7: Operational context supplied with a scan request
 */
export interface AnalysisContext {
  readonly platform: PlatformType | string;
  readonly appVersion: string;
  readonly engineVersion: number;
  readonly isOffline: boolean;
  readonly sourceOrigin?: string;
}

/**
 * Execution flags for scanning
 */
export interface ScanOptions {
  readonly fastPathOnly?: boolean;
  readonly skipThreatIntel?: boolean;
  readonly timeoutMs?: number;
}

/**
 * Model 1: Canonical scan request submitted to the detection engine
 */
export interface DetectionRequest {
  readonly id: string; // UUIDv4
  readonly timestamp: number; // Unix epoch ms
  readonly type: TargetType | InputType | string;
  readonly payload: string | Uint8Array;
  readonly context?: AnalysisContext;
  readonly options?: ScanOptions;
}

/**
 * Backwards-compatible flexible ScanRequest interface
 */
export interface ScanRequest {
  input?: string;
  content?: string;
  payload?: string | Uint8Array;
  inputType?: InputType;
  type?: string | InputType | TargetType;
  metadata?: Record<string, string>;
  id?: string;
  timestamp?: number;
  context?: AnalysisContext;
  options?: ScanOptions;
}

/**
 * Model 4: Atomic, tamper-evident token of technical telemetry produced by a detector
 */
export interface Evidence {
  // Canonical fields
  ruleId?: string;
  detectorType?: DetectorType | string;
  scoreContribution?: number; // 0-100
  metadata?: Record<string, string>;

  // Foundational fields
  source: string;
  name: string;
  description: string;
  weight: number; // 0-100 or normalized 0.0-1.0
  confidence: number; // 0.0-1.0
  type?: string;
  indicator?: string;
  isCriticalOverride?: boolean;
}

/**
 * Model 3: Canonical Threat category identified within the analyzed target
 */
export interface Threat {
  readonly id: string; // pattern: ^[a-z0-9\-]{3,32}$
  readonly category: RiskCategory | string;
  readonly severity: SeverityLevel | string;
  readonly confidence: number; // 0.0 to 1.0
  readonly description: string;
}

/**
 * Model 5: Aggregated risk calculation computed by the Multi-Factor Risk Engine
 */
export interface RiskAssessment {
  readonly overallScore: number; // 0 to 100
  readonly confidence: number; // 0.0 to 1.0
  readonly severity: SeverityLevel | string;
  readonly primaryThreatFactor: string;
  readonly detectorContributions: Record<string, number>;
  readonly uncertainty?: number;
}

/**
 * Model 6: Actionable recommendation prescribing client UI friction gate
 */
export interface Recommendation {
  readonly action: PrescribedAction | ActionRecommendation | string;
  readonly frictionLevel: FrictionLevel | string;
  readonly suggestedAction: string;
  readonly bypassPermitted: boolean;
}

/**
 * Subsystem 11 Contract: Structured threat explanation
 */
export interface Explanation {
  readonly headline: string;
  readonly plainTextSummary: string;
  readonly technicalDetails: string[];
  readonly recommendedSteps: string[];
  readonly confidenceLabel: 'HIGH' | 'MEDIUM' | 'LOW';
}

/**
 * Model 2: Complete consolidated detection verdict returned by DetectionEngine
 */
export interface DetectionResult {
  // Canonical fields (populated by DetectionPipeline)
  requestId?: string;
  verdict?: Verdict | string;
  riskAssessment?: RiskAssessment;
  threats?: Threat[];
  executionTimeMs?: number;

  // Primary fields
  scanId: string;
  id: string;
  timestamp: string;
  inputType: InputType;
  riskCategory: RiskCategory;
  riskScore: number;
  score: number;
  confidence: number;
  severity: Severity | SeverityLevel | string;
  evidence: Evidence[];
  explanation: Explanation | string;
  recommendation: ActionRecommendation | string;
  canonicalRecommendation?: Recommendation;
  action: ActionRecommendation | string;
  error?: string;
}

/**
 * Model 8: Encrypted audit log entry for local storage
 */
export interface SecurityEvent {
  readonly eventId: string; // UUIDv4
  readonly timestamp: number; // Unix ms
  readonly targetType: TargetType | InputType | string;
  readonly targetIdentifierHash: string; // SHA-256 hex
  readonly verdict: Verdict | string;
  readonly riskScore: number;
  readonly userActionTaken?: 'BLOCKED' | 'BYPASSED' | 'IGNORED' | 'WHITELISTED';
}

/**
 * Model 9: Metadata tracking installed on-device AI/ML model artifacts
 */
export interface ModelMetadata {
  readonly modelId: string;
  readonly format: 'ONNX_INT8' | 'TFLITE_INT8' | 'TEMPLATE_BUNDLE';
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly version: number;
}

/**
 * Model 10: In-memory representation of local threat intelligence database
 */
export interface ThreatIntelRecord {
  readonly databaseVersion: number;
  readonly filterType: 'BLOOM_FILTER_V1' | 'RADIX_TRIE_V1' | 'HASH_SET_V1';
  readonly capacity: number;
  readonly falsePositiveRate: number;
  readonly generatedEpoch: number;
}

/**
 * Model 11: Cryptographic manifest describing an OTA differential patch
 */
export interface UpdateMetadata {
  readonly targetVersion: number;
  readonly baseVersion: number;
  readonly patchType: 'BLOOM_DIFF' | 'RULES_JSON' | 'ENGINE_WASM';
  readonly sha256: string;
  readonly ed25519Signature: string;
  readonly downloadUrl: string;
  readonly sizeBytes: number;
}

// ==========================================
// 4. CANONICAL FILE ANALYSIS DOMAIN MODELS
// ==========================================

export interface FileScanRequest {
  readonly filePath?: string;
  readonly fileName: string;
  readonly fileSize: number;
  readonly headerBytes: Uint8Array | Buffer;
  readonly mimeType?: string;
}

export interface FileScanResult {
  readonly fileName: string;
  readonly filePath?: string;
  readonly fileSize: number;
  readonly sha256: string;
  readonly entropy: number;
  readonly magicHeader: string | null;
  readonly isExecutable: boolean;
  readonly isDeceptiveExtension: boolean;
  readonly riskScore: number;
  readonly severity: SeverityLevel;
  readonly verdict: Verdict;
  readonly threatName: string;
  readonly evidenceFactors: string[];
}
