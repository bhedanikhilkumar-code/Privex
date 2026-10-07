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
  PROCESS = 'PROCESS',
  QR = 'QR',
  DOM = 'DOM'
}

export enum TargetType {
  URL = 'URL',
  MESSAGE = 'MESSAGE',
  FILE_HEADER = 'FILE_HEADER',
  PROCESS = 'PROCESS',
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
  QUARANTINE_FILE = 'QUARANTINE_FILE',
  CONTAIN_PROCESS = 'CONTAIN_PROCESS'
}

/**
 * Canonical 6-Tier Antivirus Engine Verdict Policy (Phase B Step 10)
 * Strictly decoupled from UI presentation copy.
 */
export enum EngineVerdict {
  ALLOW = 'ALLOW',
  INFORM = 'INFORM',
  WARN = 'WARN',
  BLOCK = 'BLOCK',
  QUARANTINE = 'QUARANTINE',
  CONTAIN_PROCESS = 'CONTAIN_PROCESS'
}

/**
 * Canonical Detector Layer Categories (Phase B Step 8)
 */
export enum DetectorLayer {
  HASH_INTEL = 'HASH_INTEL',
  SIGNATURE_ENGINE = 'SIGNATURE_ENGINE',
  METADATA_ANALYZER = 'METADATA_ANALYZER',
  STATIC_HEURISTIC = 'STATIC_HEURISTIC',
  STRUCTURAL_PARSER = 'STRUCTURAL_PARSER',
  BEHAVIORAL_ENGINE = 'BEHAVIORAL_ENGINE',
  REPUTATION_LOCAL = 'REPUTATION_LOCAL',
  CORRELATION_ENGINE = 'CORRELATION_ENGINE'
}

/**
 * Explicit execution state for each detector layer.
 * Unimplemented or unexecuted layers must be reported as UNAVAILABLE or NOT_RUN, never SAFE.
 */
export type DetectorLayerState = 'EXECUTED' | 'NOT_RUN' | 'UNAVAILABLE' | 'FAILED';

export type HashDisposition = 'KNOWN_GOOD' | 'KNOWN_BAD' | 'UNKNOWN';

export enum FrictionLevel {
  NONE = 'NONE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

export type AnalysisStatus = 'COMPLETED' | 'ANALYSIS_FAILED' | 'UNKNOWN';

export type DetectionDisposition =
  | 'SAFE'
  | 'ALLOW'
  | 'SUSPICIOUS'
  | 'WARN'
  | 'MALICIOUS'
  | 'BLOCK'
  | 'QUARANTINE'
  | 'CONTAIN_PROCESS'
  | 'UNKNOWN'
  | 'ANALYSIS_FAILED';

export enum DetectorType {
  RULE = 'RULE',
  HEURISTIC = 'HEURISTIC',
  THREAT_INTEL = 'THREAT_INTEL',
  ML_MODEL = 'ML_MODEL',
  REPUTATION = 'REPUTATION',
  CORRELATION = 'CORRELATION'
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
  readonly processMetadata?: ProcessInputMetadata;
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
  processMetadata?: ProcessInputMetadata;
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
  detectorLayer?: DetectorLayer | string;
  scoreContribution?: number; // 0-100
  metadata?: Record<string, string>;
  reason?: string;
  severityLevel?: SeverityLevel | string;

  // Foundational fields
  source: string;
  name: string;
  description: string;
  weight: number; // 0-100 or normalized 0.0-1.0
  confidence: number; // 0.0-1.0
  type?: string;
  indicator?: string;
  isCriticalOverride?: boolean;
  isAllowed?: boolean;
  isMalicious?: boolean;
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
  readonly correlationMatches?: string[];
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
  engineVerdict?: EngineVerdict;
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
  analysisStatus?: AnalysisStatus;
  disposition?: DetectionDisposition;
  detectorLayers?: Record<DetectorLayer, DetectorLayerState>;
  correlationMatches?: string[];
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

export interface UpdateMetadata {
  readonly targetVersion: number;
  readonly baseVersion: number;
  readonly patchType: 'BLOOM_DIFF' | 'RULES_JSON' | 'ENGINE_WASM';
  readonly sha256: string;
  readonly ed25519Signature: string;
  readonly downloadUrl: string;
  readonly sizeBytes: number;
}

export interface PpdbManifest {
  readonly version: string;
  readonly versionSequence: number;
  readonly publishedAt: number;
  readonly sha256: string;
  readonly signature: string; // 128 hex chars Ed25519 signature
}

export interface ThreatHashEntry {
  readonly hash: string;
  readonly threatName?: string;
  readonly category?: RiskCategory | string;
  readonly severity?: SeverityLevel | string;
  readonly threatType?: 'DOMAIN' | 'URL' | 'IP' | 'HASH';
  readonly isCritical?: boolean;
}

export interface PpdbPayload {
  readonly addBadHashes?: ThreatHashEntry[];
  readonly addBadDomains?: string[];
  readonly addBadUrls?: string[];
  readonly addBadIps?: string[];
  readonly removeBadHashes?: string[];
  readonly removeBadDomains?: string[];
  readonly removeBadUrls?: string[];
  readonly removeBadIps?: string[];
  readonly metadata?: {
    readonly description?: string;
    readonly minEngineVersion?: string;
    readonly totalRules?: number;
  };
}

export interface PpdbBundle {
  readonly format: 'PPDB1';
  readonly manifest: PpdbManifest;
  readonly payload: PpdbPayload | string;
}

// ==========================================
// 4. CANONICAL FILE & PROCESS ANALYSIS DOMAIN MODELS
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
  readonly engineVerdict?: EngineVerdict;
  readonly threatName: string;
  readonly evidenceFactors: string[];
  readonly analysisStatus?: AnalysisStatus;
  readonly disposition?: DetectionDisposition;
  readonly errorReason?: string;
}

/**
 * Canonical Process Input Metadata (Phase B Step 12)
 * Command-line strings are sanitized/redacted in memory before evidence emission
 * so sensitive user tokens/credentials are never persisted.
 */
export interface ProcessInputMetadata {
  readonly pid: number;
  readonly ppid?: number;
  readonly processName: string;
  readonly parentName?: string;
  readonly executablePath?: string;
  readonly sha256?: string;
  readonly isSigned?: boolean;
  readonly signer?: string;
  readonly commandLine?: string;
  readonly creationTimestamp?: number;
}

export type ProcessScanRequest =
  | ProcessInputMetadata
  | { readonly process: ProcessInputMetadata };

export interface ProcessScanResult {
  readonly pid: number;
  readonly ppid?: number;
  readonly processName: string;
  readonly parentName?: string;
  readonly executablePath?: string;
  readonly sha256?: string;
  readonly isSigned?: boolean;
  readonly signer?: string;
  readonly sanitizedCommandLine?: string;
  readonly riskScore: number;
  readonly confidence: number;
  readonly severity: SeverityLevel;
  readonly verdict: Verdict;
  readonly engineVerdict: EngineVerdict;
  readonly actionRecommendation: ActionRecommendation;
  readonly disposition: DetectionDisposition;
  readonly analysisStatus: AnalysisStatus;
  readonly threatName: string;
  readonly evidenceFactors: string[];
  readonly evidence: Evidence[];
  readonly detectorLayers: Record<DetectorLayer, DetectorLayerState>;
  readonly errorReason?: string;
}

export interface HashLookupResult {
  readonly hash: string;
  readonly status: HashDisposition;
  readonly disposition: HashDisposition;
  readonly isMalicious: boolean;
  readonly isAllowed: boolean;
  readonly isCritical?: boolean;
  readonly threatName?: string;
  readonly category?: RiskCategory | string;
  readonly severityLevel?: SeverityLevel | string;
  readonly sourceFeed?: string;
  readonly confidence: number;
  readonly bloomFilterHit: boolean;
  readonly evidence?: Evidence;
}

