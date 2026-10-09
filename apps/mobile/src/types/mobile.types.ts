import {
  Verdict,
  SeverityLevel,
  Evidence,
  Recommendation
} from '@private-protection/core';
import { AssistantOutput } from '@private-protection/ml';

export type ScanTargetType = 'URL' | 'TEXT' | 'FILE';

declare global {
  interface Window {
    AndroidSecurityBridge?: {
      getPlatformMetadata?: () => string;
      notifyClientReady?: () => void;
      consumePendingIntent?: () => string | null;
      isSecureStorageEncrypted?: () => boolean;
      secureStorageGet?: (key: string) => string | null;
      secureStoragePut?: (key: string, value: string) => boolean;
      secureStorageRemove?: (key: string) => boolean;
      secureStorageClear?: () => boolean;
      decodeQrFrame?: (base64Image: string) => string;
      triggerWarningHaptics?: (severity: string) => void;
      dispatchNativeNotification?: (title: string, body: string, priority: string) => boolean;
      hasCameraPermission?: () => boolean;
      requestCameraPermission?: () => void;
      getDeviceSecurityPosture?: () => string;
      submitSecurityJob?: (jobTypeStr: string, metadataJsonStr: string) => string;
      cancelSecurityJob?: (jobId: string, reason: string) => boolean;
      getSecurityJobStatus?: (jobId: string) => string;
      listActiveSecurityJobs?: () => string;
      getCoordinatorStats?: () => string;
      auditPackage?: (packageName: string) => string;
      auditApkFile?: (apkFilePath: string) => string;
      requestUninstall?: (packageName: string) => boolean;
      inspectFile?: (filePath: string) => string;
      inspectFileUri?: (uriString: string, declaredFileName: string) => string;
      quarantineFile?: (filePath: string) => string;
      startDeviceScan?: (scanModeStr: string) => string;
      getPersistedSafTrees?: () => string;
      persistSafTree?: (treeUriString: string) => boolean;
      releaseSafTree?: (treeUriString: string) => boolean;
      [key: string]: any;
    };
  }
}

export interface MobileScanResult {
  scanId: string;
  targetType: ScanTargetType;
  rawInput: string;
  sanitizedTarget: string;
  verdict: Verdict;
  overallScore: number;
  severity: SeverityLevel;
  confidence: number;
  threatCategory: string;
  evidence: Evidence[];
  recommendation: Recommendation;
  aiExplanation?: AssistantOutput;
  timestamp: number;
  overridden: boolean;
  executionTimeMs: number;
}

export interface DeviceSecurityPosture {
  developerOptionsEnabled: boolean;
  adbDebuggingEnabled: boolean;
  screenLockConfigured: boolean;
  mockLocationsEnabled: boolean;
  unknownSourcesEnabled: boolean;
  overallHealth: 'HEALTHY' | 'WARNING' | 'RISK' | 'UNKNOWN';
  recommendations: string[];
  lastCheckedTimestamp: number;
}

export interface MobileSettings {
  protectionEnabled: boolean;
  readingGrade: 6 | 8;
  notificationsEnabled: boolean;
  hapticFeedbackEnabled: boolean;
  frictionGateDurationSec: number;
  allowlistDomains: string[];
}

export const DEFAULT_MOBILE_SETTINGS: MobileSettings = {
  protectionEnabled: true,
  readingGrade: 6,
  notificationsEnabled: true,
  hapticFeedbackEnabled: true,
  frictionGateDurationSec: 5,
  allowlistDomains: []
};

export interface FileMetadataInput {
  name: string;
  sizeBytes: number;
  mimeType: string;
  headerBytes: Uint8Array | number[];
}

export interface FileInspectionResult {
  fileName: string;
  sizeBytes: number;
  detectedMimeType: string;
  isExecutable: boolean;
  shannonEntropy: number;
  verdict: Verdict;
  severity: SeverityLevel;
  score: number;
  threatCategory: string;
  evidence: Evidence[];
  recommendation: Recommendation;
}

export interface DeepLinkPayload {
  valid: boolean;
  action?: 'SCAN_URL' | 'SCAN_TEXT';
  target?: string;
  error?: string;
}

// ==========================================
// PHASE T1: NATIVE SECURITY COORDINATOR
// ==========================================

export type SecurityJobState =
  | 'QUEUED'
  | 'RUNNING'
  | 'CANCELLING'
  | 'CANCELLED'
  | 'COMPLETED'
  | 'FAILED';

export type SecurityJobType =
  | 'FILE_SCAN'
  | 'URL_SCAN'
  | 'PACKAGE_AUDIT'
  | 'DOWNLOAD_INSPECT'
  | 'STORAGE_SCAN'
  | 'HEALTH_CHECK'
  | 'MAINTENANCE';

export interface SecurityJobDescriptor {
  id: string;
  type: SecurityJobType;
  state: SecurityJobState;
  progress: number;
  createdAtMs: number;
  startedAtMs?: number;
  completedAtMs?: number;
  cancellationReason?: string;
  errorReason?: string;
  metadata?: Record<string, any>;
  result?: Record<string, any>;
}

export interface CoordinatorStats {
  isShutdown: boolean;
  isThrottled: boolean;
  activeJobsCount: number;
  workerActiveThreads: number;
  workerPoolSize: number;
  workerMaxPoolSize: number;
  workerQueueSize: number;
  totalPersistedJobs: number;
}

// ==========================================
// PHASE T2: APP INSTALLATION SHIELD
// ==========================================

export interface PackageMetadataDTO {
  packageName: string;
  appLabel: string;
  versionName: string;
  versionCode: number;
  firstInstallTimeMs: number;
  lastUpdateTimeMs: number;
  installerPackageName: string;
  sourceDir: string;
  isSystemApp: boolean;
  requestedPermissions: string[];
  dangerousPermissions: string[];
  exportedComponents: string[];
  signingCertSha256s: string[];
}

export interface ApkInspectionDTO {
  isValidZip: boolean;
  hasDex: boolean;
  hasAndroidManifest: boolean;
  hasNativeLibraries: boolean;
  hasSuspiciousPayloads: boolean;
  uncompressedSizeBytes: number;
  fileCount: number;
  fileSha256: string;
  suspiciousEntries: string[];
  certEntries: string[];
}

export interface PackageAuditReport {
  packageName: string;
  appLabel: string;
  score: number;
  verdict: Verdict | 'ALLOW' | 'CAUTION' | 'SUSPICIOUS' | 'DANGEROUS';
  severity: SeverityLevel | 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendation: string;
  isSideloaded: boolean;
  isSystemApp: boolean;
  metadata?: PackageMetadataDTO;
  evidence?: Array<{
    code: string;
    severity: string;
    weight: number;
    description: string;
  }>;
  apkInspection?: ApkInspectionDTO;
  timestamp: number;
}

// ==========================================
// PHASE T3: UNIVERSAL DOWNLOAD & FILE SHIELD
// ==========================================

export interface FileIdentityDTO {
  uriString: string;
  fileName: string;
  fileExtension: string;
  detectedMimeType: string;
  sizeBytes: number;
  lastModifiedMs: number;
  sha256: string;
  sourceCollection: string;
  isExecutable: boolean;
}

export interface ArchiveInspectionReportDTO {
  isValidArchive: boolean;
  entryCount: number;
  totalUncompressedBytes: number;
  isZipBomb: boolean;
  hasPathTraversal: boolean;
  hasSuspiciousExecutables: boolean;
  suspiciousEntries: string[];
  detectedFileTypes: string[];
}

export interface UniversalFileInspectionReport {
  fileIdentity: FileIdentityDTO;
  score: number;
  verdict: Verdict | 'ALLOW' | 'CAUTION' | 'SUSPICIOUS' | 'DANGEROUS';
  severity: SeverityLevel | 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendation: string;
  evidence: Array<{
    code: string;
    severity: string;
    weight: number;
    description: string;
  }>;
  archiveInspection?: ArchiveInspectionReportDTO;
  apkInspection?: ApkInspectionDTO;
  timestamp: number;
}

export type QuarantineState =
  | 'DETECTED'
  | 'PENDING_ISOLATION'
  | 'VAULT_COPY_VERIFIED'
  | 'ORIGINAL_REMOVAL_PENDING'
  | 'ISOLATED'
  | 'SOURCE_REMAINS'
  | 'COPY_FAILED'
  | 'INTEGRITY_FAILED'
  | 'RESTORED'
  | 'RESTORE_FAILED'
  | 'QUARANTINED'
  | 'FAILED';

export interface QuarantineResult {
  status: QuarantineState;
  isolationState?: QuarantineState;
  itemId?: string;
  fileName?: string;
  sha256?: string;
  quarantinePath?: string;
  vaultPath?: string;
  originalDeleted?: boolean;
  timestamp: number;
  error?: string;
  warning?: string;
}

export interface QuarantineRecordDTO {
  id: string;
  originalPath: string;
  fileName: string;
  fileSizeBytes: number;
  mimeType: string;
  sha256: string;
  quarantineTimestamp: number;
  detectionVerdict: string;
  severity: string;
  evidenceSummary: string;
  state: QuarantineState;
  vaultFileName: string;
  originalDeleted: boolean;
  restoreHistory: Array<{
    timestamp: number;
    targetPath: string;
    success: boolean;
    details: string;
  }>;
}

export interface QuarantineVaultStatsDTO {
  totalItems: number;
  isolatedCount: number;
  sourceRemainsCount: number;
  restoredCount: number;
  totalProtectedBytes: number;
  vaultDirectory: string;
}

export interface QuarantineRestoreResultDTO {
  status: 'RESTORED' | 'FAILED';
  itemId?: string;
  restoredPath?: string;
  sha256?: string;
  trusted?: boolean;
  error?: string;
  message?: string;
}

export interface PackageRemediationPlanDTO {
  packageName: string;
  appLabel?: string;
  isSystemApp: boolean;
  status: 'USER_APP_ACTIONABLE' | 'SYSTEM_APP_PROTECTED' | 'NOT_INSTALLED';
  canUninstall: boolean;
  recommendedAction: string;
  availableActions: string[];
  explanation: string;
  timestamp?: number;
  error?: string;
}

// ==========================================
// PHASE T4: FULL ACCESSIBLE DEVICE SCAN
// ==========================================

export type DeviceScanMode = 'QUICK_SCAN' | 'STANDARD_SCAN' | 'FULL_ACCESSIBLE_SCAN';

export interface ScanScopeDTO {
  scopeId: string;
  displayName: string;
  scopeType: string;
  uriOrPath: string;
  accessibilityState: 'AUTOMATICALLY_ACCESSIBLE' | 'MEDIASTORE_ACCESSIBLE' | 'SAF_USER_GRANTED' | 'APP_PRIVATE' | 'INACCESSIBLE' | 'PERMISSION_DENIED';
  scanStatus: 'PENDING' | 'SCANNING' | 'COMPLETED' | 'PARTIAL' | 'SKIPPED' | 'FAILED' | 'CANCELLED';
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  threatsFound: number;
  startTimeMs: number;
  endTimeMs: number;
  errorDetails?: string;
}

export interface DeviceScanReport {
  scanMode: DeviceScanMode;
  status: 'SECURE' | 'ACTION_REQUIRED' | 'CANCELLED' | 'FAILED';
  startTimeMs: number;
  endTimeMs: number;
  durationMs: number;
  totalDiscovered: number;
  totalScanned: number;
  totalSkipped: number;
  threatsCount: number;
  coverage: {
    isFullDeviceClaimed: boolean;
    coverageDescription: string;
  };
  scopes: ScanScopeDTO[];
  threats: any[];
}

// ==========================================
// PHASE T5: REAL-TIME DOWNLOAD PROTECTION
// ==========================================

export type DownloadStabilizationState =
  | 'WAITING_FOR_COMPLETION'
  | 'STABILIZING'
  | 'READY_TO_SCAN'
  | 'DEFERRED'
  | 'INACCESSIBLE'
  | 'FAILED';

export interface DownloadStabilizationDTO {
  state: DownloadStabilizationState;
  size: number;
  dateModified: number;
  mimeType: string;
  reason: string;
  isReady: boolean;
}

export interface RealtimeDownloadStatus {
  isMonitoringActive: boolean;
  lastEventTimestamp: number;
  lastReconciliationTimestamp: number;
  eventsProcessed: number;
  threatsDetected: number;
  deduplicatorStats: {
    cachedEntries: number;
    maxCapacity: number;
  };
  cleanCacheCount: number;
  isPreOpenInterceptionSupported: boolean;
  platformLimitationNotice: string;
}

export interface DownloadCatchUpReport {
  discovered: number;
  rescanned: number;
  skipped: number;
  threatsFound: number;
  durationMs: number;
  timestamp: number;
  error?: string;
}

export interface RealtimeDownloadEventResult {
  status: 'COMPLETED' | 'SUPPRESSED_DUPLICATE' | 'CLEAN_CACHE_HIT' | 'WAITING_FOR_COMPLETION' | 'STABILIZING' | 'DEFERRED' | 'INACCESSIBLE' | 'FAILED';
  uri?: string;
  path?: string;
  verdict?: Verdict | 'ALLOW' | 'CAUTION' | 'SUSPICIOUS' | 'DANGEROUS';
  severity?: SeverityLevel | 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score?: number;
  cached?: boolean;
  stabilization?: DownloadStabilizationDTO;
  inspection?: UniversalFileInspectionReport;
  quarantine?: QuarantineResult;
  error?: string;
  reason?: string;
}

// ==========================================
// PHASE T6: WEB SHIELD & PHISHING PROTECTION
// ==========================================

export type UrlVerdict = 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS' | 'UNKNOWN';

export type UrlThreatType =
  | 'NONE'
  | 'DANGEROUS_SCHEME'
  | 'HOMOGLYPH_ATTACK'
  | 'PUNYCODE_SPOOF'
  | 'TYPOSQUATTING'
  | 'CREDENTIAL_HARVESTING'
  | 'SUSPICIOUS_IP_HOST'
  | 'USERINFO_SPOOF'
  | 'MALICIOUS_DOMAIN'
  | 'BIDI_OVERRIDE_SPOOF'
  | 'DECEPTIVE_REDIRECT'
  | 'INVALID_URL';

export interface UrlInspectionReport {
  normalizedUrl: string;
  domain: string;
  scheme: string;
  riskScore: number;
  verdict: UrlVerdict;
  threatType: UrlThreatType;
  indicators: string[];
  explanation: string;
  error?: string;
}

export interface RedirectHopReport {
  hopIndex: number;
  url: string;
  domain: string;
  riskScore: number;
  threatType: UrlThreatType;
}

export interface RedirectChainReport {
  isDangerous: boolean;
  totalHops: number;
  hops: RedirectHopReport[];
  initialUrl: string;
  finalUrl: string;
  reason: string;
  error?: string;
}

export interface WebShieldCapabilities {
  categoryA_directAndroid: boolean;
  categoryA_description: string;
  categoryB_browserIntegration: boolean;
  categoryB_description: string;
  categoryC_userUrlSharing: boolean;
  categoryC_description: string;
  categoryD_localVpnShield: boolean;
  categoryD_description: string;
  categoryE_systemWideBrowserHookWithoutVpn: boolean;
  categoryE_limitationExplanation: string;
}

export interface WebShieldStatus {
  isWebShieldActive: boolean;
  isAnotherVpnActive: boolean;
  totalDnsQueries: number;
  blockedDnsQueries: number;
  lastThreatTimestamp: number;
  knownBlockedDomainsCount: number;
  capabilities: WebShieldCapabilities;
  error?: string;
}

// ==========================================
// PHASE T7: PREDICTIVE PRE-THREAT WARNING
// ==========================================

export type PreThreatTargetType = 'URL' | 'FILE' | 'APP_PACKAGE' | 'DOWNLOAD';

export type WarningConfidenceLevel =
  | 'CONFIRMED_MALWARE'
  | 'STRONG_SUSPICION'
  | 'HEURISTIC_ANOMALY';

export type PreThreatActionType =
  | 'GO_BACK'
  | 'CANCEL_INSTALL'
  | 'DELETE_DOWNLOAD'
  | 'QUARANTINE'
  | 'RESCAN'
  | 'INSPECT_DETAILS'
  | 'CONTINUE_AT_OWN_RISK';

export interface PreThreatWarningEvidenceItem {
  code: string;
  severity: string;
  description: string;
  scoreContribution?: number;
}

export interface PreThreatWarningPayload {
  warningId: string;
  targetType: PreThreatTargetType;
  targetIdentifier: string;
  riskScore: number;
  verdict: 'ALLOW' | 'CAUTION' | 'SUSPICIOUS' | 'DANGEROUS';
  confidenceLevel: WarningConfidenceLevel;
  whatDetected: string;
  potentialConsequences: string;
  recommendedAction: PreThreatActionType;
  supportedChoices: PreThreatActionType[];
  evidenceDetails: PreThreatWarningEvidenceItem[];
  requiresFrictionGate: boolean;
  frictionGateSeconds: number;
  timestamp: number;
}

export interface PreThreatWarningDecision {
  warningId: string;
  targetIdentifier: string;
  selectedAction: PreThreatActionType;
  timestamp: number;
  bypassedWithFrictionGate: boolean;
}

// ==========================================
// PHASE T8: SECURE PASSWORD & PASSPHRASE GENERATOR
// ==========================================

export type PasswordGeneratorPreset = 'STANDARD' | 'STRONG' | 'VERY_STRONG' | 'CUSTOM';

export interface PasswordGeneratorOptions {
  length: number; // 12 to 128
  useUppercase: boolean;
  useLowercase: boolean;
  useNumbers: boolean;
  useSpecial: boolean;
  avoidAmbiguous: boolean; // excludes ambiguous punctuation
  avoidSimilar: boolean;   // excludes l, 1, I, o, 0, O
}

export interface PassphraseGeneratorOptions {
  wordCount: number; // 3 to 10
  separator: string; // '-', '_', ' ', '.', etc.
  capitalize: boolean;
  includeNumber: boolean;
}

export interface PasswordGenerationResult {
  secret: string;
  length: number;
  poolSize: number;
  entropyBits: number;
  entropyExplanation: string;
  strengthLevel: 'WEAK' | 'MEDIUM' | 'STRONG' | 'VERY_STRONG';
  mode: 'PASSWORD';
  characterGroups: {
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasNumbers: boolean;
    hasSpecial: boolean;
  };
}

export interface PassphraseGenerationResult {
  secret: string;
  wordCount: number;
  wordlistSize: number;
  entropyBits: number;
  entropyExplanation: string;
  strengthLevel: 'WEAK' | 'MEDIUM' | 'STRONG' | 'VERY_STRONG';
  mode: 'PASSPHRASE';
  separator: string;
}

// ==========================================
// PHASE T9: MOBILE THREAT INTELLIGENCE
// ==========================================

export type ThreatRecordType = 'DOMAIN' | 'URL' | 'FILE_HASH' | 'CERT_FINGERPRINT' | 'HEURISTIC_RULE';

export interface MobileThreatMetadata {
  databaseVersion: number;
  versionSequence: number;
  installedVersion: string;
  publishedAt: number;
  lastVerifiedAt: number;
  sourceFeed: string;
  recordsCount: number;
  sha256Digest: string;
  isFactorySeed: boolean;
  status: 'ACTIVE' | 'STAGED' | 'LKG' | 'FAILED';
}

export interface MobileThreatRecord {
  type: ThreatRecordType;
  indicator: string; // Normalized domain, full URL, or lowercase SHA-256
  threatName: string;
  category: 'PHISHING' | 'MALWARE' | 'SCAM' | 'EXTORTION' | 'SUSPICIOUS';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  sourceFeed: string;
  isCritical: boolean;
  expiresAt?: number;
}

export interface ThreatDatabaseInspectionResult {
  activeMetadata: MobileThreatMetadata;
  lkgMetadata?: MobileThreatMetadata;
  stalenessDays: number;
  stalenessState: 'FRESH' | 'AGED' | 'STALE' | 'EXPIRED_CACHE';
  isVerified: boolean;
}

export interface ThreatUpdateInspectionResult {
  success: boolean;
  targetSequence?: number;
  appliedRecordsCount?: number;
  error?: string;
}

// ==========================================
// PHASE T11: PERMISSIONS & PRIVACY CENTER DTOs
// ==========================================

export interface StorageAccessInspectionDTO {
  status: 'GRANTED_SAF' | 'GRANTED_LEGACY' | 'LIMITED' | 'DENIED';
  mechanism: 'SAF_AND_MEDIASTORE' | 'LEGACY_STORAGE' | 'MEDIASTORE' | 'UNAVAILABLE';
  persistedSafTreesCount: number;
  scopedStorageEnforced: boolean;
  safTrees: Array<{ uri: string; readable: boolean }>;
  accessibleScope: string;
  inaccessibleScope: string;
}

export interface NotificationPermissionInspectionDTO {
  runtimePermission: 'GRANTED' | 'DENIED' | 'NOT_REQUIRED';
  areNotificationsEnabled: boolean;
  dependentFeatures: string;
  alertDeliveryDisclaimer: string;
}

export interface VpnWebShieldInspectionDTO {
  serviceState: 'ACTIVE' | 'CONSENT_PENDING' | 'COEXISTENCE_CONFLICT' | 'STOPPED' | 'UNAVAILABLE';
  isVpnActive: boolean;
  isConsentRequired: boolean;
  isAnotherVpnActive: boolean;
  totalDnsQueries: number;
  blockedDnsQueries: number;
  lastThreatTimestamp: number;
  vpnCoexistenceExplanation: string;
  privacyGuarantee: string;
}

export interface InstallSourceInspectionDTO {
  installerPackage: string;
  isPreInstallInterceptionSupported: boolean;
  scopeExplanation: string;
  privilegeTruth: string;
}

export interface BackgroundScanningInspectionDTO {
  isDownloadObserverActive: boolean;
  lastEventTimestamp: number;
  lastReconciliationTimestamp: number;
  eventsProcessed: number;
  threatsDetected: number;
  status: 'MONITORING_ACTIVE' | 'MONITORING_STOPPED';
  restrictionsNotice: string;
}

export interface BatteryOptimizationInspectionDTO {
  isIgnoringBatteryOptimizations: boolean;
  status: 'OPTIMIZATION_EXEMPTED' | 'OPTIMIZATION_ENFORCED';
  explanation: string;
  isExemptionMandatory: boolean;
}

export interface TelemetryInspectionDTO {
  isTelemetryImplemented: boolean;
  isTelemetryActive: boolean;
  userPayloadsCollected: number;
  remoteEndpointsConfigured: string;
  status: 'NO_TELEMETRY_EXISTS' | 'ACTIVE' | 'DISABLED';
  explanation: string;
}

export interface ThreatDatabaseInspectionDTO {
  activeSequence: number;
  recordCount: number;
  lastUpdatedTimestamp: number;
  ageDays: number;
  staleness: 'FRESH' | 'AGED' | 'STALE' | 'EXPIRED_CACHE';
  feedSource: string;
  isCryptographicallyVerified: boolean;
  verificationMechanism: string;
}

export interface PermissionsPrivacyReportDTO {
  storage: StorageAccessInspectionDTO;
  notifications: NotificationPermissionInspectionDTO;
  vpnWebShield: VpnWebShieldInspectionDTO;
  installSource: InstallSourceInspectionDTO;
  backgroundScanning: BackgroundScanningInspectionDTO;
  batteryOptimization: BatteryOptimizationInspectionDTO;
  telemetry: TelemetryInspectionDTO;
  threatDatabase: ThreatDatabaseInspectionDTO;
  timestamp: number;
}

