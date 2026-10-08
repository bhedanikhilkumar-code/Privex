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

export interface QuarantineResult {
  status: 'QUARANTINED' | 'FAILED';
  quarantinePath?: string;
  originalDeleted?: boolean;
  timestamp: number;
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

