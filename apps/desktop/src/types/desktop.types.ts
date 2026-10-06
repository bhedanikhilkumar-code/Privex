export type ScanType = 'quick' | 'full' | 'custom';
export type ScanStatus = 'idle' | 'running' | 'paused' | 'completed' | 'cancelled' | 'error';
export type ThreatSeverity = 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical';
export type ThreatVerdict = 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK';
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

export type SecurityLogEventType =
  | 'SCAN_STARTED'
  | 'SCAN_COMPLETED'
  | 'SCAN_FAILED'
  | 'THREAT_DETECTED'
  | 'QUARANTINE_ISOLATED'
  | 'QUARANTINE_RESTORED'
  | 'QUARANTINE_DELETED'
  | 'PROCESS_CONTAINED'
  | 'ENGINE_FAILURE'
  | 'CONFIG_FAILURE'
  | 'CONFIG_UPDATED'
  | 'EXCLUSION_ADDED'
  | 'EXCLUSION_REMOVED'
  | 'EXCLUSION_TOGGLED'
  | 'EXCLUSION_CLEARED'
  | 'EXCLUSION_REJECTED'
  | 'SECURITY_VIOLATION';

export interface SecurityLogEntry {
  eventId: string;
  timestamp: number;
  type: SecurityLogEventType;
  severity: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  summary: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface DetectedThreat {
  id: string;
  filePath: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  riskScore: number;
  severity: ThreatSeverity;
  verdict: ThreatVerdict;
  threatName: string;
  detectedAt: number;
  evidenceFactors: string[];
  quarantined: boolean;
  motw?: MotwAnalysisResult;
}

export type RealtimeThreatAction = 'AUTO_QUARANTINED' | 'ALERTED';

export interface RealtimeThreatEvent {
  threat: DetectedThreat;
  actionTaken: RealtimeThreatAction;
  quarantineItem?: QuarantineItem;
  timestamp: number;
}

export interface ScanProgress {
  scanId: string;
  scanType: ScanType;
  status: ScanStatus;
  filesScanned: number;
  threatsFound: number;
  currentPath: string;
  bytesScanned: number;
  skippedCount: number;
  errorCount: number;
  startTime: number;
  elapsedMs: number;
  scanSpeedFilesPerSec: number;
}

export interface SkippedItem {
  path: string;
  reason: string;
}

export interface ScanErrorItem {
  path: string;
  error: string;
}

export interface ScanResult {
  scanId: string;
  scanType: ScanType;
  status?: ScanStatus;
  totalFilesScanned: number;
  totalBytesScanned: number;
  durationMs: number;
  threats: DetectedThreat[];
  skippedFiles: SkippedItem[];
  errors: ScanErrorItem[];
  overallVerdict: ThreatVerdict;
  analysisStatus?: AnalysisStatus;
  disposition?: DetectionDisposition;
  completedAt: number;
}

export interface QuarantineRestoreOptions {
  readonly trustSha256?: boolean;
  readonly customDestinationDir?: string;
  readonly restoreZoneIdentifier?: boolean;
}

export interface QuarantineItem {
  quarantineId: string;
  originalPath: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  threatName: string;
  riskScore: number;
  severity: ThreatSeverity;
  quarantinedAt: number;
  evidenceFactors: string[];
  blobPath: string;
  vaultVersion?: 'PPVAULT1' | 'PPVAULT2';
  zoneIdentifier?: string;
  trustedOnRestore?: boolean;
}

export interface FileAnalysisResult {
  filePath: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  entropy: number;
  magicHeader: string | null;
  isExecutable: boolean;
  isDeceptiveExtension: boolean;
  riskScore: number;
  severity: ThreatSeverity;
  verdict: ThreatVerdict;
  threatName: string;
  evidenceFactors: string[];
  analysisStatus?: AnalysisStatus;
  disposition?: DetectionDisposition;
  errorReason?: string;
  motw?: MotwAnalysisResult;
}

export interface ProcessContainmentAuthorization {
  readonly authorizationId: string;
  readonly pid: number;
  readonly processName: string;
  readonly executablePath?: string;
  readonly observedCreationTime: number;
  readonly sha256?: string;
  readonly engineVerdict: 'CONTAIN_PROCESS';
  readonly riskScore: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly reason: string;
  readonly singleUseToken: string;
}

export interface ProcessLineageNode {
  pid: number;
  ppid?: number;
  processName: string;
  executablePath?: string;
  sanitizedCommandLine: string;
  creationTime: number;
  sha256?: string;
  isSigned?: boolean;
  signer?: string;
  isLolbin?: boolean;
  isProtectedSystemProcess?: boolean;
  instanceKey: string;
}

export interface ContainProcessOptions {
  readonly force?: boolean;
  readonly reason?: string;
  readonly dryRun?: boolean;
  readonly authorizationId?: string;
  readonly token?: string;
  readonly expectedCreationTime?: number;
}

export interface ProcessContainmentResult {
  readonly success: boolean;
  readonly pid: number;
  readonly processName?: string;
  readonly action:
    | 'TERMINATED'
    | 'REJECTED_PROTECTED'
    | 'REJECTED_UNAUTHORIZED'
    | 'REJECTED_PID_REUSE'
    | 'REJECTED_IDENTITY_MISMATCH'
    | 'NOT_FOUND'
    | 'FAILED';
  readonly reason: string;
  readonly containedAt: number;
  readonly authorizationId?: string;
}

export type ProcessMonitorStatus = 'RUNNING' | 'DEGRADED' | 'STOPPED' | 'FAILED';

export type ProcessEventSourceType =
  | 'WMI_EVENT_SUBSCRIPTION'
  | 'WMI_TRACE'
  | 'CIM_EVENT'
  | 'POLLING_FALLBACK'
  | 'MOCK';

export interface ProcessEventSourceStatus {
  readonly state: 'INITIALIZING' | 'ACTIVE' | 'ERROR' | 'STOPPED';
  readonly sourceName: string;
  readonly lastError?: string;
  readonly eventsObserved: number;
}

export interface IProcessEventSource {
  start(callback?: (event: ProcessCreationEvent) => void): Promise<void>;
  stop(): Promise<void>;
  onProcessCreated(callback: (event: ProcessCreationEvent) => void): void;
  getStatus(): ProcessEventSourceStatus;
  dispose(): Promise<void>;
}

export interface ProcessMonitorHealth {
  readonly status: ProcessMonitorStatus;
  readonly isContinuous: boolean;
  readonly eventSource: ProcessEventSourceType;
  readonly queueDepth: number;
  readonly processedEvents: number;
  readonly droppedEvents: number;
  readonly activeWorkers: number;
  readonly lastEventTimestamp?: number;
  readonly lastError?: string;
}

export interface ProcessCreationEvent {
  readonly eventId: string;
  readonly pid: number;
  readonly ppid?: number;
  readonly processName: string;
  readonly executablePath?: string;
  readonly commandLine?: string;
  readonly creationTime: number;
  readonly timestamp: number;
}

export interface ProcessInfo {
  pid: number;
  processName: string;
  executablePath: string;
  isSuspicious: boolean;
  reason?: string;
  ppid?: number;
  parentName?: string;
  commandLine?: string;
  sanitizedCommandLine?: string;
  sha256?: string;
  isSigned?: boolean;
  signer?: string;
  creationDate?: number;
  riskScore?: number;
  verdict?: ThreatVerdict;
  engineVerdict?: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' | 'CONTAIN_PROCESS';
  severity?: ThreatSeverity;
  threatName?: string;
  evidenceFactors?: string[];
  isLolbin?: boolean;
  lineageChain?: string[];
  isProtectedSystemProcess?: boolean;
  authorization?: ProcessContainmentAuthorization;
}

export interface PersistenceItem {
  id: string;
  name: string;
  targetPath: string;
  locationType: 'startup_folder' | 'run_key' | 'scheduled_task';
  isSuspicious: boolean;
  reason?: string;
}

export interface RemovableDrive {
  mountPoint: string;
  label: string;
  totalBytes: number;
  freeBytes: number;
}

export interface DesktopProtectionStatus {
  realtimeShieldActive: boolean;
  monitoredPaths: string[];
  threatDatabaseVersion: string;
  threatDatabaseTimestamp: number;
  coreEngineVersion: string;
  mlAssistantReady: boolean;
  offlineMode: boolean;
  quarantinedCount: number;
  memoryRssBytes: number;
  heapUsedBytes: number;
}

export interface DesktopSettings {
  realtimeShieldEnabled: boolean;
  monitorDownloads: boolean;
  monitorTemp: boolean;
  scanLargeFilesLimitMb: number;
  entropyDetectionEnabled: boolean;
  autoQuarantineCritical: boolean;
  frictionGateEnabled: boolean;
  cognitiveLevel: 'grade6' | 'grade8';
  excludedPaths: string[];
}

export interface DesktopAssistantExplanation {
  threatTitle: string;
  summary: string;
  explanation: string;
  riskLevel: string;
  recommendedActions: string[];
  cognitiveLevel: 'grade6' | 'grade8';
}

export interface RealtimeMonitorOptions {
  recursive?: boolean;
  maxQueueSize?: number;
  concurrencyLimit?: number;
  stabilityCheckMs?: number;
  stabilityRetries?: number;
  debounceMs?: number;
  autoQuarantineCritical?: boolean;
  excludedPaths?: string[];
  monitoredPaths?: string[];
  entropyDetectionEnabled?: boolean;
  maxFileSizeBytes?: number;
}

export interface RealtimeQueueStats {
  queuedCount: number;
  inFlightCount: number;
  processedCount: number;
  droppedEventsCount: number;
  threatsDetectedCount: number;
  quarantinedCount: number;
  averageLatencyMs: number;
  p95LatencyMs: number;
}

export interface RealtimeFilesystemEvent {
  eventType: 'create' | 'modify' | 'rename' | 'delete' | 'burst';
  filePath: string;
  timestamp: number;
  isDownload?: boolean;
  previousPath?: string;
}

export interface PendingDownload {
  tempPath: string;
  targetFinalName: string;
  firstSeenAt: number;
  lastModifiedAt: number;
  initialSize: number;
}

// ============================================================
// PHASE G: RANSOMWARE SHIELD & SHADOW VAULT TYPES
// ============================================================

export type RansomwareProtectionMode = 'smart' | 'strict';

export interface TrustedApplication {
  readonly canonicalPath: string;
  readonly sha256: string;
  readonly signer?: string;
  readonly name?: string;
  readonly addedAt: number;
  readonly isRevoked?: boolean;
  readonly revocationReason?: string;
  readonly certificateThumbprint?: string;
  readonly isAuthenticodeVerified?: boolean;
}

export interface CanaryFileRecord {
  readonly filePath: string;
  readonly canonicalPath: string;
  readonly expectedSha256: string;
  readonly expectedSize: number;
  readonly folderPath: string;
  readonly deployedAt: number;
  readonly canaryId: string;
}

export interface ShadowVaultBackupRecord {
  readonly backupId: string;
  readonly incidentId?: string;
  readonly originalPath: string;
  readonly canonicalPath: string;
  readonly preAttackSha256: string;
  readonly fileSize: number;
  readonly blobPath: string;
  readonly backupTimestamp: number;
  readonly iv: string;
  readonly authTag: string;
}

export type RansomwareThreatType =
  | 'CANARY_TAMPER'
  | 'VELOCITY_BURST'
  | 'SUSPICIOUS_EXTENSION_BURST'
  | 'UNAUTHORIZED_PROTECTED_FOLDER_WRITE'
  | 'VSS_SHADOW_DELETION_ATTEMPT';

export type IncidentLifecycleState =
  | 'DETECTED'
  | 'CLASSIFIED'
  | 'CONTAINMENT_REQUESTED'
  | 'CONTAINED'
  | 'SNAPSHOT_AVAILABLE'
  | 'ROLLBACK_AVAILABLE'
  | 'ROLLED_BACK'
  | 'RECOVERED';

export interface IncidentStateTransition {
  readonly state: IncidentLifecycleState;
  readonly timestamp: number;
  readonly message?: string;
}

export interface RansomwareIncident {
  readonly incidentId: string;
  readonly detectedAt: number;
  readonly threatType: RansomwareThreatType;
  readonly reason: string;
  readonly riskScore: number;
  readonly severity: 'critical';
  readonly engineVerdict: 'CONTAIN_PROCESS' | 'BLOCK';
  readonly responsiblePid?: number;
  readonly processName?: string;
  readonly executablePath?: string;
  readonly containmentResult?: ProcessContainmentResult;
  readonly affectedFiles: string[];
  readonly backupIds: string[];
  readonly rollbackStatus: 'PENDING' | 'ROLLED_BACK' | 'PARTIAL' | 'FAILED' | 'NOT_REQUIRED';
  readonly lifecycleState?: IncidentLifecycleState;
  readonly stateHistory?: IncidentStateTransition[];
  readonly metrics: {
    readonly modificationsInWindow: number;
    readonly highEntropyCount: number;
    readonly renameCount: number;
    readonly maxEntropyObserved: number;
  };
}

export interface FileRollbackResult {
  readonly success: boolean;
  readonly filePath: string;
  readonly originalSha256: string;
  readonly restoredSha256?: string;
  readonly bytesRestored?: number;
  readonly error?: string;
}

export interface IncidentRollbackResult {
  readonly incidentId: string;
  readonly success: boolean;
  readonly totalFiles: number;
  readonly restoredCount: number;
  readonly failedCount: number;
  readonly restoredFiles: Array<{
    readonly filePath: string;
    readonly originalSha256: string;
    readonly restoredSha256: string;
    readonly bytesRestored: number;
  }>;
  readonly failedFiles: Array<{
    readonly filePath: string;
    readonly reason: string;
  }>;
  readonly completedAt: number;
}

export interface RansomwareShieldOptions {
  readonly mode?: RansomwareProtectionMode;
  readonly protectedFolders?: string[];
  readonly trustedApplications?: TrustedApplication[];
  readonly customVaultDir?: string;
  readonly dryRunContainment?: boolean;
  readonly enableCanaries?: boolean;
  readonly velocityThreshold?: number;       // default 25
  readonly velocityWindowMs?: number;        // default 3000 ms
  readonly entropyThreshold?: number;        // default 7.5
  readonly highEntropyWritesThreshold?: number; // default 8
  readonly extensionRenameThreshold?: number; // default 10
}

export interface RansomwareShieldStatus {
  readonly active: boolean;
  readonly mode: RansomwareProtectionMode;
  readonly protectedFolders: string[];
  readonly trustedAppsCount: number;
  readonly activeCanariesCount: number;
  readonly incidentsCount: number;
  readonly vaultTotalSizeBytes: number;
  readonly vaultBackupCount: number;
}

export interface ShadowVaultOptions {
  readonly customVaultDir?: string;
  readonly maxFileSizeBytes?: number; // default 50 MB
  readonly maxVaultQuotaBytes?: number; // default 2 GB
}

export interface ShadowVaultStats {
  readonly backupCount: number;
  readonly totalSizeBytes: number;
  readonly maxQuotaBytes: number;
  readonly utilizationPercent: number;
}

// ============================================================
// PHASE H: NOTIFICATION SYSTEM & STORM RATE-LIMITER TYPES
// ============================================================

export type NotificationSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type NotificationCategory =
  | 'SECURITY_ALERT'
  | 'REALTIME_INGRESS'
  | 'RANSOMWARE_BLOCKED'
  | 'PROCESS_CONTAINED'
  | 'QUARANTINE_ACTION'
  | 'SCAN_COMPLETE'
  | 'UPDATE_STATUS'
  | 'SYSTEM_HEALTH';

export interface NotificationThreatMetadata {
  readonly threatName?: string;
  readonly filePath?: string;
  readonly fileName?: string;
  readonly sha256?: string;
  readonly riskScore?: number;
  readonly verdict?: string;
  readonly incidentId?: string;
  readonly pid?: number;
  readonly count?: number;
  readonly targetSummary?: string;
}

export interface DesktopNotification {
  readonly id: string;
  readonly timestamp: number;
  readonly title: string;
  readonly message: string;
  readonly severity: NotificationSeverity;
  readonly category: NotificationCategory;
  readonly isRead: boolean;
  readonly isCoalesced?: boolean;
  readonly coalescedCount?: number;
  readonly metadata?: NotificationThreatMetadata;
  readonly actionLabel?: string;
}

export interface CreateNotificationInput {
  readonly id?: string;
  readonly title: string;
  readonly message: string;
  readonly severity?: NotificationSeverity;
  readonly category?: NotificationCategory;
  readonly metadata?: NotificationThreatMetadata;
  readonly actionLabel?: string;
  readonly forceToast?: boolean;
}

export type ToastSuppressedReason =
  | 'RATE_LIMITED'
  | 'FULLSCREEN_SUPPRESSED'
  | 'HEADLESS_FALLBACK'
  | 'NOTIFICATION_UNSUPPORTED'
  | 'ERROR';

export interface NotificationDispatchResult {
  readonly notificationId: string;
  readonly inboxInserted: boolean;
  readonly toastDispatched: boolean;
  readonly toastSuppressedReason?: ToastSuppressedReason;
  readonly isCoalesced: boolean;
  readonly totalUnread: number;
}

export interface NotificationServiceOptions {
  readonly maxInboxSize?: number;                // default 500
  readonly maxToastsPerWindow?: number;           // default 3
  readonly toastWindowMs?: number;                // default 10,000 ms
  readonly burstCoalesceThreshold?: number;       // default 3
  readonly burstWindowMs?: number;                // default 5,000 ms
  readonly isFullscreenFn?: () => boolean;
  readonly clock?: () => number;
  readonly toastDispatcher?: (title: string, message: string, severity: NotificationSeverity) => boolean;
  readonly trayUpdater?: (unreadCount: number, latestThreatTitle?: string) => void;
  readonly storageDir?: string;
}
export interface NotificationInboxState {
  readonly notifications: DesktopNotification[];
  readonly unreadCount: number;
  readonly totalCount: number;
}

// ============================================================
// PHASE I: AUTOMATIC RESPONSE LADDER & EXCLUSIONS TYPES
// ============================================================

export type ResponseTier =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'RANSOMWARE_BEHAVIOR';

export type ResponseAction =
  | 'LOG_ONLY'
  | 'WARN_USER'
  | 'HOLD_QUARANTINE'
  | 'AUTO_QUARANTINE'
  | 'CONTAIN_AND_ROLLBACK';

export interface ResponseEvaluationInput {
  readonly riskScore: number;
  readonly severity: ThreatSeverity;
  readonly verdict: ThreatVerdict | DetectionDisposition;
  readonly confidence?: 'low' | 'medium' | 'high' | number;
  readonly isProtectedSystemBinary?: boolean;
  readonly isRansomwareIncident?: boolean;
  readonly isCanaryTamper?: boolean;
  readonly threatName?: string;
  readonly evidenceFactors?: readonly string[];
  readonly isExcluded?: boolean;
  readonly exclusionReason?: string;
}

export interface ResponseEvaluationResult {
  readonly tier: ResponseTier;
  readonly action: ResponseAction;
  readonly reason: string;
  readonly requiresConfirmation: boolean;
  readonly autoQuarantine: boolean;
  readonly containProcess: boolean;
  readonly promptRollback: boolean;
  readonly isProtectedSystemBinary: boolean;
  readonly isExcluded: boolean;
  readonly exclusionId?: string;
  readonly effectiveScore: number;
  readonly effectiveVerdict: ThreatVerdict | DetectionDisposition;
}

export type ExclusionType = 'HASH' | 'PATH' | 'DOMAIN';

export type ExclusionTtl = '24h' | '7d' | '30d' | 'permanent';

export interface ExclusionItem {
  readonly id: string;
  readonly type: ExclusionType;
  readonly value: string;
  readonly canonicalValue: string;
  readonly createdAt: number;
  readonly expiresAt?: number;
  readonly reason?: string;
  readonly enabled: boolean;
  readonly createdBy: 'USER' | 'RESTORE_AND_TRUST' | 'SYSTEM';
  readonly metadata?: Record<string, string | number | boolean>;
}

export interface CreateExclusionInput {
  readonly type: ExclusionType;
  readonly value: string;
  readonly ttl?: ExclusionTtl | number;
  readonly reason?: string;
  readonly frictionToken?: string;
  readonly createdBy?: 'USER' | 'RESTORE_AND_TRUST' | 'SYSTEM';
  readonly metadata?: Record<string, string | number | boolean>;
}

export interface ExclusionCheckResult {
  readonly isExcluded: boolean;
  readonly matchedExclusion?: ExclusionItem;
  readonly reason?: string;
}

export interface ExclusionCheckContext {
  readonly isRansomware?: boolean;
  readonly isProtectedSystemBinary?: boolean;
  readonly verdict?: ThreatVerdict | DetectionDisposition;
  readonly riskScore?: number;
  readonly threatName?: string;
  readonly now?: number;
}

// ============================================================
// PHASE J: WEB & DOWNLOAD MARK-OF-THE-WEB (MOTW) PROTECTION TYPES
// ============================================================

export type MotwZoneId = 0 | 1 | 2 | 3 | 4 | -1;

export type MotwZoneName =
  | 'LOCAL_MACHINE'
  | 'INTRANET'
  | 'TRUSTED'
  | 'INTERNET'
  | 'RESTRICTED'
  | 'UNKNOWN';

export interface MotwMetadata {
  readonly hasMotw: boolean;
  readonly zoneId?: number;
  readonly zoneName?: MotwZoneName;
  readonly hostUrl?: string;
  readonly referrerUrl?: string;
  readonly hostIpAddress?: string;
  readonly rawAdsContent?: string;
}

export interface MotwUrlAnalysis {
  readonly url: string;
  readonly riskScore: number;
  readonly indicators: string[];
  readonly isMalicious: boolean;
  readonly threatName?: string;
  readonly host?: string;
}

export interface MotwAnalysisResult {
  readonly hasMotw: boolean;
  readonly metadata: MotwMetadata;
  readonly originRiskScore: number;
  readonly originSeverity: 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical';
  readonly isOriginMalicious: boolean;
  readonly threatIndicators: string[];
  readonly evidenceFactors: string[];
  readonly hostUrlAnalysis?: MotwUrlAnalysis;
  readonly referrerUrlAnalysis?: MotwUrlAnalysis;
}

