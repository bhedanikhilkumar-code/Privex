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
}

export interface ProcessLineageNode {
  pid: number;
  ppid?: number;
  processName: string;
  executablePath?: string;
  commandLine?: string;
  sanitizedCommandLine?: string;
  creationTime: number;
  sha256?: string;
  isSigned?: boolean;
  signer?: string;
  isLolbin?: boolean;
  isProtectedSystemProcess?: boolean;
  instanceKey: string;
}

export interface ProcessContainmentResult {
  success: boolean;
  pid: number;
  processName?: string;
  action: 'TERMINATED' | 'REJECTED_PROTECTED' | 'NOT_FOUND' | 'FAILED';
  reason: string;
  containedAt: number;
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

