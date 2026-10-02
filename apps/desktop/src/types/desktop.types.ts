export type ScanType = 'quick' | 'full' | 'custom';
export type ScanStatus = 'idle' | 'running' | 'paused' | 'completed' | 'cancelled' | 'error';
export type ThreatSeverity = 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical';
export type ThreatVerdict = 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK';

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
  completedAt: number;
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
}

export interface ProcessInfo {
  pid: number;
  processName: string;
  executablePath: string;
  isSuspicious: boolean;
  reason?: string;
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
