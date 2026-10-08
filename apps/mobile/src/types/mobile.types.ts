import {
  Verdict,
  SeverityLevel,
  Evidence,
  Recommendation
} from '@private-protection/core';
import { AssistantOutput } from '@private-protection/ml';

export type ScanTargetType = 'URL' | 'TEXT' | 'FILE';

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
