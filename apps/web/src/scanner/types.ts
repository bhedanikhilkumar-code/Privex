import {
  Verdict,
  SeverityLevel,
  Evidence,
  Recommendation,
  RiskAssessment
} from '@private-protection/core';
import { AssistantOutput } from '@private-protection/ml';

export type ScanType = 'URL' | 'TEXT';
export type ScanStatus = 'IDLE' | 'SCANNING' | 'COMPLETED' | 'ERROR';
export type ActiveTab = 'HOME' | 'URL_SCAN' | 'TEXT_SCAN' | 'ASSISTANT' | 'PRIVACY' | 'SETTINGS';

export interface ScanResultViewData {
  readonly id: string;
  readonly targetPreview: string; // Truncated/sanitized for display
  readonly scanType: ScanType;
  readonly verdict: Verdict;
  readonly overallScore: number;
  readonly severity: SeverityLevel | string;
  readonly confidence: number;
  readonly evidence: Evidence[];
  readonly recommendation: Recommendation;
  readonly rawAssessment: RiskAssessment;
  readonly aiExplanation?: AssistantOutput;
  readonly executionTimeMs: number;
  readonly timestamp: number;
  readonly isModelBacked: boolean;
  readonly isAllowlisted?: boolean;
  readonly privacyGuarantee: string;
}

export interface UserPreferences {
  cognitiveReadingGrade: 6 | 8;
  enableWorkerOffloading: boolean;
  allowlistDomains: string[];
}
