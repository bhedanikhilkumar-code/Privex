import { Verdict, SeverityLevel, Evidence, Recommendation } from '@private-protection/core';
import { AssistantOutput } from '@private-protection/ml';

export interface ExtensionSettings {
  enabled: boolean;
  readingGrade: number; // 6 or 8
  allowlistDomains: string[];
  showShadowDomBanners: boolean;
  frictionGateDurationSec: number;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  enabled: true,
  readingGrade: 6,
  allowlistDomains: [],
  showShadowDomBanners: true,
  frictionGateDurationSec: 5
};

export interface TabSecurityState {
  tabId: number;
  url: string;
  domain: string;
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
  isRestrictedUrl?: boolean;
}

export interface PageDomSignals {
  hasPasswordInput: boolean;
  formActionUrl?: string;
  isFormInsecure: boolean;
  isCrossOriginAction: boolean;
  hasHiddenIframes: boolean;
  detectedFormsCount: number;
  title: string;
}

export interface AuditLogEvent {
  id: string;
  timestamp: number;
  action: 'BLOCKED' | 'WARNED' | 'ALLOWED' | 'OVERRIDDEN';
  domainPrefix: string;
  verdict: Verdict;
  riskScore: number;
  threatCategory: string;
}
