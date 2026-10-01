export enum RiskCategory {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  PHISHING = 'PHISHING',
  SCAM = 'SCAM',
  MALWARE = 'MALWARE'
}

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

export enum ActionRecommendation {
  ALLOW = 'ALLOW',
  INFORM = 'INFORM',
  WARN = 'WARN',
  BLOCK = 'BLOCK'
}

export interface Evidence {
  source: string;
  name: string;
  description: string;
  weight: number;
  confidence: number;
  type?: string;
  indicator?: string;
}

export interface DetectionResult {
  scanId: string;
  id: string; // convenient alias for scanId
  timestamp: string;
  inputType: InputType;
  riskCategory: RiskCategory;
  riskScore: number;
  score: number; // convenient alias for riskScore
  confidence: number;
  severity: Severity | string;
  evidence: Evidence[];
  explanation: string;
  recommendation: ActionRecommendation;
  action: ActionRecommendation | string; // convenient alias for recommendation
  error?: string;
}

export interface ScanRequest {
  input?: string;
  content?: string;
  inputType?: InputType;
  type?: string | InputType;
  metadata?: Record<string, string>;
}
