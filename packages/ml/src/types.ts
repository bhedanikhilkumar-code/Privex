import {
  Evidence,
  Recommendation,
  RiskAssessment,
  RiskCategory,
  SeverityLevel,
  Verdict
} from '@private-protection/core';

// ==========================================
// 1. MODEL METADATA & INTEGRITY CONTRACTS
// ==========================================

export type ModelFormat = 'ONNX' | 'TFLITE' | 'GGUF';
export type ModelTask = 'INTENT_CLASSIFICATION' | 'SEMANTIC_ANALYSIS' | 'EXPLANATION_SYNTHESIS';
export type QuantizationType = 'INT8' | 'INT4' | 'FP16' | 'FP32';

export interface ModelMetadata {
  readonly modelId: string;
  readonly version: string;
  readonly format: ModelFormat;
  readonly task: ModelTask;
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly inputShape: number[];
  readonly outputClasses: string[];
  readonly quantization: QuantizationType;
  readonly isProductionArtifact: boolean;
  readonly providerName?: string;
  readonly description?: string;
  readonly inputNames?: string[];
  readonly outputNames?: string[];
}

// ==========================================
// 2. INFERENCE RUNTIME CONTRACTS
// ==========================================

export interface InferenceRequest {
  readonly requestId: string;
  readonly task: ModelTask | string;
  readonly input: string | number[] | Float32Array;
  readonly context?: Record<string, unknown>;
  readonly timeoutMs?: number;
  readonly abortSignal?: AbortSignal;
  readonly modelInputs?: Record<string, unknown>;
}

export type InferenceStatus =
  | 'SUCCESS'
  | 'MODEL_INFERRED'
  | 'UNCERTAIN'
  | 'FALLBACK'
  | 'ERROR'
  | 'DETERMINISTIC_FALLBACK'
  | 'MODEL_UNAVAILABLE';

export interface InferenceResult {
  readonly requestId: string;
  readonly predictions: Record<string, number>; // class -> probability [0.0, 1.0]
  readonly topLabel: string;
  readonly topScore: number; // [0.0, 1.0]
  readonly confidence: number; // [0.0, 1.0]
  readonly uncertainty: number; // [0.0, 1.0]
  readonly latencyMs: number;
  readonly status: InferenceStatus;
  readonly modelMetadata: ModelMetadata;
  readonly rawOutput?: unknown;
  readonly error?: string;
}

export interface ModelProvider {
  readonly id: string;
  readonly metadata: ModelMetadata;
  load(): Promise<boolean>;
  isLoaded(): boolean;
  unload(): Promise<void>;
  infer(request: InferenceRequest): Promise<InferenceResult>;
}

// ==========================================
// 3. INTENT CLASSIFICATION DOMAIN
// ==========================================

export enum ScamIntent {
  PHISHING_CREDENTIALS = 'PHISHING_CREDENTIALS',
  URGENCY_EXTORTION = 'URGENCY_EXTORTION',
  ADVANCE_FEE_FRAUD = 'ADVANCE_FEE_FRAUD',
  EMPLOYMENT_TASK_SCAM = 'EMPLOYMENT_TASK_SCAM',
  TECH_SUPPORT_INVOICE = 'TECH_SUPPORT_INVOICE',
  POSTAL_DELIVERY_FRAUD = 'POSTAL_DELIVERY_FRAUD',
  BENIGN_COMMUNICATION = 'BENIGN_COMMUNICATION'
}

export interface IntentClassificationResult {
  readonly intent: ScamIntent | string;
  readonly confidence: number;
  readonly uncertainty: number;
  readonly evidenceToken: Evidence;
  readonly latencyMs: number;
  readonly isModelBacked: boolean;
  readonly inferenceStatus: 'MODEL_INFERRED' | 'DETERMINISTIC_FALLBACK' | 'MODEL_UNAVAILABLE';
  readonly modelMetadata?: ModelMetadata;
}

// ==========================================
// 4. PROMPT INJECTION DEFENSE CONTRACTS
// ==========================================

export type InjectionSeverity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SanitizationResult {
  readonly sanitizedText: string;
  readonly injectionDetected: boolean;
  readonly detectedPatterns: string[];
  readonly severity: InjectionSeverity;
  readonly quarantinedTokens: string[];
}

export interface SecurityBoundaryViolation {
  readonly code: string;
  readonly description: string;
  readonly source: string;
  readonly timestamp: number;
}

// ==========================================
// 5. AI SECURITY ASSISTANT CONTRACTS
// (Conforming to docs/AI_ASSISTANT_CONTRACT.md)
// ==========================================

export interface AssistantEvidenceToken {
  readonly ruleId: string;
  readonly category: string;
  readonly description: string;
  readonly scoreContribution?: number;
}

export interface AssistantInput {
  readonly requestId: string;
  readonly verdict: Verdict;
  readonly riskAssessment: RiskAssessment;
  readonly evidenceTokens: AssistantEvidenceToken[];
  readonly cognitiveReadingGrade?: 6 | 8;
  readonly targetType?: string;
  readonly untrustedSnippet?: string;
}

export interface AssistantOutput {
  readonly headline: string; // Max 60 chars
  readonly summaryParagraph: string; // Max 300 chars, plain language
  readonly dangerFactors: string[]; // 1 to 4 items, max 100 chars each
  readonly recommendedSteps: string[]; // 1 to 3 items, max 120 chars each
  readonly uncertaintyNote: string; // Max 150 chars
  readonly inferenceStatus: 'LOCAL_MODEL' | 'DETERMINISTIC_FALLBACK' | 'SANITIZED';
  readonly modelId?: string;
  readonly executionTimeMs: number;
  readonly autoTaskPlan?: {
    readonly tasks: Array<{
      readonly taskId: string;
      readonly type: string;
      readonly priority: string;
      readonly title: string;
      readonly reasoning: string;
      readonly plannedActions: Array<{
        readonly id: string;
        readonly title: string;
        readonly description: string;
        readonly command: string;
        readonly canAutoExecute: boolean;
        readonly requiresUserConsent: boolean;
      }>;
      readonly createdAtMs: number;
    }>;
    readonly autoExecutedCount: number;
    readonly pendingUserConsentCount: number;
    readonly executionTimeMs: number;
  };
}
