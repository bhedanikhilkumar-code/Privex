import { Evidence, RiskCategory } from '@private-protection/core';
import { ModelLoader } from '../models/model-loader';
import { IntentClassificationResult, ModelProvider, ScamIntent } from '../types';

export class ScamIntentClassifier {
  private modelLoader?: ModelLoader;
  private providerId?: string;

  constructor(options?: { modelLoader?: ModelLoader; providerId?: string }) {
    this.modelLoader = options?.modelLoader;
    this.providerId = options?.providerId;
  }

  /**
   * Classifies intent of ambiguous text, returning calibrated intent probabilities and structured Evidence.
   */
  public async classify(text: string): Promise<IntentClassificationResult> {
    const startTime = Date.now();

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return {
        intent: ScamIntent.BENIGN_COMMUNICATION,
        confidence: 1.0,
        uncertainty: 0.0,
        evidenceToken: {
          source: 'ML_MODEL',
          name: 'Empty Payload',
          description: 'Empty or invalid text provided for intent classification',
          weight: 0,
          confidence: 1.0
        },
        latencyMs: 0.01,
        isModelBacked: false,
        inferenceStatus: 'DETERMINISTIC_FALLBACK'
      };
    }

    // Check if active model provider is loaded
    let provider: ModelProvider | undefined;
    if (this.modelLoader && this.providerId) {
      provider = this.modelLoader.getProvider(this.providerId);
    }

    if (provider && provider.isLoaded()) {
      try {
        const result = await provider.infer({
          requestId: `intent-${Date.now()}`,
          task: 'INTENT_CLASSIFICATION',
          input: text
        });

        const elapsed = Math.max(0.1, Date.now() - startTime);
        const topLabel = (result.topLabel as ScamIntent) || ScamIntent.BENIGN_COMMUNICATION;
        const confidence = result.confidence;
        const uncertainty = result.uncertainty;

        const isThreat = topLabel !== ScamIntent.BENIGN_COMMUNICATION;
        const score = isThreat ? Math.round(result.topScore * 75) : 0;

        const evidenceToken: Evidence = {
          source: 'ML_MODEL',
          name: `Intent: ${topLabel}`,
          description: `Machine learning classifier identified intent pattern: ${topLabel}`,
          weight: score,
          scoreContribution: score,
          confidence,
          indicator: `ml-intent-${topLabel.toLowerCase().replace(/_/g, '-')}`
        };

        return {
          intent: topLabel,
          confidence,
          uncertainty,
          evidenceToken,
          latencyMs: elapsed,
          isModelBacked: true,
          inferenceStatus: 'MODEL_INFERRED',
          modelMetadata: provider.metadata
        };
      } catch {
        // Fall through to deterministic intent heuristic
      }
    }

    // Deterministic semantic fallback classifier
    const lower = text.toLowerCase();
    let detectedIntent: ScamIntent = ScamIntent.BENIGN_COMMUNICATION;
    let weight = 0;
    let confidence = 0.70;

    if (/task|rating.*apps|deposit.*commission|daily.*salary|wire.*task|remote job|workbench|earn.*commission/i.test(lower)) {
      detectedIntent = ScamIntent.EMPLOYMENT_TASK_SCAM;
      weight = 65;
    } else if (/invoice|geek squad|norton|mcafee|renewed.*\$|subscription.*call|charge.*completed|auto-renewed|license invoice|receipt.*subscription/i.test(lower)) {
      detectedIntent = ScamIntent.TECH_SUPPORT_INVOICE;
      weight = 70;
    } else if (/usps|fedex|ups|dhl|postal|royal mail|package.*detained|address.*update.*fee|customs tax|customs surcharge|redelivery payment|shipment.*arrived|delivery failed/i.test(lower)) {
      detectedIntent = ScamIntent.POSTAL_DELIVERY_FRAUD;
      weight = 65;
    } else if (/ransom|files.*encrypted|pay.*decrypt|destroy.*data|blackmail|webcam|private key|wire funds immediately|monero|bitcoin.*decrypt/i.test(lower)) {
      detectedIntent = ScamIntent.URGENCY_EXTORTION;
      weight = 85;
      confidence = 0.90;
    } else if (/password|login|credentials|locked|verify.*account|unusual.*activity|confirm your identity|session expired/i.test(lower)) {
      detectedIntent = ScamIntent.PHISHING_CREDENTIALS;
      weight = 60;
    } else if (/prince|inheritance|beneficiary|million.*dollars|lottery|benefactor|grant award|estate payout|unclaimed.*fund/i.test(lower)) {
      detectedIntent = ScamIntent.ADVANCE_FEE_FRAUD;
      weight = 70;
    }

    const elapsed = Math.max(0.01, Date.now() - startTime);
    const uncertainty = Math.round((1.0 - confidence) * 100) / 100;

    const evidenceToken: Evidence = {
      source: 'ML_MODEL',
      name: `Intent: ${detectedIntent}`,
      description: `Semantic intent analysis classified message as: ${detectedIntent}`,
      weight,
      scoreContribution: weight,
      confidence,
      indicator: `semantic-intent-${detectedIntent.toLowerCase().replace(/_/g, '-')}`
    };

    const inferenceStatus = (this.modelLoader && this.providerId) ? 'MODEL_UNAVAILABLE' : 'DETERMINISTIC_FALLBACK';

    return {
      intent: detectedIntent,
      confidence,
      uncertainty,
      evidenceToken,
      latencyMs: elapsed,
      isModelBacked: false,
      inferenceStatus
    };
  }
}
