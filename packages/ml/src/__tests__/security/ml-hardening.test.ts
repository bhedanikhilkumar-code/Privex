import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import { PromptSanitizer } from '../../security/prompt-sanitizer';
import { ResponsePolicy } from '../../assistant/response-policy';
import { AISecurityAssistant } from '../../assistant/assistant-runtime';
import { ScamIntentClassifier } from '../../classifiers/intent-classifier';
import { UrlSemanticClassifier } from '../../classifiers/semantic-classifier';
import { ModelIntegrityVerifier } from '../../models/model-metadata';
import { DevelopmentMockModelProvider } from '../../models/providers/mock-provider';
import { ModelLoader } from '../../models/model-loader';
import { Verdict, SeverityLevel } from '@private-protection/core';
import { ModelMetadata } from '../../types';

describe('Phase 3 Hardening & Branch Coverage Suite', () => {
  it('should clamp text longer than 500 characters in PromptSanitizer', () => {
    const longText = 'A'.repeat(600);
    const result = PromptSanitizer.sanitize(longText);
    expect(result.sanitizedText.length).toBe(500);
  });

  it('should safely handle non-string or null inputs in PromptSanitizer', () => {
    const nullRes = PromptSanitizer.sanitize(null as any);
    expect(nullRes.sanitizedText).toBe('');
    expect(nullRes.injectionDetected).toBe(false);

    const undefRes = PromptSanitizer.sanitize(undefined as any);
    expect(undefRes.sanitizedText).toBe('');
  });

  it('should safely handle empty or null query in ResponsePolicy', () => {
    const nullRes = ResponsePolicy.evaluateUserIntent(null as any);
    expect(nullRes.isProhibited).toBe(false);

    const emptyRes = ResponsePolicy.evaluateUserIntent('');
    expect(emptyRes.isProhibited).toBe(false);
  });

  it('should exercise AISecurityAssistant inference path with active loaded mock provider', async () => {
    const loader = new ModelLoader();
    const mockProvider = new DevelopmentMockModelProvider({ simulatedLatencyMs: 0 });
    await mockProvider.load();
    loader.registerProvider(mockProvider);

    const assistant = new AISecurityAssistant({
      modelLoader: loader,
      activeProviderId: mockProvider.id
    });

    const res = await assistant.explain({
      requestId: 'test-loaded-active',
      verdict: Verdict.DANGEROUS,
      riskAssessment: {
        overallScore: 85,
        confidence: 0.9,
        severity: SeverityLevel.HIGH,
        primaryThreatFactor: 'phishing',
        detectorContributions: {}
      },
      evidenceTokens: [
        {
          ruleId: 'r1',
          category: 'PHISHING',
          description: 'Test phishing evidence'
        }
      ]
    });

    expect(res.inferenceStatus).toBe('LOCAL_MODEL');
    expect(res.headline).toBe('Warning: Deceptive Web Target');
    expect(res.dangerFactors.length).toBe(2);
  });

  it('should safely handle empty input in ScamIntentClassifier', async () => {
    const classifier = new ScamIntentClassifier();
    const res = await classifier.classify('   ');
    expect(res.intent).toBe('BENIGN_COMMUNICATION');
    expect(res.confidence).toBe(1.0);
    expect(res.isModelBacked).toBe(false);
  });

  it('should safely handle empty input in UrlSemanticClassifier', () => {
    const urlClassifier = new UrlSemanticClassifier();
    const res = urlClassifier.analyzeUrlSemantics('   ');
    expect(res.isDeceptive).toBe(false);
    expect(res.confidence).toBe(1.0);
  });

  it('should reject TFLite buffer shorter than 8 bytes in ModelIntegrityVerifier', () => {
    const shortBuf = Buffer.from('TFL');
    const metadata: ModelMetadata = {
      modelId: 'short-tflite',
      version: '1.0',
      format: 'TFLITE',
      task: 'INTENT_CLASSIFICATION',
      sha256: crypto.createHash('sha256').update(shortBuf).digest('hex'),
      sizeBytes: 3,
      inputShape: [],
      outputClasses: [],
      quantization: 'INT8',
      isProductionArtifact: false
    };

    const res = ModelIntegrityVerifier.verifyModelBuffer(shortBuf, metadata);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('CorruptedModelError');
  });

  it('should return FALLBACK status when DevelopmentMockModelProvider is invoked unloaded', async () => {
    const mockProvider = new DevelopmentMockModelProvider();
    const res = await mockProvider.infer({
      requestId: 'mock-unloaded',
      task: 'INTENT_CLASSIFICATION',
      input: 'test text'
    });

    expect(res.status).toBe('FALLBACK');
    expect(res.topLabel).toBe('UNLOADED');
    expect(res.confidence).toBe(0.0);
  });
});
