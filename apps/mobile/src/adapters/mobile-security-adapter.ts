import {
  DetectionPipeline,
  Verdict,
  SeverityLevel,
  InputType,
  ActionRecommendation,
  FrictionLevel
} from '@private-protection/core';
import {
  UrlSemanticClassifier,
  AISecurityAssistant,
  AssistantInput
} from '@private-protection/ml';
import { MobileScanResult, ScanTargetType } from '../types/mobile.types';

export class MobileSecurityAdapter {
  private pipeline: DetectionPipeline;
  private urlClassifier: UrlSemanticClassifier;
  private assistant: AISecurityAssistant;

  constructor() {
    this.pipeline = new DetectionPipeline();
    this.urlClassifier = new UrlSemanticClassifier();
    this.assistant = new AISecurityAssistant();
  }

  /**
   * Scans a candidate URL using the deterministic core pipeline and on-device ML classifiers.
   */
  public async scanUrl(
    url: string,
    readingGrade: 6 | 8 = 6,
    customAllowlist: string[] = []
  ): Promise<MobileScanResult> {
    const startTime = performance.now();

    // 1. Enforce strict byte length limit
    if (!url || typeof url !== 'string' || url.length > 2048) {
      throw new Error('URL_TOO_LONG_OR_INVALID: URLs must not exceed 2048 bytes.');
    }

    const trimmed = url.trim();

    // 2. Allowlist domain check
    try {
      const parsed = new URL(trimmed.startsWith('http') ? trimmed : `http://${trimmed}`);
      const hostname = parsed.hostname.toLowerCase();
      if (customAllowlist.some((domain) => hostname === domain.toLowerCase() || hostname.endsWith(`.${domain.toLowerCase()}`))) {
        return this.createAllowlistBypassResult(trimmed, 'URL', startTime);
      }
    } catch {
      // Proceed to pipeline for invalid/malformed URL scoring
    }

    // 3. Deterministic core scan
    const coreResult = await this.pipeline.scan({
      input: trimmed,
      inputType: InputType.URL
    });

    let verdict: Verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    let overallScore: number = coreResult.score ?? coreResult.riskScore ?? 0;
    let severity: SeverityLevel = (coreResult.riskAssessment?.severity as SeverityLevel) ??
      (verdict === Verdict.DANGEROUS ? SeverityLevel.CRITICAL : verdict === Verdict.SUSPICIOUS ? SeverityLevel.HIGH : SeverityLevel.NONE);
    let confidence: number = coreResult.confidence ?? 0.85;
    let evidence = [...(coreResult.evidence || [])];
    let threatCategory = (coreResult.riskCategory as string) || 'GENERIC';

    // 4. ML Deceptive Intent Classifier
    const semanticResult = this.urlClassifier.analyzeUrlSemantics(trimmed);
    if (semanticResult.isDeceptive && semanticResult.evidenceToken) {
      evidence.push(semanticResult.evidenceToken);
      overallScore = Math.min(100, Math.max(overallScore, semanticResult.evidenceToken.weight));
      if (overallScore >= 85) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.CRITICAL;
        threatCategory = 'PHISHING_SEMANTIC';
      } else if (overallScore >= 70) {
        verdict = Verdict.SUSPICIOUS;
        severity = SeverityLevel.HIGH;
        threatCategory = 'SUSPICIOUS_SEMANTIC';
      }
    }

    // 5. On-Device AI Assistant Synthesis
    let aiExplanation = undefined;
    if (overallScore >= 40) {
      const assistantInput: AssistantInput = {
        requestId: coreResult.id || `mob-url-${Date.now()}`,
        verdict,
        riskAssessment: coreResult.riskAssessment || {
          overallScore,
          confidence,
          severity,
          primaryThreatFactor: threatCategory,
          detectorContributions: {}
        },
        evidenceTokens: evidence.map((ev) => ({
          ruleId: ev.indicator || ev.ruleId || 'rule',
          category: ev.type || 'HEURISTIC',
          description: ev.description,
          scoreContribution: ev.scoreContribution || 10
        })),
        cognitiveReadingGrade: readingGrade,
        targetType: 'URL',
        untrustedSnippet: trimmed
      };

      try {
        aiExplanation = await this.assistant.explain(assistantInput);
      } catch {
        // Falls back safely to deterministic template inside assistant
      }
    }

    const duration = performance.now() - startTime;

    return {
      scanId: coreResult.id || `scan-${Date.now()}`,
      targetType: 'URL',
      rawInput: trimmed,
      sanitizedTarget: trimmed,
      verdict,
      overallScore,
      severity,
      confidence,
      threatCategory,
      evidence,
      recommendation: coreResult.canonicalRecommendation || {
        action: ActionRecommendation.ALLOW,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'Safe to open',
        bypassPermitted: true
      },
      aiExplanation,
      timestamp: Date.now(),
      overridden: false,
      executionTimeMs: Math.round(duration * 100) / 100
    };
  }

  /**
   * Scans user-pasted message text (SMS, email, instant message).
   */
  public async scanText(
    text: string,
    readingGrade: 6 | 8 = 6
  ): Promise<MobileScanResult> {
    const startTime = performance.now();

    if (!text || typeof text !== 'string' || text.length > 10000) {
      throw new Error('TEXT_TOO_LONG_OR_INVALID: Text messages must not exceed 10000 characters.');
    }

    const trimmed = text.trim();

    // Deterministic core scan
    const coreResult = await this.pipeline.scan({
      input: trimmed,
      inputType: InputType.TEXT
    });

    const verdict: Verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    const overallScore: number = coreResult.score ?? coreResult.riskScore ?? 0;
    const severity: SeverityLevel = (coreResult.riskAssessment?.severity as SeverityLevel) ??
      (verdict === Verdict.DANGEROUS ? SeverityLevel.CRITICAL : verdict === Verdict.SUSPICIOUS ? SeverityLevel.HIGH : SeverityLevel.NONE);
    const confidence: number = coreResult.confidence ?? 0.85;
    const evidence = [...(coreResult.evidence || [])];
    const threatCategory = (coreResult.riskCategory as string) || 'SCAM_TEXT';

    let aiExplanation = undefined;
    if (overallScore >= 40) {
      const assistantInput: AssistantInput = {
        requestId: coreResult.id || `mob-txt-${Date.now()}`,
        verdict,
        riskAssessment: coreResult.riskAssessment || {
          overallScore,
          confidence,
          severity,
          primaryThreatFactor: threatCategory,
          detectorContributions: {}
        },
        evidenceTokens: evidence.map((ev) => ({
          ruleId: ev.indicator || ev.ruleId || 'rule',
          category: ev.type || 'HEURISTIC',
          description: ev.description,
          scoreContribution: ev.scoreContribution || 10
        })),
        cognitiveReadingGrade: readingGrade,
        targetType: 'MESSAGE',
        untrustedSnippet: trimmed
      };

      try {
        aiExplanation = await this.assistant.explain(assistantInput);
      } catch {
        // Safe template fallback
      }
    }

    const duration = performance.now() - startTime;

    return {
      scanId: coreResult.id || `scan-${Date.now()}`,
      targetType: 'TEXT',
      rawInput: trimmed,
      sanitizedTarget: trimmed.length > 100 ? `${trimmed.substring(0, 97)}...` : trimmed,
      verdict,
      overallScore,
      severity,
      confidence,
      threatCategory,
      evidence,
      recommendation: coreResult.canonicalRecommendation || {
        action: ActionRecommendation.ALLOW,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'No immediate scam indicators detected',
        bypassPermitted: true
      },
      aiExplanation,
      timestamp: Date.now(),
      overridden: false,
      executionTimeMs: Math.round(duration * 100) / 100
    };
  }

  private createAllowlistBypassResult(
    target: string,
    targetType: ScanTargetType,
    startTime: number
  ): MobileScanResult {
    return {
      scanId: `allow-${Date.now()}`,
      targetType,
      rawInput: target,
      sanitizedTarget: target,
      verdict: Verdict.ALLOW,
      overallScore: 0,
      severity: SeverityLevel.NONE,
      confidence: 1.0,
      threatCategory: 'USER_ALLOWLIST',
      evidence: [
        {
          source: 'AllowlistFilter',
          name: 'Trusted Domain Override',
          description: 'Domain is present in the local user custom allowlist.',
          weight: 0,
          confidence: 1.0
        }
      ],
      recommendation: {
        action: ActionRecommendation.ALLOW,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'Domain is trusted by user settings',
        bypassPermitted: true
      },
      timestamp: Date.now(),
      overridden: false,
      executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100
    };
  }
}
