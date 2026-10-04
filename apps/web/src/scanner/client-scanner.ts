import {
  DetectionPipeline,
  InputType,
  ActionRecommendation,
  FrictionLevel,
  SeverityLevel,
  Verdict,
  RiskAssessment,
  Recommendation
} from '@private-protection/core';
import {
  AISecurityAssistant,
  ScamIntentClassifier,
  UrlSemanticClassifier,
  AssistantInput
} from '@private-protection/ml';
import { ScanResultViewData, ScanType, UserPreferences } from './types';

/**
 * CLIENT-SIDE SECURITY SCANNER (ZERO-SERVER PRIVACY GUARANTEE)
 *
 * Coordinates @private-protection/core and @private-protection/ml directly inside
 * the user's browser sandbox.
 * CONSTITUTIONAL INVARIANT:
 * Zero raw user payloads (URLs, messages, or text snippets) are EVER transmitted
 * to external servers or remote AI APIs.
 */
export class ClientScanner {
  private corePipeline: DetectionPipeline;
  private intentClassifier: ScamIntentClassifier;
  private urlSemanticClassifier: UrlSemanticClassifier;
  private aiAssistant: AISecurityAssistant;
  private allowlist: string[] = [];
  private preferences: UserPreferences = {
    cognitiveReadingGrade: 6,
    enableWorkerOffloading: true,
    allowlistDomains: [],
  };

  constructor() {
    this.corePipeline = new DetectionPipeline();
    this.intentClassifier = new ScamIntentClassifier();
    this.urlSemanticClassifier = new UrlSemanticClassifier();
    this.aiAssistant = new AISecurityAssistant();
  }

  public setAllowlist(list: string[]): void {
    this.allowlist = [...list];
    this.preferences.allowlistDomains = [...list];
  }

  public setPreferences(prefs: Partial<UserPreferences>): void {
    this.preferences = { ...this.preferences, ...prefs };
    if (prefs.allowlistDomains) {
      this.allowlist = [...prefs.allowlistDomains];
    }
  }

  public getPreferences(): UserPreferences {
    return { ...this.preferences };
  }

  /**
   * Scans a target URL completely in-browser.
   */
  public async scanUrl(url: string, prefs?: UserPreferences): Promise<ScanResultViewData> {
    const startTime = performance.now();
    const effectivePrefs = prefs ? { ...this.preferences, ...prefs } : this.preferences;
    const cleanUrl = (url || '').trim();

    if (!cleanUrl) {
      return this.buildEmptyResult('URL', 'Empty URL', effectivePrefs);
    }

    // Check allowlist (merged from instance + effective preferences using strict hostname matching)
    const activeAllowlist = [...new Set([...this.allowlist, ...(effectivePrefs.allowlistDomains || [])])];
    let isDomainAllowlisted = false;
    try {
      const parsed = new URL(cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://') ? cleanUrl : `http://${cleanUrl}`);
      const hostname = parsed.hostname.toLowerCase();
      isDomainAllowlisted = activeAllowlist.some((allowed) => {
        const cleanAllowed = (allowed || '').toLowerCase().trim();
        return cleanAllowed.length > 0 && (hostname === cleanAllowed || hostname.endsWith(`.${cleanAllowed}`));
      });
    } catch {
      isDomainAllowlisted = false;
    }
    if (isDomainAllowlisted) {
      return this.buildAllowlistedResult(cleanUrl, 'URL', effectivePrefs);
    }

    // 1. Core deterministic detection
    const coreResult = await this.corePipeline.scan({
      input: cleanUrl,
      inputType: InputType.URL
    });

    let verdict: Verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    let overallScore: number = coreResult.score ?? coreResult.riskScore ?? 0;
    let severity: any = (coreResult.riskAssessment?.severity as SeverityLevel) ??
      (verdict === Verdict.DANGEROUS ? SeverityLevel.CRITICAL : verdict === Verdict.SUSPICIOUS ? SeverityLevel.HIGH : verdict === Verdict.CAUTION ? SeverityLevel.MEDIUM : verdict === Verdict.INFORM ? SeverityLevel.LOW : SeverityLevel.NONE);
    let confidence: number = coreResult.confidence ?? 0.85;
    let evidence = [...(coreResult.evidence || [])];

    // 2. Client-side semantic analysis
    const semanticResult = this.urlSemanticClassifier.analyzeUrlSemantics(cleanUrl);
    if (semanticResult.isDeceptive && semanticResult.evidenceToken) {
      evidence.push(semanticResult.evidenceToken);
      overallScore = Math.min(100, Math.max(overallScore, semanticResult.evidenceToken.weight));
      if (overallScore >= 85) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.CRITICAL;
      } else if (overallScore >= 70) {
        verdict = Verdict.SUSPICIOUS;
        severity = SeverityLevel.HIGH;
      } else if (overallScore >= 50) {
        verdict = Verdict.CAUTION;
        severity = SeverityLevel.MEDIUM;
      }
    }

    const assessment: RiskAssessment = coreResult.riskAssessment || {
      overallScore,
      confidence,
      severity,
      primaryThreatFactor: 'PHISHING',
      detectorContributions: {},
    };

    // 3. AI Security Assistant explanation synthesis
    const assistantInput: AssistantInput = {
      requestId: coreResult.id,
      verdict,
      riskAssessment: {
        ...assessment,
        overallScore,
        severity,
      },
      evidenceTokens: evidence.map(e => ({
        ruleId: e.indicator || 'url-signal',
        category: 'PHISHING',
        description: e.description,
        scoreContribution: e.scoreContribution ?? e.weight ?? 0
      })),
      cognitiveReadingGrade: (effectivePrefs.cognitiveReadingGrade === 8 ? 8 : 6),
      targetType: 'URL',
      untrustedSnippet: cleanUrl.slice(0, 300)
    };

    const aiExplanation = await this.aiAssistant.explain(assistantInput);
    const elapsed = performance.now() - startTime;
    const recommendation: Recommendation = coreResult.canonicalRecommendation || {
      action: coreResult.recommendation,
      frictionLevel: FrictionLevel.NONE,
      suggestedAction: 'Review detection findings.',
      bypassPermitted: true
    };

    return {
      id: coreResult.id,
      targetPreview: cleanUrl.length > 70 ? cleanUrl.slice(0, 67) + '...' : cleanUrl,
      scanType: 'URL',
      verdict,
      overallScore,
      severity,
      confidence,
      evidence,
      recommendation,
      rawAssessment: assessment,
      aiExplanation,
      executionTimeMs: Math.round(elapsed * 100) / 100,
      timestamp: Date.now(),
      isModelBacked: semanticResult.inferenceStatus === 'MODEL_INFERRED',
      privacyGuarantee: '100% processed on-device in browser RAM. Zero network transmission.'
    };
  }

  /**
   * Scans a suspicious message or text communication completely in-browser.
   */
  public async scanText(text: string, prefs?: UserPreferences): Promise<ScanResultViewData> {
    const startTime = performance.now();
    const effectivePrefs = prefs ? { ...this.preferences, ...prefs } : this.preferences;
    const cleanText = (text || '').trim();

    if (!cleanText) {
      return this.buildEmptyResult('TEXT', 'Empty Message', effectivePrefs);
    }

    // 1. Core deterministic detection
    const coreResult = await this.corePipeline.scan({
      input: cleanText,
      inputType: InputType.TEXT
    });

    let verdict: Verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    let overallScore: number = coreResult.score ?? coreResult.riskScore ?? 0;
    let severity: any = (coreResult.riskAssessment?.severity as SeverityLevel) ??
      (verdict === Verdict.DANGEROUS ? SeverityLevel.CRITICAL : verdict === Verdict.SUSPICIOUS ? SeverityLevel.HIGH : verdict === Verdict.CAUTION ? SeverityLevel.MEDIUM : verdict === Verdict.INFORM ? SeverityLevel.LOW : SeverityLevel.NONE);
    let confidence: number = coreResult.confidence ?? 0.85;
    let evidence = [...(coreResult.evidence || [])];

    // 2. Client-side scam intent classification
    const intentResult = await this.intentClassifier.classify(cleanText);
    if (intentResult.intent !== 'BENIGN_COMMUNICATION' && intentResult.evidenceToken) {
      evidence.push(intentResult.evidenceToken);
      overallScore = Math.min(100, Math.max(overallScore, intentResult.evidenceToken.weight));
      if (overallScore >= 85) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.CRITICAL;
      } else if (overallScore >= 70) {
        verdict = Verdict.SUSPICIOUS;
        severity = SeverityLevel.HIGH;
      } else if (overallScore >= 50) {
        verdict = Verdict.CAUTION;
        severity = SeverityLevel.MEDIUM;
      }
    }

    const assessment: RiskAssessment = coreResult.riskAssessment || {
      overallScore,
      confidence,
      severity,
      primaryThreatFactor: 'SCAM',
      detectorContributions: {},
    };

    // 3. AI Security Assistant explanation synthesis
    const assistantInput: AssistantInput = {
      requestId: coreResult.id,
      verdict,
      riskAssessment: {
        ...assessment,
        overallScore,
        severity,
      },
      evidenceTokens: evidence.map(e => ({
        ruleId: e.indicator || 'text-intent',
        category: 'SCAM',
        description: e.description,
        scoreContribution: e.scoreContribution ?? e.weight ?? 0
      })),
      cognitiveReadingGrade: (effectivePrefs.cognitiveReadingGrade === 8 ? 8 : 6),
      targetType: 'MESSAGE',
      untrustedSnippet: cleanText.slice(0, 300)
    };

    const aiExplanation = await this.aiAssistant.explain(assistantInput);
    const elapsed = performance.now() - startTime;
    const recommendation: Recommendation = coreResult.canonicalRecommendation || {
      action: coreResult.recommendation,
      frictionLevel: FrictionLevel.NONE,
      suggestedAction: 'Review detection findings.',
      bypassPermitted: true
    };

    return {
      id: coreResult.id,
      targetPreview: cleanText.length > 70 ? cleanText.slice(0, 67) + '...' : cleanText,
      scanType: 'TEXT',
      verdict,
      overallScore,
      severity,
      confidence,
      evidence,
      recommendation,
      rawAssessment: assessment,
      aiExplanation,
      executionTimeMs: Math.round(elapsed * 100) / 100,
      timestamp: Date.now(),
      isModelBacked: intentResult.isModelBacked,
      privacyGuarantee: '100% processed on-device in browser RAM. Zero network transmission.'
    };
  }

  /**
   * Safe empty result factory (fails closed to protect user)
   */
  private buildEmptyResult(scanType: ScanType, label: string, _prefs: UserPreferences): ScanResultViewData {
    const defaultRec: Recommendation = {
      action: ActionRecommendation.BLOCK,
      frictionLevel: FrictionLevel.HIGH,
      suggestedAction: 'Please enter a valid URL or message to analyze.',
      bypassPermitted: false
    };
    const defaultAssessment: RiskAssessment = {
      overallScore: 100,
      confidence: 1.0,
      severity: SeverityLevel.CRITICAL,
      primaryThreatFactor: 'EMPTY_INPUT',
      detectorContributions: {},
    };

    return {
      id: `empty-${Date.now()}`,
      targetPreview: label,
      scanType,
      verdict: Verdict.DANGEROUS,
      overallScore: 100,
      severity: SeverityLevel.CRITICAL,
      confidence: 1.0,
      evidence: [
        {
          source: 'DETERMINISTIC_RULES',
          name: 'Malformed Input',
          indicator: 'empty-malformed-input',
          type: 'MALFORMED',
          scoreContribution: 100,
          weight: 100,
          confidence: 1.0,
          description: 'Empty or malformed input provided. Cannot verify safety.'
        }
      ],
      recommendation: defaultRec,
      rawAssessment: defaultAssessment,
      aiExplanation: {
        headline: 'Empty or Malformed Input',
        summaryParagraph: 'No valid content was provided to analyze. The system fails closed to protect your security.',
        dangerFactors: ['Input cannot be verified as safe.'],
        recommendedSteps: ['Enter a valid URL or message to analyze.'],
        uncertaintyNote: 'Fails closed by security policy.',
        inferenceStatus: 'DETERMINISTIC_FALLBACK',
        executionTimeMs: 0.05
      },
      executionTimeMs: 0.05,
      timestamp: Date.now(),
      isModelBacked: false,
      privacyGuarantee: '100% processed on-device in browser RAM. Zero network transmission.'
    };
  }

  /**
   * Factory for locally allowlisted domains
   */
  private buildAllowlistedResult(cleanTarget: string, scanType: ScanType, _prefs: UserPreferences): ScanResultViewData {
    const defaultRec: Recommendation = {
      action: ActionRecommendation.ALLOW,
      frictionLevel: FrictionLevel.NONE,
      suggestedAction: 'Domain is in your trusted personal allowlist.',
      bypassPermitted: true
    };
    const defaultAssessment: RiskAssessment = {
      overallScore: 0,
      confidence: 1.0,
      severity: SeverityLevel.LOW,
      primaryThreatFactor: 'NONE',
      detectorContributions: {},
    };

    return {
      id: `allowlisted-${Date.now()}`,
      targetPreview: cleanTarget.length > 70 ? cleanTarget.slice(0, 67) + '...' : cleanTarget,
      scanType,
      verdict: Verdict.ALLOW,
      overallScore: 0,
      severity: SeverityLevel.LOW,
      confidence: 1.0,
      evidence: [
        {
          source: 'USER_ALLOWLIST',
          name: 'Allowlist Match',
          indicator: 'user-allowlist-match',
          type: 'ALLOWLIST',
          scoreContribution: 0,
          weight: 0,
          confidence: 1.0,
          description: 'Destination matches user local allowlist entry.'
        }
      ],
      recommendation: defaultRec,
      rawAssessment: defaultAssessment,
      aiExplanation: {
        headline: 'Trusted Domain (Personal Allowlist)',
        summaryParagraph: 'This destination is in your personal allowlist. You marked it as trusted.',
        dangerFactors: [],
        recommendedSteps: ['Safe to proceed.'],
        uncertaintyNote: 'Explicit user override active.',
        inferenceStatus: 'DETERMINISTIC_FALLBACK',
        executionTimeMs: 0.05
      },
      executionTimeMs: 0.05,
      timestamp: Date.now(),
      isModelBacked: false,
      isAllowlisted: true,
      privacyGuarantee: '100% processed on-device in browser RAM. Zero network transmission.'
    };
  }
}
