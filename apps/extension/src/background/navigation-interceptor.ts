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
import { TabSecurityState, ExtensionSettings } from '../shared/types';
import { ExtensionStorage } from '../shared/storage';
import { extractDomain, isRestrictedUrl } from '../shared/formatters';

export class NavigationInterceptor {
  private pipeline: DetectionPipeline;
  private urlClassifier: UrlSemanticClassifier;
  private assistant: AISecurityAssistant;

  constructor() {
    this.pipeline = new DetectionPipeline();
    this.urlClassifier = new UrlSemanticClassifier();
    this.assistant = new AISecurityAssistant();
  }

  public async evaluateUrl(
    tabId: number,
    url: string,
    settings?: ExtensionSettings
  ): Promise<{ state: TabSecurityState; action: 'ALLOW' | 'WARN' | 'BLOCK'; redirectUrl?: string }> {
    const activeSettings = settings || await ExtensionStorage.getSettings();
    const domain = extractDomain(url);

    // 1. Check if URL is internal browser protocol (e.g. chrome://, about:, extension)
    if (isRestrictedUrl(url)) {
      const restrictedState: TabSecurityState = {
        tabId,
        url,
        domain,
        verdict: Verdict.ALLOW,
        overallScore: 0,
        severity: SeverityLevel.NONE,
        confidence: 1.0,
        threatCategory: 'INTERNAL_PAGE',
        evidence: [],
        recommendation: {
          action: ActionRecommendation.ALLOW,
          frictionLevel: FrictionLevel.NONE,
          suggestedAction: 'Internal browser page.',
          bypassPermitted: true
        },
        timestamp: Date.now(),
        overridden: false,
        isRestrictedUrl: true
      };
      await ExtensionStorage.setTabState(tabId, restrictedState);
      return { state: restrictedState, action: 'ALLOW' };
    }

    // 2. Check if protection is disabled
    if (!activeSettings.enabled) {
      const disabledState: TabSecurityState = {
        tabId,
        url,
        domain,
        verdict: Verdict.ALLOW,
        overallScore: 0,
        severity: SeverityLevel.NONE,
        confidence: 1.0,
        threatCategory: 'PROTECTION_DISABLED',
        evidence: [],
        recommendation: {
          action: ActionRecommendation.ALLOW,
          frictionLevel: FrictionLevel.NONE,
          suggestedAction: 'Protection is currently paused.',
          bypassPermitted: true
        },
        timestamp: Date.now(),
        overridden: false
      };
      await ExtensionStorage.setTabState(tabId, disabledState);
      return { state: disabledState, action: 'ALLOW' };
    }

    // 3. Check custom local allowlist
    const isAllowlisted = activeSettings.allowlistDomains.some((ad) => {
      const cleanAd = ad.toLowerCase().trim();
      return domain === cleanAd || domain.endsWith(`.${cleanAd}`);
    });

    if (isAllowlisted) {
      const allowState: TabSecurityState = {
        tabId,
        url,
        domain,
        verdict: Verdict.ALLOW,
        overallScore: 0,
        severity: SeverityLevel.NONE,
        confidence: 1.0,
        threatCategory: 'CUSTOM_ALLOWLIST',
        evidence: [],
        recommendation: {
          action: ActionRecommendation.ALLOW,
          frictionLevel: FrictionLevel.NONE,
          suggestedAction: 'Trusted domain configured in local settings.',
          bypassPermitted: true
        },
        timestamp: Date.now(),
        overridden: true
      };
      await ExtensionStorage.setTabState(tabId, allowState);
      return { state: allowState, action: 'ALLOW' };
    }

    // 4. Check if user already explicitly bypassed warning for this tab
    const existingState = await ExtensionStorage.getTabState(tabId);
    if (existingState && existingState.overridden && existingState.url === url) {
      return { state: existingState, action: 'ALLOW' };
    }

    // 5. Execute Core Deterministic Pipeline Scan
    const coreResult = await this.pipeline.scan({
      input: url,
      inputType: InputType.URL
    });

    let verdict: Verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    let overallScore: number = coreResult.score ?? coreResult.riskScore ?? 0;
    let severity: SeverityLevel =
      (coreResult.riskAssessment?.severity as SeverityLevel) ??
      (verdict === Verdict.DANGEROUS
        ? SeverityLevel.CRITICAL
        : verdict === Verdict.SUSPICIOUS
          ? SeverityLevel.HIGH
          : verdict === Verdict.CAUTION
            ? SeverityLevel.MEDIUM
            : verdict === Verdict.INFORM
              ? SeverityLevel.LOW
              : SeverityLevel.NONE);
    let confidence: number = coreResult.confidence ?? 0.85;
    let evidence = [...(coreResult.evidence || [])];
    let threatCategory = (coreResult.riskCategory as string) || 'GENERIC';

    // 6. ML & AI Assistant Layer
    const semanticResult = this.urlClassifier.analyzeUrlSemantics(url);
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
      } else if (overallScore >= 50) {
        verdict = Verdict.CAUTION;
        severity = SeverityLevel.MEDIUM;
        threatCategory = 'SUSPICIOUS_SEMANTIC';
      }
    }

    let aiExplanation = undefined;
    if (overallScore >= 50) {
      // Synthesize plain-language explanation
      const assistantInput: AssistantInput = {
        requestId: coreResult.id || `nav-${Date.now()}-${tabId}`,
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
        cognitiveReadingGrade: (activeSettings.readingGrade as 6 | 8) || 6,
        targetType: 'URL',
        untrustedSnippet: url
      };

      try {
        aiExplanation = await this.assistant.explain(assistantInput);
      } catch {
        // Safe template fallback occurs inside assistant
      }
    }

    const state: TabSecurityState = {
      tabId,
      url,
      domain,
      verdict,
      overallScore,
      severity,
      confidence,
      threatCategory,
      evidence,
      recommendation: coreResult.canonicalRecommendation || {
        action: ActionRecommendation.ALLOW,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'Proceed safely',
        bypassPermitted: true
      },
      aiExplanation,
      timestamp: Date.now(),
      overridden: false
    };

    await ExtensionStorage.setTabState(tabId, state);

    // 7. Map canonical verdict to extension action
    if (verdict === Verdict.DANGEROUS) {
      await ExtensionStorage.addAuditLog({
        id: `audit-${Date.now()}`,
        timestamp: Date.now(),
        action: 'BLOCKED',
        domainPrefix: domain.substring(0, 15),
        verdict: Verdict.DANGEROUS,
        riskScore: overallScore,
        threatCategory
      });

      const interstitialUrl = this.getInterstitialUrl(tabId, url);
      return { state, action: 'BLOCK', redirectUrl: interstitialUrl };
    }

    if (verdict === Verdict.SUSPICIOUS) {
      await ExtensionStorage.addAuditLog({
        id: `audit-${Date.now()}`,
        timestamp: Date.now(),
        action: 'WARNED',
        domainPrefix: domain.substring(0, 15),
        verdict: Verdict.SUSPICIOUS,
        riskScore: overallScore,
        threatCategory
      });

      const interstitialUrl = this.getInterstitialUrl(tabId, url);
      return { state, action: 'WARN', redirectUrl: interstitialUrl };
    }

    return { state, action: 'ALLOW' };
  }

  private getInterstitialUrl(tabId: number, targetUrl: string): string {
    const encodedTarget = encodeURIComponent(targetUrl);
    if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
      return chrome.runtime.getURL(`interstitial.html?tabId=${tabId}&target=${encodedTarget}`);
    }
    return `interstitial.html?tabId=${tabId}&target=${encodedTarget}`;
  }
}
