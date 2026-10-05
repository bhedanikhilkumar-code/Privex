import {
  ActionRecommendation,
  Evidence,
  FrictionLevel,
  PrescribedAction,
  Recommendation,
  RiskAssessment,
  RiskCategory,
  Severity,
  SeverityLevel,
  Verdict
} from '../types';

export interface ScoreResult {
  score: number;
  category: RiskCategory;
  severity: Severity | SeverityLevel | string;
  confidence: number;
  recommendation: ActionRecommendation;
  recommendedAction: string;
  // Subsystem 9 Canonical RiskAssessment struct
  riskAssessment?: RiskAssessment;
  verdict?: Verdict;
  canonicalRecommendation?: Recommendation;
}

export class RiskScorer {
  /**
   * Detector plane base reliability weights (docs/RISK_ENGINE_ARCHITECTURE.md Section 2)
   */
  private detectorWeights: Record<string, number> = {
    RULE_ENGINE: 1.0,
    FILEHEADERANALYZER: 1.0,
    FILE_ANALYZER: 1.0,
    THREAT_INTEL: 0.95,
    DOM_ANALYZER: 0.90,
    URL_ANALYZER: 0.85,
    TEXT_ANALYZER: 0.75,
    ML_MODEL: 0.65,
    DEFAULT: 0.75
  };

  public calculate(evidence: Evidence[], stalenessDays: number = 0): ScoreResult {
    return this.calculateScore(evidence, stalenessDays);
  }

  public calculateScore(evidence: any[], stalenessDays: number = 0): ScoreResult {
    if (!evidence || evidence.length === 0) {
      const canonicalRec: Recommendation = {
        action: PrescribedAction.PROCEED,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'Content verified. Safe to proceed.',
        bypassPermitted: true
      };

      const emptyAssessment: RiskAssessment = {
        overallScore: 0,
        confidence: 1.0,
        severity: SeverityLevel.NONE,
        primaryThreatFactor: 'NONE',
        detectorContributions: {}
      };

      return {
        score: 0,
        category: RiskCategory.SAFE,
        severity: 'SAFE',
        confidence: 1.0,
        recommendation: ActionRecommendation.ALLOW,
        recommendedAction: 'allow',
        verdict: Verdict.ALLOW,
        riskAssessment: emptyAssessment,
        canonicalRecommendation: canonicalRec
      };
    }

    // 1. Calculate detector contributions and find primary threat factor
    const detectorContributions: Record<string, number> = {};
    let primaryThreatFactor = 'UNKNOWN';
    let maxSignalValue = -1;
    let criticalOverrideScore = 0;

    const normalizedTokens = evidence.map((e: any) => {
      let rawScore: number;
      if (typeof e.scoreContribution === 'number' && Number.isFinite(e.scoreContribution)) {
        rawScore = e.scoreContribution;
      } else if (typeof e.weight === 'number' && Number.isFinite(e.weight)) {
        rawScore = e.weight;
      } else {
        // Fail-closed invariant (GAP-22): Non-finite numeric evidence (NaN, Infinity, -Infinity)
        // must NEVER silently evaluate to zero or ALLOW. Clamp to an anomaly warning score.
        rawScore = 50;
      }
      // Bound rawScore to [0, 100]
      rawScore = Math.min(100, Math.max(0, rawScore));

      const sourceKey = (e.source || e.detectorType || e.type || 'DEFAULT').toUpperCase();
      let baseWeight = this.detectorWeights[sourceKey];
      if (baseWeight === undefined || !Number.isFinite(baseWeight) || baseWeight <= 0) {
        if (sourceKey.includes('RULE')) baseWeight = this.detectorWeights.RULE_ENGINE;
        else if (sourceKey.includes('THREAT')) baseWeight = this.detectorWeights.THREAT_INTEL;
        else if (sourceKey.includes('DOM')) baseWeight = this.detectorWeights.DOM_ANALYZER;
        else if (sourceKey.includes('URL')) baseWeight = this.detectorWeights.URL_ANALYZER;
        else if (sourceKey.includes('TEXT')) baseWeight = this.detectorWeights.TEXT_ANALYZER;
        else if (sourceKey.includes('ML')) baseWeight = this.detectorWeights.ML_MODEL;
        else if (sourceKey === 'TEST') baseWeight = 1.0;
        else baseWeight = this.detectorWeights.DEFAULT;
      }

      const defaultConf = (sourceKey === 'TEST' || sourceKey.includes('RULE')) ? 1.0 : 0.85;
      let confidence = (typeof e.confidence === 'number' && Number.isFinite(e.confidence)) ? e.confidence : defaultConf;
      confidence = Math.min(1.0, Math.max(0.01, confidence));

      const indicator = e.indicator || e.name || 'threat-signal';
      let effectiveSignal = rawScore * baseWeight * confidence;
      if (!Number.isFinite(effectiveSignal) || Number.isNaN(effectiveSignal)) {
        effectiveSignal = 50;
      }
      effectiveSignal = Math.min(100, Math.max(0, effectiveSignal));

      if (effectiveSignal > maxSignalValue) {
        maxSignalValue = effectiveSignal;
        primaryThreatFactor = indicator;
      }

      if (e.isCriticalOverride || (sourceKey.includes('THREAT') && rawScore >= 90)) {
        if (Number.isFinite(rawScore)) {
          criticalOverrideScore = Math.max(criticalOverrideScore, rawScore);
        }
      }

      const categorySource = e.source || e.detectorType || 'RULE_ENGINE';
      detectorContributions[categorySource] = (detectorContributions[categorySource] || 0) + rawScore;

      return {
        rawScore,
        baseWeight,
        confidence,
        effectiveSignal,
        indicator,
        source: categorySource
      };
    });

    // 2. Bounded Non-Linear Diminishing-Returns Aggregation Model
    // R_raw = 100 * (1 - PRODUCT_{i=1}^n (1 - x_i / 100))
    // (docs/RISK_ENGINE_ARCHITECTURE.md Section 1.2)
    let productTerm = 1.0;
    for (const token of normalizedTokens) {
      const x_i = token.effectiveSignal;
      productTerm *= (1.0 - (x_i / 100.0));
    }
    let rawR = 100.0 * (1.0 - productTerm);
    if (!Number.isFinite(rawR) || Number.isNaN(rawR)) {
      rawR = 60.0; // Fail-closed on mathematical anomaly
    }
    let calculatedScore = Math.min(100, Math.max(0, Math.round(rawR)));

    // 3. Critical Rule Priority Override (docs/RISK_ENGINE_ARCHITECTURE.md Section 1.3)
    if (criticalOverrideScore > 0 && Number.isFinite(criticalOverrideScore)) {
      calculatedScore = Math.max(calculatedScore, Math.round(criticalOverrideScore));
    }
    if (!Number.isFinite(calculatedScore) || Number.isNaN(calculatedScore)) {
      calculatedScore = 75; // Fail-closed fallback
    }
    calculatedScore = Math.min(100, Math.max(0, calculatedScore));

    // 4. Multi-Factor Confidence & Uncertainty Calculation
    // C_final = mean(c_i) * (1 - P_stale) * consensus * agreement
    const avgConfidence = normalizedTokens.reduce((a, t) => a + t.confidence, 0) / normalizedTokens.length;

    // Staleness Penalty (Section 3.1)
    let stalenessPenalty = 0.0;
    if (stalenessDays > 7) {
      stalenessPenalty = Math.min(0.20, (stalenessDays - 7) / 100);
    }

    // Signal Agreement (A = 1.0 - stdDev / 100)
    let agreement = 1.0;
    if (normalizedTokens.length >= 2) {
      const meanScore = normalizedTokens.reduce((a, t) => a + t.rawScore, 0) / normalizedTokens.length;
      const variance = normalizedTokens.reduce((a, t) => a + Math.pow(t.rawScore - meanScore, 2), 0) / normalizedTokens.length;
      const stdDev = Math.sqrt(variance);
      agreement = Math.max(0.6, 1.0 - (stdDev / 100.0));
    }

    // Multi-signal consensus boost
    const consensusBoost = normalizedTokens.length >= 2 ? 0.05 : 0.0;
    const finalConfidence = Math.min(
      1.0,
      Math.max(0.2, (avgConfidence + consensusBoost) * (1.0 - stalenessPenalty) * agreement)
    );
    const roundedConfidence = Math.round(finalConfidence * 100) / 100;
    const uncertainty = Math.round((1.0 - roundedConfidence) * 100) / 100;

    // 5. Determine Verdict, Severity Level, and Recommendations
    // Canonical 5-Tier Thresholds (docs/RISK_ENGINE_ARCHITECTURE.md Section 4):
    // 0-19: ALLOW / NONE / Silent Proceed
    // 20-49: INFORM / LOW / Passive Badge
    // 50-69: CAUTION / MEDIUM / Warning Banner
    // 70-84: SUSPICIOUS / HIGH / Modal Interstitial
    // 85-100: DANGEROUS / CRITICAL / Hard Interstitial
    let category = RiskCategory.SAFE;
    let severity: Severity | SeverityLevel | string = 'SAFE';
    let sevLevel = SeverityLevel.NONE;
    let recommendation = ActionRecommendation.ALLOW;
    let recommendedAction = 'allow';
    let verdict = Verdict.ALLOW;
    let canonicalAction = PrescribedAction.PROCEED;
    let friction = FrictionLevel.NONE;
    let suggestedAction = 'Content appears safe. Safe to proceed.';

    if (calculatedScore >= 85) {
      category = RiskCategory.MALWARE;
      severity = 'BLOCK';
      sevLevel = SeverityLevel.CRITICAL;
      verdict = Verdict.DANGEROUS;
      recommendation = ActionRecommendation.BLOCK;
      recommendedAction = 'block';
      canonicalAction = PrescribedAction.BLOCK_NAVIGATION;
      friction = FrictionLevel.HIGH;
      suggestedAction = 'Do not proceed. Threat poses imminent risk to security. Access blocked.';
    } else if (calculatedScore >= 70) {
      const isScam = evidence.some((e: any) =>
        (e.name && e.name.toLowerCase().includes('scam')) ||
        (e.indicator && e.indicator.includes('scam')) ||
        (e.type === 'text') ||
        (e.source === 'TEXT_ANALYZER')
      );
      category = isScam ? RiskCategory.SCAM : RiskCategory.PHISHING;
      severity = 'SUSPICIOUS';
      sevLevel = SeverityLevel.HIGH;
      verdict = Verdict.SUSPICIOUS;
      recommendation = ActionRecommendation.WARN;
      recommendedAction = 'warn';
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.MEDIUM;
      suggestedAction = 'Suspicious indicators identified. Do not enter credentials or pay.';
    } else if (calculatedScore >= 50) {
      const isScam = evidence.some((e: any) =>
        (e.name && e.name.toLowerCase().includes('scam')) ||
        (e.indicator && e.indicator.includes('scam')) ||
        (e.type === 'text') ||
        (e.source === 'TEXT_ANALYZER')
      );
      category = isScam ? RiskCategory.SCAM : RiskCategory.PHISHING;
      severity = 'WARNING';
      sevLevel = SeverityLevel.MEDIUM;
      verdict = Verdict.CAUTION;
      recommendation = ActionRecommendation.WARN;
      recommendedAction = 'warn';
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.LOW;
      suggestedAction = 'Exercise caution. Multiple suspicious patterns identified.';
    } else if (calculatedScore >= 20) {
      category = RiskCategory.SUSPICIOUS;
      severity = 'LOW';
      sevLevel = SeverityLevel.LOW;
      verdict = Verdict.INFORM;
      recommendation = ActionRecommendation.INFORM;
      recommendedAction = 'inform';
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.LOW;
      suggestedAction = 'Low risk detected. Verify source if requesting information.';
    } else {
      category = RiskCategory.SAFE;
      severity = 'SAFE';
      sevLevel = SeverityLevel.NONE;
      verdict = Verdict.ALLOW;
      recommendation = ActionRecommendation.ALLOW;
      recommendedAction = 'allow';
      canonicalAction = PrescribedAction.PROCEED;
      friction = FrictionLevel.NONE;
      suggestedAction = 'Content appears safe.';
    }

    // Edge-Case Safety Rule (docs/RISK_ENGINE_ARCHITECTURE.md Section 4):
    // If Score >= 70 but Confidence < 0.40, clamp verdict to CAUTION
    if (calculatedScore >= 70 && roundedConfidence < 0.40) {
      verdict = Verdict.CAUTION;
      severity = 'WARNING';
      sevLevel = SeverityLevel.MEDIUM;
      friction = FrictionLevel.LOW;
    }

    const riskAssessment: RiskAssessment = {
      overallScore: calculatedScore,
      confidence: roundedConfidence,
      severity: sevLevel,
      primaryThreatFactor,
      detectorContributions,
      uncertainty
    };

    const canonicalRecommendation: Recommendation = {
      action: canonicalAction,
      frictionLevel: friction,
      suggestedAction,
      bypassPermitted: calculatedScore < 85
    };

    return {
      score: calculatedScore,
      category,
      severity,
      confidence: roundedConfidence,
      recommendation,
      recommendedAction,
      verdict,
      riskAssessment,
      canonicalRecommendation
    };
  }
}

