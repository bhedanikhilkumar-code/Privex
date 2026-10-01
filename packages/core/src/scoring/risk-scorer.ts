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
      const rawScore = typeof e.scoreContribution === 'number'
        ? e.scoreContribution
        : (typeof e.weight === 'number' ? e.weight : 20);

      const source = (e.source || e.detectorType || 'DEFAULT').toUpperCase();
      const baseWeight = this.detectorWeights[source] ?? this.detectorWeights.DEFAULT;
      const confidence = typeof e.confidence === 'number' ? e.confidence : 0.85;

      const indicator = e.indicator || e.name || 'threat-signal';
      const effectiveSignal = rawScore * baseWeight * confidence;

      if (effectiveSignal > maxSignalValue) {
        maxSignalValue = effectiveSignal;
        primaryThreatFactor = indicator;
      }

      if (e.isCriticalOverride || (source === 'THREAT_INTEL' && rawScore >= 90)) {
        criticalOverrideScore = Math.max(criticalOverrideScore, rawScore);
      }

      detectorContributions[source] = (detectorContributions[source] || 0) + rawScore;

      return {
        rawScore,
        baseWeight,
        confidence,
        effectiveSignal,
        indicator,
        source
      };
    });

    // 2. Bounded Non-Linear Diminishing-Returns Aggregation Model
    // (docs/RISK_ENGINE_ARCHITECTURE.md Section 1)
    const sortedScores = normalizedTokens.map(t => t.rawScore).sort((a, b) => b - a);
    const maxScore = sortedScores[0];
    const secondaryScores = sortedScores.slice(1);
    const bonus = secondaryScores.reduce((acc, s) => acc + s * 0.25, 0);

    let calculatedScore = Math.min(100, Math.round(maxScore + bonus));

    // Apply Critical Rule Priority Override
    if (criticalOverrideScore > 0) {
      calculatedScore = Math.max(calculatedScore, criticalOverrideScore);
    }

    // 3. Multi-Factor Confidence Calculation
    // C_final = mean(c_i) * (1 - P_stale) * consensus
    const avgConfidence = normalizedTokens.reduce((a, t) => a + t.confidence, 0) / normalizedTokens.length;

    // Staleness Penalty
    let stalenessPenalty = 0.0;
    if (stalenessDays > 7) {
      stalenessPenalty = Math.min(0.20, (stalenessDays - 7) / 100);
    }

    // Multi-signal consensus boost
    const consensusBoost = normalizedTokens.length >= 2 ? 0.05 : 0.0;
    const finalConfidence = Math.min(1.0, Math.max(0.2, (avgConfidence + consensusBoost) * (1 - stalenessPenalty)));
    const roundedConfidence = Math.round(finalConfidence * 100) / 100;

    // 4. Determine Verdict, Severity Level, and Recommendations
    let category = RiskCategory.SAFE;
    let severity: Severity | SeverityLevel | string = 'SAFE';
    let recommendation = ActionRecommendation.ALLOW;
    let recommendedAction = 'allow';
    let verdict = Verdict.ALLOW;
    let canonicalAction = PrescribedAction.PROCEED;
    let friction = FrictionLevel.NONE;
    let suggestedAction = 'Content verified. Safe to proceed.';

    if (calculatedScore >= 85) {
      category = RiskCategory.MALWARE;
      severity = 'BLOCK';
      verdict = Verdict.DANGEROUS;
      recommendation = ActionRecommendation.BLOCK;
      recommendedAction = 'block';
      canonicalAction = PrescribedAction.BLOCK_NAVIGATION;
      friction = FrictionLevel.HIGH;
      suggestedAction = 'Do not proceed. Threat poses imminent risk to security.';
    } else if (calculatedScore >= 60) {
      const isScam = evidence.some((e: any) =>
        (e.name && e.name.toLowerCase().includes('scam')) ||
        (e.indicator && e.indicator.includes('scam')) ||
        (e.type === 'text') ||
        (e.source === 'TEXT_ANALYZER')
      );
      category = isScam ? RiskCategory.SCAM : RiskCategory.PHISHING;
      severity = 'WARNING';
      verdict = Verdict.CAUTION;
      recommendation = ActionRecommendation.WARN;
      recommendedAction = 'warn';
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.MEDIUM;
      suggestedAction = 'Exercise extreme caution. Do not enter credentials or pay.';
    } else if (calculatedScore >= 30) {
      category = RiskCategory.SUSPICIOUS;
      severity = 'SUSPICIOUS';
      verdict = Verdict.INFORM;
      recommendation = ActionRecommendation.INFORM;
      recommendedAction = 'inform';
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.LOW;
      suggestedAction = 'Verify source before interacting.';
    } else {
      category = RiskCategory.SAFE;
      severity = 'SAFE';
      verdict = Verdict.ALLOW;
      recommendation = ActionRecommendation.ALLOW;
      recommendedAction = 'allow';
      canonicalAction = PrescribedAction.PROCEED;
      friction = FrictionLevel.NONE;
      suggestedAction = 'Content appears safe.';
    }

    const riskAssessment: RiskAssessment = {
      overallScore: calculatedScore,
      confidence: roundedConfidence,
      severity: severity as SeverityLevel,
      primaryThreatFactor,
      detectorContributions
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
