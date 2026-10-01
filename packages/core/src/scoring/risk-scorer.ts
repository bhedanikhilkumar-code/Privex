import { ActionRecommendation, Evidence, RiskCategory, Severity } from '../types';

export interface ScoreResult {
  score: number;
  category: RiskCategory;
  severity: Severity | string;
  confidence: number;
  recommendation: ActionRecommendation;
  recommendedAction: string;
}

export class RiskScorer {
  public calculate(evidence: Evidence[]): ScoreResult {
    return this.calculateScore(evidence);
  }

  public calculateScore(evidence: any[]): ScoreResult {
    if (!evidence || evidence.length === 0) {
      return {
        score: 0,
        category: RiskCategory.SAFE,
        severity: 'SAFE',
        confidence: 1.0,
        recommendation: ActionRecommendation.ALLOW,
        recommendedAction: 'allow'
      };
    }

    const weights = evidence.map(e => (typeof e.weight === 'number' ? e.weight : 20));
    const sorted = [...weights].sort((a, b) => b - a);
    const maxWeight = sorted[0];
    const otherWeights = sorted.slice(1);
    const bonus = otherWeights.reduce((acc, w) => acc + w * 0.25, 0);

    const calculatedScore = Math.min(100, Math.round(maxWeight + bonus));

    // Calculate confidence
    const confidences = evidence.map(e => (typeof e.confidence === 'number' ? e.confidence : 0.85));
    const avgConfidence = confidences.reduce((a, b) => a + b, 0) / confidences.length;

    let category = RiskCategory.SAFE;
    let severity: Severity | string = 'SAFE';
    let recommendation = ActionRecommendation.ALLOW;
    let recommendedAction = 'allow';

    if (calculatedScore >= 85) {
      category = RiskCategory.MALWARE;
      severity = 'BLOCK';
      recommendation = ActionRecommendation.BLOCK;
      recommendedAction = 'block';
    } else if (calculatedScore >= 60) {
      const isScam = evidence.some(e =>
        (e.name && e.name.toLowerCase().includes('scam')) ||
        (e.indicator && e.indicator.includes('scam')) ||
        (e.type === 'text')
      );
      category = isScam ? RiskCategory.SCAM : RiskCategory.PHISHING;
      severity = 'WARNING';
      recommendation = ActionRecommendation.WARN;
      recommendedAction = 'warn';
    } else if (calculatedScore >= 30) {
      category = RiskCategory.SUSPICIOUS;
      severity = 'SUSPICIOUS';
      recommendation = ActionRecommendation.INFORM;
      recommendedAction = 'inform';
    } else {
      category = RiskCategory.SAFE;
      severity = 'SAFE';
      recommendation = ActionRecommendation.ALLOW;
      recommendedAction = 'allow';
    }

    return {
      score: calculatedScore,
      category,
      severity,
      confidence: Math.round(avgConfidence * 100) / 100,
      recommendation,
      recommendedAction
    };
  }
}
