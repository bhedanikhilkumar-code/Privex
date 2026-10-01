import { describe, it, expect, beforeEach } from 'vitest';
import { RiskScorer } from '../../scoring/risk-scorer';
import {
  ActionRecommendation,
  FrictionLevel,
  PrescribedAction,
  RiskCategory,
  SeverityLevel,
  Verdict
} from '../../types';

describe('RiskScorer Canonical Engine & Threshold Boundaries', () => {
  let scorer: RiskScorer;

  beforeEach(() => {
    scorer = new RiskScorer();
  });

  describe('Empty & Single Signal Baseline', () => {
    it('should return SAFE and ALLOW for empty evidence array', () => {
      const result = scorer.calculateScore([]);
      expect(result.score).toBe(0);
      expect(result.severity).toBe('SAFE');
      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.recommendation).toBe(ActionRecommendation.ALLOW);
      expect(result.confidence).toBe(1.0);
      expect(result.riskAssessment?.severity).toBe(SeverityLevel.NONE);
      expect(result.canonicalRecommendation?.action).toBe(PrescribedAction.PROCEED);
      expect(result.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.NONE);
    });

    it('should calculate accurate score for single low-weight evidence', () => {
      const result = scorer.calculateScore([{ type: 'text', weight: 10, indicator: 'typo' }]);
      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThan(20);
      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.severity).toBe('SAFE');
      expect(result.recommendation).toBe(ActionRecommendation.ALLOW);
    });

    it('should calculate accurate score for single high-confidence evidence', () => {
      const result = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 85, confidence: 1.0, indicator: 'severe-rule' }
      ]);
      expect(result.score).toBe(85);
      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.severity).toBe('BLOCK');
      expect(result.recommendation).toBe(ActionRecommendation.BLOCK);
      expect(result.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.HIGH);
    });

    it('should scale effective signal down for low-confidence evidence', () => {
      const highConf = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 60, confidence: 1.0, indicator: 'signal' }
      ]);
      const lowConf = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 60, confidence: 0.5, indicator: 'signal' }
      ]);
      expect(highConf.score).toBe(60);
      expect(lowConf.score).toBe(30); // 60 * 1.0 * 0.5 = 30
      expect(lowConf.confidence).toBeLessThan(highConf.confidence);
    });
  });

  describe('Canonical 5-Tier Boundary Thresholds (19, 20, 49, 50, 69, 70, 84, 85, 100)', () => {
    it('Boundary 19: should map to Tier 1 ALLOW / NONE / Silent Proceed', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 19 }]);
      expect(res.score).toBe(19);
      expect(res.verdict).toBe(Verdict.ALLOW);
      expect(res.severity).toBe('SAFE');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.NONE);
      expect(res.recommendation).toBe(ActionRecommendation.ALLOW);
      expect(res.recommendedAction).toBe('allow');
      expect(res.canonicalRecommendation?.action).toBe(PrescribedAction.PROCEED);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.NONE);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(true);
    });

    it('Boundary 20: should map to Tier 2 INFORM / LOW / Passive Badge', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 20 }]);
      expect(res.score).toBe(20);
      expect(res.verdict).toBe(Verdict.INFORM);
      expect(res.severity).toBe('LOW');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.LOW);
      expect(res.recommendation).toBe(ActionRecommendation.INFORM);
      expect(res.recommendedAction).toBe('inform');
      expect(res.canonicalRecommendation?.action).toBe(PrescribedAction.WARN_USER);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.LOW);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(true);
    });

    it('Boundary 49: should map to Tier 2 INFORM / LOW / Passive Badge', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 49 }]);
      expect(res.score).toBe(49);
      expect(res.verdict).toBe(Verdict.INFORM);
      expect(res.severity).toBe('LOW');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.LOW);
      expect(res.recommendation).toBe(ActionRecommendation.INFORM);
      expect(res.recommendedAction).toBe('inform');
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.LOW);
    });

    it('Boundary 50: should map to Tier 3 CAUTION / MEDIUM / Warning Banner', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 50 }]);
      expect(res.score).toBe(50);
      expect(res.verdict).toBe(Verdict.CAUTION);
      expect(res.severity).toBe('WARNING');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.MEDIUM);
      expect(res.recommendation).toBe(ActionRecommendation.WARN);
      expect(res.recommendedAction).toBe('warn');
      expect(res.canonicalRecommendation?.action).toBe(PrescribedAction.WARN_USER);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.LOW);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(true);
    });

    it('Boundary 69: should map to Tier 3 CAUTION / MEDIUM / Warning Banner', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 69 }]);
      expect(res.score).toBe(69);
      expect(res.verdict).toBe(Verdict.CAUTION);
      expect(res.severity).toBe('WARNING');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.MEDIUM);
      expect(res.recommendation).toBe(ActionRecommendation.WARN);
      expect(res.recommendedAction).toBe('warn');
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.LOW);
    });

    it('Boundary 70: should map to Tier 4 SUSPICIOUS / HIGH / Modal Interstitial', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 70 }]);
      expect(res.score).toBe(70);
      expect(res.verdict).toBe(Verdict.SUSPICIOUS);
      expect(res.severity).toBe('SUSPICIOUS');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.HIGH);
      expect(res.recommendation).toBe(ActionRecommendation.WARN);
      expect(res.recommendedAction).toBe('warn');
      expect(res.canonicalRecommendation?.action).toBe(PrescribedAction.WARN_USER);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.MEDIUM);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(true);
    });

    it('Boundary 84: should map to Tier 4 SUSPICIOUS / HIGH / Modal Interstitial', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 84 }]);
      expect(res.score).toBe(84);
      expect(res.verdict).toBe(Verdict.SUSPICIOUS);
      expect(res.severity).toBe('SUSPICIOUS');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.HIGH);
      expect(res.recommendation).toBe(ActionRecommendation.WARN);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.MEDIUM);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(true);
    });

    it('Boundary 85: should map to Tier 5 DANGEROUS / CRITICAL / Hard Interstitial', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 85 }]);
      expect(res.score).toBe(85);
      expect(res.verdict).toBe(Verdict.DANGEROUS);
      expect(res.severity).toBe('BLOCK');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.CRITICAL);
      expect(res.recommendation).toBe(ActionRecommendation.BLOCK);
      expect(res.recommendedAction).toBe('block');
      expect(res.canonicalRecommendation?.action).toBe(PrescribedAction.BLOCK_NAVIGATION);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.HIGH);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(false);
    });

    it('Boundary 100: should map to Tier 5 DANGEROUS / CRITICAL / Hard Interstitial', () => {
      const res = scorer.calculateScore([{ type: 'test', weight: 100 }]);
      expect(res.score).toBe(100);
      expect(res.verdict).toBe(Verdict.DANGEROUS);
      expect(res.severity).toBe('BLOCK');
      expect(res.riskAssessment?.severity).toBe(SeverityLevel.CRITICAL);
      expect(res.recommendation).toBe(ActionRecommendation.BLOCK);
      expect(res.recommendedAction).toBe('block');
      expect(res.canonicalRecommendation?.action).toBe(PrescribedAction.BLOCK_NAVIGATION);
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.HIGH);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(false);
    });
  });

  describe('Bounded Non-Linear Math & Diminishing Returns', () => {
    it('should aggregate two signals via R = 100 * (1 - (1 - x1/100)(1 - x2/100))', () => {
      // Two signals of x = 50: (1 - 0.5)*(1 - 0.5) = 0.25 -> R = 75
      const res = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 50, confidence: 1.0 },
        { source: 'RULE_ENGINE', weight: 50, confidence: 1.0 }
      ]);
      expect(res.score).toBe(75);
      expect(res.verdict).toBe(Verdict.SUSPICIOUS);
    });

    it('should demonstrate diminishing returns across three and many signals without inflation', () => {
      // Three signals of x = 50: (1 - 0.5)^3 = 0.125 -> R = 87.5 -> 88
      const res3 = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 50, confidence: 1.0 },
        { source: 'RULE_ENGINE', weight: 50, confidence: 1.0 },
        { source: 'RULE_ENGINE', weight: 50, confidence: 1.0 }
      ]);
      expect(res3.score).toBe(88);

      // 10 signals of x = 20 should strictly remain bounded <= 100
      const manySignals = Array.from({ length: 10 }, () => ({
        source: 'RULE_ENGINE',
        weight: 20,
        confidence: 1.0
      }));
      const resMany = scorer.calculateScore(manySignals);
      expect(resMany.score).toBeLessThanOrEqual(100);
      expect(resMany.score).toBeGreaterThan(85);
    });

    it('should handle duplicate identical signals gracefully', () => {
      const single = scorer.calculateScore([{ source: 'RULE_ENGINE', weight: 40, confidence: 1.0 }]);
      const duplicates = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 40, confidence: 1.0 },
        { source: 'RULE_ENGINE', weight: 40, confidence: 1.0 }
      ]);
      expect(single.score).toBe(40);
      // R = 100 * (1 - (1 - 0.4)^2) = 100 * (1 - 0.36) = 64
      expect(duplicates.score).toBe(64);
      expect(duplicates.score).toBeLessThan(100);
    });
  });

  describe('Critical Override Logic', () => {
    it('should override combined score when an indicator has isCriticalOverride: true', () => {
      const res = scorer.calculateScore([
        { source: 'TEXT_ANALYZER', weight: 20, confidence: 0.5 },
        { source: 'TEXT_ANALYZER', weight: 95, confidence: 0.9, isCriticalOverride: true, indicator: 'ransomware-extortion' }
      ]);
      expect(res.score).toBe(95);
      expect(res.verdict).toBe(Verdict.DANGEROUS);
      expect(res.severity).toBe('BLOCK');
      expect(res.recommendation).toBe(ActionRecommendation.BLOCK);
      expect(res.riskAssessment?.primaryThreatFactor).toBe('ransomware-extortion');
    });

    it('should automatically trigger critical override for THREAT_INTEL hits with weight >= 90', () => {
      const res = scorer.calculateScore([
        { source: 'THREAT_INTEL', weight: 100, confidence: 0.95, indicator: 'known-malicious-domain' }
      ]);
      expect(res.score).toBe(100);
      expect(res.verdict).toBe(Verdict.DANGEROUS);
      expect(res.canonicalRecommendation?.bypassPermitted).toBe(false);
    });
  });

  describe('Conflicting Detectors & Staleness Handling', () => {
    it('should handle layer disagreement gracefully (safe vs threat)', () => {
      const result = scorer.calculateScore([
        { source: 'URL_ANALYZER', weight: 10, confidence: 0.9, indicator: 'benign-tld' },
        { source: 'TEXT_ANALYZER', weight: 80, confidence: 0.9, indicator: 'extortion-keywords' }
      ]);
      expect(result.score).toBeGreaterThanOrEqual(50);
      expect(['WARNING', 'SUSPICIOUS', 'BLOCK']).toContain(result.severity);
    });

    it('should penalize confidence when threat intelligence is stale (> 7 days)', () => {
      const freshResult = scorer.calculateScore(
        [{ source: 'THREAT_INTEL', weight: 80, confidence: 0.9 }],
        0 // fresh
      );
      const staleResult = scorer.calculateScore(
        [{ source: 'THREAT_INTEL', weight: 80, confidence: 0.9 }],
        30 // 30 days stale
      );
      expect(staleResult.confidence).toBeLessThan(freshResult.confidence);
      expect(staleResult.riskAssessment?.uncertainty).toBeGreaterThan(freshResult.riskAssessment?.uncertainty || 0);
    });

    it('should clamp verdict to CAUTION when score >= 70 but confidence < 0.40 (Edge-Case Safety Rule)', () => {
      const res = scorer.calculateScore([
        { source: 'RULE_ENGINE', weight: 85, confidence: 0.35, isCriticalOverride: true, indicator: 'noisy-unverified-classifier' }
      ]);
      expect(res.score).toBeGreaterThanOrEqual(70);
      expect(res.confidence).toBeLessThan(0.40);
      expect(res.verdict).toBe(Verdict.CAUTION);
      expect(res.severity).toBe('WARNING');
      expect(res.canonicalRecommendation?.frictionLevel).toBe(FrictionLevel.LOW);
    });
  });
});
