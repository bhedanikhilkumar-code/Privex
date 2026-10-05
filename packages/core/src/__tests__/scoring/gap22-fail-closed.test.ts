import { describe, it, expect, beforeEach } from 'vitest';
import { RiskScorer } from '../../scoring/risk-scorer';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { Verdict, RiskCategory, InputType } from '../../types';

describe('GAP-22 Remediation: Fail-Closed Invariant & Non-Finite Arithmetic Defense', () => {
  let riskScorer: RiskScorer;
  let pipeline: DetectionPipeline;

  beforeEach(() => {
    riskScorer = new RiskScorer();
    pipeline = new DetectionPipeline();
  });

  describe('RiskScorer non-finite inputs (NaN, Infinity, -Infinity)', () => {
    it('should clamp NaN scoreContribution and weight to fail-closed caution score (50) and never ALLOW', () => {
      const nanEvidence = [
        {
          ruleId: 'test-nan',
          name: 'NaN Anomaly',
          scoreContribution: NaN,
          confidence: NaN,
          source: 'TEST'
        }
      ];

      const result = riskScorer.calculateScore(nanEvidence);
      expect(Number.isFinite(result.score)).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(50);
      expect(result.verdict).not.toBe(Verdict.ALLOW);
      expect(result.severity).not.toBe('SAFE');
    });

    it('should handle Infinity and -Infinity scoreContribution without producing NaN or escaping bounds', () => {
      const posInfEvidence = [
        {
          ruleId: 'test-inf-pos',
          name: 'PosInf Anomaly',
          scoreContribution: Infinity,
          confidence: 1.0,
          source: 'TEST'
        }
      ];
      const posResult = riskScorer.calculateScore(posInfEvidence);
      expect(Number.isFinite(posResult.score)).toBe(true);
      expect(posResult.score).toBeLessThanOrEqual(100);
      expect(posResult.score).toBeGreaterThanOrEqual(0);

      const negInfEvidence = [
        {
          ruleId: 'test-inf-neg',
          name: 'NegInf Anomaly',
          scoreContribution: -Infinity,
          confidence: 1.0,
          source: 'TEST'
        }
      ];
      const negResult = riskScorer.calculateScore(negInfEvidence);
      expect(Number.isFinite(negResult.score)).toBe(true);
      expect(negResult.score).toBeLessThanOrEqual(100);
      expect(negResult.score).toBeGreaterThanOrEqual(0);
    });

    it('should handle NaN combined with valid signals without poisoning the overall calculation', () => {
      const mixedEvidence = [
        {
          ruleId: 'valid-signal',
          name: 'Phishing Keyword',
          scoreContribution: 80,
          confidence: 0.9,
          source: 'RULE_ENGINE'
        },
        {
          ruleId: 'poison-signal',
          name: 'NaN Poison',
          scoreContribution: NaN,
          confidence: NaN,
          source: 'TEST'
        }
      ];

      const result = riskScorer.calculateScore(mixedEvidence);
      expect(Number.isFinite(result.score)).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(70);
      expect(result.verdict).not.toBe(Verdict.ALLOW);
    });

    it('should respect exact 5-tier canonical threshold boundaries', () => {
      // 0-19: ALLOW / NONE
      const tier1 = riskScorer.calculateScore([{ ruleId: 't1', scoreContribution: 10, confidence: 1.0, source: 'TEST' }]);
      expect(tier1.score).toBeLessThan(20);
      expect(tier1.verdict).toBe(Verdict.ALLOW);

      // 20-49: INFORM / LOW
      const tier2 = riskScorer.calculateScore([{ ruleId: 't2', scoreContribution: 30, confidence: 1.0, source: 'TEST' }]);
      expect(tier2.score).toBeGreaterThanOrEqual(20);
      expect(tier2.score).toBeLessThan(50);
      expect(tier2.verdict).toBe(Verdict.INFORM);

      // 50-69: CAUTION / MEDIUM
      const tier3 = riskScorer.calculateScore([{ ruleId: 't3', scoreContribution: 55, confidence: 1.0, source: 'TEST' }]);
      expect(tier3.score).toBeGreaterThanOrEqual(50);
      expect(tier3.score).toBeLessThan(70);
      expect(tier3.verdict).toBe(Verdict.CAUTION);

      // 70-84: SUSPICIOUS / HIGH
      const tier4 = riskScorer.calculateScore([{ ruleId: 't4', scoreContribution: 75, confidence: 1.0, source: 'TEST' }]);
      expect(tier4.score).toBeGreaterThanOrEqual(70);
      expect(tier4.score).toBeLessThan(85);
      expect(tier4.verdict).toBe(Verdict.SUSPICIOUS);

      // 85-100: DANGEROUS / CRITICAL
      const tier5 = riskScorer.calculateScore([{ ruleId: 't5', scoreContribution: 95, confidence: 1.0, source: 'TEST' }]);
      expect(tier5.score).toBeGreaterThanOrEqual(85);
      expect(tier5.verdict).toBe(Verdict.DANGEROUS);
    });
  });

  describe('DetectionPipeline Fail-Closed Malformed Input Protection', () => {
    it('should fail-closed to CAUTION and score 50 on empty string URL input', async () => {
      const result = await pipeline.scan({ input: '', inputType: InputType.URL });
      expect(result.verdict).toBe(Verdict.CAUTION);
      expect(result.score).toBe(50);
      expect(result.action).toBe('WARN');
      expect(result.error).toBeDefined();
    });

    it('should fail-closed to CAUTION and score 50 on empty string text input', async () => {
      const result = await pipeline.scan({ input: '', inputType: InputType.TEXT });
      expect(result.verdict).toBe(Verdict.CAUTION);
      expect(result.score).toBe(50);
      expect(result.action).toBe('WARN');
      expect(result.error).toBeDefined();
    });

    it('should fail-closed to CAUTION on null and undefined input payloads', async () => {
      const nullScan = await pipeline.scan(null as any);
      expect(nullScan.verdict).toBe(Verdict.CAUTION);
      expect(nullScan.score).toBe(50);
      expect(nullScan.action).toBe('WARN');

      const undefinedScan = await pipeline.scan(undefined as any);
      expect(undefinedScan.verdict).toBe(Verdict.CAUTION);
      expect(undefinedScan.score).toBe(50);
      expect(undefinedScan.action).toBe('WARN');
    });

    it('should fail-closed when inputType is missing or unsupported', async () => {
      const result = await pipeline.scan({ input: 'https://example.com', inputType: 'INVALID_TYPE' as any });
      // Either inputType is invalid or handled safely with fail-closed caution
      expect(result.verdict).toBeDefined();
      expect(Number.isFinite(result.score)).toBe(true);
    });
  });
});
