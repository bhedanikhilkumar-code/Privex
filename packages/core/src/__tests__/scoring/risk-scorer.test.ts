import { describe, it, expect, beforeEach } from 'vitest';
import { RiskScorer } from '../../scoring/risk-scorer';

describe('RiskScorer', () => {
  let scorer: RiskScorer;

  beforeEach(() => {
    scorer = new RiskScorer();
  });

  it('should return SAFE score for empty evidence', () => {
    const result = scorer.calculateScore([]);
    expect(result.score).toBeLessThan(30);
    expect(result.severity).toBe('SAFE');
  });

  it('should return low score for single low-weight evidence', () => {
    const result = scorer.calculateScore([{ type: 'text', weight: 10, indicator: 'typo' }]);
    expect(result.score).toBeGreaterThan(0);
    expect(result.score).toBeLessThan(30);
    expect(result.severity).toBe('SAFE');
  });

  it('should return high score for multiple high-weight evidence', () => {
    const result = scorer.calculateScore([
      { type: 'url', weight: 80, indicator: 'phishing-domain' },
      { type: 'text', weight: 50, indicator: 'urgency' }
    ]);
    expect(result.score).toBeGreaterThanOrEqual(85);
    expect(result.severity).toBe('BLOCK');
  });

  it('should correctly apply score thresholds', () => {
    expect(scorer.calculateScore([{ type: 'test', weight: 20 }]).severity).toBe('SAFE');
    expect(scorer.calculateScore([{ type: 'test', weight: 45 }]).severity).toBe('SUSPICIOUS');
    expect(scorer.calculateScore([{ type: 'test', weight: 70 }]).severity).toBe('WARNING');
    expect(scorer.calculateScore([{ type: 'test', weight: 90 }]).severity).toBe('BLOCK');
  });

  it('should calculate confidence based on evidence count and weights', () => {
    const result = scorer.calculateScore([
      { type: 'url', weight: 90, indicator: 'known-malware' },
      { type: 'threat-intel', weight: 100, indicator: 'blacklisted' }
    ]);
    expect(result.confidence).toBeGreaterThan(0.8);
  });

  it('should provide appropriate action recommendation mapping', () => {
    expect(scorer.calculateScore([{ type: 'test', weight: 90 }]).recommendedAction).toBe('block');
    expect(scorer.calculateScore([{ type: 'test', weight: 70 }]).recommendedAction).toBe('warn');
    expect(scorer.calculateScore([{ type: 'test', weight: 10 }]).recommendedAction).toBe('allow');
  });

  it('should handle layer disagreement gracefully', () => {
    const result = scorer.calculateScore([
      { type: 'url', weight: 10, indicator: 'safe-domain' }, // Low risk
      { type: 'text', weight: 90, indicator: 'scam-content' } // High risk
    ]);
    // Generally should err on the side of caution or combine appropriately
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(['WARNING', 'BLOCK']).toContain(result.severity);
  });
});
