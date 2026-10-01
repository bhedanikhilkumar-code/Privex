import { describe, it, expect, vi } from 'vitest';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { ActionRecommendation, InputType, PrescribedAction, SeverityLevel, Verdict } from '../../types';

describe('Offline Parity & Pipeline Verification (Phase 2)', () => {
  const pipeline = new DetectionPipeline();

  it('should operate 100% offline without making any network requests', async () => {
    // Spy on global fetch and verify 0 calls are made
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const testUrl = 'http://198.51.100.23/login?auth=token';
    const result = await pipeline.scan({
      input: testUrl,
      inputType: InputType.URL
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.evidence.length).toBeGreaterThan(0);
    expect(result.explanation).toBeDefined();

    vi.unstubAllGlobals();
  });

  it('should return fully populated canonical domain models', async () => {
    const scamText = 'Final Notice from IRS: An arrest warrant has been issued. Wire $1,000 immediately to avoid prison.';
    const result = await pipeline.scan({
      id: '550e8400-e29b-41d4-a716-446655440000',
      payload: scamText,
      type: 'MESSAGE'
    });

    // Model 1 / Model 2 links
    expect(result.requestId).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(result.verdict).toBe(Verdict.DANGEROUS);
    expect(result.executionTimeMs).toBeGreaterThan(0);
    expect(result.executionTimeMs).toBeLessThan(100); // SLA < 100ms

    // Model 5: RiskAssessment
    expect(result.riskAssessment).toBeDefined();
    expect(result.riskAssessment.overallScore).toBeGreaterThanOrEqual(85);
    expect(result.riskAssessment.primaryThreatFactor).toBeDefined();
    expect(Object.keys(result.riskAssessment.detectorContributions).length).toBeGreaterThan(0);

    // Model 3: Threats
    expect(result.threats.length).toBeGreaterThan(0);
    expect(result.threats[0].severity).toBe(SeverityLevel.CRITICAL);
    expect(result.threats[0].confidence).toBeGreaterThan(0.8);

    // Model 6: Recommendation
    expect(result.recommendation).toBe(ActionRecommendation.BLOCK);
    expect(result.canonicalRecommendation).toBeDefined();
    expect(result.canonicalRecommendation?.action).toBe(PrescribedAction.BLOCK_NAVIGATION);
    expect(result.canonicalRecommendation?.suggestedAction).toContain('Do not proceed');

    // Subsystem 11: Explanation
    expect(typeof result.explanation).toBe('string');
    expect(result.explanation).toContain('Recommended action:');
  });

  it('should enforce constitutional allowlist precedence in end-to-end pipeline', async () => {
    // Even if an allowed domain has some unusual path or features, allowlist suppresses false alarms
    const allowedUrl = 'https://google.com/search?q=urgent+verification+needed';
    const result = await pipeline.scan({
      input: allowedUrl,
      inputType: InputType.URL
    });

    expect(result.riskScore).toBeLessThan(30);
    expect(result.recommendation).toBe(ActionRecommendation.ALLOW);
    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.evidence.some(e => e.name === 'Known Good Domain')).toBe(true);
  });

  it('should handle offline threat intelligence staleness degradation gracefully', async () => {
    // Construct a pipeline with simulated stale database (> 30 days old)
    const pipelineStale = new DetectionPipeline();
    // Simulate staleness by setting lastUpdated back 35 days
    (pipelineStale.threatIntel as any).lastUpdated = Date.now() - 35 * 24 * 60 * 60 * 1000;

    expect(pipelineStale.threatIntel.getStalenessState()).toBe('STALE');
    expect(pipelineStale.threatIntel.getStalenessPenalty()).toBeGreaterThan(0.1);

    const result = await pipelineStale.scan({
      input: 'http://malicious-crypto-drainer.cc',
      inputType: InputType.URL
    });

    // Detection still succeeds due to constitutional offline guarantee
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
  });
});
