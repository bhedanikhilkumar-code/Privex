import { describe, it, expect, beforeEach } from 'vitest';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';

describe('DetectionPipeline', () => {
  let pipeline: DetectionPipeline;

  beforeEach(() => {
    pipeline = new DetectionPipeline();
  });

  it('should perform end-to-end URL scan allowing safe URLs', async () => {
    const result = await pipeline.scan({ type: 'url', content: 'https://www.github.com' });
    expect(result.action).toBe('ALLOW');
    expect(result.score).toBeLessThan(30);
  });

  it('should perform end-to-end URL scan blocking phishing URLs', async () => {
    const result = await pipeline.scan({ type: 'url', content: 'http://192.168.1.1/login-paypal' });
    expect(['BLOCK', 'WARN']).toContain(result.action);
    expect(result.score).toBeGreaterThanOrEqual(60);
  });

  it('should perform end-to-end text scan allowing safe text', async () => {
    const result = await pipeline.scan({ type: 'text', content: 'Hey team, let us meet at 10 AM.' });
    expect(result.action).toBe('ALLOW');
    expect(result.score).toBeLessThan(30);
  });

  it('should perform end-to-end text scan warning/blocking scam text', async () => {
    const result = await pipeline.scan({ type: 'text', content: 'URGENT: Send $500 Bitcoin to wallet 1xYz immediately or be arrested.' });
    expect(['BLOCK', 'WARN']).toContain(result.action);
    expect(result.score).toBeGreaterThanOrEqual(60);
  });

  it('should produce complete DetectionResult with all fields populated', async () => {
    const result = await pipeline.scan({ type: 'text', content: 'Test content' });
    expect(result.id).toBeDefined();
    expect(result.timestamp).toBeDefined();
    expect(result.score).toBeDefined();
    expect(result.severity).toBeDefined();
    expect(result.action).toBeDefined();
    expect(result.explanation).toBeDefined();
    expect(Array.isArray(result.evidence)).toBe(true);
  });

  it('should handle invalid input gracefully', async () => {
    const result = await pipeline.scan({ type: 'unknown' as any, content: null as any });
    expect(result.action).toBe('ALLOW');
    expect(result.error).toBeDefined();
  });

  it('should generate unique scan IDs', async () => {
    const result1 = await pipeline.scan({ type: 'text', content: 'A' });
    const result2 = await pipeline.scan({ type: 'text', content: 'B' });
    expect(result1.id).not.toBe(result2.id);
  });

  it('should provide valid ISO string timestamps', async () => {
    const result = await pipeline.scan({ type: 'text', content: 'A' });
    expect(() => new Date(result.timestamp).toISOString()).not.toThrow();
    expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp);
  });
});
