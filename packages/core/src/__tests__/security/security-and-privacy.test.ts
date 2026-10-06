import { describe, it, expect } from 'vitest';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { URLAnalyzer } from '../../analyzers/url-analyzer';
import { TextAnalyzer } from '../../analyzers/text-analyzer';
import { RuleEngine } from '../../rules/rule-engine';
import { InputType, RiskCategory, Verdict } from '../../types';

describe('Security Hardening & Privacy Audits (Phase 2)', () => {
  const pipeline = new DetectionPipeline();
  const urlAnalyzer = new URLAnalyzer();
  const textAnalyzer = new TextAnalyzer();
  const ruleEngine = new RuleEngine();

  it('should be resilient against catastrophic ReDoS backtracking', () => {
    // Pathological regex inputs designed to trigger polynomial/exponential backtracking
    const redosPatterns = [
      'a'.repeat(500) + '!',
      'https://' + 'sub.'.repeat(100) + 'example.com',
      'urgent '.repeat(500) + 'verify',
      'http://192.168.1.' + '1'.repeat(200),
      '(' + 'a'.repeat(200) + ')' + 'b'.repeat(200)
    ];

    for (const pattern of redosPatterns) {
      const t0 = performance.now();
      urlAnalyzer.analyze(pattern);
      textAnalyzer.analyze(pattern);
      ruleEngine.evaluateAll(pattern, InputType.URL);
      ruleEngine.evaluateAll(pattern, InputType.TEXT);
      const elapsed = performance.now() - t0;

      // Must execute quickly even for pathological strings (real ReDoS takes seconds/minutes; 100ms accommodates thread scheduling)
      expect(elapsed).toBeLessThan(100);
    }
  });

  it('should safely clamp huge 100KB payloads without memory exhaustion', async () => {
    const hugePayload = 'http://example.com/' + 'A'.repeat(100000);
    const t0 = performance.now();
    const result = await pipeline.scan({
      input: hugePayload,
      inputType: InputType.URL
    });
    const elapsed = performance.now() - t0;

    expect(result).toBeDefined();
    // Must execute quickly even for 100KB payloads without memory exhaustion (actual ~0.5ms; 100ms accommodates thread scheduling)
    expect(elapsed).toBeLessThan(100);
  });

  it('should neutralize prototype pollution payloads in requests or metadata', async () => {
    const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}, "constructor": {"prototype": {"admin": true}}}');
    const result = await pipeline.scan({
      input: 'https://example.com/login',
      inputType: InputType.URL,
      metadata: maliciousPayload
    });

    expect(result).toBeDefined();
    expect((Object.prototype as any).polluted).toBeUndefined();
    expect((Object.prototype as any).admin).toBeUndefined();
  });

  it('Privacy Mandate: should NEVER expose raw Tier 1 user payloads in Evidence metadata', async () => {
    const privateSecretMessage = 'CONFIDENTIAL: Wire $50,000 to account #987654321 from user Jane Doe';
    const result = await pipeline.scan({
      input: privateSecretMessage,
      inputType: InputType.TEXT
    });

    for (const ev of result.evidence) {
      // Evidence descriptions and names must contain generic taxonomy, not user PII
      expect(ev.description).not.toContain('Jane Doe');
      expect(ev.description).not.toContain('987654321');
      if (ev.metadata) {
        for (const val of Object.values(ev.metadata)) {
          expect(val).not.toContain('Jane Doe');
          expect(val).not.toContain('987654321');
        }
      }
    }
  });

  it('Fail-Closed: should safely handle malformed, null, or empty scan requests without crashing', async () => {
    const emptyResult = await pipeline.scan({} as any);
    expect(emptyResult.verdict).toBe(Verdict.CAUTION);
    expect(emptyResult.riskCategory).toBe(RiskCategory.SUSPICIOUS);
    expect(emptyResult.score).toBe(50);
    expect(emptyResult.error).toBeDefined();

    const nullResult = await pipeline.scan({ input: null as any, inputType: null as any });
    expect(nullResult.verdict).toBe(Verdict.CAUTION);
    expect(nullResult.score).toBe(50);
    expect(nullResult.error).toBeDefined();
  });
});
