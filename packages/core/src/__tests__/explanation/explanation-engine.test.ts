import { describe, it, expect, beforeEach } from 'vitest';
import { ExplanationEngine } from '../../explanation/explanation-engine';

describe('ExplanationEngine', () => {
  let engine: ExplanationEngine;

  beforeEach(() => {
    engine = new ExplanationEngine();
  });

  it('should generate phishing-specific explanation for phishing evidence', () => {
    const explanation = engine.generateExplanation({
      score: 90,
      severity: 'BLOCK',
      evidence: [{ type: 'url', indicator: 'typosquatting', description: 'Domain looks like google.com' }]
    });
    expect(explanation.text.toLowerCase()).toContain('looks like');
    expect(explanation.text.toLowerCase()).toContain('google.com');
  });

  it('should generate scam-specific explanation for scam evidence', () => {
    const explanation = engine.generateExplanation({
      score: 85,
      severity: 'BLOCK',
      evidence: [{ type: 'text', indicator: 'financial-scam', description: 'Requests cryptocurrency payment' }]
    });
    expect(explanation.text.toLowerCase()).toContain('scam');
    expect(explanation.text.toLowerCase()).toContain('cryptocurrency');
  });

  it('should combine multiple evidence items into a coherent narrative', () => {
    const explanation = engine.generateExplanation({
      score: 75,
      severity: 'WARNING',
      evidence: [
        { type: 'text', indicator: 'urgency', description: 'Creates false sense of urgency' },
        { type: 'url', indicator: 'suspicious-tld', description: 'Uses a low-reputation domain extension' }
      ]
    });
    expect(explanation.text.toLowerCase()).toContain('urgency');
    expect(explanation.text.toLowerCase()).toContain('domain');
  });

  it('should be jargon-free', () => {
    const explanation = engine.generateExplanation({
      score: 95,
      severity: 'BLOCK',
      evidence: [{ type: 'url', indicator: 'punycode-domain', description: 'IDN homograph attack' }]
    });
    // Should translate "punycode/IDN homograph" to simpler terms
    expect(explanation.text.toLowerCase()).not.toContain('punycode');
    expect(explanation.text.toLowerCase()).not.toContain('homograph');
    expect(explanation.text.toLowerCase()).toContain('deceptive');
  });

  it('should include a recommended action in every explanation', () => {
    const explanation = engine.generateExplanation({ score: 90, severity: 'BLOCK', evidence: [] });
    expect(explanation.action).toBeDefined();
    expect(explanation.action.toLowerCase()).toContain('do not click');
  });

  it('should generate positive confirmation for SAFE results', () => {
    const explanation = engine.generateExplanation({ score: 10, severity: 'SAFE', evidence: [] });
    expect(explanation.text.toLowerCase()).toContain('safe');
    expect(explanation.action.toLowerCase()).toContain('safe to proceed');
  });
});
