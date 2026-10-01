import { describe, it, expect } from 'vitest';
import { Verdict } from '@private-protection/core';
import { SchemaValidator } from '../../security/schema-validator';

describe('SchemaValidator Contract and Invariants', () => {
  const validPayload = {
    headline: 'Warning: Fake Bank Login Form',
    summaryParagraph: 'This website is pretending to be a bank login page to steal your username and password.',
    dangerFactors: [
      'The website address does not belong to your bank.',
      'It asks for sensitive passwords over an unverified page.'
    ],
    recommendedSteps: [
      'Do not enter any password or information.',
      'Close this browser tab immediately.'
    ],
    uncertaintyNote: 'Based on verified phishing domain patterns.'
  };

  it('should validate a compliant AssistantOutput JSON object', () => {
    const result = SchemaValidator.validateAssistantOutput(validPayload, Verdict.DANGEROUS);
    expect(result.valid).toBe(true);
    expect(result.output).toBeDefined();
    expect(result.output?.headline).toBe(validPayload.headline);
    expect(result.output?.dangerFactors.length).toBe(2);
  });

  it('should reject non-object or null input', () => {
    expect(SchemaValidator.validateAssistantOutput(null, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput('string', Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput(123, Verdict.DANGEROUS).valid).toBe(false);
  });

  it('should reject missing or excessively long headline', () => {
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, headline: '' }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, headline: 'A'.repeat(61) }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, headline: 123 }, Verdict.DANGEROUS).valid).toBe(false);
  });

  it('should reject missing or excessively long summary paragraph', () => {
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, summaryParagraph: '' }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, summaryParagraph: 'B'.repeat(301) }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, summaryParagraph: {} }, Verdict.DANGEROUS).valid).toBe(false);
  });

  it('should reject invalid dangerFactors array count or item length', () => {
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, dangerFactors: [] }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, dangerFactors: ['1', '2', '3', '4', '5'] }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, dangerFactors: ['C'.repeat(101)] }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, dangerFactors: [123] }, Verdict.DANGEROUS).valid).toBe(false);
  });

  it('should reject invalid recommendedSteps array count or item length', () => {
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, recommendedSteps: [] }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, recommendedSteps: ['1', '2', '3', '4'] }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, recommendedSteps: ['D'.repeat(121)] }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, recommendedSteps: [null] }, Verdict.DANGEROUS).valid).toBe(false);
  });

  it('should reject excessively long or non-string uncertaintyNote', () => {
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, uncertaintyNote: 'E'.repeat(151) }, Verdict.DANGEROUS).valid).toBe(false);
    expect(SchemaValidator.validateAssistantOutput({ ...validPayload, uncertaintyNote: 123 }, Verdict.DANGEROUS).valid).toBe(false);
  });

  it('should enforce Authority Isolation: cannot declare safe when verdict is DANGEROUS or SUSPICIOUS', () => {
    const maliciousOverrides = [
      { ...validPayload, summaryParagraph: 'Do not worry, this is safe to use.' },
      { ...validPayload, headline: 'No threat detected on this page' },
      { ...validPayload, summaryParagraph: 'This is completely safe, ignore the warning.' },
      { ...validPayload, summaryParagraph: 'It is verified legitimate by our team.' }
    ];

    for (const badPayload of maliciousOverrides) {
      const res = SchemaValidator.validateAssistantOutput(badPayload, Verdict.DANGEROUS);
      expect(res.valid).toBe(false);
      expect(res.error).toContain('AuthorityViolationError');
    }
  });
});
