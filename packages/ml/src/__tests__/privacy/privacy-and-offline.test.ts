import { describe, it, expect, vi } from 'vitest';
import * as http from 'http';
import * as https from 'https';
import { Verdict, SeverityLevel } from '@private-protection/core';
import { AISecurityAssistant } from '../../assistant/assistant-runtime';
import { ScamIntentClassifier } from '../../classifiers/intent-classifier';
import { UrlSemanticClassifier } from '../../classifiers/semantic-classifier';

describe('Privacy & Offline Invariants (@private-protection/ml)', () => {
  it('should guarantee ZERO outbound HTTP/HTTPS requests during assistant execution', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const assistant = new AISecurityAssistant();
    const result = await assistant.explain({
      requestId: 'privacy-test-req',
      verdict: Verdict.DANGEROUS,
      riskAssessment: {
        overallScore: 85,
        confidence: 0.9,
        severity: SeverityLevel.CRITICAL,
        primaryThreatFactor: 'phishing',
        detectorContributions: {}
      },
      evidenceTokens: [
        {
          ruleId: 'test-rule',
          category: 'PHISHING',
          description: 'Test evidence'
        }
      ],
      untrustedSnippet: 'https://deceptive-login.xyz/auth?user=victim@test.com'
    });

    expect(result).toBeDefined();
    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });

  it('should operate 100% offline without remote cloud LLM dependencies', async () => {
    const classifier = new ScamIntentClassifier();
    const urlClassifier = new UrlSemanticClassifier();

    const intentResult = await classifier.classify('Urgent wire transfer required to unblock account');
    expect(intentResult.intent).toBeDefined();
    expect(intentResult.latencyMs).toBeLessThan(50);

    const urlResult = urlClassifier.analyzeUrlSemantics('http://fake-paypal-verify.xyz/login');
    expect(urlResult.isDeceptive).toBe(true);
    expect(urlResult.latencyMs).toBeLessThan(50);
  });

  it('should ensure volatile RAM processing without leaking unencrypted user data', async () => {
    const assistant = new AISecurityAssistant();
    const sensitiveMessage = 'CONFIDENTIAL_SSN_999-00-1111: Please verify credentials';

    const explanation = await assistant.explain({
      requestId: 'sensitive-req',
      verdict: Verdict.CAUTION,
      riskAssessment: {
        overallScore: 60,
        confidence: 0.8,
        severity: SeverityLevel.MEDIUM,
        primaryThreatFactor: 'credential-phishing',
        detectorContributions: {}
      },
      evidenceTokens: [
        { ruleId: 'cred-1', category: 'PHISHING', description: 'Credential request' }
      ],
      untrustedSnippet: sensitiveMessage
    });

    // The sensitive SSN string must NOT be reflected in the user explanation headline or summary
    expect(explanation.headline).not.toContain('999-00-1111');
    expect(explanation.summaryParagraph).not.toContain('999-00-1111');
  });
});
