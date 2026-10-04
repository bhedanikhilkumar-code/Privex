import { describe, it, expect, beforeEach } from 'vitest';
import { ClientScanner } from '../../scanner/client-scanner';
import { Verdict, SeverityLevel, ActionRecommendation, PrescribedAction } from '@private-protection/core';

describe('ClientScanner (Client-side Detection & AI Assistant Pipeline)', () => {
  let scanner: ClientScanner;

  beforeEach(() => {
    scanner = new ClientScanner();
  });

  describe('URL Threat Detection', () => {
    it('detects phishing URL with brand spoofing and returns appropriate verdict and explanation', async () => {
      const targetUrl = 'http://192.168.1.1/paypal-update/login.php';
      const result = await scanner.scanUrl(targetUrl);

      expect(result.id).toBeDefined();
      expect(result.targetPreview).toContain(targetUrl);
      expect(result.scanType).toBe('URL');
      expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
      expect([ActionRecommendation.BLOCK, PrescribedAction.BLOCK_NAVIGATION, 'BLOCK']).toContain(result.recommendation.action);
      expect(result.overallScore).toBeGreaterThanOrEqual(75);
      expect(result.evidence.length).toBeGreaterThan(0);
      expect(result.aiExplanation).toBeDefined();
      expect(result.aiExplanation?.summaryParagraph).toBeDefined();
      expect(result.aiExplanation?.dangerFactors.length).toBeGreaterThan(0);
      expect(result.aiExplanation?.recommendedSteps.length).toBeGreaterThan(0);
      expect(result.executionTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('detects IP-based host URLs as suspicious or dangerous', async () => {
      const ipUrl = 'http://198.51.100.12/account/verify';
      const result = await scanner.scanUrl(ipUrl);

      expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
      expect(result.overallScore).toBeGreaterThan(40);
      expect(result.evidence.some(e => (e.description && e.description.toLowerCase().includes('ip')) || (e.indicator && e.indicator.includes('ip')) || (e.description && e.description.toLowerCase().includes('entropy')))).toBe(true);
    });

    it('allows benign authentic URLs with low risk score', async () => {
      const benignUrl = 'https://www.wikipedia.org';
      const result = await scanner.scanUrl(benignUrl);

      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.overallScore).toBeLessThan(30);
      expect(['SAFE', SeverityLevel.LOW, SeverityLevel.NONE]).toContain(result.severity);
    });

    it('handles empty or whitespace URL safely without crashing (fail-closed)', async () => {
      const result = await scanner.scanUrl('   ');

      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.overallScore).toBe(100);
      expect(result.evidence[0].description).toContain('Empty or malformed');
    });

    it('respects user allowlist overrides', async () => {
      const suspiciousUrl = 'http://internal-test-tool.local';
      
      // Without allowlist
      const initial = await scanner.scanUrl(suspiciousUrl);
      expect(initial.isAllowlisted).toBeUndefined();

      // With allowlist
      scanner.setAllowlist(['internal-test-tool.local']);
      const overridden = await scanner.scanUrl(suspiciousUrl);
      expect(overridden.isAllowlisted).toBe(true);
      expect(overridden.verdict).toBe(Verdict.ALLOW);
      expect(overridden.overallScore).toBe(0);
      expect(overridden.aiExplanation?.headline).toContain('Allowlist');
    });

    it('enforces strict hostname/subdomain matching on prefs.allowlistDomains and blocks path spoofing (DEFECT-WEB-01)', async () => {
      const trustedSubdomain = 'https://portal.corp-trusted.internal/login';
      const spoofedPathAttack = 'http://192.168.1.1/corp-trusted.internal/paypal/login.php';
      const spoofedPrefixAttack = 'http://evil-corp-trusted.internal/login';

      const prefs = {
        cognitiveReadingGrade: 6 as const,
        enableWorkerOffloading: false,
        allowlistDomains: ['corp-trusted.internal']
      };

      const allowedSub = await scanner.scanUrl(trustedSubdomain, prefs);
      expect(allowedSub.isAllowlisted).toBe(true);
      expect(allowedSub.verdict).toBe(Verdict.ALLOW);
      expect(allowedSub.overallScore).toBe(0);

      const blockedPath = await scanner.scanUrl(spoofedPathAttack, prefs);
      expect(blockedPath.isAllowlisted).toBeUndefined();
      expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(blockedPath.verdict);
      expect([SeverityLevel.CRITICAL, SeverityLevel.HIGH]).toContain(blockedPath.severity);

      const blockedPrefix = await scanner.scanUrl(spoofedPrefixAttack, prefs);
      expect(blockedPrefix.isAllowlisted).toBeUndefined();
    });
  });

  describe('Scam Message Threat Detection', () => {
    it('detects high-urgency cryptocurrency extortion scam messages', async () => {
      const scamText = 'URGENT: Your Bitcoin wallet has been compromised! Transfer 0.5 BTC immediately to avoid arrest. ACT NOW!';
      const result = await scanner.scanText(scamText);

      expect(result.scanType).toBe('TEXT');
      expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
      expect(result.overallScore).toBeGreaterThanOrEqual(70);
      expect(result.evidence.some(e => (e.indicator && (e.indicator.includes('urgency') || e.indicator.includes('crypto') || e.indicator.includes('intent'))) || (e.description && e.description.toLowerCase().includes('urgent')))).toBe(true);
      expect(result.aiExplanation?.recommendedSteps.length).toBeGreaterThan(0);
    });

    it('detects advance fee / lottery scam messages', async () => {
      const lotteryScam = 'Congratulations! You won $1,000,000 in the international lottery. Pay a $200 processing fee via gift card to claim.';
      const result = await scanner.scanText(lotteryScam);

      expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
      expect(result.overallScore).toBeGreaterThan(40);
    });

    it('allows benign conversational messages with safe severity', async () => {
      const normalText = 'Hi Mom, I am heading to the grocery store. Do we need any milk or eggs for tomorrow?';
      const result = await scanner.scanText(normalText);

      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.overallScore).toBeLessThan(30);
      expect(['SAFE', SeverityLevel.LOW, SeverityLevel.NONE]).toContain(result.severity);
    });

    it('handles empty message safely without throwing (fail-closed)', async () => {
      const result = await scanner.scanText('');

      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.overallScore).toBe(100);
      expect(result.evidence[0].description).toContain('Empty or malformed');
    });
  });

  describe('AI Explanation Synthesis', () => {
    it('produces plain-language threat explanations with fallback resilience', async () => {
      const result = await scanner.scanText('URGENT: Verify your bank password now or your account will be frozen permanently!');
      expect(result.aiExplanation).toBeDefined();
      expect(result.aiExplanation?.headline.length).toBeGreaterThan(0);
      expect(result.aiExplanation?.summaryParagraph.length).toBeGreaterThan(10);
      expect(['LOCAL_MODEL', 'DETERMINISTIC_FALLBACK', 'SANITIZED']).toContain(result.aiExplanation?.inferenceStatus);
    });

    it('honors configured reading grade level preferences without runtime failure', async () => {
      scanner.setPreferences({ cognitiveReadingGrade: 8 });
      const result = await scanner.scanUrl('http://10.0.0.1/fake-bank/login');
      expect(result.aiExplanation).toBeDefined();
      expect(result.aiExplanation?.recommendedSteps.length).toBeGreaterThan(0);
    });
  });
});
