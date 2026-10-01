import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ClientScanner } from '../../scanner/client-scanner';
import { Verdict, SeverityLevel } from '@private-protection/core';

describe('Offline Parity & Air-Gapped Scanner Capability', () => {
  let scanner: ClientScanner;
  let originalOnLine: boolean;

  beforeEach(() => {
    scanner = new ClientScanner();
    originalOnLine = navigator.onLine;

    // Simulate strict offline air-gapped state
    Object.defineProperty(navigator, 'onLine', {
      value: false,
      configurable: true,
      writable: true
    });
  });

  afterEach(() => {
    Object.defineProperty(navigator, 'onLine', {
      value: originalOnLine,
      configurable: true,
      writable: true
    });
  });

  it('runs complete URL phishing scan while completely offline', async () => {
    expect(navigator.onLine).toBe(false);

    const result = await scanner.scanUrl('http://192.168.1.1/paypal/login.php');

    expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
    expect(result.overallScore).toBeGreaterThanOrEqual(75);
    expect(result.severity).toBe(SeverityLevel.CRITICAL);
    expect(result.evidence.length).toBeGreaterThan(0);
    expect(result.aiExplanation?.headline).toBeDefined();
    expect(result.privacyGuarantee).toContain('100% processed on-device');
  });

  it('runs complete scam message classification while completely offline', async () => {
    expect(navigator.onLine).toBe(false);

    const scamMsg = 'URGENT: Transfer 1 Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or your files will be deleted!';
    const result = await scanner.scanText(scamMsg);

    expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
    expect(result.overallScore).toBeGreaterThanOrEqual(70);
    expect(result.aiExplanation?.summaryParagraph).toBeDefined();
  });

  it('allows safe content with zero degradation while offline', async () => {
    expect(navigator.onLine).toBe(false);

    const safeUrl = 'https://www.wikipedia.org';
    const result = await scanner.scanUrl(safeUrl);

    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.overallScore).toBeLessThan(30);
  });

  it('executes in sub-millisecond to low millisecond latency offline', async () => {
    expect(navigator.onLine).toBe(false);

    const start = performance.now();
    await scanner.scanUrl('https://benign-site.org');
    const elapsed = performance.now() - start;

    // Must execute locally without network timeouts or stalls
    expect(elapsed).toBeLessThan(100);
  });
});
