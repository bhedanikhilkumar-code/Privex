import { describe, it, expect, beforeEach } from 'vitest';
import { MobileSecurityAdapter } from '../../adapters/mobile-security-adapter';
import { Verdict } from '@private-protection/core';

describe('Offline Parity Verification (Mobile Air-Gapped Operation)', () => {
  beforeEach(() => {
    // Simulate airplane mode / offline network interfaces
    Object.defineProperty(globalThis.navigator, 'onLine', {
      value: false,
      configurable: true
    });
  });

  it('executes full detection pipeline and generates plain-language AI explanation while offline', async () => {
    const adapter = new MobileSecurityAdapter();
    const result = await adapter.scanUrl('http://192.168.1.100/login');

    expect(result.verdict).toBe(Verdict.DANGEROUS);
    expect(result.overallScore).toBeGreaterThanOrEqual(70);
    expect(result.aiExplanation).toBeDefined();
    expect(result.aiExplanation?.headline).toBeDefined();
    expect(result.aiExplanation?.dangerFactors.length).toBeGreaterThan(0);
  });
});
