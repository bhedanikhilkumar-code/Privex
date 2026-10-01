import { describe, it, expect } from 'vitest';
import { MobileSecurityAdapter } from '../../adapters/mobile-security-adapter';
import { Verdict, SeverityLevel } from '@private-protection/core';

describe('MobileSecurityAdapter Integration & Core Re-use', () => {
  const adapter = new MobileSecurityAdapter();

  it('scans a safe URL and returns an ALLOW verdict with zero friction', async () => {
    const result = await adapter.scanUrl('https://example.com');
    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.overallScore).toBeLessThan(30);
    expect(result.targetType).toBe('URL');
    expect(result.executionTimeMs).toBeGreaterThan(0);
    expect(result.recommendation.bypassPermitted).toBe(true);
  });

  it('scans a deceptive IP phish URL and returns a DANGEROUS verdict with high severity', async () => {
    const result = await adapter.scanUrl('http://192.168.1.100/login.php');
    expect(result.verdict).toBe(Verdict.DANGEROUS);
    expect(result.overallScore).toBeGreaterThanOrEqual(70);
    expect(result.severity).toBe(SeverityLevel.CRITICAL);
    expect(result.aiExplanation).toBeDefined();
    expect(result.aiExplanation?.headline).toBeDefined();
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it('respects custom domain allowlist and returns immediate bypass result', async () => {
    const result = await adapter.scanUrl('http://192.168.1.100/login.php', 6, ['192.168.1.100']);
    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.overallScore).toBe(0);
    expect(result.threatCategory).toBe('USER_ALLOWLIST');
  });

  it('enforces maximum URL byte limits', async () => {
    const hugeUrl = 'https://example.com/' + 'a'.repeat(2500);
    await expect(adapter.scanUrl(hugeUrl)).rejects.toThrow(/URL_TOO_LONG/);
  });

  it('scans a suspicious urgency message and returns SCAM indicators', async () => {
    const text = 'URGENT: Your account will be locked within 1 hour! Send 0.1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately.';
    const result = await adapter.scanText(text, 6);
    expect(result.overallScore).toBeGreaterThanOrEqual(50);
    expect(result.targetType).toBe('TEXT');
    expect(result.aiExplanation).toBeDefined();
  });

  it('scans safe benign message text and returns an ALLOW verdict', async () => {
    const text = 'Hey, what time are we meeting for lunch today? Let me know!';
    const result = await adapter.scanText(text, 6);
    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.overallScore).toBeLessThan(30);
  });

  it('enforces maximum text character limits', async () => {
    const hugeText = 'Hello '.repeat(3000);
    await expect(adapter.scanText(hugeText)).rejects.toThrow(/TEXT_TOO_LONG/);
  });
});
