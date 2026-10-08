import { describe, it, expect, beforeEach, vi } from 'vitest';
import { WebShieldService } from '../../services/web-shield.service';

describe('WebShieldService (Phase T6 Mobile)', () => {
  let service: WebShieldService;

  beforeEach(() => {
    vi.restoreAllMocks();
    delete (window as any).AndroidBridge;
    service = WebShieldService.getInstance();
  });

  it('inspects a clean legitimate URL correctly in simulation', async () => {
    const report = await service.inspectUrl('https://example.com/about');
    expect(report.verdict).toBe('SAFE');
    expect(report.threatType).toBe('NONE');
    expect(report.riskScore).toBeLessThan(30);
  });

  it('detects dangerous schemes (javascript:, data:) as DANGEROUS', async () => {
    const jsReport = await service.inspectUrl('javascript:alert(1)');
    expect(jsReport.verdict).toBe('DANGEROUS');
    expect(jsReport.threatType).toBe('DANGEROUS_SCHEME');
    expect(jsReport.riskScore).toBeGreaterThanOrEqual(90);

    const dataReport = await service.inspectUrl('data:text/html,malicious');
    expect(dataReport.verdict).toBe('DANGEROUS');
    expect(dataReport.threatType).toBe('DANGEROUS_SCHEME');
  });

  it('flags verified malicious phishing domain in simulation', async () => {
    const report = await service.inspectUrl('https://phishing-bank-login.com/login');
    expect(report.verdict).toBe('DANGEROUS');
    expect(report.threatType).toBe('MALICIOUS_DOMAIN');
    expect(report.domain).toBe('phishing-bank-login.com');
  });

  it('analyzes redirect chains and marks dangerous if target is malicious', async () => {
    const safeChain = await service.inspectRedirectChain([
      'https://short.url/123',
      'https://legitimate.org/docs',
    ]);
    expect(safeChain.isDangerous).toBe(false);
    expect(safeChain.totalHops).toBe(2);

    const evilChain = await service.inspectRedirectChain([
      'https://short.url/promo',
      'https://intermediate-hop.net',
      'https://phishing-bank-login.com/steal',
    ]);
    expect(evilChain.isDangerous).toBe(true);
    expect(evilChain.totalHops).toBe(3);
  });

  it('honestly exposes Android capability matrix with Category E marked false', async () => {
    const status = await service.getStatus();
    expect(status.capabilities.categoryA_directAndroid).toBe(true);
    expect(status.capabilities.categoryB_browserIntegration).toBe(true);
    expect(status.capabilities.categoryC_userUrlSharing).toBe(true);
    expect(status.capabilities.categoryD_localVpnShield).toBe(true);

    // Crucial truthful capability constraint
    expect(status.capabilities.categoryE_systemWideBrowserHookWithoutVpn).toBe(false);
    expect(status.capabilities.categoryE_limitationExplanation).toContain('sandbox');
  });

  it('delegates to native AndroidBridge when present', async () => {
    const mockBridge = {
      inspectUrl: vi.fn().mockReturnValue(JSON.stringify({
        normalizedUrl: 'https://test.com',
        domain: 'test.com',
        scheme: 'https',
        riskScore: 0,
        verdict: 'SAFE',
        threatType: 'NONE',
        indicators: [],
        explanation: 'Native bridge confirmed safe',
      })),
      inspectRedirectChain: vi.fn().mockReturnValue(JSON.stringify({
        isDangerous: false,
        totalHops: 1,
        hops: [],
        initialUrl: 'https://test.com',
        finalUrl: 'https://test.com',
        reason: 'Clean',
      })),
      startWebShield: vi.fn().mockReturnValue(true),
      stopWebShield: vi.fn().mockReturnValue(true),
      getWebShieldStatus: vi.fn().mockReturnValue(JSON.stringify({
        isWebShieldActive: true,
        isAnotherVpnActive: false,
        totalDnsQueries: 42,
        blockedDnsQueries: 3,
        lastThreatTimestamp: 12345678,
        knownBlockedDomainsCount: 10,
        capabilities: {
          categoryA_directAndroid: true,
          categoryA_description: 'Native',
          categoryB_browserIntegration: true,
          categoryB_description: 'Native',
          categoryC_userUrlSharing: true,
          categoryC_description: 'Native',
          categoryD_localVpnShield: true,
          categoryD_description: 'Native',
          categoryE_systemWideBrowserHookWithoutVpn: false,
          categoryE_limitationExplanation: 'Sandbox',
        },
      })),
    };

    (window as any).AndroidBridge = mockBridge;

    const report = await service.inspectUrl('https://test.com');
    expect(mockBridge.inspectUrl).toHaveBeenCalledWith('https://test.com');
    expect(report.explanation).toBe('Native bridge confirmed safe');

    const started = await service.startWebShield();
    expect(mockBridge.startWebShield).toHaveBeenCalled();
    expect(started).toBe(true);

    const status = await service.getStatus();
    expect(mockBridge.getWebShieldStatus).toHaveBeenCalled();
    expect(status.isWebShieldActive).toBe(true);
    expect(status.totalDnsQueries).toBe(42);
  });
});
