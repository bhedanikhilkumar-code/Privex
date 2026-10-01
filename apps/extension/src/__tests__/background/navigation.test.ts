import { describe, it, expect, beforeEach } from 'vitest';
import { NavigationInterceptor } from '../../background/navigation-interceptor';
import { ExtensionStorage } from '../../shared/storage';
import { Verdict } from '@private-protection/core';

describe('NavigationInterceptor (Background Service Worker URL Protection)', () => {
  let interceptor: NavigationInterceptor;

  beforeEach(async () => {
    await ExtensionStorage.clearAllStorage();
    interceptor = new NavigationInterceptor();
  });

  it('allows safe and benign URLs immediately', async () => {
    const result = await interceptor.evaluateUrl(1, 'https://www.wikipedia.org/wiki/Computer_security');

    expect(result.action).toBe('ALLOW');
    expect(result.state.verdict).toBe(Verdict.ALLOW);
    expect(result.state.overallScore).toBeLessThan(30);
    expect(result.redirectUrl).toBeUndefined();
  });

  it('blocks dangerous phishing URLs and provides interstitial redirect URL', async () => {
    const dangerousUrl = 'http://192.168.1.100/paypal/security/login.php';
    const result = await interceptor.evaluateUrl(2, dangerousUrl);

    expect(result.action).toBe('BLOCK');
    expect(result.state.verdict).toBe(Verdict.DANGEROUS);
    expect(result.state.overallScore).toBeGreaterThanOrEqual(85);
    expect(result.redirectUrl).toBeDefined();
    expect(result.redirectUrl).toContain('interstitial.html');
    expect(result.redirectUrl).toContain('tabId=2');
  });

  it('warns on suspicious URLs with brand typosquatting', async () => {
    const typosquatUrl = 'http://paypa1-account-verify.buzz/login';
    const result = await interceptor.evaluateUrl(3, typosquatUrl);

    expect(['WARN', 'BLOCK']).toContain(result.action);
    expect([Verdict.SUSPICIOUS, Verdict.DANGEROUS]).toContain(result.state.verdict);
    expect(result.redirectUrl).toBeDefined();
  });

  it('ignores internal browser protocols (chrome://, about:, extension:)', async () => {
    const internalUrl = 'chrome://settings/';
    const result = await interceptor.evaluateUrl(4, internalUrl);

    expect(result.action).toBe('ALLOW');
    expect(result.state.isRestrictedUrl).toBe(true);
    expect(result.state.overallScore).toBe(0);
  });

  it('honors user custom allowlist settings', async () => {
    const internalServer = 'http://internal-test-server.corp.local/login';
    await ExtensionStorage.saveSettings({
      enabled: true,
      readingGrade: 6,
      allowlistDomains: ['internal-test-server.corp.local'],
      showShadowDomBanners: true,
      frictionGateDurationSec: 5
    });

    const result = await interceptor.evaluateUrl(5, internalServer);
    expect(result.action).toBe('ALLOW');
    expect(result.state.threatCategory).toBe('CUSTOM_ALLOWLIST');
    expect(result.state.overridden).toBe(true);
  });

  it('respects protection disabled state in settings', async () => {
    await ExtensionStorage.saveSettings({
      enabled: false,
      readingGrade: 6,
      allowlistDomains: [],
      showShadowDomBanners: false,
      frictionGateDurationSec: 5
    });

    const dangerousUrl = 'http://192.168.1.100/login';
    const result = await interceptor.evaluateUrl(6, dangerousUrl);
    expect(result.action).toBe('ALLOW');
    expect(result.state.threatCategory).toBe('PROTECTION_DISABLED');
  });

  it('respects tab-specific user overrides', async () => {
    const dangerousUrl = 'http://192.168.1.100/login.php';
    // Initial evaluation blocks
    await interceptor.evaluateUrl(7, dangerousUrl);

    // User explicitly overrides
    const state = await ExtensionStorage.getTabState(7);
    expect(state).not.toBeNull();
    state!.overridden = true;
    await ExtensionStorage.setTabState(7, state!);

    // Re-evaluating same URL allows navigation
    const result2 = await interceptor.evaluateUrl(7, dangerousUrl);
    expect(result2.action).toBe('ALLOW');
  });
});
