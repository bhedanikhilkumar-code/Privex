import { describe, it, expect, beforeEach } from 'vitest';
import { NavigationInterceptor } from '../../background/navigation-interceptor';
import { ExtensionStorage } from '../../shared/storage';
import { Verdict } from '@private-protection/core';

describe('Background Service Worker Lifecycle & Session Rehydration', () => {
  beforeEach(async () => {
    await ExtensionStorage.clearAllStorage();
  });

  it('preserves tab state across simulated service worker termination and restart', async () => {
    // 1. Initial Service Worker instance evaluates tab 10
    const worker1 = new NavigationInterceptor();
    await worker1.evaluateUrl(10, 'http://192.168.1.100/login.php');

    const stateBefore = await ExtensionStorage.getTabState(10);
    expect(stateBefore).not.toBeNull();
    expect(stateBefore?.verdict).toBe(Verdict.DANGEROUS);

    // 2. Simulate worker shutdown and restart with fresh instance
    const worker2 = new NavigationInterceptor();
    expect(worker2).toBeDefined();
    const stateAfter = await ExtensionStorage.getTabState(10);

    expect(stateAfter).not.toBeNull();
    expect(stateAfter?.tabId).toBe(10);
    expect(stateAfter?.verdict).toBe(Verdict.DANGEROUS);
    expect(stateAfter?.overallScore).toBe(stateBefore?.overallScore);
  });

  it('manages concurrent distinct states for multiple tabs', async () => {
    const worker = new NavigationInterceptor();

    // Tab 1: Safe
    await worker.evaluateUrl(1, 'https://www.google.com/search?q=test');
    // Tab 2: Phish
    await worker.evaluateUrl(2, 'http://192.168.1.50/account/login');
    // Tab 3: Restricted
    await worker.evaluateUrl(3, 'chrome://extensions');

    const state1 = await ExtensionStorage.getTabState(1);
    const state2 = await ExtensionStorage.getTabState(2);
    const state3 = await ExtensionStorage.getTabState(3);

    expect(state1?.verdict).toBe(Verdict.ALLOW);
    expect(state2?.verdict).toBe(Verdict.DANGEROUS);
    expect(state3?.isRestrictedUrl).toBe(true);
  });

  it('cleans up tab session data on tab close', async () => {
    const worker = new NavigationInterceptor();
    await worker.evaluateUrl(5, 'https://example.com');

    expect(await ExtensionStorage.getTabState(5)).not.toBeNull();

    // Tab closed
    await ExtensionStorage.clearTabState(5);
    expect(await ExtensionStorage.getTabState(5)).toBeNull();
  });
});
