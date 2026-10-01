import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { NavigationInterceptor } from '../../background/navigation-interceptor';
import { Verdict } from '@private-protection/core';

describe('Offline Parity (Air-Gapped Real-Time Browser Extension)', () => {
  let origOnLine: boolean;

  beforeEach(() => {
    origOnLine = navigator.onLine;
    Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });
  });

  afterEach(() => {
    Object.defineProperty(navigator, 'onLine', { value: origOnLine, configurable: true });
  });

  it('runs complete URL analysis pipeline offline with zero degradation', async () => {
    expect(navigator.onLine).toBe(false);

    const interceptor = new NavigationInterceptor();

    // 1. Phishing check
    const phish = await interceptor.evaluateUrl(101, 'http://192.168.1.100/login');
    expect(phish.action).toBe('BLOCK');
    expect(phish.state.verdict).toBe(Verdict.DANGEROUS);

    // 2. Benign check
    const benign = await interceptor.evaluateUrl(102, 'https://www.wikipedia.org');
    expect(benign.action).toBe('ALLOW');
    expect(benign.state.verdict).toBe(Verdict.ALLOW);
  });
});
