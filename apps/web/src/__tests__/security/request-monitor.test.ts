import { describe, it, expect, beforeEach } from 'vitest';
import {
  sanitizeRequestUrl,
  classifyRequestDestination,
  NetworkRequestMonitor
} from '../../lib/security/request-monitor';
import { securityEventManager } from '../../lib/security/security-events';

describe('Network Request Security Monitor & URL Sanitizer', () => {
  beforeEach(() => {
    securityEventManager.clearAllEvents();
  });

  it('redacts sensitive query tokens and secrets from URLs', () => {
    const raw = 'https://api.example.com/v1/auth?token=superSecret123&user=john&apiKey=key999';
    const { sanitizedUrl, domain } = sanitizeRequestUrl(raw);

    expect(sanitizedUrl).toContain('token=%5BREDACTED%5D');
    expect(sanitizedUrl).toContain('apiKey=%5BREDACTED%5D');
    expect(sanitizedUrl).toContain('user=john');
    expect(domain).toBe('api.example.com');
  });

  it('classifies first-party destinations accurately', () => {
    const res = classifyRequestDestination('localhost', 'localhost');
    expect(res.destinationType).toBe('FIRST_PARTY');
    expect(res.riskLevel).toBe('SAFE');

    const sub = classifyRequestDestination('api.privateprotection.com', 'privateprotection.com');
    expect(sub.destinationType).toBe('FIRST_PARTY');
  });

  it('classifies third-party destinations without labeling them malicious', () => {
    const res = classifyRequestDestination('cdnjs.cloudflare.com', 'privateprotection.com');
    expect(res.destinationType).toBe('THIRD_PARTY');
    expect(res.riskLevel).toBe('SAFE');
    expect(res.reason).toContain('third-party');
  });

  it('detects numeric IP destinations as suspicious', () => {
    const res = classifyRequestDestination('192.168.1.55', 'localhost');
    expect(res.destinationType).toBe('UNKNOWN_SUSPICIOUS');
    expect(res.riskLevel).toBe('SUSPICIOUS');
  });

  it('detects high-abuse top-level domains as suspicious', () => {
    const res = classifyRequestDestination('free-login-verify.top', 'localhost');
    expect(res.destinationType).toBe('UNKNOWN_SUSPICIOUS');
    expect(res.riskLevel).toBe('SUSPICIOUS');
  });

  it('detects punycode homograph domains as warning', () => {
    const res = classifyRequestDestination('xn--apple-43d.com', 'localhost');
    expect(res.destinationType).toBe('UNKNOWN_SUSPICIOUS');
    expect(res.riskLevel).toBe('WARNING');
  });

  it('records requests in rolling history and prunes oldest entries', () => {
    const monitor = NetworkRequestMonitor.getInstance({ maxHistorySize: 5 });
    monitor.clearHistory();

    for (let i = 1; i <= 8; i++) {
      monitor.recordRequest({
        url: `https://example.com/item/${i}`,
        method: 'GET'
      });
    }

    const history = monitor.getHistory();
    expect(history.length).toBe(5);
    expect(history[0].url).toContain('item/8');
  });

  it('triggers HIGH_REQUEST_ACTIVITY alert when burst threshold is exceeded', () => {
    const monitor = NetworkRequestMonitor.getInstance({
      maxHistorySize: 100,
      requestOverloadThreshold: 10,
      timeWindowMs: 5000
    });
    monitor.clearHistory();
    securityEventManager.clearAllEvents();

    for (let i = 0; i < 12; i++) {
      monitor.recordRequest({
        url: 'https://overload-test.com/api/ping',
        method: 'POST'
      });
    }

    const events = securityEventManager.getEvents();
    const overloadEvent = events.find((e) => e.type === 'HIGH_REQUEST_ACTIVITY');
    expect(overloadEvent).toBeDefined();
    expect(overloadEvent?.domain).toBe('overload-test.com');
    expect(overloadEvent?.severity).toBe('medium');
  });
});
