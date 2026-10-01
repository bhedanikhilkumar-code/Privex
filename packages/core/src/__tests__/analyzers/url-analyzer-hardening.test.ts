import { describe, it, expect } from 'vitest';
import { URLAnalyzer } from '../../analyzers/url-analyzer';

describe('URLAnalyzer Hardening (Phase 2)', () => {
  const analyzer = new URLAnalyzer();

  it('should detect standard and bracketed IPv6 hostnames', () => {
    const res = analyzer.analyze('http://[2001:db8::1]/path');
    expect(res.isValid).toBe(true);
    expect(res.ipBasedHost).toBe(true);
    expect(res.indicators).toContain('ip-based-host');
  });

  it('should detect private IP addresses, localhost, and cloud metadata SSRF vectors', () => {
    // Localhost
    const localhostRes = analyzer.analyze('http://localhost:8080/admin');
    expect(localhostRes.indicators).toContain('private-ip-ssrf');

    // RFC1918 Private IP
    const rfc1918Res = analyzer.analyze('http://192.168.1.1/router');
    expect(rfc1918Res.indicators).toContain('private-ip-ssrf');

    // Cloud Metadata link-local SSRF
    const metadataRes = analyzer.analyze('http://169.254.169.254/latest/meta-data/');
    expect(metadataRes.indicators).toContain('private-ip-ssrf');
    expect(metadataRes.riskScore).toBeGreaterThanOrEqual(75);
  });

  it('should detect abnormal and dangerous port numbers', () => {
    // Dangerous SSH port
    const dangerousPortRes = analyzer.analyze('http://example.com:22/payload');
    expect(dangerousPortRes.indicators).toContain('abnormal-port');
    expect(dangerousPortRes.some(e => e.name === 'Dangerous Non-Web Port')).toBe(true);

    // Unusual web proxy port
    const altPortRes = analyzer.analyze('http://phishing-site.xyz:8080/login');
    expect(altPortRes.indicators).toContain('abnormal-port');
  });

  it('should detect mixed-script Unicode homoglyphs imitating brands', () => {
    // 'pаypal.com' with Cyrillic 'а' (\u0430) mixed with Latin letters
    const homoglyphUrl = 'https://p\u0430ypal.com/signin';
    const res = analyzer.analyze(homoglyphUrl);
    expect(res.indicators).toContain('punycode-domain');
    expect(res.riskScore).toBeGreaterThanOrEqual(80);
  });

  it('should detect nested double percent-encoding evasion', () => {
    const res = analyzer.analyze('http://example.com/%252e%252e/admin');
    expect(res.indicators).toContain('double-percent-encoding');
  });

  it('should enforce 2,048-byte input clamping without memory exhaustion', () => {
    const hugeUrl = 'https://example.com/' + 'a'.repeat(5000);
    const res = analyzer.analyze(hugeUrl);
    expect(res.isValid).toBe(false);
    expect(res.indicators).toContain('payload-clamped');
    expect(res.riskScore).toBe(30);
  });

  it('should return canonical Subsystem 2 interface fields', () => {
    const res = analyzer.analyze('https://paypal.com/home');
    expect(res.normalizedUrl).toBeDefined();
    expect(res.canonicalHost).toBe('paypal.com');
    expect(res.punycodeDecodedHost).toBe('paypal.com');
    expect(typeof res.entropy).toBe('number');
    expect(typeof res.subdomainDepth).toBe('number');
    expect(typeof res.suspiciousTld).toBe('boolean');
    expect(typeof res.ipBasedHost).toBe('boolean');
    expect(Array.isArray(res.evidence)).toBe(true);
  });
});
