import { describe, it, expect, beforeEach } from 'vitest';
import { UrlAnalyzer } from '../../analyzers/url-analyzer';

describe('UrlAnalyzer', () => {
  let analyzer: UrlAnalyzer;

  beforeEach(() => {
    analyzer = new UrlAnalyzer();
  });

  it('should classify normal safe URLs as low risk', () => {
    const result = analyzer.analyze('https://github.com/microsoft/vscode');
    expect(result.riskScore).toBeLessThan(30);
  });

  it('should detect IP-based URLs', () => {
    const result = analyzer.analyze('http://10.0.0.1/admin');
    expect(result.indicators).toContain('ip-based-host');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
  });

  it('should detect typosquatting', () => {
    const result = analyzer.analyze('https://www.g00gle.com');
    expect(result.indicators).toContain('typosquatting');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
  });

  it('should detect suspicious TLDs', () => {
    const result = analyzer.analyze('http://update.win.xyz');
    expect(result.indicators).toContain('suspicious-tld');
  });

  it('should detect URL shorteners', () => {
    const result = analyzer.analyze('https://bit.ly/3xyz789');
    expect(result.indicators).toContain('url-shortener');
  });

  it('should flag URLs with @ symbols (credential inclusion)', () => {
    const result = analyzer.analyze('http://google.com-update@192.168.1.1/login');
    expect(result.indicators).toContain('credentials-in-url');
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
  });

  it('should detect Punycode/IDN domains', () => {
    const result = analyzer.analyze('https://www.xn--googl-0qa.com');
    expect(result.indicators).toContain('punycode-domain');
  });

  it('should flag HTTP vs HTTPS', () => {
    const httpResult = analyzer.analyze('http://example.com');
    const httpsResult = analyzer.analyze('https://example.com');
    expect(httpResult.riskScore).toBeGreaterThan(httpsResult.riskScore);
  });

  it('should calculate subdomain depth', () => {
    const result = analyzer.analyze('https://a.b.c.d.e.example.com');
    expect(result.indicators).toContain('excessive-subdomains');
  });

  it('should evaluate entropy calculation accuracy', () => {
    const result = analyzer.analyze('https://example.com/zxcvbnmasdfghjklqwertyuiop');
    expect(result.indicators).toContain('high-entropy-path');
  });

  it('should handle malformed URLs gracefully', () => {
    const result = analyzer.analyze('not-a-url');
    expect(result.riskScore).toBeLessThan(30);
    expect(result.isValid).toBe(false);
  });

  it('should handle edge cases', () => {
    expect(analyzer.analyze('').isValid).toBe(false);
    expect(analyzer.analyze('http://').isValid).toBe(false);
    expect(analyzer.analyze('a'.repeat(2000)).isValid).toBe(false);
  });
});
