import { describe, it, expect } from 'vitest';
import {
  escapeHtml,
  formatRiskScore,
  formatVerdict,
  formatSeverity,
  extractDomain,
  isRestrictedUrl
} from '../../shared/formatters';
import { Verdict, SeverityLevel } from '@private-protection/core';

describe('Shared Formatters & Helpers (Extension)', () => {
  it('escapes HTML special characters safely', () => {
    const raw = '<script>alert("xss")</script>&foo=\'bar\'';
    const escaped = escapeHtml(raw);

    expect(escaped).not.toContain('<script>');
    expect(escaped).toContain('&lt;script&gt;');
    expect(escaped).toContain('&amp;');
    expect(escaped).toContain('&quot;');
    expect(escaped).toContain('&#39;');
  });

  it('formats risk scores into color categories', () => {
    expect(formatRiskScore(90).color).toBe('#ef4444');
    expect(formatRiskScore(75).color).toBe('#f97316');
    expect(formatRiskScore(55).color).toBe('#eab308');
    expect(formatRiskScore(30).color).toBe('#3b82f6');
    expect(formatRiskScore(10).color).toBe('#10b981');
  });

  it('formats verdicts and severity levels', () => {
    expect(formatVerdict(Verdict.DANGEROUS)).toBe('DANGEROUS THREAT');
    expect(formatVerdict(Verdict.ALLOW)).toBe('SAFE / ALLOWED');
    expect(formatSeverity(SeverityLevel.CRITICAL)).toBe('Critical');
    expect(formatSeverity(SeverityLevel.NONE)).toBe('None');
  });

  it('extracts hostnames cleanly from URLs', () => {
    expect(extractDomain('https://sub.example.com/path?query=1')).toBe('sub.example.com');
    expect(extractDomain('http://192.168.1.1:8080/login')).toBe('192.168.1.1');
  });

  it('identifies restricted browser URLs', () => {
    expect(isRestrictedUrl('chrome://settings')).toBe(true);
    expect(isRestrictedUrl('about:blank')).toBe(true);
    expect(isRestrictedUrl('edge://flags')).toBe(true);
    expect(isRestrictedUrl('chrome-extension://abcdef/popup.html')).toBe(true);
    expect(isRestrictedUrl('https://google.com')).toBe(false);
  });
});
