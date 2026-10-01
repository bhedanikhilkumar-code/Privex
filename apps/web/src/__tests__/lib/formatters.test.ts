import { describe, it, expect } from 'vitest';
import {
  formatRiskScore,
  formatVerdict,
  formatSeverity,
  getVerdictVisuals,
  escapeHtml,
  truncateText
} from '../../lib/formatters';
import { Verdict, SeverityLevel } from '@private-protection/core';

describe('Formatters & Visual Helpers', () => {
  it('formats risk scores accurately into color categories', () => {
    expect(formatRiskScore(90).color).toBe('#ef4444');
    expect(formatRiskScore(75).color).toBe('#f97316');
    expect(formatRiskScore(55).color).toBe('#eab308');
    expect(formatRiskScore(30).color).toBe('#3b82f6');
    expect(formatRiskScore(10).color).toBe('#10b981');
  });

  it('formats verdicts correctly into human-readable strings', () => {
    expect(formatVerdict(Verdict.DANGEROUS)).toBe('Dangerous Threat');
    expect(formatVerdict(Verdict.SUSPICIOUS)).toBe('Suspicious Caution');
    expect(formatVerdict(Verdict.CAUTION)).toBe('Caution Advised');
    expect(formatVerdict(Verdict.ALLOW)).toBe('Safe / Allowed');
  });

  it('formats severity levels with proper labels', () => {
    expect(formatSeverity(SeverityLevel.CRITICAL)).toBe('Critical');
    expect(formatSeverity(SeverityLevel.HIGH)).toBe('High');
    expect(formatSeverity(SeverityLevel.MEDIUM)).toBe('Medium');
    expect(formatSeverity(SeverityLevel.LOW)).toBe('Low');
    expect(formatSeverity(SeverityLevel.NONE)).toBe('None');
  });

  it('provides verdict visual styling parameters', () => {
    const dangerousVisuals = getVerdictVisuals(Verdict.DANGEROUS);
    expect(dangerousVisuals.badgeBg).toBeDefined();
    expect(dangerousVisuals.borderColor).toBeDefined();
    expect(dangerousVisuals.label).toBe('DANGEROUS THREAT');

    const allowVisuals = getVerdictVisuals(Verdict.ALLOW);
    expect(allowVisuals.label).toBe('SAFE');
  });

  it('safely escapes HTML characters to prevent XSS injection in display templates', () => {
    const unsafe = '<script>alert("xss")</script>&foo="bar"\'test\'';
    const escaped = escapeHtml(unsafe);
    expect(escaped).not.toContain('<script>');
    expect(escaped).toContain('&lt;script&gt;');
    expect(escaped).toContain('&amp;');
    expect(escaped).toContain('&quot;');
    expect(escaped).toContain('&#39;');
  });

  it('safely truncates long text while preserving short strings', () => {
    expect(truncateText('hello', 10)).toBe('hello');
    expect(truncateText('abcdefghijklmnopqrstuvwxyz', 10)).toBe('abcdefg...');
  });
});
