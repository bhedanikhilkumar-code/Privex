import { describe, it, expect } from 'vitest';
import {
  analyzePasswordSecurity,
  generateSecurePassword
} from '../../lib/security/password-security';

describe('Password Security & Entropy Analysis', () => {
  it('analyzes empty input safely without errors', () => {
    const res = analyzePasswordSecurity('');
    expect(res.score).toBe(0);
    expect(res.level).toBe('VERY WEAK');
    expect(res.criteria.length).toBe(6);
  });

  it('detects common breached passwords and rates them VERY WEAK', () => {
    const res = analyzePasswordSecurity('password');
    expect(res.isCommonPassword).toBe(true);
    expect(res.level).toBe('VERY WEAK');
    expect(res.score).toBeLessThanOrEqual(10);
  });

  it('detects sequential numeric passwords', () => {
    const res = analyzePasswordSecurity('12345678');
    expect(res.hasSequentialChars).toBe(true);
    expect(res.level).toBe('VERY WEAK');
  });

  it('rates weak combinations accordingly', () => {
    const res = analyzePasswordSecurity('Password123');
    expect(res.hasUppercase).toBe(true);
    expect(res.hasLowercase).toBe(true);
    expect(res.hasNumbers).toBe(true);
    expect(res.hasSpecial).toBe(false);
    expect(['WEAK', 'MEDIUM']).toContain(res.level);
  });

  it('rates mixed alphanumeric and special character passwords as MEDIUM or STRONG', () => {
    const res = analyzePasswordSecurity('Password@123');
    expect(res.hasSpecial).toBe(true);
    expect(res.score).toBeGreaterThanOrEqual(45);
  });

  it('rates long, high-entropy passwords as VERY STRONG', () => {
    const res = analyzePasswordSecurity('VeryStrongRandomPassword!2026');
    expect(res.level).toBe('VERY STRONG');
    expect(res.score).toBeGreaterThanOrEqual(85);
    expect(res.criteria.every((c) => c.met)).toBe(true);
  });

  it('calculates non-zero Shannon entropy for non-empty passwords', () => {
    const res = analyzePasswordSecurity('Tr0ub4dor&3');
    expect(res.estimatedEntropyBits).toBeGreaterThan(30);
  });
});

describe('Cryptographically Secure Password Generator', () => {
  it('generates passwords of requested lengths', () => {
    const lengths = [8, 12, 16, 20, 24];
    for (const len of lengths) {
      const pwd = generateSecurePassword({
        length: len,
        useUppercase: true,
        useLowercase: true,
        useNumbers: true,
        useSpecial: true,
        avoidAmbiguous: false,
        avoidSimilar: false
      });
      expect(pwd.length).toBe(len);
    }
  });

  it('respects character set constraints', () => {
    const numOnly = generateSecurePassword({
      length: 12,
      useUppercase: false,
      useLowercase: false,
      useNumbers: true,
      useSpecial: false,
      avoidAmbiguous: false,
      avoidSimilar: false
    });
    expect(/^\d+$/.test(numOnly)).toBe(true);

    const alphaOnly = generateSecurePassword({
      length: 14,
      useUppercase: true,
      useLowercase: true,
      useNumbers: false,
      useSpecial: false,
      avoidAmbiguous: false,
      avoidSimilar: false
    });
    expect(/^[A-Za-z]+$/.test(alphaOnly)).toBe(true);
  });

  it('avoids similar characters when requested', () => {
    for (let i = 0; i < 5; i++) {
      const pwd = generateSecurePassword({
        length: 20,
        useUppercase: true,
        useLowercase: true,
        useNumbers: true,
        useSpecial: true,
        avoidAmbiguous: false,
        avoidSimilar: true
      });
      expect(pwd).not.toMatch(/[IOlo01]/);
    }
  });

  it('avoids ambiguous characters when requested', () => {
    for (let i = 0; i < 5; i++) {
      const pwd = generateSecurePassword({
        length: 20,
        useUppercase: true,
        useLowercase: true,
        useNumbers: true,
        useSpecial: true,
        avoidAmbiguous: true,
        avoidSimilar: false
      });
      expect(pwd).not.toMatch(/[{}\[\]()\/\\'"`~,;:.<>]/);
    }
  });
});
