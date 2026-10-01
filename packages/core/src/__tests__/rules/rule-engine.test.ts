import { describe, it, expect, beforeEach } from 'vitest';
import { RuleEngine } from '../../rules/rule-engine';

describe('RuleEngine', () => {
  let ruleEngine: RuleEngine;

  beforeEach(() => {
    ruleEngine = new RuleEngine();
  });

  describe('URL Rules', () => {
    it('should trigger on known phishing URLs (IP addresses)', () => {
      const result = ruleEngine.evaluateUrl('http://192.168.1.1/login');
      expect(result.triggered).toBe(true);
      expect(result.matches.some(m => m.ruleId === 'url-ip-based')).toBe(true);
    });

    it('should trigger on suspicious TLDs', () => {
      const result = ruleEngine.evaluateUrl('http://freemoney.top/bonus');
      expect(result.triggered).toBe(true);
      expect(result.matches.some(m => m.ruleId === 'url-suspicious-tld')).toBe(true);
    });

    it('should not trigger on clean URLs', () => {
      const result = ruleEngine.evaluateUrl('https://www.google.com/search?q=test');
      expect(result.triggered).toBe(false);
      expect(result.matches.length).toBe(0);
    });
  });

  describe('Text Rules', () => {
    it('should trigger on scam text with urgency', () => {
      const result = ruleEngine.evaluateText('Act NOW or your account will be SUSPENDED!!!');
      expect(result.triggered).toBe(true);
      expect(result.matches.some(m => m.ruleId === 'text-urgency')).toBe(true);
    });

    it('should trigger on financial scam keywords', () => {
      const result = ruleEngine.evaluateText('Send $500 in bitcoin to claim your prize');
      expect(result.triggered).toBe(true);
      expect(result.matches.some(m => m.ruleId === 'text-financial-scam')).toBe(true);
    });

    it('should not trigger on clean text', () => {
      const result = ruleEngine.evaluateText('Hey, are we still on for lunch tomorrow at 12?');
      expect(result.triggered).toBe(false);
      expect(result.matches.length).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty input gracefully', () => {
      expect(ruleEngine.evaluateUrl('').triggered).toBe(false);
      expect(ruleEngine.evaluateText('').triggered).toBe(false);
    });

    it('should handle null or undefined gracefully', () => {
      expect(ruleEngine.evaluateUrl(null as any).triggered).toBe(false);
      expect(ruleEngine.evaluateText(undefined as any).triggered).toBe(false);
    });

    it('should handle very long input', () => {
      const longText = 'a'.repeat(10000);
      expect(ruleEngine.evaluateText(longText).triggered).toBe(false);
    });

    it('should handle unicode input', () => {
      const result = ruleEngine.evaluateText('🚨 URGENŢ 🚨 Account sűspended! 💸💰');
      expect(result.triggered).toBe(true);
    });
  });
});
