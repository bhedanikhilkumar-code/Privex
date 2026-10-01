import { describe, it, expect, beforeEach } from 'vitest';
import { TextAnalyzer } from '../../analyzers/text-analyzer';

describe('TextAnalyzer', () => {
  let analyzer: TextAnalyzer;

  beforeEach(() => {
    analyzer = new TextAnalyzer();
  });

  it('should score normal conversational text low', () => {
    const result = analyzer.analyze('Hello, checking in on the project status. Let me know when you are free.');
    expect(result.riskScore).toBeLessThan(30);
  });

  it('should detect scam messages with urgency', () => {
    const result = analyzer.analyze('Act NOW or your account will be SUSPENDED!!! Please verify immediately.');
    expect(result.indicators).toContain('urgency');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
  });

  it('should detect financial scam text', () => {
    const result = analyzer.analyze('Send $500 in bitcoin to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to unlock your computer.');
    expect(result.indicators).toContain('financial-scam');
    expect(result.indicators).toContain('cryptocurrency');
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
  });

  it('should detect phishing text', () => {
    const result = analyzer.analyze('Click here to verify your PayPal account and restore access.');
    expect(result.indicators).toContain('account-verification');
    expect(result.indicators).toContain('brand-impersonation');
  });

  it('should detect IRS/government impersonation scams', () => {
    const result = analyzer.analyze('IRS ALERT: You have an unpaid tax bill. An arrest warrant has been issued. Call 555-0199 immediately.');
    expect(result.indicators).toContain('government-impersonation');
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
  });

  it('should detect prize/lottery scams', () => {
    const result = analyzer.analyze('CONGRATULATIONS! You have won $1,000,000 in the international lottery. Pay $50 processing fee to claim.');
    expect(result.indicators).toContain('lottery-scam');
  });

  it('should identify messages with embedded links', () => {
    const result = analyzer.analyze('Please review the document here: http://bit.ly/malicious');
    expect(result.indicators).toContain('embedded-link');
  });

  it('should identify messages with phone numbers', () => {
    const result = analyzer.analyze('Call tech support at 1-800-555-0199 for refund.');
    expect(result.indicators).toContain('phone-number');
  });

  it('should handle mixed legitimate and suspicious content', () => {
    const result = analyzer.analyze('Hi Mom, how are you? By the way, my phone broke, please send money to this new account: 123456789.');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
  });

  it('should handle edge cases', () => {
    expect(analyzer.analyze('').riskScore).toBe(0);
    expect(analyzer.analyze('Hello').riskScore).toBeLessThan(30);
    expect(analyzer.analyze('A'.repeat(5000)).riskScore).toBeLessThan(30);
  });
});
