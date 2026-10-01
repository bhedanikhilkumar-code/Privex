import { describe, it, expect } from 'vitest';
import { TextAnalyzer } from '../../analyzers/text-analyzer';

describe('TextAnalyzer Hardening & False Positive Shields (Phase 2)', () => {
  const analyzer = new TextAnalyzer();

  it('should detect postal delivery fee scams (USPS / FedEx parcel detained)', () => {
    const text = 'USPS: Your package was detained due to an incomplete address. Please pay redelivery fee at usps-redelivery.link';
    const res = analyzer.analyze(text);
    expect(res.indicators).toContain('delivery-fee-scam');
    expect(res.indicators).toContain('embedded-link');
    expect(res.authorityImpersonationMarkers).toContain('POSTAL_SERVICE');
    expect(res.riskScore).toBeGreaterThanOrEqual(80);
  });

  it('should detect fake tech support auto-renewal invoice fraud', () => {
    const text = 'Geek Squad: Your subscription auto-renewal of $399.99 has been charged. If you did not authorize this, call our support at 1-800-555-0199 immediately.';
    const res = analyzer.analyze(text);
    expect(res.indicators).toContain('tech-support-invoice-scam');
    expect(res.indicators).toContain('phone-number');
    expect(res.riskScore).toBeGreaterThanOrEqual(80);
  });

  it('should detect cryptocurrency recovery / high-yield investment scams', () => {
    const text = 'Guaranteed returns: Our certified recovery agent has recovered your lost crypto. Send 0.05 Bitcoin to release your funds.';
    const res = analyzer.analyze(text);
    expect(res.indicators).toContain('crypto-recovery-scam');
    expect(res.paymentExtortionDetected).toBe(true);
    expect(res.riskScore).toBeGreaterThanOrEqual(85);
  });

  it('should strip zero-width characters and detect hidden keywords', () => {
    // 'bitcoin' obfuscated with zero-width spaces: 'b\u200Bi\u200Ct\u200Dc\u200Bo\u200Ci\u200Dn'
    const obfuscated = 'Unlock your files by sending b\u200Bi\u200Ct\u200Dc\u200Bo\u200Ci\u200Dn immediately';
    const res = analyzer.analyze(obfuscated);
    expect(res.indicators).toContain('cryptocurrency');
    expect(res.paymentExtortionDetected).toBe(true);
  });

  it('should clamp input text at 10,000 characters without memory issues', () => {
    const hugeText = 'Hello world! ' + 'urgent '.repeat(3000);
    const res = analyzer.analyze(hugeText);
    expect(res.indicators).toContain('text-clamped');
    expect(res.riskScore).toBeGreaterThan(0);
  });

  it('should safely allow legitimate 2FA OTP security verification messages (False Positive Shield)', () => {
    const apple2FA = 'Your Apple ID verification code is 849201. Do not share this code with anyone.';
    const appleRes = analyzer.analyze(apple2FA);
    expect(appleRes.riskScore).toBe(0);
    expect(appleRes.indicators.length).toBe(0);

    const google2FA = 'Google verification code: G-392817. Never give this code to anyone.';
    const googleRes = analyzer.analyze(google2FA);
    expect(googleRes.riskScore).toBe(0);
  });

  it('should safely allow benign purchase receipts and shipping notifications', () => {
    const receipt = 'Your transaction of $14.50 at Starbucks Coffee was approved on your debit card.';
    const res = analyzer.analyze(receipt);
    expect(res.riskScore).toBe(0);

    const delivered = 'Your Amazon order #112-9481923 has been delivered to your front door.';
    const delivRes = analyzer.analyze(delivered);
    expect(delivRes.riskScore).toBe(0);
  });

  it('should return canonical Subsystem 3 interface fields', () => {
    const sample = 'Urgent: Wire transfer of $500 required to avoid arrest by the IRS. Visit http://irs-pay.tk';
    const res = analyzer.analyze(sample);
    expect(typeof res.urgencyScore).toBe('number');
    expect(res.paymentExtortionDetected).toBe(true);
    expect(Array.isArray(res.cryptocurrencyAddresses)).toBe(true);
    expect(res.extractedUrls).toContain('http://irs-pay.tk');
    expect(res.authorityImpersonationMarkers).toContain('LAW_ENFORCEMENT');
    expect(Array.isArray(res.evidence)).toBe(true);
  });
});
