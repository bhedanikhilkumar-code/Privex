import { Evidence } from '../types';

export type TextAnalysisResult = Evidence[] & {
  riskScore: number;
  indicators: string[];
  // Subsystem 3 Canonical Contract Fields
  urgencyScore: number;
  paymentExtortionDetected: boolean;
  cryptocurrencyAddresses: string[];
  extractedUrls: string[];
  authorityImpersonationMarkers: string[];
  evidence: Evidence[];
};

export class TextAnalyzer {
  public analyze(rawText: string): TextAnalysisResult {
    const evidenceList: Evidence[] = [];
    const indicators: string[] = [];
    const extractedUrls: string[] = [];
    const cryptoAddresses: string[] = [];
    const authorityMarkers: string[] = [];

    const buildResult = (score: number, urgency: number, paymentExtortion: boolean): TextAnalysisResult => {
      const res = [...evidenceList] as unknown as TextAnalysisResult;
      res.riskScore = score;
      res.indicators = indicators;
      res.urgencyScore = urgency;
      res.paymentExtortionDetected = paymentExtortion;
      res.cryptocurrencyAddresses = cryptoAddresses;
      res.extractedUrls = extractedUrls;
      res.authorityImpersonationMarkers = authorityMarkers;
      res.evidence = evidenceList;
      return res;
    };

    if (!rawText || typeof rawText !== 'string' || rawText.trim().length === 0) {
      return buildResult(0, 0, false);
    }

    // Input Clamping: Enforce 10,000 character maximum
    let text = rawText;
    if (text.length > 10000) {
      text = text.slice(0, 10000);
      indicators.push('text-clamped');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Text Clamped',
        description: 'Text was clamped to maximum allowed length of 10,000 characters',
        weight: 10,
        scoreContribution: 10,
        confidence: 1.0,
        indicator: 'text-clamped'
      });
    }

    // Unicode Normalization & Invisible/Zero-Width Character Stripping
    const cleanText = text
      .normalize('NFKD')
      .replace(/[\u200B-\u200D\uFEFF\u00AD\u202A-\u202E]/g, ''); // Strip zero-width and bidi override chars

    const lower = cleanText.toLowerCase();

    // 0. Extract URLs (schemed, www, or prominent TLDs)
    const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|[a-z0-9-]+\.(?:link|com|net|org|info|xyz|tk|cc|buzz|top|site)(?:\/[^\s<>"'{}|\\^`]*)?|bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+/gi;
    let urlMatch: RegExpExecArray | null;
    while ((urlMatch = urlRegex.exec(cleanText)) !== null) {
      extractedUrls.push(urlMatch[0]);
    }

    if (extractedUrls.length > 0) {
      indicators.push('embedded-link');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Embedded Link',
        description: `Message contains embedded link(s): ${extractedUrls.slice(0, 2).join(', ')}`,
        weight: 25,
        scoreContribution: 25,
        confidence: 1.0,
        indicator: 'embedded-link'
      });
    }

    // 1. Extract Phone Numbers
    const phoneRegex = /(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}/g;
    if (phoneRegex.test(cleanText)) {
      indicators.push('phone-number');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Contact Phone Number',
        description: 'Contains a phone number for direct contact',
        weight: 15,
        scoreContribution: 15,
        confidence: 0.9,
        indicator: 'phone-number'
      });
    }

    // 2. Benign Notification / 2FA Shield (False Positive Mitigation)
    const is2FA = /(?:verification|security|one-time|login)\s+code(?:\s+is)?[:\s]+\d{4,8}/i.test(cleanText) ||
                  /your\s+(?:google|apple|microsoft|bank|amazon)\s+code\s+is/i.test(lower);
    const isReceiptOrTransaction = /(?:transaction|charge|purchase)\s+of\s+\$\d+(?:\.\d{2})?\s+at\s+[a-z0-9\s]+/i.test(lower) ||
                                  /order\s+#[a-z0-9-]+\s+has\s+been\s+delivered/i.test(lower);
    const hasScamCallToAction = /click\s+here|urgent|suspended|wire\s+transfer|gift\s+card|bitcoin|arrest|tax\s+fraud/i.test(lower);

    if ((is2FA || isReceiptOrTransaction) && !hasScamCallToAction && extractedUrls.length === 0) {
      // Legitimate notification without suspicious calls to action
      return buildResult(0, 0, false);
    }

    // 3. Urgency Analysis
    const urgencyKeywords = [
      'act now', 'immediately', 'suspended', 'urgent', 'action required',
      'expires today', 'within 24 hours', 'final notice', 'time sensitive',
      'account suspended', 'account frozen'
    ];
    const matchedUrgency = urgencyKeywords.filter(k => lower.includes(k));
    const exclamationCount = (cleanText.match(/!/g) || []).length;
    const allCapsWords = (cleanText.match(/\b[A-Z]{3,}\b/g) || []).length;

    let urgencyScore = 0;
    if (matchedUrgency.length > 0 || exclamationCount >= 3 || allCapsWords >= 2) {
      urgencyScore = Math.min(100, 30 + matchedUrgency.length * 25 + (allCapsWords >= 2 ? 15 : 0));
      indicators.push('urgency');
      const isAccountUrgency = lower.includes('account') || lower.includes('suspended') || lower.includes('frozen');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Urgent Tone',
        description: 'Text contains high urgency cues or pressure tactics: ' + (matchedUrgency.join(', ') || 'exclamations/caps'),
        weight: isAccountUrgency ? 65 : 40,
        scoreContribution: isAccountUrgency ? 65 : 40,
        confidence: 0.9,
        indicator: 'urgency'
      });
    }

    // 4. Ransomware / Extortion & Scareware
    let paymentExtortionDetected = false;
    const isExtortion = /unlock\s+your\s+computer|ransom|files\s+encrypted|pay\s+to\s+decrypt|destroy\s+all\s+data/i.test(lower);
    if (isExtortion) {
      paymentExtortionDetected = true;
      indicators.push('ransomware-extortion');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Ransomware Extortion',
        description: 'Threatens device lock or file encryption demanding payment',
        weight: 90,
        scoreContribution: 90,
        confidence: 0.95,
        indicator: 'ransomware-extortion',
        isCriticalOverride: true
      });
    }

    const isScareware = /trojan|infections|antivirus|passwords.*leaked|clean files|malware detected|compromised system/i.test(lower);
    if (isScareware) {
      indicators.push('scareware-tech-support');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Scareware / Tech Support Threat',
        description: 'Fabricates device infections or credential leaks to coerce user',
        weight: 75,
        scoreContribution: 75,
        confidence: 0.9,
        indicator: 'scareware-tech-support'
      });
    }

    // 5. Tech Support & Invoice Auto-Renewal Scams (Geek Squad, Norton, McAfee invoice)
    const isInvoiceScam = /(?:invoice|auto-renewal|subscription\s+renewed|charged\s+\$\d{2,4})\b/i.test(lower) &&
                          /(?:geek squad|norton|mcafee|paypal|support|refund|call\s+(?:us|our)|cancel)/i.test(lower);
    if (isInvoiceScam) {
      indicators.push('tech-support-invoice-scam');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Fake Invoice / Tech Support Scam',
        description: 'Impersonates subscription invoice with bogus charge to trick user into calling support',
        weight: 80,
        scoreContribution: 80,
        confidence: 0.95,
        indicator: 'tech-support-invoice-scam'
      });
    }

    // 6. Law Enforcement & Criminal Threat Extortion
    const isLegalThreat = /police report|arrest warrant|illegal activity|irs|tax bill|marshals|criminal prosecution|subpoena/i.test(lower);
    if (isLegalThreat) {
      paymentExtortionDetected = true;
      indicators.push('legal-police-threat');
      authorityMarkers.push('LAW_ENFORCEMENT');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Law Enforcement Threat',
        description: 'Threatens arrest, police action, or criminal charges to coerce immediate compliance',
        weight: 85,
        scoreContribution: 85,
        confidence: 0.95,
        indicator: 'legal-police-threat'
      });
    }

    // 7. Delivery & Postal Impersonation Scams (USPS, FedEx, DHL, Package detained)
    const isDeliveryScam = /(?:usps|fedex|ups|dhl|postal|post|package|shipment|parcel)\b/i.test(lower) &&
                          /(?:detained|failed\s+delivery|incomplete\s+address|redelivery\s+fee|customs\s+fee|update\s+address)/i.test(lower);
    if (isDeliveryScam) {
      indicators.push('delivery-fee-scam');
      authorityMarkers.push('POSTAL_SERVICE');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Postal Delivery Scam',
        description: 'Impersonates delivery service demanding fee or address update to steal credentials/cards',
        weight: 80,
        scoreContribution: 80,
        confidence: 0.95,
        indicator: 'delivery-fee-scam'
      });
    }

    // 8. Cryptocurrency & Financial Fraud
    const isCrypto = /bitcoin|btc|eth|ethereum|crypto|usdt|wallet\s+[0-9a-zA-Z]{10,}/i.test(cleanText);
    if (isCrypto) {
      indicators.push('cryptocurrency');
      // Match typical BTC or ETH addresses
      const btcMatches = cleanText.match(/\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b/g);
      if (btcMatches) cryptoAddresses.push(...btcMatches);
    }

    const isFinancial = /send\s+\$?\d+|wire\s+transfer|gift\s+card|send\s+money|new\s+account|cash\s+app|zelle|venmo/i.test(lower);
    if (isCrypto || isFinancial) {
      indicators.push('financial-scam');
      paymentExtortionDetected = true;
      const cryptoExtortionWeight = isCrypto && isExtortion ? 90 : (isCrypto ? 85 : 55);
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Financial Request',
        description: 'Requests payment, cryptocurrency, or untraceable funds transfer',
        weight: cryptoExtortionWeight,
        scoreContribution: cryptoExtortionWeight,
        confidence: 0.9,
        indicator: 'financial-scam'
      });
    }

    // 9. Crypto Recovery & High-Yield Investment Scams
    const isCryptoInvestment = /(?:guaranteed\s+(?:returns|profit)|1000%\s+daily|recover\s+lost\s+crypto|funds\s+recovered)/i.test(lower) &&
                               (isCrypto || isFinancial);
    if (isCryptoInvestment) {
      indicators.push('crypto-recovery-scam');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Crypto Investment / Recovery Fraud',
        description: 'Prompts high-yield investment or fake asset recovery services',
        weight: 85,
        scoreContribution: 85,
        confidence: 0.9,
        indicator: 'crypto-recovery-scam'
      });
    }

    // 10. Family Impersonation Scam ("Hi Mom / My phone broke")
    if ((lower.includes('hi mom') || lower.includes('hi dad') || lower.includes('my phone broke')) &&
        (lower.includes('send money') || lower.includes('new account') || lower.includes('transfer') || lower.includes('help me'))) {
      indicators.push('family-impersonation-scam');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Family Impersonation Scam',
        description: 'Common family impersonation pretext requesting funds to a new account',
        weight: 65,
        scoreContribution: 65,
        confidence: 0.9,
        indicator: 'family-impersonation-scam'
      });
    }

    // 11. Account Verification / Phishing
    if (/verify\s+(?:your\s+)?|restore\s+access|click\s+here\s+to\s+verify|update\s+account|re-activate/i.test(lower)) {
      indicators.push('account-verification');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Account Verification Phishing',
        description: 'Requests credential or account verification',
        weight: 55,
        scoreContribution: 55,
        confidence: 0.85,
        indicator: 'account-verification'
      });
    }

    // 12. Brand / Government Impersonation
    const govTargets = ['irs', 'tax bill', 'arrest warrant', 'fbi', 'law enforcement', 'social security administration'];
    if (govTargets.some(t => lower.includes(t))) {
      indicators.push('government-impersonation');
      authorityMarkers.push('GOVERNMENT_AGENCY');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Government Impersonation',
        description: 'Impersonates government or tax agency accompanied by threats',
        weight: 85,
        scoreContribution: 85,
        confidence: 0.95,
        indicator: 'government-impersonation'
      });
    }

    const brandTargets = ['paypal', 'apple', 'microsoft', 'amazon', 'bank of america', 'chase', 'netflix', 'geek squad', 'norton'];
    if (brandTargets.some(t => lower.includes(t))) {
      indicators.push('brand-impersonation');
      authorityMarkers.push('COMMERCIAL_BRAND');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Brand Impersonation',
        description: 'Mentions prominent brand name commonly spoofed in phishing',
        weight: 50,
        scoreContribution: 50,
        confidence: 0.85,
        indicator: 'brand-impersonation'
      });
    }

    // 13. Lottery / Prize Scam
    if ((/won\s+\$|lottery|prize|claim/i.test(lower)) && (/congratulations|fee|claim|lucky/i.test(lower))) {
      indicators.push('lottery-scam');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Lottery / Prize Scam',
        description: 'Claims unexpected monetary prize requiring fee or action',
        weight: 65,
        scoreContribution: 65,
        confidence: 0.9,
        indicator: 'lottery-scam'
      });
    }

    // Composite risk calculation
    let score = 0;
    if (evidenceList.length > 0) {
      const maxWeight = Math.max(...evidenceList.map(e => e.weight));
      const bonus = (evidenceList.length - 1) * 8;
      score = Math.min(100, maxWeight + bonus);
    }

    return buildResult(score, urgencyScore, paymentExtortionDetected);
  }
}
