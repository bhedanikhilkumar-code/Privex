import { Evidence } from '../types';

export type TextAnalysisResult = Evidence[] & {
  riskScore: number;
  indicators: string[];
};

export class TextAnalyzer {
  public analyze(text: string): TextAnalysisResult {
    const evidenceList: Evidence[] = [];
    const indicators: string[] = [];

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      const empty = [] as unknown as TextAnalysisResult;
      empty.riskScore = 0;
      empty.indicators = [];
      return empty;
    }

    const lower = text.toLowerCase();

    // 1. Embedded Links
    if (/(https?:\/\/[^\s]+|bit\.ly\/[^\s]+)/i.test(text)) {
      indicators.push('embedded-link');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Embedded Link',
        description: 'Message contains an embedded URL or shortened link',
        weight: 25,
        confidence: 1.0,
        indicator: 'embedded-link'
      });
    }

    // 2. Phone Numbers
    if (/(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}/.test(text)) {
      indicators.push('phone-number');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Contact Phone Number',
        description: 'Contains a phone number for direct contact',
        weight: 15,
        confidence: 0.9,
        indicator: 'phone-number'
      });
    }

    // 3. Urgency Indicators & Account Pressure
    const urgencyKeywords = ['act now', 'immediately', 'suspended', 'urgent', 'action required', 'expires today'];
    const hasUrgencyWords = urgencyKeywords.some(k => lower.includes(k));
    const exclamationCount = (text.match(/!/g) || []).length;
    const allCapsWords = (text.match(/\b[A-Z]{3,}\b/g) || []).length;

    if (hasUrgencyWords || exclamationCount >= 3 || allCapsWords >= 2) {
      indicators.push('urgency');
      const isAccountUrgency = lower.includes('account') || lower.includes('suspended');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Urgent Tone',
        description: 'Text contains high urgency cues or pressure tactics',
        weight: isAccountUrgency ? 65 : 40,
        confidence: 0.9,
        indicator: 'urgency'
      });
    }

    // 4. Ransomware / Extortion & Scareware
    const isExtortion = /unlock\s+your\s+computer|ransom|files\s+encrypted|pay\s+to\s+decrypt/i.test(lower);
    if (isExtortion) {
      indicators.push('ransomware-extortion');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Ransomware Extortion',
        description: 'Threatens device lock or file encryption demanding payment',
        weight: 90,
        confidence: 0.95,
        indicator: 'ransomware-extortion'
      });
    }

    const isScareware = /trojan|infections|antivirus|passwords.*leaked|clean files|malware detected/i.test(lower);
    if (isScareware) {
      indicators.push('scareware-tech-support');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Scareware / Tech Support Threat',
        description: 'Fabricates device infections or credential leaks to pressure user into calling or paying',
        weight: 75,
        confidence: 0.9,
        indicator: 'scareware-tech-support'
      });
    }

    // 5. Law Enforcement & Criminal Threat Extortion
    const isLegalThreat = /police report|arrest warrant|illegal activity|irs|tax bill|marshals|criminal prosecution/i.test(lower);
    if (isLegalThreat) {
      indicators.push('legal-police-threat');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Law Enforcement Threat',
        description: 'Threatens arrest, police action, or criminal charges to coerce immediate compliance',
        weight: 85,
        confidence: 0.95,
        indicator: 'legal-police-threat'
      });
    }

    // 6. Cryptocurrency / Financial Scam
    const isCrypto = /bitcoin|btc|eth|crypto|wallet\s+[0-9a-zA-Z]{10,}/i.test(text);
    if (isCrypto) {
      indicators.push('cryptocurrency');
    }

    const isFinancial = /send\s+\$?\d+|wire\s+transfer|gift\s+card|send\s+money|new\s+account/i.test(lower);
    if (isCrypto || isFinancial) {
      indicators.push('financial-scam');
      const cryptoExtortionWeight = isCrypto && isExtortion ? 90 : (isCrypto ? 85 : 55);
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Financial Request',
        description: 'Requests payment, cryptocurrency, or untraceable funds transfer',
        weight: cryptoExtortionWeight,
        confidence: 0.9,
        indicator: 'financial-scam'
      });
    }

    // 7. Family Impersonation Scam ("Hi Mom / My phone broke")
    if ((lower.includes('hi mom') || lower.includes('hi dad') || lower.includes('my phone broke')) &&
        (lower.includes('send money') || lower.includes('new account') || lower.includes('transfer'))) {
      indicators.push('family-impersonation-scam');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Family Impersonation Scam',
        description: 'Common family impersonation pretext requesting funds to a new account',
        weight: 65,
        confidence: 0.9,
        indicator: 'family-impersonation-scam'
      });
    }

    // 8. Account Verification / Phishing
    if (/verify\s+(your\s+)?|restore\s+access|click\s+here\s+to\s+verify|update\s+account/i.test(lower)) {
      indicators.push('account-verification');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Account Verification Phishing',
        description: 'Requests credential or account verification',
        weight: 55,
        confidence: 0.85,
        indicator: 'account-verification'
      });
    }

    // 9. Brand / Government Impersonation
    const govTargets = ['irs', 'tax bill', 'arrest warrant', 'fbi', 'law enforcement'];
    if (govTargets.some(t => lower.includes(t))) {
      indicators.push('government-impersonation');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Government Impersonation',
        description: 'Impersonates government or tax agency accompanied by threats',
        weight: 85,
        confidence: 0.95,
        indicator: 'government-impersonation'
      });
    }

    const brandTargets = ['paypal', 'apple', 'microsoft', 'amazon', 'bank of america', 'chase', 'netflix', 'geek squad', 'norton'];
    if (brandTargets.some(t => lower.includes(t))) {
      indicators.push('brand-impersonation');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Brand Impersonation',
        description: 'Mentions prominent brand name commonly spoofed in phishing',
        weight: 50,
        confidence: 0.85,
        indicator: 'brand-impersonation'
      });
    }

    // 10. Lottery / Prize Scam
    if ((/won\s+\$|lottery|prize|claim/i.test(lower)) && (/congratulations|fee|claim/i.test(lower))) {
      indicators.push('lottery-scam');
      evidenceList.push({
        source: 'TEXT_ANALYZER',
        name: 'Lottery / Prize Scam',
        description: 'Claims unexpected monetary prize requiring fee or action',
        weight: 65,
        confidence: 0.9,
        indicator: 'lottery-scam'
      });
    }

    // Calculate composite risk score
    let score = 0;
    if (evidenceList.length > 0) {
      const maxWeight = Math.max(...evidenceList.map(e => e.weight));
      const bonus = (evidenceList.length - 1) * 8;
      score = Math.min(100, maxWeight + bonus);
    }

    const result = evidenceList as TextAnalysisResult;
    result.riskScore = score;
    result.indicators = indicators;

    return result;
  }
}
