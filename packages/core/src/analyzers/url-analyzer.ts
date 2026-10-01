import { Evidence } from '../types';
import { calculateEntropy, levenshteinDistance } from '../utils/crypto';

export interface URLFeatures {
  domainLength: number;
  pathLength: number;
  subdomainCount: number;
  isHttps: boolean;
  isIpAddress: boolean;
  entropy: number;
  levenshteinScores: Record<string, number>;
  dotsCount: number;
  digitsToLettersRatio: number;
}

export type URLAnalysisResult = Evidence[] & {
  riskScore: number;
  indicators: string[];
  isValid: boolean;
  features?: URLFeatures;
};

export class URLAnalyzer {
  private topBrands = ['paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix', 'chase', 'bankofamerica'];
  private suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click'];
  private shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly'];

  public analyze(urlInput: string): URLAnalysisResult {
    const evidenceList: Evidence[] = [];
    const indicators: string[] = [];

    if (!urlInput || typeof urlInput !== 'string' || urlInput.trim().length === 0 || urlInput.length > 1000) {
      const emptyResult = [] as unknown as URLAnalysisResult;
      emptyResult.riskScore = 0;
      emptyResult.indicators = [];
      emptyResult.isValid = false;
      return emptyResult;
    }

    let url: URL;
    try {
      if (!urlInput.includes('.') && !urlInput.includes(':') && !urlInput.includes('/')) {
        throw new Error('Not a valid domain or URL');
      }
      url = new URL(urlInput.startsWith('http://') || urlInput.startsWith('https://') ? urlInput : `http://${urlInput}`);
      if (!url.hostname || url.hostname.length === 0) {
        throw new Error('Missing hostname');
      }
    } catch {
      const invalidResult = [{
        source: 'URL_ANALYZER',
        name: 'Malformed URL',
        description: 'The URL provided could not be parsed properly',
        weight: 10,
        confidence: 1.0,
        indicator: 'malformed-url'
      }] as unknown as URLAnalysisResult;
      invalidResult.riskScore = 10;
      invalidResult.indicators = ['malformed-url'];
      invalidResult.isValid = false;
      return invalidResult;
    }

    const features = this.extractFeatures(url, urlInput);
    const lowerPath = url.pathname.toLowerCase();
    const isSensitivePath = /auth|login|signin|verify|account|claim|suspended|patch|billing|secure/i.test(lowerPath);

    // 1. IP address check
    if (features.isIpAddress) {
      indicators.push('ip-based-host');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'IP Address URL',
        description: 'URL uses an IP address host instead of a domain name',
        weight: 65,
        confidence: 0.95,
        indicator: 'ip-based-host'
      });
    }

    // 2. Suspicious TLD
    if (this.suspiciousTLDs.some(tld => url.hostname.endsWith(tld))) {
      indicators.push('suspicious-tld');
      const tldWeight = isSensitivePath || !features.isHttps ? 65 : 45;
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Suspicious TLD',
        description: 'Domain uses a top-level domain frequently abused in phishing',
        weight: tldWeight,
        confidence: 0.9,
        indicator: 'suspicious-tld'
      });
    }

    // 3. Shorteners
    if (this.shorteners.some(s => url.hostname.includes(s))) {
      indicators.push('url-shortener');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'URL Shortener',
        description: 'URL shortening service obscures destination',
        weight: 25,
        confidence: 0.9,
        indicator: 'url-shortener'
      });
    }

    // 4. Credentials in URL
    if (url.username || url.password || urlInput.replace(/^https?:\/\//, '').split('/')[0].includes('@')) {
      indicators.push('credentials-in-url');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Credentials in URL',
        description: 'URL contains an @ symbol to mask the true destination domain',
        weight: 85,
        confidence: 0.95,
        indicator: 'credentials-in-url'
      });
    }

    // 5. Punycode (IDN homograph attack)
    if (url.hostname.includes('xn--')) {
      indicators.push('punycode-domain');
      const punyWeight = isSensitivePath ? 75 : 50;
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Punycode Domain',
        description: 'Domain uses Punycode/IDN which can be used for homograph attacks',
        weight: punyWeight,
        confidence: 0.9,
        indicator: 'punycode-domain'
      });
    }

    // 6. Subdomain brand spoofing and excessive depth
    const domainParts = url.hostname.split('.');
    const rootDomain = domainParts.slice(-2).join('.');
    const subdomains = domainParts.slice(0, -2).join('.');

    const hasBrandInSubdomain = this.topBrands.some(brand =>
      subdomains.includes(brand) && !rootDomain.includes(brand)
    );

    if (hasBrandInSubdomain) {
      indicators.push('subdomain-brand-spoofing');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Subdomain Brand Spoofing',
        description: 'Subdomain contains trusted brand name to deceive users into false trust',
        weight: 80,
        confidence: 0.95,
        indicator: 'subdomain-brand-spoofing'
      });
    }

    if (features.subdomainCount >= 3) {
      indicators.push('excessive-subdomains');
      const depthWeight = features.subdomainCount >= 4 ? 65 : 35;
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Excessive Subdomains',
        description: 'More than 3 subdomain levels detected',
        weight: depthWeight,
        confidence: 0.85,
        indicator: 'excessive-subdomains'
      });
    }

    // 7. Path entropy
    const pathEntropy = calculateEntropy(url.pathname);
    if (url.pathname.length > 15 && pathEntropy > 3.8) {
      indicators.push('high-entropy-path');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'High Entropy Path',
        description: 'URL path has high randomness, typical of phishing tokens',
        weight: 30,
        confidence: 0.75,
        indicator: 'high-entropy-path'
      });
    }

    // 8. Typosquatting
    for (const [brand, distance] of Object.entries(features.levenshteinScores)) {
      if (distance > 0 && distance <= 2 && url.hostname !== `${brand}.com`) {
        indicators.push('typosquatting');
        evidenceList.push({
          source: 'URL_ANALYZER',
          name: 'Typosquatting Detected',
          description: `Domain is visually similar to a major brand: ${brand}`,
          weight: 85,
          confidence: 0.9,
          indicator: 'typosquatting'
        });
        break;
      }
    }

    // 9. HTTP vs HTTPS
    if (!features.isHttps) {
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Unencrypted Connection',
        description: 'URL uses unencrypted HTTP',
        weight: 15,
        confidence: 0.8,
        indicator: 'unencrypted-http'
      });
    }

    // Compute aggregated risk score for URL
    let totalScore = 0;
    if (evidenceList.length > 0) {
      const maxWeight = Math.max(...evidenceList.map(e => e.weight));
      const bonus = (evidenceList.length - 1) * 5;
      totalScore = Math.min(100, maxWeight + bonus);
    }

    const result = evidenceList as URLAnalysisResult;
    result.riskScore = totalScore;
    result.indicators = indicators;
    result.isValid = true;
    result.features = features;

    return result;
  }

  private extractFeatures(url: URL, rawInput: string): URLFeatures {
    const hostname = url.hostname;
    const isIpAddress = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/.test(hostname);
    const domainParts = hostname.split('.');

    let digitsCount = 0;
    let lettersCount = 0;
    for (const char of hostname) {
      if (/[0-9]/.test(char)) digitsCount++;
      else if (/[a-zA-Z]/.test(char)) lettersCount++;
    }

    const levenshteinScores: Record<string, number> = {};
    const primaryDomain = domainParts.length > 1 ? domainParts[domainParts.length - 2] : hostname;

    for (const brand of this.topBrands) {
      if (!isIpAddress) {
        levenshteinScores[brand] = levenshteinDistance(primaryDomain, brand);
      }
    }

    return {
      domainLength: hostname.length,
      pathLength: url.pathname.length,
      subdomainCount: Math.max(0, domainParts.length - 2),
      isHttps: rawInput.startsWith('https://'),
      isIpAddress,
      entropy: calculateEntropy(hostname),
      levenshteinScores,
      dotsCount: Math.max(0, domainParts.length - 1),
      digitsToLettersRatio: lettersCount > 0 ? digitsCount / lettersCount : digitsCount
    };
  }
}

export const UrlAnalyzer = URLAnalyzer;
