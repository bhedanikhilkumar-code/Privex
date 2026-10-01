import { Evidence } from '../types';
import { calculateEntropy, levenshteinDistance } from '../utils/crypto';

export interface URLFeatures {
  domainLength: number;
  pathLength: number;
  subdomainCount: number;
  isHttps: boolean;
  isIpAddress: boolean;
  isPrivateOrLocalhost: boolean;
  isAbnormalPort: boolean;
  port?: string;
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
  // Subsystem 2 Canonical Fields
  normalizedUrl: string;
  canonicalHost: string;
  punycodeDecodedHost: string;
  entropy: number;
  subdomainDepth: number;
  suspiciousTld: boolean;
  ipBasedHost: boolean;
  brandSpoofDistance?: { brand: string; distance: number };
  evidence: Evidence[];
};

export class URLAnalyzer {
  private topBrands = [
    'paypal',
    'google',
    'facebook',
    'microsoft',
    'apple',
    'amazon',
    'netflix',
    'chase',
    'bankofamerica',
    'wellsfargo',
    'coinbase',
    'binance',
    'instagram',
    'twitter',
    'telegram',
    'whatsapp'
  ];

  private suspiciousTLDs = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click',
    '.zip', '.mov', '.fit', '.surf', '.work', '.monster', '.country', '.stream', '.gdn', '.kim'
  ];

  private shorteners = [
    'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy', 'cutt.ly'
  ];

  private dangerousPorts = new Set(['21', '22', '23', '25', '110', '143', '6667']);
  private unusualWebPorts = new Set(['8080', '8443', '8888', '3128', '1337', '9000', '9090']);

  public analyze(urlInput: string): URLAnalysisResult {
    const evidenceList: Evidence[] = [];
    const indicators: string[] = [];

    // Helper to create empty or invalid response
    const buildResult = (
      isValid: boolean,
      score: number,
      inds: string[],
      normUrl: string = '',
      host: string = '',
      feat?: URLFeatures
    ): URLAnalysisResult => {
      const res = [...evidenceList] as unknown as URLAnalysisResult;
      res.riskScore = score;
      res.indicators = inds;
      res.isValid = isValid;
      res.features = feat;
      res.normalizedUrl = normUrl;
      res.canonicalHost = host;
      res.punycodeDecodedHost = host;
      res.entropy = feat?.entropy ?? 0;
      res.subdomainDepth = feat?.subdomainCount ?? 0;
      res.suspiciousTld = feat ? this.suspiciousTLDs.some(t => host.endsWith(t)) : false;
      res.ipBasedHost = feat?.isIpAddress ?? false;
      res.evidence = evidenceList;
      return res;
    };

    if (!urlInput || typeof urlInput !== 'string' || urlInput.trim().length === 0) {
      return buildResult(false, 0, []);
    }

    // Input Clamping: Enforce 2,048 byte limit as mandated by docs/INTERFACE_CONTRACTS.md
    if (Buffer.byteLength(urlInput, 'utf-8') > 2048) {
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Payload Clamped',
        description: 'URL length exceeds maximum safe scanning limit of 2,048 bytes',
        weight: 30,
        scoreContribution: 30,
        confidence: 1.0,
        indicator: 'payload-clamped'
      });
      return buildResult(false, 30, ['payload-clamped'], urlInput.slice(0, 2048));
    }

    let url: URL;
    let normalizedInput = urlInput.trim();

    // Check for double percent-encoding evasion
    if (/%25[0-9a-f]{2}/i.test(normalizedInput)) {
      indicators.push('double-percent-encoding');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Obfuscated URL Encoding',
        description: 'URL uses nested percent-encoding often used to bypass security filters',
        weight: 50,
        scoreContribution: 50,
        confidence: 0.9,
        indicator: 'double-percent-encoding'
      });
    }

    // Check for blob: URI scheme
    if (normalizedInput.toLowerCase().startsWith('blob:')) {
      indicators.push('url-blob-uri');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Blob URI Scheme',
        description: 'Blob URI used to execute or display untrusted in-memory content',
        weight: 85,
        scoreContribution: 85,
        confidence: 0.95,
        indicator: 'url-blob-uri'
      });
      return buildResult(true, 85, indicators, normalizedInput);
    }

    try {
      if (!normalizedInput.includes('.') && !normalizedInput.includes(':') && !normalizedInput.includes('/')) {
        throw new Error('Not a valid domain or URL');
      }
      url = new URL(
        normalizedInput.startsWith('http://') || normalizedInput.startsWith('https://')
          ? normalizedInput
          : `http://${normalizedInput}`
      );
      if (!url.hostname || url.hostname.length === 0) {
        throw new Error('Missing hostname');
      }
    } catch {
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Malformed URL',
        description: 'The URL provided could not be parsed properly',
        weight: 10,
        scoreContribution: 10,
        confidence: 1.0,
        indicator: 'malformed-url'
      });
      return buildResult(false, 10, ['malformed-url'], normalizedInput);
    }

    const features = this.extractFeatures(url, normalizedInput);
    const lowerPath = url.pathname.toLowerCase();
    const isSensitivePath = /auth|login|signin|verify|account|claim|suspended|patch|billing|secure|update/i.test(lowerPath);

    // 1. IP address check (IPv4, IPv6, hex, octal, dword)
    if (features.isIpAddress) {
      indicators.push('ip-based-host');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'IP Address URL',
        description: 'URL uses an IP address host instead of a domain name',
        weight: 65,
        scoreContribution: 65,
        confidence: 0.95,
        indicator: 'ip-based-host'
      });
    }

    // 2. Private IP / Localhost / SSRF Threat Check
    if (features.isPrivateOrLocalhost) {
      indicators.push('private-ip-ssrf');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Internal Network Target',
        description: 'URL targets internal private IP range, localhost, or cloud metadata service (potential SSRF)',
        weight: 75,
        scoreContribution: 75,
        confidence: 0.95,
        indicator: 'private-ip-ssrf'
      });
    }

    // 3. Dangerous or abnormal port check
    if (features.isAbnormalPort && features.port) {
      indicators.push('abnormal-port');
      const isDangerous = this.dangerousPorts.has(features.port);
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: isDangerous ? 'Dangerous Non-Web Port' : 'Unusual Web Port',
        description: `URL uses non-standard port :${features.port}`,
        weight: isDangerous ? 60 : 25,
        scoreContribution: isDangerous ? 60 : 25,
        confidence: 0.9,
        indicator: 'abnormal-port'
      });
    }

    // 4. Suspicious TLD
    if (this.suspiciousTLDs.some(tld => url.hostname.endsWith(tld))) {
      indicators.push('suspicious-tld');
      const tldWeight = isSensitivePath || !features.isHttps ? 65 : 45;
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Suspicious TLD',
        description: 'Domain uses a top-level domain frequently abused in phishing',
        weight: tldWeight,
        scoreContribution: tldWeight,
        confidence: 0.9,
        indicator: 'suspicious-tld'
      });
    }

    // 5. Shorteners
    if (this.shorteners.some(s => url.hostname.includes(s))) {
      indicators.push('url-shortener');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'URL Shortener',
        description: 'URL shortening service obscures destination',
        weight: 25,
        scoreContribution: 25,
        confidence: 0.9,
        indicator: 'url-shortener'
      });
    }

    // 6. Credentials / Userinfo in URL (e.g. https://google.com@evil.com)
    if (url.username || url.password || normalizedInput.replace(/^https?:\/\//, '').split('/')[0].includes('@')) {
      indicators.push('credentials-in-url');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Credentials in URL',
        description: 'URL contains an @ symbol to mask the true destination domain',
        weight: 85,
        scoreContribution: 85,
        confidence: 0.95,
        indicator: 'credentials-in-url'
      });
    }

    // 7. Punycode & Mixed-script Homoglyphs
    const hasPunycode = url.hostname.includes('xn--');
    const hasMixedScriptHomoglyphs = this.hasMixedScriptHomoglyphs(url.hostname);

    if (hasPunycode || hasMixedScriptHomoglyphs) {
      indicators.push('punycode-domain');
      const punyWeight = isSensitivePath ? 85 : 60;
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Punycode Domain',
        description: 'Domain uses Punycode or mixed-script homoglyphs designed to imitate trusted brands',
        weight: punyWeight,
        scoreContribution: punyWeight,
        confidence: 0.95,
        indicator: 'punycode-domain',
        isCriticalOverride: hasMixedScriptHomoglyphs && isSensitivePath
      });
    }

    // 8. Subdomain brand spoofing and excessive depth
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
        scoreContribution: 80,
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
        scoreContribution: depthWeight,
        confidence: 0.85,
        indicator: 'excessive-subdomains'
      });
    }

    // 9. Path entropy
    const pathEntropy = calculateEntropy(url.pathname);
    if (url.pathname.length > 15 && pathEntropy > 3.8) {
      indicators.push('high-entropy-path');
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'High Entropy Path',
        description: 'URL path has high randomness, typical of phishing tokens',
        weight: 30,
        scoreContribution: 30,
        confidence: 0.75,
        indicator: 'high-entropy-path'
      });
    }

    // 10. Typosquatting / Levenshtein
    let closestBrandMatch: { brand: string; distance: number } | undefined;
    for (const [brand, distance] of Object.entries(features.levenshteinScores)) {
      if (distance > 0 && distance <= 2 && url.hostname !== `${brand}.com`) {
        closestBrandMatch = { brand, distance };
        indicators.push('typosquatting');
        evidenceList.push({
          source: 'URL_ANALYZER',
          name: 'Typosquatting Detected',
          description: `Domain is visually similar to a major brand: ${brand}`,
          weight: 85,
          scoreContribution: 85,
          confidence: 0.9,
          indicator: 'typosquatting'
        });
        break;
      }
    }

    // 11. HTTP vs HTTPS
    if (!features.isHttps) {
      evidenceList.push({
        source: 'URL_ANALYZER',
        name: 'Unencrypted Connection',
        description: 'URL uses unencrypted HTTP',
        weight: 15,
        scoreContribution: 15,
        confidence: 0.8,
        indicator: 'unencrypted-http'
      });
    }

    // Calculate composite risk score
    let totalScore = 0;
    if (evidenceList.length > 0) {
      const maxWeight = Math.max(...evidenceList.map(e => e.weight));
      const bonus = (evidenceList.length - 1) * 5;
      totalScore = Math.min(100, maxWeight + bonus);
    }

    const finalResult = buildResult(
      true,
      totalScore,
      indicators,
      url.toString(),
      url.hostname,
      features
    );
    finalResult.brandSpoofDistance = closestBrandMatch;
    return finalResult;
  }

  private hasMixedScriptHomoglyphs(hostname: string): boolean {
    // Check for Cyrillic / Greek characters mixed into a hostname
    const hasLatin = /[a-zA-Z]/.test(hostname);
    const hasCyrillic = /[\u0400-\u04FF]/.test(hostname);
    const hasGreek = /[\u0370-\u03FF]/.test(hostname);
    return (hasLatin && hasCyrillic) || (hasLatin && hasGreek);
  }

  private extractFeatures(url: URL, rawInput: string): URLFeatures {
    const hostname = url.hostname;

    // IPv4 standard regex
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
    // IPv6 standard regex (e.g. [::1] or bracketed format)
    const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
    // Hex, octal, or integer dword IP forms (e.g. 0x7f000001, 2130706433, 0177.0.0.1)
    const hexOrDwordIp = /^0x[0-9a-fA-F]+$|^\d{8,11}$|^0[0-7]+(?:\.0[0-7]+){3}$/;

    const isIpv4 = ipv4Regex.test(hostname);
    const isIpv6 = hostname.includes(':') && ipv6Regex.test(hostname);
    const isObfuscatedIp = hexOrDwordIp.test(hostname);
    const isIpAddress = isIpv4 || isIpv6 || isObfuscatedIp;

    // Private IP, localhost, SSRF checks
    const isLocalhost = hostname === 'localhost' || hostname.endsWith('.localhost');
    const isPrivateIpv4 =
      /^127\./.test(hostname) ||
      /^10\./.test(hostname) ||
      /^192\.168\./.test(hostname) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname) ||
      /^169\.254\./.test(hostname); // Link-local cloud metadata (AWS, GCP, Azure)
    const isPrivateIpv6 = hostname === '[::1]' || hostname === '::1' || /^\[?fe80:/i.test(hostname);

    const isPrivateOrLocalhost = isLocalhost || isPrivateIpv4 || isPrivateIpv6;

    // Port checks
    const port = url.port;
    const isAbnormalPort = Boolean(port && (this.dangerousPorts.has(port) || this.unusualWebPorts.has(port)));

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
      isPrivateOrLocalhost,
      isAbnormalPort,
      port: port || undefined,
      entropy: calculateEntropy(hostname),
      levenshteinScores,
      dotsCount: Math.max(0, domainParts.length - 1),
      digitsToLettersRatio: lettersCount > 0 ? digitsCount / lettersCount : digitsCount
    };
  }
}

export const UrlAnalyzer = URLAnalyzer;
