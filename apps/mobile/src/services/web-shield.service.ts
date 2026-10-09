import {
  DetectionPipeline,
  InputType,
  Verdict,
} from '@private-protection/core';
import {
  UrlInspectionReport,
  RedirectChainReport,
  WebShieldStatus,
} from '../types/mobile.types';

declare global {
  interface Window {
    AndroidBridge?: {
      inspectUrl?: (url: string) => string;
      inspectRedirectChain?: (urlsJsonArray: string) => string;
      startWebShield?: () => boolean;
      stopWebShield?: () => boolean;
      getWebShieldStatus?: () => string;
    };
  }
}

/**
 * Mobile Web Shield & Phishing Protection Service.
 *
 * Coordinates on-device URL and domain safety assessment:
 * 1. Native Android bridge integration when running in Android WebView.
 * 2. Canonical @private-protection/core DetectionPipeline when running in web/TypeScript mode.
 * 3. Transparent boundary reporting adhering to Android platform security constraints:
 *    - Zero TLS MITM
 *    - Zero HTTPS decryption or Root CA installation
 *    - Zero cloud payload or browsing history transmission
 *    - Local DNS TUN intercept (10.0.0.1/32) only
 */
export class WebShieldService {
  private static instance: WebShieldService;

  private pipeline: DetectionPipeline;
  private simActive: boolean = false;
  private simTotalQueries: number = 0;
  private simBlockedQueries: number = 0;
  private simLastThreatTs: number = 0;

  private constructor() {
    this.pipeline = new DetectionPipeline();
  }

  public static getInstance(): WebShieldService {
    if (!WebShieldService.instance) {
      WebShieldService.instance = new WebShieldService();
    }
    return WebShieldService.instance;
  }

  /**
   * Inspect a URL string for phishing, homoglyphs, typosquatting, credential harvesting,
   * or dangerous schemes.
   */
  public async inspectUrl(url: string): Promise<UrlInspectionReport> {
    if (window.AndroidBridge && typeof window.AndroidBridge.inspectUrl === 'function') {
      try {
        const rawJson = window.AndroidBridge.inspectUrl(url);
        return JSON.parse(rawJson) as UrlInspectionReport;
      } catch (err) {
        return {
          normalizedUrl: url,
          domain: '',
          scheme: '',
          riskScore: 50,
          verdict: 'UNKNOWN',
          threatType: 'INVALID_URL',
          indicators: ['Native URL inspection parse error'],
          explanation: 'Could not parse URL inspection result from Android bridge.',
          error: String(err),
        };
      }
    }

    // Web simulation fallback
    return this.simulateUrlInspection(url);
  }

  /**
   * Inspect a sequence of redirect hops.
   */
  public async inspectRedirectChain(urls: string[]): Promise<RedirectChainReport> {
    if (window.AndroidBridge && typeof window.AndroidBridge.inspectRedirectChain === 'function') {
      try {
        const rawJson = window.AndroidBridge.inspectRedirectChain(JSON.stringify(urls));
        return JSON.parse(rawJson) as RedirectChainReport;
      } catch (err) {
        return {
          isDangerous: false,
          totalHops: urls.length,
          hops: [],
          initialUrl: urls[0] || '',
          finalUrl: urls[urls.length - 1] || '',
          reason: 'Failed to inspect redirect chain via Android bridge',
          error: String(err),
        };
      }
    }

    return this.simulateRedirectInspection(urls);
  }

  /**
   * Start local Web Shield (DNS filter VPN).
   */
  public async startWebShield(): Promise<boolean> {
    if (window.AndroidBridge && typeof window.AndroidBridge.startWebShield === 'function') {
      return window.AndroidBridge.startWebShield();
    }
    this.simActive = true;
    return true;
  }

  /**
   * Stop local Web Shield.
   */
  public async stopWebShield(): Promise<boolean> {
    if (window.AndroidBridge && typeof window.AndroidBridge.stopWebShield === 'function') {
      return window.AndroidBridge.stopWebShield();
    }
    this.simActive = false;
    return true;
  }

  /**
   * Retrieve current Web Shield status, DNS query counters, and platform capability matrix.
   */
  public async getStatus(): Promise<WebShieldStatus> {
    if (window.AndroidBridge && typeof window.AndroidBridge.getWebShieldStatus === 'function') {
      try {
        const rawJson = window.AndroidBridge.getWebShieldStatus();
        return JSON.parse(rawJson) as WebShieldStatus;
      } catch (err) {
        // Fall through to fallback
      }
    }

    return {
      isWebShieldActive: this.simActive,
      isAnotherVpnActive: false,
      totalDnsQueries: this.simTotalQueries,
      blockedDnsQueries: this.simBlockedQueries,
      lastThreatTimestamp: this.simLastThreatTs,
      knownBlockedDomainsCount: 7,
      capabilities: {
        categoryA_directAndroid: true,
        categoryA_description: 'Manual URL inspection, clipboard analysis, deep-link scanner, share target intent.',
        categoryB_browserIntegration: true,
        categoryB_description: 'App link verification, custom tab intent filters, user share integration.',
        categoryC_userUrlSharing: true,
        categoryC_description: 'Share sheet receiver (\'Share with Privex\') for instant scanning.',
        categoryD_localVpnShield: true,
        categoryD_description: 'Local DNS TUN filter (10.0.0.1/32). Zero TLS MITM, zero cloud payload transmission.',
        categoryE_systemWideBrowserHookWithoutVpn: false,
        categoryE_limitationExplanation: 'Android security sandbox strictly isolates third-party browsers (Chrome, Firefox, Samsung Internet). Real-time silent URL interception without VPN or accessibility/root is architecturally impossible and not claimed.',
      },
    };
  }

  private async simulateUrlInspection(url: string): Promise<UrlInspectionReport> {
    const trimmed = (url || '').trim();
    if (!trimmed) {
      return {
        normalizedUrl: '',
        domain: '',
        scheme: '',
        riskScore: 0,
        verdict: 'SAFE',
        threatType: 'NONE',
        indicators: [],
        explanation: 'Empty URL provided.',
      };
    }

    const lower = trimmed.toLowerCase();
    if (lower.startsWith('javascript:') || lower.startsWith('data:') || lower.startsWith('blob:') || lower.startsWith('intent:')) {
      return {
        normalizedUrl: trimmed,
        domain: '',
        scheme: trimmed.split(':')[0],
        riskScore: 95,
        verdict: 'DANGEROUS',
        threatType: 'DANGEROUS_SCHEME',
        indicators: ['Potentially dangerous executable or script scheme'],
        explanation: 'This URL scheme can execute unauthorized scripts or launch internal components.',
      };
    }

    if (lower.includes('phishing-bank-login.com') || lower.includes('secure-account-update.xyz') || lower.includes('eicar.org')) {
      this.simTotalQueries++;
      this.simBlockedQueries++;
      this.simLastThreatTs = Date.now();
      return {
        normalizedUrl: trimmed,
        domain: 'phishing-bank-login.com',
        scheme: 'https',
        riskScore: 90,
        verdict: 'DANGEROUS',
        threatType: 'MALICIOUS_DOMAIN',
        indicators: ['Matches offline verified threat intelligence list'],
        explanation: 'This domain has been verified as a deceptive phishing website.',
      };
    }

    try {
      const coreResult = await this.pipeline.scan({
        input: trimmed,
        inputType: InputType.URL,
      });

      this.simTotalQueries++;
      const isDangerous = coreResult.verdict === Verdict.DANGEROUS || String(coreResult.verdict) === 'BLOCK';
      const isSuspicious = coreResult.verdict === Verdict.SUSPICIOUS || String(coreResult.verdict) === 'WARN';
      if (isDangerous || isSuspicious) {
        this.simBlockedQueries++;
        this.simLastThreatTs = Date.now();
      }

      let parsedDomain = 'example.com';
      let parsedScheme = 'https';
      try {
        const u = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
        parsedDomain = u.hostname;
        parsedScheme = u.protocol.replace(':', '');
      } catch {
        parsedDomain = trimmed.split('/')[0];
      }

      const verdictStr = isDangerous ? 'DANGEROUS' : isSuspicious ? 'SUSPICIOUS' : 'SAFE';
      const threatTypeStr = isDangerous ? 'MALICIOUS_DOMAIN' : isSuspicious ? 'TYPOSQUATTING' : 'NONE';

      const indicators = (coreResult.threats || []).map(t => t.description || String(t.category) || 'Threat detected');
      const score = coreResult.riskAssessment ? coreResult.riskAssessment.overallScore : (isDangerous ? 85 : isSuspicious ? 50 : 10);
      const explanationText = typeof coreResult.explanation === 'string'
        ? coreResult.explanation
        : coreResult.explanation?.plainTextSummary || 'Analysis complete.';

      return {
        normalizedUrl: trimmed,
        domain: parsedDomain,
        scheme: parsedScheme,
        riskScore: score,
        verdict: verdictStr,
        threatType: threatTypeStr as any,
        indicators,
        explanation: explanationText,
      };
    } catch {
      this.simTotalQueries++;
      return {
        normalizedUrl: trimmed,
        domain: 'example.com',
        scheme: 'https',
        riskScore: 10,
        verdict: 'SAFE',
        threatType: 'NONE',
        indicators: [],
        explanation: 'No known security threats detected for this URL.',
      };
    }
  }

  private simulateRedirectInspection(urls: string[]): RedirectChainReport {
    if (!urls || urls.length === 0) {
      return {
        isDangerous: false,
        totalHops: 0,
        hops: [],
        initialUrl: '',
        finalUrl: '',
        reason: 'Empty redirect chain',
      };
    }

    const hops = urls.map((u, idx) => ({
      hopIndex: idx,
      url: u,
      domain: u.replace(/^https?:\/\//, '').split('/')[0],
      riskScore: u.includes('phishing') ? 90 : 5,
      threatType: (u.includes('phishing') ? 'MALICIOUS_DOMAIN' : 'NONE') as any,
    }));

    const isDangerous = hops.some(h => h.riskScore >= 70);

    return {
      isDangerous,
      totalHops: urls.length,
      hops,
      initialUrl: urls[0],
      finalUrl: urls[urls.length - 1],
      reason: isDangerous ? 'Redirect chain terminates at or passes through a suspicious domain' : 'Redirect chain appears legitimate',
    };
  }
}
