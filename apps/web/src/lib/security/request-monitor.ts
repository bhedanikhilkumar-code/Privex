/**
 * URL & APPLICATION NETWORK REQUEST SECURITY MONITOR
 *
 * CONSTITUTIONAL PRIVACY & SECURITY MANDATE:
 * - Monitors ONLY inbound/outbound requests initiated by this browser application.
 * - ZERO intrusive scanning, port scanning, or external attacks.
 * - Automatic URL sanitization: query tokens, secrets, and auth credentials are REDACTED.
 * - Strictly bounded rolling memory buffer (max 200 items, zero memory leaks).
 * - Third-party requests are NOT presumed malicious; careful categorization is maintained.
 */

import { securityEventManager } from './security-events';

export type RequestDestinationType = 'FIRST_PARTY' | 'THIRD_PARTY' | 'UNKNOWN_SUSPICIOUS';
export type RequestRiskLevel = 'SAFE' | 'WARNING' | 'SUSPICIOUS';

export interface MonitoredRequest {
  id: string;
  url: string; // Sanitized URL
  domain: string;
  method: string;
  timestamp: number;
  destinationType: RequestDestinationType;
  riskLevel: RequestRiskLevel;
  status?: number;
  responseTimeMs?: number;
  reason?: string;
}

export interface NetworkMonitorConfig {
  maxHistorySize: number;
  requestOverloadThreshold: number; // e.g. 50 requests
  timeWindowMs: number; // e.g. 10000 ms (10s)
  enableAutoInterception: boolean;
}

export const DEFAULT_MONITOR_CONFIG: NetworkMonitorConfig = {
  maxHistorySize: 200,
  requestOverloadThreshold: 50,
  timeWindowMs: 10000,
  enableAutoInterception: true
};

// Known high-abuse or suspicious TLDs often correlated with malicious throwaway hosts
const HIGH_ABUSE_TLDS = new Set(['.top', '.xyz', '.buzz', '.click', '.country', '.kim', '.work', '.gq', '.cf', '.tk', '.ml', '.ga']);

/**
 * Sanitizes URLs to remove sensitive credentials, tokens, and authorization parameters.
 * E.g.: "https://example.com/api?token=secret123&user=john" -> "https://example.com/api?token=[REDACTED]&user=john"
 */
export function sanitizeRequestUrl(rawUrl: string): { sanitizedUrl: string; domain: string } {
  try {
    const parsed = new URL(rawUrl, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
    const domain = parsed.hostname.toLowerCase();

    const sensitiveParamNames = [
      'token', 'secret', 'password', 'passwd', 'auth', 'apikey', 'api_key',
      'access_token', 'refresh_token', 'code', 'session', 'jwt', 'signature', 'sig'
    ];

    const searchParams = new URLSearchParams(parsed.search);
    for (const key of Array.from(searchParams.keys())) {
      const lowerKey = key.toLowerCase();
      if (sensitiveParamNames.some((s) => lowerKey.includes(s))) {
        searchParams.set(key, '[REDACTED]');
      }
    }

    parsed.search = searchParams.toString();
    return {
      sanitizedUrl: parsed.toString(),
      domain
    };
  } catch {
    // If invalid URL, strip non-alphanumeric and truncate safely
    const clean = rawUrl.split('?')[0].slice(0, 150);
    return {
      sanitizedUrl: clean || 'unknown-destination',
      domain: 'unknown-destination'
    };
  }
}

/**
 * Categorizes a destination domain and determines risk level.
 */
export function classifyRequestDestination(
  domain: string,
  currentOriginHostname?: string
): { destinationType: RequestDestinationType; riskLevel: RequestRiskLevel; reason: string } {
  let cleanDomain = (domain || '').toLowerCase().trim();

  // Strip optional port (e.g. "localhost:3000" -> "localhost", "192.168.1.1:8080" -> "192.168.1.1")
  if (cleanDomain.startsWith('[') && cleanDomain.includes(']:')) {
    cleanDomain = cleanDomain.slice(0, cleanDomain.indexOf(']:') + 1);
  } else if (!cleanDomain.startsWith('[') && cleanDomain.includes(':') && !cleanDomain.includes('::')) {
    cleanDomain = cleanDomain.split(':')[0];
  }

  const currentHost = (currentOriginHostname || (typeof window !== 'undefined' ? window.location.hostname : 'localhost')).toLowerCase().split(':')[0];
  const lowerDomain = cleanDomain;

  // First Party detection
  if (
    lowerDomain === currentHost ||
    lowerDomain === 'localhost' ||
    lowerDomain === '127.0.0.1' ||
    lowerDomain === '[::1]' ||
    lowerDomain.endsWith(`.${currentHost}`)
  ) {
    return {
      destinationType: 'FIRST_PARTY',
      riskLevel: 'SAFE',
      reason: 'First-party application endpoint'
    };
  }

  // Raw IPv4/IPv6 destination address check
  const isRawIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(lowerDomain) || lowerDomain.includes(':');
  if (isRawIp && lowerDomain !== '127.0.0.1' && lowerDomain !== '[::1]') {
    return {
      destinationType: 'UNKNOWN_SUSPICIOUS',
      riskLevel: 'SUSPICIOUS',
      reason: 'Direct numeric IP destination without validated hostname'
    };
  }

  // Check for high-abuse TLDs
  for (const tld of HIGH_ABUSE_TLDS) {
    if (lowerDomain.endsWith(tld)) {
      return {
        destinationType: 'UNKNOWN_SUSPICIOUS',
        riskLevel: 'SUSPICIOUS',
        reason: `Destination uses high-abuse top-level domain (${tld})`
      };
    }
  }

  // Punycode / IDN homograph indicator check
  if (lowerDomain.startsWith('xn--') || lowerDomain.includes('.xn--')) {
    return {
      destinationType: 'UNKNOWN_SUSPICIOUS',
      riskLevel: 'WARNING',
      reason: 'Punycode internationalized domain label detected'
    };
  }

  // Standard Third-Party destination (e.g. CDNs, APIs, external integrations)
  return {
    destinationType: 'THIRD_PARTY',
    riskLevel: 'SAFE',
    reason: 'Standard third-party external service'
  };
}

export class NetworkRequestMonitor {
  private static instance: NetworkRequestMonitor | null = null;
  private config: NetworkMonitorConfig;
  private requestHistory: MonitoredRequest[] = [];
  private listeners: Set<(requests: MonitoredRequest[]) => void> = new Set();
  private originalFetch: typeof window.fetch | null = null;
  private isInterceptionActive = false;

  private constructor(config: Partial<NetworkMonitorConfig> = {}) {
    this.config = { ...DEFAULT_MONITOR_CONFIG, ...config };
  }

  public static getInstance(config?: Partial<NetworkMonitorConfig>): NetworkRequestMonitor {
    if (!NetworkRequestMonitor.instance) {
      NetworkRequestMonitor.instance = new NetworkRequestMonitor(config);
    } else if (config) {
      NetworkRequestMonitor.instance.updateConfig(config);
    }
    return NetworkRequestMonitor.instance;
  }

  public getConfig(): NetworkMonitorConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<NetworkMonitorConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  public getHistory(): MonitoredRequest[] {
    return [...this.requestHistory];
  }

  public subscribe(listener: (requests: MonitoredRequest[]) => void): () => void {
    this.listeners.add(listener);
    listener(this.getHistory());
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    const history = this.getHistory();
    this.listeners.forEach((fn) => fn(history));
  }

  /**
   * Records a request into the rolling history and analyzes overload patterns.
   */
  public recordRequest(entry: {
    url: string;
    method?: string;
    status?: number;
    responseTimeMs?: number;
    destinationType?: RequestDestinationType;
    riskLevel?: RequestRiskLevel;
    reason?: string;
  }): MonitoredRequest {
    const { sanitizedUrl, domain } = sanitizeRequestUrl(entry.url);
    const classification = classifyRequestDestination(domain);

    const destType = entry.destinationType || classification.destinationType;
    const risk = entry.riskLevel || classification.riskLevel;
    const reasonText = entry.reason || classification.reason;

    const monitored: MonitoredRequest = {
      id: `req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      url: sanitizedUrl,
      domain,
      method: (entry.method || 'GET').toUpperCase(),
      timestamp: Date.now(),
      destinationType: destType,
      riskLevel: risk,
      status: entry.status ?? 200,
      responseTimeMs: entry.responseTimeMs,
      reason: reasonText
    };

    // Add to rolling history
    this.requestHistory.unshift(monitored);
    if (this.requestHistory.length > this.config.maxHistorySize) {
      this.requestHistory.length = this.config.maxHistorySize;
    }

    // Trigger security events if applicable
    if (destType === 'UNKNOWN_SUSPICIOUS' || risk === 'SUSPICIOUS') {
      securityEventManager.addEvent({
        type: 'SUSPICIOUS_REQUEST',
        severity: 'high',
        domain,
        message: `Suspicious destination detected: ${domain} (${reasonText})`,
        metadata: { url: sanitizedUrl, domain }
      });
    } else if (destType === 'THIRD_PARTY') {
      // Third party detected - log low severity informational event if unknown
      securityEventManager.addEvent({
        type: 'UNKNOWN_THIRD_PARTY',
        severity: 'low',
        domain,
        message: `Third-party request observed to external service: ${domain}`,
        metadata: { url: sanitizedUrl, domain }
      });
    }

    // Evaluate Request Overload on this domain
    this.evaluateRequestOverload(domain);

    this.notify();
    return monitored;
  }

  /**
   * Checks if requests to a domain exceed the overload threshold within the time window.
   */
  private evaluateRequestOverload(domain: string): void {
    const now = Date.now();
    const cutoff = now - this.config.timeWindowMs;

    const recentRequestsForDomain = this.requestHistory.filter(
      (r) => r.domain === domain && r.timestamp >= cutoff
    );

    if (recentRequestsForDomain.length >= this.config.requestOverloadThreshold) {
      securityEventManager.addEvent({
        type: 'HIGH_REQUEST_ACTIVITY',
        severity: 'medium',
        domain,
        requestCount: recentRequestsForDomain.length,
        timeWindow: this.config.timeWindowMs,
        message: `Unusually high request activity detected: ${recentRequestsForDomain.length} requests to "${domain}" within ${this.config.timeWindowMs / 1000}s.`,
        metadata: { domain, count: recentRequestsForDomain.length }
      });
    }
  }

  /**
   * Clears in-memory history safely.
   */
  public clearHistory(): void {
    this.requestHistory = [];
    this.notify();
  }

  /**
   * Initializes non-intrusive fetch wrapping.
   */
  public startInterception(): void {
    if (typeof window === 'undefined' || this.isInterceptionActive) return;

    this.originalFetch = window.fetch;
    const self = this;

    window.fetch = async function (...args: any[]) {
      const startTime = performance.now();
      const input = args[0];
      const init = args[1] || {};

      let requestUrl = '';
      if (typeof input === 'string') {
        requestUrl = input;
      } else if (input instanceof URL) {
        requestUrl = input.toString();
      } else if (input && typeof input.url === 'string') {
        requestUrl = input.url;
      }

      const method = init.method || (input && (input as any).method) || 'GET';

      try {
        const response = await (self.originalFetch as any).apply(this, args);
        const duration = Math.round(performance.now() - startTime);

        if (requestUrl) {
          self.recordRequest({
            url: requestUrl,
            method,
            status: response.status,
            responseTimeMs: duration
          });
        }

        return response;
      } catch (err) {
        const duration = Math.round(performance.now() - startTime);
        if (requestUrl) {
          self.recordRequest({
            url: requestUrl,
            method,
            status: 0,
            responseTimeMs: duration,
            reason: 'Request network failure or blocked'
          });
        }
        throw err;
      }
    };

    this.isInterceptionActive = true;
  }

  public stopInterception(): void {
    if (typeof window !== 'undefined' && this.originalFetch && this.isInterceptionActive) {
      window.fetch = this.originalFetch;
      this.isInterceptionActive = false;
    }
  }
}

export const requestMonitor = NetworkRequestMonitor.getInstance();
