import { sha256 } from '../utils/crypto';
import { Evidence } from '../types';

export interface ThreatIntelEntry {
  hash: string;
  expiresAt?: number;
}

export interface ThreatIntelResult extends Evidence {
  isMalicious: boolean;
}

export class ThreatIntel {
  private badDomainHashes: Map<string, ThreatIntelEntry> = new Map();
  private goodDomainHashes: Set<string> = new Set();
  private lastUpdated: number;

  constructor() {
    this.lastUpdated = Date.now();
    this.loadSeedData();
  }

  private loadSeedData() {
    const badSeeds = [
      'secure-paypa1.com',
      'amaz0n-verify.tk',
      'login-apple-support.xyz',
      'netflix-update-billing.gq'
    ];

    badSeeds.forEach(domain => {
      this.addMaliciousDomain(domain);
    });

    const goodSeeds = [
      'google.com',
      'paypal.com',
      'apple.com',
      'microsoft.com',
      'github.com'
    ];

    goodSeeds.forEach(domain => {
      this.addAllowedDomain(domain);
    });
  }

  public addMaliciousDomain(domain: string, options?: { ttl?: number }) {
    const hash = sha256(domain.toLowerCase().trim());
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    this.badDomainHashes.set(hash, { hash, expiresAt });
    this.lastUpdated = Date.now();
  }

  public addBadDomain(domain: string) {
    this.addMaliciousDomain(domain);
  }

  public addAllowedDomain(domain: string) {
    this.goodDomainHashes.add(sha256(domain.toLowerCase().trim()));
  }

  public removeMaliciousDomain(domain: string) {
    const hash = sha256(domain.toLowerCase().trim());
    this.badDomainHashes.delete(hash);
  }

  public addMaliciousHash(hash: string, options?: { ttl?: number }) {
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    this.badDomainHashes.set(hash.toLowerCase().trim(), { hash: hash.toLowerCase().trim(), expiresAt });
  }

  public checkHash(hash: string): ThreatIntelResult {
    const normalizedHash = hash.toLowerCase().trim();

    if (this.goodDomainHashes.has(normalizedHash)) {
      return {
        source: 'THREAT_INTEL',
        name: 'Known Good Domain',
        description: 'Domain is on the verified allowlist',
        weight: 0,
        confidence: 1.0,
        isMalicious: false
      };
    }

    const entry = this.badDomainHashes.get(normalizedHash);
    if (entry) {
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        this.badDomainHashes.delete(normalizedHash);
      } else {
        return {
          source: 'THREAT_INTEL',
          name: 'Known Malicious Domain',
          description: 'Domain matches known threat intelligence blocklist',
          weight: 100,
          confidence: 1.0,
          isMalicious: true
        };
      }
    }

    return {
      source: 'THREAT_INTEL',
      name: 'Clean Domain',
      description: 'No threat intelligence flags for this domain',
      weight: 0,
      confidence: 0.5,
      isMalicious: false
    };
  }

  public checkDomain(domain: string): ThreatIntelResult {
    if (!domain) {
      return {
        source: 'THREAT_INTEL',
        name: 'Clean Domain',
        description: 'Empty domain provided',
        weight: 0,
        confidence: 0.5,
        isMalicious: false
      };
    }

    const hash = sha256(domain.toLowerCase().trim());
    return this.checkHash(hash);
  }

  public getStalenessDays(): number {
    return (Date.now() - this.lastUpdated) / (1000 * 60 * 60 * 24);
  }
}
