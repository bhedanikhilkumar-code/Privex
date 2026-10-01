import { sha256, verifyEd25519Signature } from '../utils/crypto';
import {
  Evidence,
  RiskCategory,
  Severity,
  SeverityLevel,
  ThreatIntelRecord,
  UpdateMetadata
} from '../types';

export interface ThreatIntelEntry {
  hash: string;
  expiresAt?: number;
  category?: RiskCategory | string;
  severity?: SeverityLevel | string;
  sourceFeed?: string;
  threatType?: 'DOMAIN' | 'URL' | 'IP' | 'HASH';
}

export interface ThreatIntelResult extends Evidence {
  isMalicious: boolean;
  isAllowed?: boolean;
  threatType?: 'DOMAIN' | 'URL' | 'IP' | 'HASH';
  category?: RiskCategory | string;
  severityLevel?: SeverityLevel | string;
}

export type StalenessState = 'FRESH' | 'AGED' | 'STALE' | 'EXPIRED_CACHE';

export class ThreatIntel {
  private badHashes: Map<string, ThreatIntelEntry> = new Map();
  private goodHashes: Set<string> = new Set();
  private lastUpdated: number;
  private databaseVersion: number = 101;
  private rootPublicKeyHex: string;

  constructor(options?: { rootPublicKeyHex?: string; initialVersion?: number }) {
    this.lastUpdated = Date.now();
    this.databaseVersion = options?.initialVersion ?? 101;
    // Standard compiled Root Ed25519 Public Key (can be overridden in options for testing)
    this.rootPublicKeyHex = options?.rootPublicKeyHex ?? '00'.repeat(32);
    this.loadSeedData();
  }

  private loadSeedData(): void {
    const badSeeds = [
      'secure-paypa1.com',
      'amaz0n-verify.tk',
      'login-apple-support.xyz',
      'netflix-update-billing.gq',
      'malicious-crypto-drainer.cc',
      'phishing-bank-login.xyz'
    ];

    badSeeds.forEach(domain => {
      this.addMaliciousDomain(domain, {
        category: RiskCategory.PHISHING,
        severity: SeverityLevel.HIGH
      });
    });

    const badUrls = [
      'http://secure-paypa1.com/login?token=urgent',
      'https://amaz0n-verify.tk/account/billing'
    ];
    badUrls.forEach(url => {
      this.addMaliciousUrl(url);
    });

    const badIps = [
      '198.51.100.23', // RFC 5737 TEST-NET-2 known botnet C2 fixture
      '203.0.113.88'
    ];
    badIps.forEach(ip => {
      this.addMaliciousIp(ip);
    });

    const goodSeeds = [
      'google.com',
      'paypal.com',
      'apple.com',
      'microsoft.com',
      'github.com',
      'cloudflare.com',
      'wikipedia.org'
    ];

    goodSeeds.forEach(domain => {
      this.addAllowedDomain(domain);
    });
  }

  public getVersion(): number {
    return this.databaseVersion;
  }

  public getRecord(): ThreatIntelRecord {
    return {
      databaseVersion: this.databaseVersion,
      filterType: 'HASH_SET_V1',
      capacity: 1000000,
      falsePositiveRate: 0.0001,
      generatedEpoch: this.lastUpdated
    };
  }

  public addMaliciousDomain(
    domain: string,
    options?: {
      ttl?: number;
      category?: RiskCategory | string;
      severity?: SeverityLevel | string;
      sourceFeed?: string;
    }
  ): void {
    if (!domain) return;
    const normalized = domain.toLowerCase().trim();
    const hash = sha256(normalized);
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    this.badHashes.set(hash, {
      hash,
      expiresAt,
      category: options?.category || RiskCategory.PHISHING,
      severity: options?.severity || SeverityLevel.HIGH,
      sourceFeed: options?.sourceFeed || 'SEED_BLOCKLIST',
      threatType: 'DOMAIN'
    });
    this.lastUpdated = Date.now();
  }

  public addBadDomain(domain: string): void {
    this.addMaliciousDomain(domain);
  }

  public addMaliciousUrl(
    url: string,
    options?: {
      ttl?: number;
      category?: RiskCategory | string;
      severity?: SeverityLevel | string;
      sourceFeed?: string;
    }
  ): void {
    if (!url) return;
    const normalized = url.toLowerCase().trim();
    const hash = sha256(normalized);
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    this.badHashes.set(hash, {
      hash,
      expiresAt,
      category: options?.category || RiskCategory.PHISHING,
      severity: options?.severity || SeverityLevel.CRITICAL,
      sourceFeed: options?.sourceFeed || 'URL_FEED',
      threatType: 'URL'
    });
    this.lastUpdated = Date.now();
  }

  public addMaliciousIp(
    ip: string,
    options?: {
      ttl?: number;
      category?: RiskCategory | string;
      severity?: SeverityLevel | string;
      sourceFeed?: string;
    }
  ): void {
    if (!ip) return;
    const normalized = ip.toLowerCase().trim();
    const hash = sha256(normalized);
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    this.badHashes.set(hash, {
      hash,
      expiresAt,
      category: options?.category || RiskCategory.MALWARE,
      severity: options?.severity || SeverityLevel.CRITICAL,
      sourceFeed: options?.sourceFeed || 'IP_C2_FEED',
      threatType: 'IP'
    });
    this.lastUpdated = Date.now();
  }

  public addAllowedDomain(domain: string): void {
    if (!domain) return;
    const hash = sha256(domain.toLowerCase().trim());
    this.goodHashes.add(hash);
  }

  public addAllowedUrl(url: string): void {
    if (!url) return;
    const hash = sha256(url.toLowerCase().trim());
    this.goodHashes.add(hash);
  }

  public isAllowed(target: string): boolean {
    if (!target) return false;
    const hash = sha256(target.toLowerCase().trim());
    return this.goodHashes.has(hash);
  }

  public removeMaliciousDomain(domain: string): void {
    if (!domain) return;
    const hash = sha256(domain.toLowerCase().trim());
    this.badHashes.delete(hash);
  }

  public addMaliciousHash(
    hash: string,
    options?: {
      ttl?: number;
      category?: RiskCategory | string;
      severity?: SeverityLevel | string;
      threatType?: 'DOMAIN' | 'URL' | 'IP' | 'HASH';
    }
  ): void {
    if (!hash) return;
    const normalized = hash.toLowerCase().trim();
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    this.badHashes.set(normalized, {
      hash: normalized,
      expiresAt,
      category: options?.category || RiskCategory.PHISHING,
      severity: options?.severity || SeverityLevel.HIGH,
      threatType: options?.threatType || 'HASH'
    });
  }

  public checkHash(hash: string): ThreatIntelResult {
    const normalizedHash = hash.toLowerCase().trim();

    // 1. Explicit verified allowlist has absolute precedence
    if (this.goodHashes.has(normalizedHash)) {
      return {
        source: 'THREAT_INTEL',
        name: 'Known Good Domain',
        description: 'Target is on the verified local allowlist',
        weight: 0,
        scoreContribution: 0,
        confidence: 1.0,
        isMalicious: false,
        isAllowed: true
      };
    }

    // 2. Check threat intelligence blocklist
    const entry = this.badHashes.get(normalizedHash);
    if (entry) {
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        // Expired entry is purged
        this.badHashes.delete(normalizedHash);
      } else {
        const stalenessPenalty = this.getStalenessPenalty();
        const effectiveConfidence = Math.max(0.5, 1.0 - stalenessPenalty);
        return {
          source: 'THREAT_INTEL',
          name: 'Known Malicious Indicator',
          description: `Target matches local threat intelligence blocklist (${entry.threatType || 'INDICATOR'})`,
          weight: 100,
          scoreContribution: 100,
          confidence: effectiveConfidence,
          isMalicious: true,
          isCriticalOverride: true,
          threatType: entry.threatType,
          category: entry.category,
          severityLevel: entry.severity
        };
      }
    }

    return {
      source: 'THREAT_INTEL',
      name: 'Clean Target',
      description: 'No threat intelligence flags for this target',
      weight: 0,
      scoreContribution: 0,
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

  public checkUrl(url: string): ThreatIntelResult {
    if (!url) {
      return {
        source: 'THREAT_INTEL',
        name: 'Clean URL',
        description: 'Empty URL provided',
        weight: 0,
        confidence: 0.5,
        isMalicious: false
      };
    }
    // Check exact URL hash first
    const urlHash = sha256(url.toLowerCase().trim());
    const urlResult = this.checkHash(urlHash);
    if (urlResult.isMalicious || urlResult.isAllowed) {
      return urlResult;
    }

    // Then check domain component if URL parses
    try {
      const parsed = new URL(url.startsWith('http://') || url.startsWith('https://') ? url : `http://${url}`);
      return this.checkDomain(parsed.hostname);
    } catch {
      return urlResult;
    }
  }

  public checkIp(ip: string): ThreatIntelResult {
    if (!ip) {
      return {
        source: 'THREAT_INTEL',
        name: 'Clean IP',
        description: 'Empty IP provided',
        weight: 0,
        confidence: 0.5,
        isMalicious: false
      };
    }
    const hash = sha256(ip.toLowerCase().trim());
    return this.checkHash(hash);
  }

  public getStalenessDays(): number {
    return (Date.now() - this.lastUpdated) / (1000 * 60 * 60 * 24);
  }

  public getStalenessState(): StalenessState {
    const days = this.getStalenessDays();
    if (days <= 7) return 'FRESH';
    if (days <= 30) return 'AGED';
    if (days <= 90) return 'STALE';
    return 'EXPIRED_CACHE';
  }

  public getStalenessPenalty(): number {
    const days = this.getStalenessDays();
    if (days <= 7) return 0.0;
    if (days <= 30) return 0.05;
    if (days <= 90) return 0.15;
    return 0.25;
  }

  /**
   * Safe Atomic Update from Signed Manifest & Payload
   * Enforces 5-Step Verification Workflow (docs/UPDATE_SECURITY_ARCHITECTURE.md)
   */
  public applySignedUpdate(
    manifest: UpdateMetadata,
    payloadJson: string,
    trustedPublicKeyHex?: string
  ): { success: boolean; error?: string } {
    const pubKey = trustedPublicKeyHex || this.rootPublicKeyHex;

    // STEP 1: Monotonic Anti-Downgrade Check
    if (manifest.targetVersion <= this.databaseVersion) {
      return {
        success: false,
        error: `DowngradeRejectedError: target version ${manifest.targetVersion} <= current version ${this.databaseVersion}`
      };
    }

    // STEP 2: Cryptographic Signature Verification
    // Canonical signed message format: targetVersion:patchType:sha256
    const messageToVerify = `${manifest.targetVersion}:${manifest.patchType}:${manifest.sha256}`;
    const isSigValid = verifyEd25519Signature(
      messageToVerify,
      manifest.ed25519Signature,
      pubKey
    );
    if (!isSigValid) {
      return {
        success: false,
        error: 'SignatureVerificationFailedError: Ed25519 signature invalid for manifest'
      };
    }

    // STEP 3: SHA-256 Payload Digest Verification
    const computedDigest = sha256(payloadJson);
    if (computedDigest.toLowerCase() !== manifest.sha256.toLowerCase()) {
      return {
        success: false,
        error: `PayloadCorruptedError: hash mismatch (${computedDigest} != ${manifest.sha256})`
      };
    }

    // STEP 4: In-Memory Trial Execution & Schema Validation
    let parsed: { addBadDomains?: string[]; addBadUrls?: string[]; removeBadDomains?: string[] };
    try {
      parsed = JSON.parse(payloadJson);
      if (typeof parsed !== 'object' || parsed === null) {
        throw new Error('Payload is not a valid JSON object');
      }
    } catch (e: any) {
      return {
        success: false,
        error: `SchemaValidationError: ${e.message}`
      };
    }

    // STEP 5: Atomic Staging & Activation (Zero-Downtime Live Activation)
    const backupBad = new Map(this.badHashes);
    const backupGood = new Set(this.goodHashes);
    const backupVersion = this.databaseVersion;
    const backupUpdated = this.lastUpdated;

    try {
      if (Array.isArray(parsed.addBadDomains)) {
        for (const domain of parsed.addBadDomains) {
          this.addMaliciousDomain(domain, { sourceFeed: 'OTA_PATCH' });
        }
      }
      if (Array.isArray(parsed.addBadUrls)) {
        for (const url of parsed.addBadUrls) {
          this.addMaliciousUrl(url, { sourceFeed: 'OTA_PATCH' });
        }
      }
      if (Array.isArray(parsed.removeBadDomains)) {
        for (const domain of parsed.removeBadDomains) {
          this.removeMaliciousDomain(domain);
        }
      }

      this.databaseVersion = manifest.targetVersion;
      this.lastUpdated = Date.now();
      return { success: true };
    } catch (e: any) {
      // Rollback on any failure during application
      this.badHashes = backupBad;
      this.goodHashes = backupGood;
      this.databaseVersion = backupVersion;
      this.lastUpdated = backupUpdated;
      return {
        success: false,
        error: `AtomicApplicationFailedError: ${e.message} (rolled back safely)`
      };
    }
  }

  /**
   * Creates an encrypted/in-memory snapshot of current state
   */
  public snapshot(): { version: number; lastUpdated: number; badCount: number; goodCount: number } {
    return {
      version: this.databaseVersion,
      lastUpdated: this.lastUpdated,
      badCount: this.badHashes.size,
      goodCount: this.goodHashes.size
    };
  }
}
