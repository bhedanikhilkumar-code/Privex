import { sha256, verifyEd25519Signature } from '../utils/crypto';
import { BloomFilter } from './bloom-filter';
import {
  DetectorLayer,
  DetectorType,
  Evidence,
  HashDisposition,
  HashLookupResult,
  RiskCategory,
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
  threatName?: string;
  isCritical?: boolean;
}

export interface ThreatIntelResult extends Evidence {
  isMalicious: boolean;
  isAllowed?: boolean;
  status?: HashDisposition;
  disposition?: HashDisposition;
  threatType?: 'DOMAIN' | 'URL' | 'IP' | 'HASH';
  threatName?: string;
  category?: RiskCategory | string;
  severityLevel?: SeverityLevel | string;
  bloomFilterHit?: boolean;
}

export type StalenessState = 'FRESH' | 'AGED' | 'STALE' | 'EXPIRED_CACHE';

/**
 * Canonical Phase B Hash Precedence Policy (Step 6):
 * 1. Critical Malicious Hash Intelligence (`KNOWN_BAD` with `isCritical: true`, e.g. EICAR and confirmed malware SHA-256)
 *    takes strict precedence over standard user allowlists so critical malware cannot be masked by allowlist abuse,
 *    UNLESS the caller/policy explicitly grants `allowCriticalOverride: true` (e.g. friction-gated forensic restore).
 * 2. Verified Domain/URL Allowlists (`goodHashes`) and non-critical file allowlists (`fileAllowlist`) return `KNOWN_GOOD`.
 * 3. Unrecognized hashes or Bloom-filter-only false positives (where `bloomFilter.has(h)` is true but `badHashes.get(h)` is absent)
 *    explicitly return `UNKNOWN` (`isMalicious: false, isAllowed: false`) — NEVER `KNOWN_GOOD`.
 */
export class ThreatIntel {
  public static readonly EICAR_SHA256 =
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

  public static readonly SYNTHETIC_MALWARE_HASHES: ReadonlyArray<{
    hash: string;
    threatName: string;
    category: RiskCategory;
    severity: SeverityLevel;
  }> = [
    {
      hash: ThreatIntel.EICAR_SHA256,
      threatName: 'EICAR_TEST_FILE',
      category: RiskCategory.MALWARE,
      severity: SeverityLevel.CRITICAL
    },
    {
      hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b801',
      threatName: 'SYNTHETIC_TROJAN_DROPPER_A',
      category: RiskCategory.MALWARE,
      severity: SeverityLevel.CRITICAL
    },
    {
      hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff02',
      threatName: 'SYNTHETIC_RANSOMWARE_SIM_B',
      category: RiskCategory.EXTORTION,
      severity: SeverityLevel.CRITICAL
    },
    {
      hash: 'deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef',
      threatName: 'SYNTHETIC_CREDENTIAL_STEALER_C',
      category: RiskCategory.MALWARE,
      severity: SeverityLevel.HIGH
    }
  ];

  private static sharedInstance: ThreatIntel | null = null;

  public static getSharedInstance(): ThreatIntel {
    if (!ThreatIntel.sharedInstance) {
      ThreatIntel.sharedInstance = new ThreatIntel();
    }
    return ThreatIntel.sharedInstance;
  }

  public static resetSharedInstance(): void {
    ThreatIntel.sharedInstance = null;
  }

  private badHashes: Map<string, ThreatIntelEntry> = new Map();
  private goodHashes: Set<string> = new Set();
  private fileAllowlist: Set<string> = new Set();
  private criticalOverrideAllowlist: Set<string> = new Set();
  private bloomFilter: BloomFilter;
  private lastUpdated: number;
  private databaseVersion: number = 101;
  private versionSequence: number = 100;
  private installedVersion: string = '1.0.0-seed';
  private rootPublicKeyHex: string;

  constructor(options?: {
    rootPublicKeyHex?: string;
    initialVersion?: number;
    initialSequence?: number;
    installedVersion?: string;
  }) {
    this.lastUpdated = Date.now();
    this.databaseVersion = options?.initialVersion ?? 101;
    this.versionSequence = options?.initialSequence ?? 100;
    this.installedVersion = options?.installedVersion ?? '1.0.0-seed';
    // Standard compiled Root Ed25519 Public Key (can be overridden in options for testing)
    this.rootPublicKeyHex = options?.rootPublicKeyHex ?? '00'.repeat(32);
    this.bloomFilter = new BloomFilter({ expectedElements: 100000, targetFalsePositiveRate: 0.001 });
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

    badSeeds.forEach((domain) => {
      this.addMaliciousDomain(domain, {
        category: RiskCategory.PHISHING,
        severity: SeverityLevel.HIGH
      });
    });

    const badUrls = [
      'http://secure-paypa1.com/login?token=urgent',
      'https://amaz0n-verify.tk/account/billing'
    ];
    badUrls.forEach((url) => {
      this.addMaliciousUrl(url);
    });

    const badIps = [
      '198.51.100.23', // RFC 5737 TEST-NET-2 known botnet C2 fixture
      '203.0.113.88'
    ];
    badIps.forEach((ip) => {
      this.addMaliciousIp(ip);
    });

    // Seed canonical EICAR SHA-256 and deterministic synthetic test malware hashes
    for (const seed of ThreatIntel.SYNTHETIC_MALWARE_HASHES) {
      this.addMaliciousHash(seed.hash, {
        category: seed.category,
        severity: seed.severity,
        threatType: 'HASH',
        threatName: seed.threatName,
        sourceFeed: 'CORE_SEED_MALWARE_DB',
        isCritical: true
      });
    }

    const goodSeeds = [
      'google.com',
      'paypal.com',
      'apple.com',
      'microsoft.com',
      'github.com',
      'cloudflare.com',
      'wikipedia.org'
    ];

    goodSeeds.forEach((domain) => {
      this.addAllowedDomain(domain);
    });
  }

  public getVersion(): number {
    return this.databaseVersion;
  }

  public getRecord(): ThreatIntelRecord {
    return {
      databaseVersion: this.databaseVersion,
      filterType: 'BLOOM_FILTER_V1',
      capacity: this.bloomFilter.capacity,
      falsePositiveRate: this.bloomFilter.getFalsePositiveRate() || 0.0001,
      generatedEpoch: this.lastUpdated
    };
  }

  public getBloomFilter(): BloomFilter {
    return this.bloomFilter;
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
    this.bloomFilter.add(hash);
    this.badHashes.set(hash, {
      hash,
      expiresAt,
      category: options?.category || RiskCategory.PHISHING,
      severity: options?.severity || SeverityLevel.HIGH,
      sourceFeed: options?.sourceFeed || 'SEED_BLOCKLIST',
      threatType: 'DOMAIN',
      isCritical: false
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
    this.bloomFilter.add(hash);
    this.badHashes.set(hash, {
      hash,
      expiresAt,
      category: options?.category || RiskCategory.PHISHING,
      severity: options?.severity || SeverityLevel.CRITICAL,
      sourceFeed: options?.sourceFeed || 'URL_FEED',
      threatType: 'URL',
      isCritical: false
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
    this.bloomFilter.add(hash);
    this.badHashes.set(hash, {
      hash,
      expiresAt,
      category: options?.category || RiskCategory.MALWARE,
      severity: options?.severity || SeverityLevel.CRITICAL,
      sourceFeed: options?.sourceFeed || 'IP_C2_FEED',
      threatType: 'IP',
      isCritical: true
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

  /**
   * Adds a SHA-256 file hash to the trusted local file allowlist.
   * By default, user allowlist entries cannot override critical malware signatures (`isCritical: true`)
   * unless `options.allowCriticalOverride === true` is explicitly passed under documented policy.
   */
  public addAllowedHash(
    hash: string,
    options?: { allowCriticalOverride?: boolean }
  ): void {
    if (!hash || typeof hash !== 'string') return;
    const normalized = hash.toLowerCase().trim();
    if (!normalized) return;
    this.fileAllowlist.add(normalized);
    this.goodHashes.add(normalized);
    if (options?.allowCriticalOverride === true) {
      this.criticalOverrideAllowlist.add(normalized);
    }
  }

  public removeAllowedHash(hash: string): void {
    if (!hash || typeof hash !== 'string') return;
    const normalized = hash.toLowerCase().trim();
    this.fileAllowlist.delete(normalized);
    this.goodHashes.delete(normalized);
    this.criticalOverrideAllowlist.delete(normalized);
  }

  public isHashAllowed(hash: string): boolean {
    if (!hash || typeof hash !== 'string') return false;
    const normalized = hash.toLowerCase().trim();
    return this.fileAllowlist.has(normalized) || this.goodHashes.has(normalized);
  }

  public isAllowed(target: string): boolean {
    if (!target || typeof target !== 'string') return false;
    const trimmed = target.toLowerCase().trim();
    if (BloomFilter.isSha256Hex(trimmed) && this.goodHashes.has(trimmed)) {
      return true;
    }
    const hash = sha256(trimmed);
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
      threatName?: string;
      sourceFeed?: string;
      isCritical?: boolean;
    }
  ): void {
    if (!hash || typeof hash !== 'string') return;
    const normalized = hash.toLowerCase().trim();
    if (!normalized) return;
    const expiresAt = options?.ttl !== undefined ? Date.now() + options.ttl : undefined;
    const threatType = options?.threatType || 'HASH';
    this.bloomFilter.add(normalized);
    this.badHashes.set(normalized, {
      hash: normalized,
      expiresAt,
      category:
        options?.category ||
        (threatType === 'HASH' ? RiskCategory.MALWARE : RiskCategory.PHISHING),
      severity:
        options?.severity ||
        (threatType === 'HASH' ? SeverityLevel.CRITICAL : SeverityLevel.HIGH),
      threatType,
      threatName: options?.threatName,
      sourceFeed: options?.sourceFeed || 'LOCAL_HASH_INTEL',
      isCritical: options?.isCritical ?? (threatType === 'HASH')
    });
    this.lastUpdated = Date.now();
  }

  /**
   * Canonical O(1) SHA-256 Hash Intelligence Lookup (Phase B Steps 4 & 6).
   * Returns explicit KNOWN_GOOD, KNOWN_BAD, or UNKNOWN state.
   * Never defaults an unrecognized hash or Bloom-filter-only hit to KNOWN_GOOD or KNOWN_BAD.
   */
  public lookupHash(
    hash: string,
    options?: { allowUserOverrideOnCritical?: boolean }
  ): HashLookupResult {
    if (!hash || typeof hash !== 'string') {
      return {
        hash: '',
        status: 'UNKNOWN',
        disposition: 'UNKNOWN',
        isMalicious: false,
        isAllowed: false,
        confidence: 0,
        bloomFilterHit: false
      };
    }

    const normalizedHash = hash.toLowerCase().trim();
    if (!normalizedHash) {
      return {
        hash: '',
        status: 'UNKNOWN',
        disposition: 'UNKNOWN',
        isMalicious: false,
        isAllowed: false,
        confidence: 0,
        bloomFilterHit: false
      };
    }

    const isInGoodList =
      this.fileAllowlist.has(normalizedHash) || this.goodHashes.has(normalizedHash);
    const hasCriticalOverrideGrant =
      options?.allowUserOverrideOnCritical === true ||
      this.criticalOverrideAllowlist.has(normalizedHash);

    // Check Bloom Filter fast-path
    const bloomHit = this.bloomFilter.has(normalizedHash);
    if (bloomHit) {
      const entry = this.badHashes.get(normalizedHash);
      if (entry) {
        if (entry.expiresAt && Date.now() > entry.expiresAt) {
          this.badHashes.delete(normalizedHash);
        } else {
          // Precedence check:
          // Domain/URL entries or non-critical entries yield to goodHashes allowlist.
          // Critical HASH entries (isCritical === true) ONLY yield if explicit critical override policy is granted.
          const isCriticalHashEntry = entry.threatType === 'HASH' && entry.isCritical !== false;
          if (isInGoodList && (!isCriticalHashEntry || hasCriticalOverrideGrant)) {
            return {
              hash: normalizedHash,
              status: 'KNOWN_GOOD',
              disposition: 'KNOWN_GOOD',
              isMalicious: false,
              isAllowed: true,
              confidence: 1.0,
              bloomFilterHit: true,
              evidence: {
                ruleId: 'threat-intel-allowlist',
                detectorType: DetectorType.THREAT_INTEL,
                detectorLayer: DetectorLayer.HASH_INTEL,
                source: 'THREAT_INTEL',
                name: 'Known Good Indicator',
                description: 'Target matches verified local allowlist',
                reason: 'Target matches verified local allowlist',
                severityLevel: SeverityLevel.NONE,
                weight: 0,
                scoreContribution: 0,
                confidence: 1.0,
                isAllowed: true,
                isMalicious: false
              }
            };
          }

          const stalenessPenalty = this.getStalenessPenalty();
          const effectiveConfidence = Math.max(0.5, 1.0 - stalenessPenalty);
          const threatName = entry.threatName || 'KNOWN_MALICIOUS_INDICATOR';
          const desc = `Target matches local threat intelligence blocklist (${entry.threatType || 'INDICATOR'}: ${threatName})`;
          return {
            hash: normalizedHash,
            status: 'KNOWN_BAD',
            disposition: 'KNOWN_BAD',
            isMalicious: true,
            isAllowed: false,
            isCritical: isCriticalHashEntry,
            threatName,
            category: entry.category || RiskCategory.MALWARE,
            severityLevel: entry.severity || SeverityLevel.CRITICAL,
            sourceFeed: entry.sourceFeed,
            confidence: effectiveConfidence,
            bloomFilterHit: true,
            evidence: {
              ruleId: 'threat-intel-known-bad',
              detectorType: DetectorType.THREAT_INTEL,
              detectorLayer: DetectorLayer.HASH_INTEL,
              source: 'THREAT_INTEL',
              name: 'Known Malicious Indicator',
              description: desc,
              reason: desc,
              severityLevel: entry.severity || SeverityLevel.CRITICAL,
              weight: 100,
              scoreContribution: 100,
              confidence: effectiveConfidence,
              isCriticalOverride: true,
              isMalicious: true,
              isAllowed: false
            }
          };
        }
      }
    }

    if (isInGoodList) {
      return {
        hash: normalizedHash,
        status: 'KNOWN_GOOD',
        disposition: 'KNOWN_GOOD',
        isMalicious: false,
        isAllowed: true,
        confidence: 1.0,
        bloomFilterHit: bloomHit,
        evidence: {
          ruleId: 'threat-intel-allowlist',
          detectorType: DetectorType.THREAT_INTEL,
          detectorLayer: DetectorLayer.HASH_INTEL,
          source: 'THREAT_INTEL',
          name: 'Known Good Indicator',
          description: 'Target matches verified local allowlist',
          reason: 'Target matches verified local allowlist',
          severityLevel: SeverityLevel.NONE,
          weight: 0,
          scoreContribution: 0,
          confidence: 1.0,
          isAllowed: true,
          isMalicious: false
        }
      };
    }

    // Explicit UNKNOWN state (including when bloomHit === true due to Bloom filter false positive)
    return {
      hash: normalizedHash,
      status: 'UNKNOWN',
      disposition: 'UNKNOWN',
      isMalicious: false,
      isAllowed: false,
      confidence: 0.5,
      bloomFilterHit: bloomHit
    };
  }

  public checkHash(
    hash: string,
    options?: { allowUserOverrideOnCritical?: boolean }
  ): ThreatIntelResult {
    const lookup = this.lookupHash(hash, options);

    if (lookup.status === 'KNOWN_GOOD') {
      return {
        ruleId: 'threat-intel-allowlist',
        detectorType: DetectorType.THREAT_INTEL,
        detectorLayer: DetectorLayer.HASH_INTEL,
        source: 'THREAT_INTEL',
        name: 'Known Good Domain',
        description: 'Target is on the verified local allowlist',
        weight: 0,
        scoreContribution: 0,
        confidence: 1.0,
        isMalicious: false,
        isAllowed: true,
        status: 'KNOWN_GOOD',
        disposition: 'KNOWN_GOOD',
        bloomFilterHit: lookup.bloomFilterHit
      };
    }

    if (lookup.status === 'KNOWN_BAD') {
      const entry = this.badHashes.get(lookup.hash);
      return {
        ruleId: 'threat-intel-known-bad',
        detectorType: DetectorType.THREAT_INTEL,
        detectorLayer: DetectorLayer.HASH_INTEL,
        source: 'THREAT_INTEL',
        name: 'Known Malicious Indicator',
        description: `Target matches local threat intelligence blocklist (${entry?.threatType || 'INDICATOR'})`,
        weight: 100,
        scoreContribution: 100,
        confidence: lookup.confidence,
        isMalicious: true,
        isAllowed: false,
        isCriticalOverride: true,
        status: 'KNOWN_BAD',
        disposition: 'KNOWN_BAD',
        threatType: entry?.threatType,
        threatName: lookup.threatName,
        category: lookup.category,
        severityLevel: lookup.severityLevel,
        bloomFilterHit: true
      };
    }

    return {
      ruleId: 'threat-intel-unknown',
      detectorType: DetectorType.THREAT_INTEL,
      detectorLayer: DetectorLayer.HASH_INTEL,
      source: 'THREAT_INTEL',
      name: 'Clean Target',
      description: 'No threat intelligence flags for this target',
      weight: 0,
      scoreContribution: 0,
      confidence: 0.5,
      isMalicious: false,
      isAllowed: false,
      status: 'UNKNOWN',
      disposition: 'UNKNOWN',
      bloomFilterHit: lookup.bloomFilterHit
    };
  }

  public checkDomain(domain: string): ThreatIntelResult {
    if (!domain || typeof domain !== 'string' || !domain.trim()) {
      return {
        source: 'THREAT_INTEL',
        name: 'Clean Domain',
        description: 'Empty domain provided',
        weight: 0,
        confidence: 0.5,
        isMalicious: false,
        status: 'UNKNOWN',
        disposition: 'UNKNOWN'
      };
    }
    const hash = sha256(domain.toLowerCase().trim());
    return this.checkHash(hash);
  }

  public checkUrl(url: string): ThreatIntelResult {
    if (!url || typeof url !== 'string' || !url.trim()) {
      return {
        source: 'THREAT_INTEL',
        name: 'Clean URL',
        description: 'Empty URL provided',
        weight: 0,
        confidence: 0.5,
        isMalicious: false,
        status: 'UNKNOWN',
        disposition: 'UNKNOWN'
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
      const parsed = new URL(
        url.startsWith('http://') || url.startsWith('https://') ? url : `http://${url}`
      );
      return this.checkDomain(parsed.hostname);
    } catch {
      return urlResult;
    }
  }

  public checkIp(ip: string): ThreatIntelResult {
    if (!ip || typeof ip !== 'string' || !ip.trim()) {
      return {
        source: 'THREAT_INTEL',
        name: 'Clean IP',
        description: 'Empty IP provided',
        weight: 0,
        confidence: 0.5,
        isMalicious: false,
        status: 'UNKNOWN',
        disposition: 'UNKNOWN'
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
    const backupFilterBytes = this.bloomFilter.serialize();
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
      this.bloomFilter = BloomFilter.deserialize(backupFilterBytes);
      this.databaseVersion = backupVersion;
      this.lastUpdated = backupUpdated;
      return {
        success: false,
        error: `AtomicApplicationFailedError: ${e.message} (rolled back safely)`
      };
    }
  }

  public getVersionSequence(): number {
    return this.versionSequence;
  }

  public setVersionSequence(seq: number): void {
    if (typeof seq === 'number' && Number.isInteger(seq) && seq > 0) {
      this.versionSequence = seq;
    }
  }

  public getInstalledVersion(): string {
    return this.installedVersion;
  }

  public setInstalledVersion(ver: string): void {
    if (typeof ver === 'string' && ver.trim()) {
      this.installedVersion = ver.trim();
    }
  }

  public setDatabaseVersion(ver: number): void {
    if (typeof ver === 'number' && Number.isInteger(ver) && ver > 0) {
      this.databaseVersion = ver;
    }
  }

  public getBadHashesCount(): number {
    return this.badHashes.size;
  }

  public getGoodHashesCount(): number {
    return this.goodHashes.size;
  }

  public removeMaliciousHash(hash: string): void {
    if (!hash || typeof hash !== 'string') return;
    const normalized = hash.toLowerCase().trim();
    this.badHashes.delete(normalized);
  }

  public removeMaliciousUrl(url: string): void {
    if (!url || typeof url !== 'string') return;
    const hash = sha256(url.toLowerCase().trim());
    this.badHashes.delete(hash);
  }

  public removeMaliciousIp(ip: string): void {
    if (!ip || typeof ip !== 'string') return;
    const hash = sha256(ip.toLowerCase().trim());
    this.badHashes.delete(hash);
  }

  /**
   * Resets this ThreatIntel instance to the immutable compiled-in factory seed dataset.
   */
  public resetToFactorySeed(): void {
    this.badHashes.clear();
    this.goodHashes.clear();
    this.fileAllowlist.clear();
    this.criticalOverrideAllowlist.clear();
    this.bloomFilter = new BloomFilter({ expectedElements: 100000, targetFalsePositiveRate: 0.001 });
    this.databaseVersion = 101;
    this.versionSequence = 100;
    this.installedVersion = '1.0.0-seed';
    this.lastUpdated = Date.now();
    this.loadSeedData();
  }

  /**
   * Applies an offline PPDB payload to the active threat intelligence state.
   */
  public applyPpdbPayload(
    payload: any,
    newVersion: string,
    newSequence: number,
    publishedAt?: number
  ): { success: boolean; error?: string } {
    if (!payload || typeof payload !== 'object') {
      return { success: false, error: 'Invalid PPDB payload: payload must be an object' };
    }

    const backupBad = new Map(this.badHashes);
    const backupGood = new Set(this.goodHashes);
    const backupFilterBytes = this.bloomFilter.serialize();
    const backupVersion = this.databaseVersion;
    const backupSequence = this.versionSequence;
    const backupInstalled = this.installedVersion;
    const backupUpdated = this.lastUpdated;

    try {
      const hashesToAdd = Array.isArray(payload.addBadHashes)
        ? payload.addBadHashes
        : (Array.isArray(payload.maliciousHashes) ? payload.maliciousHashes : []);

      for (const entry of hashesToAdd) {
        if (entry && typeof entry.hash === 'string') {
          this.addMaliciousHash(entry.hash, {
            threatName: entry.threatName || 'MALICIOUS_HASH_INDICATOR',
            category: entry.category,
            severity: entry.severity,
            threatType: entry.threatType || 'HASH',
            isCritical: entry.isCritical ?? true,
            sourceFeed: 'PPDB_OTA_UPDATE'
          });
        }
      }

      const domainsToAdd = Array.isArray(payload.addBadDomains)
        ? payload.addBadDomains
        : (Array.isArray(payload.maliciousDomains) ? payload.maliciousDomains : []);
      for (const domain of domainsToAdd) {
        if (typeof domain === 'string') {
          this.addMaliciousDomain(domain, { sourceFeed: 'PPDB_OTA_UPDATE' });
        }
      }

      const urlsToAdd = Array.isArray(payload.addBadUrls)
        ? payload.addBadUrls
        : (Array.isArray(payload.maliciousUrls) ? payload.maliciousUrls : []);
      for (const url of urlsToAdd) {
        if (typeof url === 'string') {
          this.addMaliciousUrl(url, { sourceFeed: 'PPDB_OTA_UPDATE' });
        }
      }

      const ipsToAdd = Array.isArray(payload.addBadIps)
        ? payload.addBadIps
        : (Array.isArray(payload.maliciousIps) ? payload.maliciousIps : []);
      for (const ip of ipsToAdd) {
        if (typeof ip === 'string') {
          this.addMaliciousIp(ip, { sourceFeed: 'PPDB_OTA_UPDATE' });
        }
      }

      const hashesToRemove = Array.isArray(payload.removeBadHashes)
        ? payload.removeBadHashes
        : (Array.isArray(payload.removeMaliciousHashes) ? payload.removeMaliciousHashes : []);
      for (const hash of hashesToRemove) {
        if (typeof hash === 'string') {
          this.removeMaliciousHash(hash);
        }
      }

      const domainsToRemove = Array.isArray(payload.removeBadDomains)
        ? payload.removeBadDomains
        : (Array.isArray(payload.removeMaliciousDomains) ? payload.removeMaliciousDomains : []);
      for (const domain of domainsToRemove) {
        if (typeof domain === 'string') {
          this.removeMaliciousDomain(domain);
        }
      }

      const urlsToRemove = Array.isArray(payload.removeBadUrls)
        ? payload.removeBadUrls
        : (Array.isArray(payload.removeMaliciousUrls) ? payload.removeMaliciousUrls : []);
      for (const url of urlsToRemove) {
        if (typeof url === 'string') {
          this.removeMaliciousUrl(url);
        }
      }

      const ipsToRemove = Array.isArray(payload.removeBadIps)
        ? payload.removeBadIps
        : (Array.isArray(payload.removeMaliciousIps) ? payload.removeMaliciousIps : []);
      for (const ip of ipsToRemove) {
        if (typeof ip === 'string') {
          this.removeMaliciousIp(ip);
        }
      }

      this.databaseVersion = newSequence;
      this.versionSequence = newSequence;
      this.installedVersion = newVersion;
      this.lastUpdated = publishedAt && publishedAt > 0 ? publishedAt : Date.now();
      return { success: true };
    } catch (err: any) {
      // Rollback to pristine state
      this.badHashes = backupBad;
      this.goodHashes = backupGood;
      this.bloomFilter = BloomFilter.deserialize(backupFilterBytes);
      this.databaseVersion = backupVersion;
      this.versionSequence = backupSequence;
      this.installedVersion = backupInstalled;
      this.lastUpdated = backupUpdated;
      return { success: false, error: `Payload application failed: ${err.message}` };
    }
  }

  /**
   * Serializes current threat intelligence state to a JSON string.
   */
  public exportState(): string {
    return JSON.stringify({
      databaseVersion: this.databaseVersion,
      versionSequence: this.versionSequence,
      installedVersion: this.installedVersion,
      lastUpdated: this.lastUpdated,
      badHashes: Array.from(this.badHashes.entries()),
      goodHashes: Array.from(this.goodHashes),
      fileAllowlist: Array.from(this.fileAllowlist),
      criticalOverrideAllowlist: Array.from(this.criticalOverrideAllowlist),
      bloomFilterBytes: Buffer.from(this.bloomFilter.serialize()).toString('base64')
    });
  }

  /**
   * Restores threat intelligence state from a serialized JSON string.
   */
  public loadState(serializedJson: string): void {
    if (!serializedJson || typeof serializedJson !== 'string') {
      throw new Error('Invalid serialized state: must be a non-empty string');
    }
    const parsed = JSON.parse(serializedJson);
    this.databaseVersion = typeof parsed.databaseVersion === 'number' ? parsed.databaseVersion : 101;
    this.versionSequence = typeof parsed.versionSequence === 'number' ? parsed.versionSequence : 100;
    this.installedVersion = typeof parsed.installedVersion === 'string' ? parsed.installedVersion : '1.0.0-seed';
    this.lastUpdated = typeof parsed.lastUpdated === 'number' ? parsed.lastUpdated : Date.now();

    this.badHashes = new Map(parsed.badHashes || []);
    this.goodHashes = new Set(parsed.goodHashes || []);
    this.fileAllowlist = new Set(parsed.fileAllowlist || []);
    this.criticalOverrideAllowlist = new Set(parsed.criticalOverrideAllowlist || []);

    if (parsed.bloomFilterBytes) {
      const buf = Buffer.from(parsed.bloomFilterBytes, 'base64');
      this.bloomFilter = BloomFilter.deserialize(new Uint8Array(buf));
    }
  }

  /**
   * Creates an encrypted/in-memory snapshot of current state
   */
  public snapshot(): {
    version: number;
    versionSequence: number;
    installedVersion: string;
    lastUpdated: number;
    badCount: number;
    goodCount: number;
    bloomFilterBits: number;
    bloomFilterElements: number;
  } {
    return {
      version: this.databaseVersion,
      versionSequence: this.versionSequence,
      installedVersion: this.installedVersion,
      lastUpdated: this.lastUpdated,
      badCount: this.badHashes.size,
      goodCount: this.goodHashes.size,
      bloomFilterBits: this.bloomFilter.sizeBits,
      bloomFilterElements: this.bloomFilter.elementCount
    };
  }
}

