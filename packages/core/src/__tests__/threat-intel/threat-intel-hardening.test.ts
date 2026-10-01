import { describe, it, expect, beforeEach } from 'vitest';
import { ThreatIntel } from '../../threat-intel/threat-intel';
import { ThreatIntelUpdater, UpdateProvider } from '../../threat-intel/threat-intel-updater';
import { generateEd25519KeyPair, signEd25519, sha256 } from '../../utils/crypto';
import { RiskCategory, SeverityLevel, UpdateMetadata } from '../../types';

describe('ThreatIntel Hardening & Precedence (Phase 2)', () => {
  let threatIntel: ThreatIntel;
  let keyPair: { publicKeyHex: string; privateKey: any };

  beforeEach(() => {
    keyPair = generateEd25519KeyPair();
    threatIntel = new ThreatIntel({
      rootPublicKeyHex: keyPair.publicKeyHex,
      initialVersion: 100
    });
  });

  it('should support URL hash and domain fallback lookups', () => {
    threatIntel.addMaliciousUrl('https://evil-phish.xyz/login/verify');
    
    // Direct exact URL check
    const urlHit = threatIntel.checkUrl('https://evil-phish.xyz/login/verify');
    expect(urlHit.isMalicious).toBe(true);
    expect(urlHit.weight).toBe(100);

    // Domain check fallback when URL not in database but domain is
    threatIntel.addMaliciousDomain('bad-domain.cc');
    const domainFallbackHit = threatIntel.checkUrl('http://bad-domain.cc/some/subpath');
    expect(domainFallbackHit.isMalicious).toBe(true);
  });

  it('should support malicious IP lookups', () => {
    threatIntel.addMaliciousIp('198.51.100.99', {
      category: RiskCategory.MALWARE,
      severity: SeverityLevel.CRITICAL
    });

    const ipResult = threatIntel.checkIp('198.51.100.99');
    expect(ipResult.isMalicious).toBe(true);
    expect(ipResult.threatType).toBe('IP');
    expect(ipResult.category).toBe(RiskCategory.MALWARE);

    const cleanIp = threatIntel.checkIp('8.8.8.8');
    expect(cleanIp.isMalicious).toBe(false);
  });

  it('should give explicit allowlist absolute precedence over blocklist', () => {
    // Both allowlist and blocklist contain the same domain
    const target = 'partner-service.com';
    threatIntel.addMaliciousDomain(target);
    threatIntel.addAllowedDomain(target);

    const check = threatIntel.checkDomain(target);
    expect(check.isMalicious).toBe(false);
    expect(check.isAllowed).toBe(true);
    expect(check.name).toBe('Known Good Domain');
    expect(check.weight).toBe(0);
  });

  it('should correctly purge expired TTL entries', () => {
    const expiringDomain = 'temp-threat.top';
    // Add domain with negative TTL (already expired)
    threatIntel.addMaliciousDomain(expiringDomain, { ttl: -1000 });

    const result = threatIntel.checkDomain(expiringDomain);
    expect(result.isMalicious).toBe(false);
    expect(result.name).toBe('Clean Target');
  });

  it('should report correct staleness state and penalty', () => {
    expect(threatIntel.getStalenessState()).toBe('FRESH');
    expect(threatIntel.getStalenessPenalty()).toBe(0.0);
  });

  it('should verify and apply Ed25519 signed OTA updates atomically', () => {
    const payload = JSON.stringify({
      addBadDomains: ['newly-discovered-threat.info'],
      addBadUrls: ['https://newly-discovered-threat.info/claim']
    });
    const payloadHash = sha256(payload);
    const targetVersion = 105;
    const message = `${targetVersion}:BLOOM_DIFF:${payloadHash}`;
    const signature = signEd25519(message, keyPair.privateKey);

    const manifest: UpdateMetadata = {
      targetVersion,
      baseVersion: 100,
      patchType: 'BLOOM_DIFF',
      sha256: payloadHash,
      ed25519Signature: signature,
      downloadUrl: 'https://cdn.example.com/patches/diff.json',
      sizeBytes: Buffer.byteLength(payload)
    };

    const updateResult = threatIntel.applySignedUpdate(manifest, payload, keyPair.publicKeyHex);
    expect(updateResult.success).toBe(true);
    expect(threatIntel.getVersion()).toBe(105);

    // Verify newly added domain is now detected
    const check = threatIntel.checkDomain('newly-discovered-threat.info');
    expect(check.isMalicious).toBe(true);
  });

  it('should reject anti-downgrade versions (targetVersion <= currentVersion)', () => {
    const payload = JSON.stringify({ addBadDomains: ['stale.org'] });
    const payloadHash = sha256(payload);
    const manifest: UpdateMetadata = {
      targetVersion: 99, // Lower than 100
      baseVersion: 90,
      patchType: 'BLOOM_DIFF',
      sha256: payloadHash,
      ed25519Signature: 'aa'.repeat(64),
      downloadUrl: 'https://cdn.example.com/patch.json',
      sizeBytes: 50
    };

    const result = threatIntel.applySignedUpdate(manifest, payload, keyPair.publicKeyHex);
    expect(result.success).toBe(false);
    expect(result.error).toContain('DowngradeRejectedError');
    expect(threatIntel.getVersion()).toBe(100);
  });

  it('should reject updates with invalid Ed25519 signatures', () => {
    const payload = JSON.stringify({ addBadDomains: ['bad.org'] });
    const payloadHash = sha256(payload);
    const manifest: UpdateMetadata = {
      targetVersion: 102,
      baseVersion: 100,
      patchType: 'BLOOM_DIFF',
      sha256: payloadHash,
      ed25519Signature: '00'.repeat(64), // Invalid signature
      downloadUrl: 'https://cdn.example.com/patch.json',
      sizeBytes: 50
    };

    const result = threatIntel.applySignedUpdate(manifest, payload, keyPair.publicKeyHex);
    expect(result.success).toBe(false);
    expect(result.error).toContain('SignatureVerificationFailedError');
    expect(threatIntel.getVersion()).toBe(100);
  });

  it('should reject updates with corrupted payload hashes', () => {
    const payload = JSON.stringify({ addBadDomains: ['tampered.org'] });
    const fakeHash = sha256('different-content');
    const message = `102:BLOOM_DIFF:${fakeHash}`;
    const signature = signEd25519(message, keyPair.privateKey);

    const manifest: UpdateMetadata = {
      targetVersion: 102,
      baseVersion: 100,
      patchType: 'BLOOM_DIFF',
      sha256: fakeHash,
      ed25519Signature: signature,
      downloadUrl: 'https://cdn.example.com/patch.json',
      sizeBytes: 50
    };

    const result = threatIntel.applySignedUpdate(manifest, payload, keyPair.publicKeyHex);
    expect(result.success).toBe(false);
    expect(result.error).toContain('PayloadCorruptedError');
  });

  it('should update via ThreatIntelUpdater provider abstraction', async () => {
    const updater = new ThreatIntelUpdater(threatIntel, keyPair.publicKeyHex);

    const payload = JSON.stringify({ addBadDomains: ['via-updater.com'] });
    const payloadHash = sha256(payload);
    const targetVersion = 110;
    const message = `${targetVersion}:BLOOM_DIFF:${payloadHash}`;
    const signature = signEd25519(message, keyPair.privateKey);

    const mockProvider: UpdateProvider = {
      fetchManifest: async () => ({
        targetVersion,
        baseVersion: 100,
        patchType: 'BLOOM_DIFF',
        sha256: payloadHash,
        ed25519Signature: signature,
        downloadUrl: 'https://cdn.test/patch.json',
        sizeBytes: 40
      }),
      fetchPatch: async () => payload
    };

    const res = await updater.checkAndUpdate(mockProvider);
    expect(res.updated).toBe(true);
    expect(res.newVersion).toBe(110);
    expect(threatIntel.checkDomain('via-updater.com').isMalicious).toBe(true);
  });

  it('should handle updater provider failure cases gracefully', async () => {
    const updater = new ThreatIntelUpdater(threatIntel, keyPair.publicKeyHex);

    // 1. fetchManifest returns null
    const nullManifestProvider: UpdateProvider = {
      fetchManifest: async () => null,
      fetchPatch: async () => null
    };
    const nullManifestRes = await updater.checkAndUpdate(nullManifestProvider);
    expect(nullManifestRes.updated).toBe(false);

    // 2. targetVersion <= currentVersion
    const staleProvider: UpdateProvider = {
      fetchManifest: async () => ({
        targetVersion: 100,
        baseVersion: 90,
        patchType: 'BLOOM_DIFF',
        sha256: 'abc',
        ed25519Signature: 'sig',
        downloadUrl: 'url',
        sizeBytes: 10
      }),
      fetchPatch: async () => 'data'
    };
    const staleRes = await updater.checkAndUpdate(staleProvider);
    expect(staleRes.updated).toBe(false);
    expect(staleRes.error).toContain('DowngradeRejectedError');

    // 3. fetchPatch returns null
    const noPatchProvider: UpdateProvider = {
      fetchManifest: async () => ({
        targetVersion: 105,
        baseVersion: 100,
        patchType: 'BLOOM_DIFF',
        sha256: 'abc',
        ed25519Signature: 'sig',
        downloadUrl: 'url',
        sizeBytes: 10
      }),
      fetchPatch: async () => null
    };
    const noPatchRes = await updater.checkAndUpdate(noPatchProvider);
    expect(noPatchRes.updated).toBe(false);
    expect(noPatchRes.error).toContain('NetworkUnavailableError');

    // 4. Provider throws unexpected exception
    const throwingProvider: UpdateProvider = {
      fetchManifest: async () => { throw new Error('Simulated network timeout'); },
      fetchPatch: async () => null
    };
    const throwingRes = await updater.checkAndUpdate(throwingProvider);
    expect(throwingRes.updated).toBe(false);
    expect(throwingRes.error).toContain('UnexpectedUpdateError');
  });

  it('should reject invalid JSON schema payloads during atomic update', () => {
    const invalidPayload = 'not a valid json string {[';
    const payloadHash = sha256(invalidPayload);
    const targetVersion = 104;
    const message = `${targetVersion}:BLOOM_DIFF:${payloadHash}`;
    const signature = signEd25519(message, keyPair.privateKey);

    const manifest: UpdateMetadata = {
      targetVersion,
      baseVersion: 100,
      patchType: 'BLOOM_DIFF',
      sha256: payloadHash,
      ed25519Signature: signature,
      downloadUrl: 'https://cdn.test/patch.json',
      sizeBytes: 20
    };

    const res = threatIntel.applySignedUpdate(manifest, invalidPayload, keyPair.publicKeyHex);
    expect(res.success).toBe(false);
    expect(res.error).toContain('SchemaValidationError');
  });

  it('should expose records, snapshots, and allowlist queries correctly', () => {
    const record = threatIntel.getRecord();
    expect(record.databaseVersion).toBe(100);
    expect(record.filterType).toBe('BLOOM_FILTER_V1');
    expect(record.capacity).toBeGreaterThan(0);

    const snap = threatIntel.snapshot();
    expect(snap.version).toBe(100);
    expect(snap.badCount).toBeGreaterThan(0);
    expect(snap.goodCount).toBeGreaterThan(0);

    threatIntel.addAllowedUrl('https://internal.company.com/safe');
    expect(threatIntel.isAllowed('https://internal.company.com/safe')).toBe(true);
    expect(threatIntel.isAllowed('')).toBe(false);

    expect(threatIntel.checkUrl('').isMalicious).toBe(false);
    expect(threatIntel.checkIp('').isMalicious).toBe(false);
    expect(threatIntel.checkDomain('').isMalicious).toBe(false);
  });
});
