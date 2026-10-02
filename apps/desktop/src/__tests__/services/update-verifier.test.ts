import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import { UpdateVerifierService, UpdatePackageManifest } from '../../services/update-verifier.service';
import { generateEd25519KeyPair, signEd25519 } from '@private-protection/core';

describe('UpdateVerifierService (Signed OTA Updates & Anti-Downgrade Defense)', () => {
  const { publicKeyHex, privateKey } = generateEd25519KeyPair();
  const verifier = new UpdateVerifierService(publicKeyHex, 100);

  it('rejects updates with sequence number lower than or equal to current version (Anti-Downgrade)', () => {
    const payload = Buffer.from('payload-diff');
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    const signature = signEd25519(hash, privateKey);

    const manifest: UpdatePackageManifest = {
      version: '1.0.0-downgrade',
      versionSequence: 95, // Older than 100
      publishedAt: Date.now(),
      sha256: hash,
      signature
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('ANTI_DOWNGRADE_REJECT');
  });

  it('rejects update packages when payload hash does not match manifest SHA-256', () => {
    const payload = Buffer.from('tampered-payload');
    const signature = signEd25519('0000000000000000000000000000000000000000000000000000000000000000', privateKey);
    const manifest: UpdatePackageManifest = {
      version: '1.1.0',
      versionSequence: 105,
      publishedAt: Date.now(),
      sha256: '0000000000000000000000000000000000000000000000000000000000000000',
      signature
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('HASH_MISMATCH');
  });

  it('rejects update packages with forged or unauthentic Ed25519 signatures', () => {
    const payload = Buffer.from('payload-diff');
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    // Forged dummy 128 hex chars signature
    const forgedSignature = 'deadbeef'.repeat(16);

    const manifest: UpdatePackageManifest = {
      version: '1.1.0',
      versionSequence: 105,
      publishedAt: Date.now(),
      sha256: hash,
      signature: forgedSignature
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('SIGNATURE_INVALID');
  });

  it('rejects update packages signed with a different key (wrong key)', () => {
    const otherKey = generateEd25519KeyPair();
    const payload = Buffer.from('payload-diff');
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    const signatureFromOtherKey = signEd25519(hash, otherKey.privateKey);

    const manifest: UpdatePackageManifest = {
      version: '1.1.0',
      versionSequence: 105,
      publishedAt: Date.now(),
      sha256: hash,
      signature: signatureFromOtherKey
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('SIGNATURE_INVALID');
  });

  it('accepts authentic update packages with valid sequence, hash, and authentic Ed25519 signature', () => {
    const payload = Buffer.from('authentic-delta-bloom-filter-diff');
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    const signature = signEd25519(hash, privateKey);

    const manifest: UpdatePackageManifest = {
      version: '1.1.0',
      versionSequence: 105,
      publishedAt: Date.now(),
      sha256: hash,
      signature
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(true);
  });
});
