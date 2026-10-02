import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import { UpdateVerifierService, UpdatePackageManifest } from '../../services/update-verifier.service';

describe('UpdateVerifierService (Signed OTA Updates & Anti-Downgrade Defense)', () => {
  const verifier = new UpdateVerifierService('embedded_public_key_32_bytes_len_ok', 100);

  it('rejects updates with sequence number lower than or equal to current version (Anti-Downgrade)', () => {
    const payload = Buffer.from('payload-diff');
    const hash = crypto.createHash('sha256').update(payload).digest('hex');

    const manifest: UpdatePackageManifest = {
      version: '1.0.0-downgrade',
      versionSequence: 95, // Older than 100
      publishedAt: Date.now(),
      sha256: hash,
      signature: 'valid_signature_string_that_exceeds_32_chars_length'
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('ANTI_DOWNGRADE_REJECT');
  });

  it('rejects update packages when payload hash does not match manifest SHA-256', () => {
    const payload = Buffer.from('tampered-payload');
    const manifest: UpdatePackageManifest = {
      version: '1.1.0',
      versionSequence: 105,
      publishedAt: Date.now(),
      sha256: '0000000000000000000000000000000000000000000000000000000000000000',
      signature: 'valid_signature_string_that_exceeds_32_chars_length'
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('HASH_MISMATCH');
  });

  it('accepts authentic update packages with valid sequence and hash', () => {
    const payload = Buffer.from('authentic-delta-bloom-filter-diff');
    const hash = crypto.createHash('sha256').update(payload).digest('hex');

    const manifest: UpdatePackageManifest = {
      version: '1.1.0',
      versionSequence: 105,
      publishedAt: Date.now(),
      sha256: hash,
      signature: 'valid_signature_string_that_exceeds_32_chars_length'
    };

    const result = verifier.verifyUpdateManifest(manifest, payload);
    expect(result.valid).toBe(true);
  });
});
