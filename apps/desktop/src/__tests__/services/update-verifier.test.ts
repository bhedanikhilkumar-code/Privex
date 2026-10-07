import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { UpdateVerifierService } from '../../services/update-verifier.service';
import { PpdbManifest, PpdbPayload } from '../../types/desktop.types';
import { generateEd25519KeyPair } from '@private-protection/core';

describe('UpdateVerifierService (Phase O Cryptographically Signed Updates & Anti-Downgrade)', () => {
  const { publicKeyHex, privateKey } = generateEd25519KeyPair();
  let verifier: UpdateVerifierService;
  let tempDir: string;

  beforeEach(() => {
    verifier = new UpdateVerifierService(publicKeyHex, 1000);
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-update-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it('computes canonical message format correctly (${version}:${versionSequence}:${publishedAt}:${sha256})', () => {
    const manifest: PpdbManifest = {
      version: '2026.11.01',
      versionSequence: 1001,
      publishedAt: 1762000000000,
      sha256: 'a'.repeat(64),
      signature: 'b'.repeat(128)
    };
    const canonical = UpdateVerifierService.computeCanonicalMessage(manifest);
    expect(canonical).toBe('2026.11.01:1001:1762000000000:' + 'a'.repeat(64));
  });

  it('creates and verifies a valid signed .ppdb bundle object', () => {
    const payload: PpdbPayload = {
      maliciousHashes: [
        {
          hash: 'c'.repeat(64),
          threatName: 'Test.Trojan.A',
          severity: 'critical'
        }
      ],
      maliciousUrls: ['https://evil-phishing-test.com'],
      maliciousIps: ['198.51.100.25']
    };

    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 1000,
      payload,
      privateKey,
      publicKeyHex
    );

    const result = verifier.verifyBundle(bundle, 1000);
    expect(result.valid).toBe(true);
    expect(result.code).toBe('UPDATE_OK');
    expect(result.manifest).toBeDefined();
    expect(result.payload).toBeDefined();
    expect(result.payload?.maliciousHashes).toHaveLength(1);
  });

  it('verifies a signed .ppdb bundle from a disk file', () => {
    const payload: PpdbPayload = {
      maliciousHashes: [
        {
          hash: 'e'.repeat(64),
          threatName: 'Test.Ransomware.B',
          severity: 'dangerous'
        }
      ]
    };

    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.02',
      1002,
      Date.now() - 500,
      payload,
      privateKey,
      publicKeyHex
    );

    const filePath = path.join(tempDir, 'threat-intel-2026.11.02.ppdb');
    fs.writeFileSync(filePath, JSON.stringify(bundle, null, 2), 'utf8');

    const result = verifier.verifyBundleFile(filePath, 1000);
    expect(result.valid).toBe(true);
    expect(result.code).toBe('UPDATE_OK');
    expect(result.manifest?.versionSequence).toBe(1002);
  });

  it('rejects updates with sequence number lower than or equal to current version (Anti-Downgrade)', () => {
    const payload: PpdbPayload = { maliciousHashes: [] };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.09.01',
      1000, // Equal to current
      Date.now() - 500,
      payload,
      privateKey,
      publicKeyHex
    );

    const result = verifier.verifyBundle(bundle, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('ANTI_DOWNGRADE_REJECT');
    expect(result.reason).toContain('sequence (1000) must be strictly greater than current (1000)');

    const olderBundle = UpdateVerifierService.createSignedBundle(
      '2026.08.01',
      999, // Lower than current
      Date.now() - 500,
      payload,
      privateKey,
      publicKeyHex
    );
    const result2 = verifier.verifyBundle(olderBundle, 1000);
    expect(result2.valid).toBe(false);
    expect(result2.code).toBe('ANTI_DOWNGRADE_REJECT');
  });

  it('rejects update packages when payload SHA-256 does not match manifest hash', () => {
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: '1'.repeat(64), threatName: 'Bad1', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1005,
      Date.now() - 500,
      payload,
      privateKey,
      publicKeyHex
    );

    // Tamper with payload
    bundle.payload.maliciousUrls = ['https://tampered-after-signing.com'];

    const result = verifier.verifyBundle(bundle, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('HASH_MISMATCH');
    expect(result.reason).toContain('Calculated payload SHA-256 does not match manifest');
  });

  it('rejects update packages with forged or tampered Ed25519 signatures', () => {
    const payload: PpdbPayload = { maliciousHashes: [] };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1005,
      Date.now() - 500,
      payload,
      privateKey,
      publicKeyHex
    );

    // Tamper with 1 hex char of signature
    const sigChars = (bundle.signature || '').split('');
    sigChars[0] = sigChars[0] === 'a' ? 'b' : 'a';
    bundle.signature = sigChars.join('');
    bundle.manifest.signature = bundle.signature;

    const result = verifier.verifyBundle(bundle, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('SIGNATURE_INVALID');
    expect(result.reason).toContain('Cryptographic signature check failed');
  });

  it('rejects update packages signed with a different key', () => {
    const otherKey = generateEd25519KeyPair();
    const payload: PpdbPayload = { maliciousHashes: [] };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1005,
      Date.now() - 500,
      payload,
      otherKey.privateKey,
      otherKey.publicKeyHex
    );

    const result = verifier.verifyBundle(bundle, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('SIGNATURE_INVALID');
  });

  it('rejects manifest with future publishedAt timestamp beyond clock drift tolerance', () => {
    const payload: PpdbPayload = { maliciousHashes: [] };
    const futureTime = Date.now() + 600000; // 10 minutes in future
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1005,
      futureTime,
      payload,
      privateKey,
      publicKeyHex
    );

    const result = verifier.verifyBundle(bundle, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('TIMESTAMP_INVALID');
    expect(result.reason).toContain('future');
  });

  it('rejects bundle file exceeding maximum allowed size', () => {
    const bigFilePath = path.join(tempDir, 'huge.ppdb');
    // Write 51 MB dummy file
    const bigBuffer = Buffer.alloc(51 * 1024 * 1024, 0);
    fs.writeFileSync(bigFilePath, bigBuffer);

    const result = verifier.verifyBundleFile(bigFilePath, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('BUNDLE_TOO_LARGE');
  });

  it('rejects non-existent bundle file', () => {
    const missingPath = path.join(tempDir, 'non-existent.ppdb');
    const result = verifier.verifyBundleFile(missingPath, 1000);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('FILE_NOT_FOUND');
  });
});
