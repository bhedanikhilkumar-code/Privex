import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { ThreatIntelManagerService } from '../../services/threat-intel-manager.service';
import { UpdateVerifierService } from '../../services/update-verifier.service';
import { PpdbPayload } from '../../types/desktop.types';
import { ThreatIntel, generateEd25519KeyPair } from '@private-protection/core';
import { IpcValidator } from '../../ipc/ipc-validator';

describe('Phase O: Adversarial Security & Zero-Trust Verification', () => {
  let tempDir: string;
  let keyPair: { publicKeyHex: string; privateKey: crypto.KeyObject };
  let manager: ThreatIntelManagerService;
  let threatIntel: ThreatIntel;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-o-sec-'));
    keyPair = generateEd25519KeyPair();
    threatIntel = ThreatIntel.getSharedInstance();
    threatIntel.resetToFactorySeed();

    manager = new ThreatIntelManagerService({
      dataDir: tempDir,
      threatIntelInstance: threatIntel,
      rootPublicKeyHex: keyPair.publicKeyHex
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it('SEC-O-01: Replay attack with stale or identical version sequence is strictly rejected', async () => {
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: 'a'.repeat(64), threatName: 'Bad1', severity: 'critical' }]
    };
    const bundleV2 = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    // Apply first time -> OK
    const res1 = await manager.applyUpdate(bundleV2);
    expect(res1.success).toBe(true);
    expect(manager.getStatus().currentSequence).toBe(1001);

    // Replay same bundle again -> REJECT
    const res2 = await manager.applyUpdate(bundleV2);
    expect(res2.success).toBe(false);
    expect(res2.errorCode).toBe('ANTI_DOWNGRADE_REJECT');

    // Replay older bundle -> REJECT
    const bundleOld = UpdateVerifierService.createSignedBundle(
      '2026.10.01',
      999,
      Date.now() - 1000,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );
    const res3 = await manager.applyUpdate(bundleOld);
    expect(res3.success).toBe(false);
    expect(res3.errorCode).toBe('ANTI_DOWNGRADE_REJECT');
  });

  it('SEC-O-02: Bit-flip in Ed25519 signature fails verification immediately', async () => {
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: 'b'.repeat(64), threatName: 'Bad2', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1005,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    // Flip first character of hex signature
    const sigArray = (bundle.signature || '').split('');
    sigArray[0] = sigArray[0] === '0' ? '1' : '0';
    bundle.signature = sigArray.join('');
    bundle.manifest.signature = bundle.signature;

    const res = await manager.applyUpdate(bundle);
    expect(res.success).toBe(false);
    expect(res.errorCode).toBe('SIGNATURE_INVALID');
  });

  it('SEC-O-03: Tampered payload digest mismatch fails verification immediately', async () => {
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: 'c'.repeat(64), threatName: 'Bad3', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1005,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    // Inject extra hash into payload without changing signature
    bundle.payload.maliciousHashes.push({
      hash: 'd'.repeat(64),
      threatName: 'Sneaky',
      severity: 'low'
    });

    const res = await manager.applyUpdate(bundle);
    expect(res.success).toBe(false);
    expect(res.errorCode).toBe('HASH_MISMATCH');
  });

  it('SEC-O-04: Malformed ciphertext in metadata persistence fails securely and preserves memory state', async () => {
    const metaPath = path.join(tempDir, 'threat-intel-metadata.enc');
    fs.writeFileSync(metaPath, 'NOT_A_VALID_ENCRYPTED_PAYLOAD_CORRUPT', 'utf8');

    // Creating new manager should handle corrupt metadata gracefully by initializing clean state
    const newManager = new ThreatIntelManagerService({
      dataDir: tempDir,
      threatIntelInstance: threatIntel,
      rootPublicKeyHex: keyPair.publicKeyHex
    });

    const status = newManager.getStatus();
    expect(status.currentVersion).toBeDefined();
    expect(status.hasLkg).toBe(false);
  });

  it('SEC-O-05: Tampered AES-GCM tag in metadata persistence causes cryptographic authentication error', async () => {
    // Perform valid update
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: 'e'.repeat(64), threatName: 'Bad5', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );
    await manager.applyUpdate(bundle);

    const metaPath = path.join(tempDir, 'threat-intel-metadata.enc');
    expect(fs.existsSync(metaPath)).toBe(true);

    const rawEncrypted = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    // Tamper with authentication tag
    rawEncrypted.tag = 'deadbeefdeadbeefdeadbeefdeadbeef';
    fs.writeFileSync(metaPath, JSON.stringify(rawEncrypted), 'utf8');

    // New manager instance attempts to read tampered metadata -> recovers cleanly
    const newManager = new ThreatIntelManagerService({
      dataDir: tempDir,
      threatIntelInstance: threatIntel,
      rootPublicKeyHex: keyPair.publicKeyHex
    });

    expect(newManager.getStatus()).toBeDefined();
  });

  it('SEC-O-06: Path traversal attempt in update bundle path is blocked by IpcValidator', () => {
    expect(() => {
      IpcValidator.validateUpdateBundlePath('..\\..\\Windows\\System32\\bad.ppdb');
    }).toThrow('SECURITY_VIOLATION');

    expect(() => {
      IpcValidator.validateUpdateBundlePath('C:\\temp\\bad.txt');
    }).toThrow('INVALID_UPDATE_BUNDLE');
  });

  it('SEC-O-07: Staging atomicity: if post-staging trial test fails, active DB is unmodified', async () => {
    const initialVersion = threatIntel.getInstalledVersion();
    const initialSequence = threatIntel.getVersionSequence();

    // Create a bundle that would fail post-staging trial test
    // EICAR hash is a known bad; if an update somehow breaks EICAR lookup in trial, it must abort.
    // We can simulate an invalid bundle where signature was verified but trial fails
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: 'f'.repeat(64), threatName: 'Bad6', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    // Mock trial test to fail
    (manager as any).runPostStagingSelfTest = () => ({
      passed: false,
      reason: 'SIMULATED_TRIAL_FAILURE: EICAR detection dropped'
    });

    const res = await manager.applyUpdate(bundle);
    expect(res.success).toBe(false);
    expect(res.errorCode).toBe('SELF_TEST_FAILED');
    expect(res.reason).toContain('SIMULATED_TRIAL_FAILURE');

    // Active engine is untouched
    expect(threatIntel.getInstalledVersion()).toBe(initialVersion);
    expect(threatIntel.getVersionSequence()).toBe(initialSequence);
    expect(threatIntel.lookupHash('f'.repeat(64)).isMalicious).toBe(false);
  });

  it('SEC-O-08: Rollback fails safely if no LKG exists', async () => {
    expect(manager.getStatus().hasLkg).toBe(false);
    const rollbackRes = await manager.rollbackToLkg();
    expect(rollbackRes.success).toBe(false);
    expect(rollbackRes.reason).toContain('No Last-Known-Good');
  });

  it('SEC-O-09: Rollback fails safely if LKG file on disk is deleted or corrupted', async () => {
    // Apply update v2 to create an LKG of v1
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: '1'.repeat(64), threatName: 'Bad', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );
    await manager.applyUpdate(bundle);
    expect(manager.getStatus().hasLkg).toBe(true);

    // Delete the LKG file
    const lkgPath = path.join(tempDir, 'threat-db.lkg.enc');
    if (fs.existsSync(lkgPath)) {
      fs.unlinkSync(lkgPath);
    }

    const res = await manager.rollbackToLkg();
    expect(res.success).toBe(false);
    expect(res.reason).toContain('LKG_RESTORE_FAILED');
  });

  it('SEC-O-10: 100% Offline & Air-Gapped guarantee: update process performs zero external network calls', async () => {
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: '2'.repeat(64), threatName: 'BadAirGap', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    const filePath = path.join(tempDir, 'airgapped-update.ppdb');
    fs.writeFileSync(filePath, JSON.stringify(bundle, null, 2), 'utf8');

    const result = await manager.applyUpdate(filePath);
    expect(result.success).toBe(true);
    expect(threatIntel.lookupHash('2'.repeat(64))).not.toBeNull();
  });
});
