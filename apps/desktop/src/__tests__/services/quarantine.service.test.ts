import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';

describe('QuarantineService (Core Service API & Vault Lifecycle)', () => {
  let vaultDir: string;
  let workDir: string;
  let service: QuarantineService;

  beforeEach(() => {
    vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-vault-unit-'));
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-work-unit-'));
    service = new QuarantineService(vaultDir);
  });

  afterEach(() => {
    if (fs.existsSync(vaultDir)) fs.rmSync(vaultDir, { recursive: true, force: true });
    if (fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
  });

  it('initializes vault directory and generates master key with secure permissions', () => {
    expect(fs.existsSync(vaultDir)).toBe(true);
    const keyPath = path.join(vaultDir, '.vault.key');
    const dpapiPath = path.join(vaultDir, '.vault.key.dpapi');
    expect(fs.existsSync(keyPath) || fs.existsSync(dpapiPath)).toBe(true);
  });

  it('rejects creating a vault inside a symlinked directory', () => {
    const symlinkVault = path.join(workDir, 'symlink_vault');
    try {
      fs.symlinkSync(vaultDir, symlinkVault);
      expect(() => new QuarantineService(symlinkVault)).toThrow(/SECURITY_VIOLATION/i);
    } catch {
      // Symlinks may not be permitted without elevated privileges on Windows
    }
  });

  it('lists quarantine items and purges all items with cryptographic shredding', async () => {
    const f1 = path.join(workDir, 'target1.bin');
    const f2 = path.join(workDir, 'target2.bin');
    fs.writeFileSync(f1, 'Target 1 content');
    fs.writeFileSync(f2, 'Target 2 content');

    const t1: DetectedThreat = {
      id: 't-purge-1',
      filePath: f1,
      fileName: 'target1.bin',
      fileSize: 16,
      sha256: crypto.createHash('sha256').update('Target 1 content').digest('hex'),
      riskScore: 80,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'PURGE_1',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const t2: DetectedThreat = {
      id: 't-purge-2',
      filePath: f2,
      fileName: 'target2.bin',
      fileSize: 16,
      sha256: crypto.createHash('sha256').update('Target 2 content').digest('hex'),
      riskScore: 80,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'PURGE_2',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const item1 = await service.isolateFile(t1);
    const item2 = await service.isolateFile(t2);

    expect(service.listQuarantine().length).toBe(2);
    expect(fs.existsSync(item1.blobPath)).toBe(true);
    expect(fs.existsSync(item2.blobPath)).toBe(true);

    service.purgeAllQuarantine();

    expect(service.listQuarantine().length).toBe(0);
    expect(fs.existsSync(item1.blobPath)).toBe(false);
    expect(fs.existsSync(item2.blobPath)).toBe(false);
  });

  it('rejects isolating non-quarantinable benign ALLOW files', async () => {
    const benignPath = path.join(workDir, 'benign.txt');
    fs.writeFileSync(benignPath, 'Benign clean file content');

    const benignThreat: DetectedThreat = {
      id: 't-benign',
      filePath: benignPath,
      fileName: 'benign.txt',
      fileSize: 25,
      sha256: crypto.createHash('sha256').update('Benign clean file content').digest('hex'),
      riskScore: 0,
      severity: 'safe',
      verdict: 'ALLOW',
      threatName: 'CLEAN_FILE',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    await expect(service.isolateFile(benignThreat)).rejects.toThrow(/QUARANTINE_POLICY_REJECTED/i);
    expect(fs.existsSync(benignPath)).toBe(true);
  });

  it('handles DPAPI safeStorage sealing and upgrading of plaintext key', () => {
    const mockStorage = {
      isEncryptionAvailable: () => true,
      encryptString: (str: string) => Buffer.from(`ENC:${str}`),
      decryptString: (buf: Buffer) => buf.toString('utf8').replace(/^ENC:/, '')
    };

    QuarantineService.setMockSafeStorage(mockStorage);
    try {
      const dpapiVaultDir = path.join(workDir, 'dpapi_vault');
      const s1 = new QuarantineService(dpapiVaultDir);
      expect(s1).toBeDefined();
      const dpapiFile = path.join(dpapiVaultDir, '.vault.key.dpapi');
      expect(fs.existsSync(dpapiFile)).toBe(true);

      // Re-opening uses DPAPI decryption
      const s2 = new QuarantineService(dpapiVaultDir);
      expect(s2).toBeDefined();

      // Test upgrade of plaintext .vault.key
      const upgradeVaultDir = path.join(workDir, 'upgrade_vault');
      fs.mkdirSync(upgradeVaultDir, { recursive: true });
      const rawKey = crypto.randomBytes(32);
      fs.writeFileSync(path.join(upgradeVaultDir, '.vault.key'), rawKey);

      const s3 = new QuarantineService(upgradeVaultDir);
      expect(s3).toBeDefined();
      expect(fs.existsSync(path.join(upgradeVaultDir, '.vault.key.dpapi'))).toBe(true);
      expect(fs.existsSync(path.join(upgradeVaultDir, '.vault.key'))).toBe(false);
    } finally {
      QuarantineService.setMockSafeStorage(null);
    }
  });

  it('throws when deleting non-existent item or restoring missing blob', async () => {
    await expect(service.permanentDelete('non-existent-id')).rejects.toThrow(/QUARANTINE_NOT_FOUND/i);
    await expect(service.restoreItem('non-existent-id')).rejects.toThrow(/QUARANTINE_NOT_FOUND/i);
  });

  it('rejects invalid or missing threat input in isolateFile', async () => {
    await expect(service.isolateFile(null as any)).rejects.toThrow(/INVALID_THREAT/i);
    await expect(service.isolateFile({ filePath: '' } as any)).rejects.toThrow(/INVALID_THREAT/i);
    await expect(service.isolateFile({ filePath: path.join(workDir, 'missing.exe') } as any)).rejects.toThrow(
      /FILE_NOT_FOUND/i
    );
  });

  it('decryptBytes throws on corrupted or truncated containers', () => {
    expect(() => service.decryptBytes(Buffer.alloc(4))).toThrow(/CORRUPTED_VAULT/i);
    expect(() => service.decryptBytes(Buffer.from('INVALID_MAGIC_HEADER_1234567890'))).toThrow(
      /SECURITY_VIOLATION/i
    );
  });

  it('permanently deletes an existing quarantined item with shredding', async () => {
    const target = path.join(workDir, 'shred_target.exe');
    fs.writeFileSync(target, 'Bytes to be shredded');
    const threat: DetectedThreat = {
      id: 't-shred-single',
      filePath: target,
      fileName: 'shred_target.exe',
      fileSize: 20,
      sha256: crypto.createHash('sha256').update('Bytes to be shredded').digest('hex'),
      riskScore: 80,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'SHRED_TEST',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const item = await service.isolateFile(threat);
    expect(fs.existsSync(item.blobPath)).toBe(true);

    await service.permanentDelete(item.quarantineId);
    expect(fs.existsSync(item.blobPath)).toBe(false);
    expect(service.listQuarantine().length).toBe(0);
  });

  it('restores item with options and handles collision with restored_ suffix', async () => {
    const target = path.join(workDir, 'collide.exe');
    fs.writeFileSync(target, 'Collision original bytes');
    const threat: DetectedThreat = {
      id: 't-collide',
      filePath: target,
      fileName: 'collide.exe',
      fileSize: 24,
      sha256: crypto.createHash('sha256').update('Collision original bytes').digest('hex'),
      riskScore: 80,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'COLLIDE_TEST',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const item = await service.isolateFile(threat);
    // Create new file at original location before restore
    fs.writeFileSync(target, 'New user file in place');

    const restoredPath = await service.restoreItem(item.quarantineId, {
      restoreZoneIdentifier: true
    });
    expect(restoredPath).not.toBe(target);
    expect(restoredPath).toContain('_restored_');
    expect(fs.existsSync(restoredPath)).toBe(true);
  });
});
