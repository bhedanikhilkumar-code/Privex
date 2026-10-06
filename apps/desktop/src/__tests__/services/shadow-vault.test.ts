import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { ShadowVaultService } from '../../services/shadow-vault.service';

describe('ShadowVaultService (Phase G)', () => {
  let testVaultDir: string;
  let testWorkDir: string;
  let shadowVault: ShadowVaultService;

  beforeEach(() => {
    const id = crypto.randomUUID();
    testVaultDir = path.join(os.tmpdir(), `pp-vault-test-${id}`);
    testWorkDir = path.join(os.tmpdir(), `pp-work-test-${id}`);
    fs.mkdirSync(testVaultDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(testWorkDir, { recursive: true, mode: 0o700 });

    shadowVault = new ShadowVaultService({
      customVaultDir: testVaultDir,
      maxFileSizeBytes: 50 * 1024 * 1024,
      maxVaultQuotaBytes: 500 * 1024 // 500 KB quota for rapid FIFO tests
    });
  });

  afterEach(() => {
    try {
      if (fs.existsSync(testVaultDir)) {
        fs.rmSync(testVaultDir, { recursive: true, force: true });
      }
      if (fs.existsSync(testWorkDir)) {
        fs.rmSync(testWorkDir, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });

  it('initializes safe vault directory and master key', () => {
    expect(fs.existsSync(testVaultDir)).toBe(true);
    const keyPath = path.join(testVaultDir, '.vault.key');
    expect(fs.existsSync(keyPath)).toBe(true);
    const key = fs.readFileSync(keyPath);
    expect(key.length).toBe(32);
  });

  it('rejects vault directory initialization if directory is a symlink', () => {
    const symlinkDir = path.join(os.tmpdir(), `pp-vault-symlink-${crypto.randomUUID()}`);
    try {
      fs.symlinkSync(testVaultDir, symlinkDir, 'junction');
      expect(() => new ShadowVaultService({ customVaultDir: symlinkDir })).toThrow(/SECURITY_VIOLATION/);
    } catch (e: any) {
      if (e.message.includes('SECURITY_VIOLATION')) {
        expect(e.message).toContain('SECURITY_VIOLATION');
      }
    } finally {
      try {
        fs.unlinkSync(symlinkDir);
      } catch {
        // Ignore
      }
    }
  });

  it('creates authenticated Copy-on-Write backup of target document', async () => {
    const filePath = path.join(testWorkDir, 'QuarterlyReport.docx');
    const content = Buffer.from('CONFIDENTIAL_EXECUTIVE_SUMMARY_DATA_REPORT_12345', 'utf8');
    fs.writeFileSync(filePath, content);
    const expectedSha256 = crypto.createHash('sha256').update(content).digest('hex');

    const backup = await shadowVault.backupFile(filePath, 'incident-001');

    expect(backup.backupId).toMatch(/^bk-/);
    expect(backup.incidentId).toBe('incident-001');
    expect(backup.preAttackSha256).toBe(expectedSha256);
    expect(backup.fileSize).toBe(content.length);
    expect(fs.existsSync(backup.blobPath)).toBe(true);

    // Verify blob is encrypted (magic header PPSHADOW1)
    const blobBytes = fs.readFileSync(backup.blobPath);
    expect(blobBytes.subarray(0, 9).toString('utf8')).toBe('PPSHADOW1');
    expect(blobBytes.includes(content)).toBe(false);
  });

  it('enforces 50 MB boundary: backs up files <= 50 MB and rejects > 50 MB', async () => {
    const smallVault = new ShadowVaultService({
      customVaultDir: path.join(os.tmpdir(), `pp-vault-50mb-${crypto.randomUUID()}`),
      maxFileSizeBytes: 1024 // 1 KB limit for testing boundary
    });

    try {
      const allowedFile = path.join(testWorkDir, 'Allowed.txt');
      fs.writeFileSync(allowedFile, Buffer.alloc(500, 0x41));
      const backup = await smallVault.backupFile(allowedFile);
      expect(backup.fileSize).toBe(500);

      const oversizedFile = path.join(testWorkDir, 'Oversized.bin');
      fs.writeFileSync(oversizedFile, Buffer.alloc(2048, 0x42));
      await expect(smallVault.backupFile(oversizedFile)).rejects.toThrow(/EXCEEDS_FILE_SIZE_LIMIT/);
    } finally {
      smallVault.purgeAll();
      try {
        fs.rmSync(smallVault.getVaultDir(), { recursive: true, force: true });
      } catch {
        // Ignore
      }
    }
  });

  it('enforces FIFO quota eviction when total vault size exceeds quota', async () => {
    // 500 KB quota. Backing up 6 files of 100 KB each. Total 600 KB -> oldest must be evicted.
    const backups: any[] = [];
    for (let i = 0; i < 6; i++) {
      const filePath = path.join(testWorkDir, `Doc_${i}.dat`);
      fs.writeFileSync(filePath, Buffer.alloc(100 * 1024, i + 1));
      const b = await shadowVault.backupFile(filePath, 'incident-burst');
      backups.push(b);
      // Small sleep to ensure distinct timestamps
      await new Promise((r) => setTimeout(r, 10));
    }

    const stats = shadowVault.getStats();
    expect(stats.totalSizeBytes).toBeLessThanOrEqual(500 * 1024);
    // Oldest backup (Doc_0) should have been evicted
    const allBackups = shadowVault.getBackups();
    expect(allBackups.some((b) => b.backupId === backups[0].backupId)).toBe(false);
    expect(fs.existsSync(backups[0].blobPath)).toBe(false);
    // Newest backups should still be present
    expect(allBackups.some((b) => b.backupId === backups[5].backupId)).toBe(true);
  });

  it('restores clean file and verifies exact pre-attack SHA-256', async () => {
    const filePath = path.join(testWorkDir, 'Financial_Ledger.xlsx');
    const originalContent = Buffer.from('ORIGINAL_BALANCE_SHEET_DATA_2026', 'utf8');
    fs.writeFileSync(filePath, originalContent);
    const originalSha256 = crypto.createHash('sha256').update(originalContent).digest('hex');

    const backup = await shadowVault.backupFile(filePath, 'incident-attack-01');

    // Simulate ransomware attack: overwrite file with encrypted garbage
    fs.writeFileSync(filePath, crypto.randomBytes(1024));
    expect(crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')).not.toBe(originalSha256);

    // Rollback
    const result = await shadowVault.rollbackFile(backup.backupId);
    expect(result.success).toBe(true);
    expect(result.restoredSha256).toBe(originalSha256);
    expect(result.originalSha256).toBe(originalSha256);

    // Verify on disk
    const restoredBytes = fs.readFileSync(filePath);
    expect(restoredBytes.equals(originalContent)).toBe(true);
  });

  it('fails closed and reports RESTORATION_HASH_MISMATCH if restored content is altered', async () => {
    const filePath = path.join(testWorkDir, 'Tampered.txt');
    fs.writeFileSync(filePath, Buffer.from('CLEAN_DATA', 'utf8'));
    const backup = await shadowVault.backupFile(filePath, 'incident-tamper');

    // Tamper with the encrypted blob ciphertext
    const blobBytes = fs.readFileSync(backup.blobPath);
    // Flip a byte in the ciphertext portion
    blobBytes[blobBytes.length - 1] ^= 0xff;
    fs.writeFileSync(backup.blobPath, blobBytes);

    const rollbackResult = await shadowVault.rollbackFile(backup.backupId);
    expect(rollbackResult.success).toBe(false);
    expect(rollbackResult.error).toMatch(/Authentication tag verification failed|CORRUPTED_BACKUP/);
  });

  it('executes 1-click rollbackIncident() restoring all incident files to exact SHA-256', async () => {
    const incidentId = 'incident-multi-01';
    const files: Array<{ path: string; data: Buffer; sha: string }> = [];

    for (let i = 0; i < 5; i++) {
      const p = path.join(testWorkDir, `Spreadsheet_${i}.xlsx`);
      const data = Buffer.from(`DATA_ROW_${i}_${crypto.randomBytes(32).toString('hex')}`, 'utf8');
      fs.writeFileSync(p, data);
      const sha = crypto.createHash('sha256').update(data).digest('hex');
      files.push({ path: p, data, sha });
      await shadowVault.backupFile(p, incidentId);
    }

    // Encrypt all 5 files in attack
    for (const f of files) {
      fs.writeFileSync(f.path, crypto.randomBytes(256));
    }

    // 1-Click Rollback
    const rollback = await shadowVault.rollbackIncident(incidentId);
    expect(rollback.success).toBe(true);
    expect(rollback.totalFiles).toBe(5);
    expect(rollback.restoredCount).toBe(5);
    expect(rollback.failedCount).toBe(0);

    // Check each file on disk
    for (const f of files) {
      const current = fs.readFileSync(f.path);
      const sha = crypto.createHash('sha256').update(current).digest('hex');
      expect(sha).toBe(f.sha);
      expect(current.equals(f.data)).toBe(true);
    }
  });

  it('returns failure if incidentId does not exist', async () => {
    const result = await shadowVault.rollbackIncident('non-existent-incident');
    expect(result.success).toBe(false);
    expect(result.restoredCount).toBe(0);
    expect(result.failedCount).toBe(1);
    expect(result.failedFiles[0].reason).toContain('INCIDENT_NOT_FOUND');
  });
});
