import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';

describe('QuarantineService (Cryptographic Vault & Safe Remediation)', () => {
  let vaultDir: string;
  let workDir: string;
  let quarantine: QuarantineService;

  beforeEach(() => {
    vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-vault-test-'));
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-work-test-'));
    quarantine = new QuarantineService(vaultDir);
  });

  afterEach(() => {
    if (fs.existsSync(vaultDir)) fs.rmSync(vaultDir, { recursive: true, force: true });
    if (fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
  });

  it('isolates a detected file, scrambles its bytes in vault, and unlinks original', async () => {
    const maliciousFilePath = path.join(workDir, 'trojan.pdf.exe');
    const originalContent = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x12, 0x34]); // MZ header
    fs.writeFileSync(maliciousFilePath, originalContent);

    const threat: DetectedThreat = {
      id: 'threat-1',
      filePath: maliciousFilePath,
      fileName: 'trojan.pdf.exe',
      fileSize: originalContent.length,
      sha256: crypto.createHash('sha256').update(originalContent).digest('hex'),
      riskScore: 90,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'DECEPTIVE_DOUBLE_EXTENSION',
      detectedAt: Date.now(),
      evidenceFactors: ['Double extension deception'],
      quarantined: false
    };

    const item = await quarantine.isolateFile(threat);
    expect(item.quarantineId).toMatch(/^quarantine-/);
    expect(fs.existsSync(maliciousFilePath)).toBe(false); // Unlinked from disk
    expect(fs.existsSync(item.blobPath)).toBe(true); // Stored in vault

    // Verify blob bytes are scrambled (header bytes must NOT be MZ 0x4D, 0x5A)
    const vaultBytes = fs.readFileSync(item.blobPath);
    expect(vaultBytes[0]).not.toBe(0x4d);
    expect(vaultBytes[1]).not.toBe(0x5a);
  });

  it('restores a quarantined item safely and verifies SHA-256 byte integrity', async () => {
    const filePath = path.join(workDir, 'false_positive.exe');
    const originalContent = Buffer.from('Original authentic application payload');
    fs.writeFileSync(filePath, originalContent);

    const sha256 = crypto.createHash('sha256').update(originalContent).digest('hex');
    const threat: DetectedThreat = {
      id: 'threat-2',
      filePath,
      fileName: 'false_positive.exe',
      fileSize: originalContent.length,
      sha256,
      riskScore: 60,
      severity: 'dangerous',
      verdict: 'BLOCK',
      threatName: 'SUSPICIOUS_HEURISTIC',
      detectedAt: Date.now(),
      evidenceFactors: ['High entropy'],
      quarantined: false
    };

    const qItem = await quarantine.isolateFile(threat);
    expect(fs.existsSync(filePath)).toBe(false);

    // Restore back to original location
    const restoredPath = await quarantine.restoreItem(qItem.quarantineId);
    expect(restoredPath).toBe(filePath);
    expect(fs.existsSync(restoredPath)).toBe(true);

    const restoredContent = fs.readFileSync(restoredPath);
    expect(restoredContent.toString()).toBe(originalContent.toString());
  });

  it('handles restore collision safely by creating a renamed copy instead of overwriting', async () => {
    const filePath = path.join(workDir, 'conflict_file.txt');
    fs.writeFileSync(filePath, 'Original threat version');

    const threat: DetectedThreat = {
      id: 'threat-3',
      filePath,
      fileName: 'conflict_file.txt',
      fileSize: 22,
      sha256: crypto.createHash('sha256').update('Original threat version').digest('hex'),
      riskScore: 50,
      severity: 'suspicious',
      verdict: 'WARN',
      threatName: 'TEST_THREAT',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const qItem = await quarantine.isolateFile(threat);

    // Now re-create a new file at the original path before restore
    fs.writeFileSync(filePath, 'New legitimate file that user created');

    const restoredPath = await quarantine.restoreItem(qItem.quarantineId);
    expect(restoredPath).not.toBe(filePath);
    expect(restoredPath).toContain('_restored_');
    expect(fs.existsSync(filePath)).toBe(true);
    expect(fs.readFileSync(filePath, 'utf8')).toBe('New legitimate file that user created');
    expect(fs.readFileSync(restoredPath, 'utf8')).toBe('Original threat version');
  });

  it('rejects path traversal attempts on destination during restoration', async () => {
    const filePath = path.join(workDir, 'test.txt');
    fs.writeFileSync(filePath, 'test');
    const threat: DetectedThreat = {
      id: 'threat-4',
      filePath,
      fileName: 'test.txt',
      fileSize: 4,
      sha256: crypto.createHash('sha256').update('test').digest('hex'),
      riskScore: 50,
      severity: 'suspicious',
      verdict: 'WARN',
      threatName: 'TEST',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const qItem = await quarantine.isolateFile(threat);

    // Attempt restoring with path traversal directory
    await expect(
      quarantine.restoreItem(qItem.quarantineId, path.join(workDir, '..', '..', 'forbidden'))
    ).rejects.toThrow();
  });

  it('permanently deletes quarantined item using cryptographic byte overwriting', async () => {
    const filePath = path.join(workDir, 'delete_target.exe');
    fs.writeFileSync(filePath, 'Dangerous malware bytes');

    const threat: DetectedThreat = {
      id: 'threat-5',
      filePath,
      fileName: 'delete_target.exe',
      fileSize: 22,
      sha256: crypto.createHash('sha256').update('Dangerous malware bytes').digest('hex'),
      riskScore: 90,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'MALWARE_SAMPLE',
      detectedAt: Date.now(),
      evidenceFactors: [],
      quarantined: false
    };

    const qItem = await quarantine.isolateFile(threat);
    expect(fs.existsSync(qItem.blobPath)).toBe(true);

    await quarantine.permanentDelete(qItem.quarantineId);
    expect(fs.existsSync(qItem.blobPath)).toBe(false);
    expect(quarantine.listQuarantine().length).toBe(0);
  });
});
