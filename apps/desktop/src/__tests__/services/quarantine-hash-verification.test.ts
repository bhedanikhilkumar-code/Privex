import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';

function computeSha256(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

describe('SEC-E-03 — Streaming SHA-256 Verification & TOCTOU Integrity Suite', () => {
  let tempRoot: string;
  let vaultDir: string;
  let workDir: string;
  let quarantine: QuarantineService;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-hash-verify-test-'));
    vaultDir = path.join(tempRoot, 'vault');
    workDir = path.join(tempRoot, 'work');
    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(workDir, { recursive: true });
    quarantine = new QuarantineService(vaultDir);
  });

  afterEach(() => {
    if (fs.existsSync(tempRoot)) {
      try {
        fs.rmSync(tempRoot, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  });

  it('A & E: succeeds when expected threat SHA-256 matches actual streamed content hash', async () => {
    const content = Buffer.from('4d5a90000300000004000000ffff0000MaliciousPayload123', 'utf8');
    const actualHash = computeSha256(content);
    const targetFile = path.join(workDir, 'confirmed_threat.pdf.exe');
    fs.writeFileSync(targetFile, content);

    const threat: DetectedThreat = {
      id: 'threat-1',
      filePath: targetFile,
      fileName: 'confirmed_threat.pdf.exe',
      fileSize: content.length,
      sha256: actualHash,
      threatName: 'Trojan.Synthetic',
      riskScore: 95,
      severity: 'critical',
      verdict: 'BLOCK',
      evidenceFactors: ['PE_HEADER', 'HIGH_RISK_EXTENSION'],
      detectedAt: Date.now(),
      quarantined: false
    };

    const item = await quarantine.isolateFile(threat);

    expect(item).toBeDefined();
    expect(item.sha256).toBe(actualHash.toLowerCase());
    expect(quarantine.getQuarantinedItem(item.quarantineId)).toBeDefined();
    expect(fs.existsSync(item.blobPath)).toBe(true);
    expect(fs.existsSync(targetFile)).toBe(false); // Unlinked from user workspace
  });

  it('B & D: fails when expected threat SHA-256 differs from actual streamed file hash', async () => {
    const actualContent = Buffer.from('4d5a90000300000004000000ffff0000RealPayloadOnDisk', 'utf8');
    const fakeExpectedHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // Different hash
    const targetFile = path.join(workDir, 'swapped_threat.exe');
    fs.writeFileSync(targetFile, actualContent);

    const threat: DetectedThreat = {
      id: 'threat-mismatch',
      filePath: targetFile,
      fileName: 'swapped_threat.exe',
      fileSize: actualContent.length,
      sha256: fakeExpectedHash,
      threatName: 'Trojan.Swapped',
      riskScore: 90,
      severity: 'critical',
      verdict: 'BLOCK',
      evidenceFactors: ['HASH_MISMATCH'],
      detectedAt: Date.now(),
      quarantined: false
    };

    const itemsBefore = quarantine.listQuarantine().length;

    await expect(quarantine.isolateFile(threat)).rejects.toThrow(/TOCTOU_DETECTED/);

    // Invariants:
    // 1. Manifest must NOT be committed with an unverified hash
    expect(quarantine.listQuarantine().length).toBe(itemsBefore);
    // 2. Source file must remain intact
    expect(fs.existsSync(targetFile)).toBe(true);
    // 3. No orphan .tmp or blob files left behind
    const filesInVault = fs.readdirSync(vaultDir);
    const tmpFiles = filesInVault.filter((f) => f.includes('.tmp'));
    expect(tmpFiles.length).toBe(0);
  });

  it('C & G: rejects quarantine and prevents partial manifest entry when TOCTOU mutation occurs', async () => {
    const initialContent = Buffer.from('4d5a90000300000004000000ffff0000InitialBytes', 'utf8');
    const initialHash = computeSha256(initialContent);
    const targetFile = path.join(workDir, 'mutated_threat.exe');
    // Pre-calculated hash represents prior scan result, but attacker modified file on disk
    const mutatedContent = Buffer.from('4d5a90000300000004000000ffff0000AttackerSwappedBytes', 'utf8');
    fs.writeFileSync(targetFile, mutatedContent);

    const threat: DetectedThreat = {
      id: 'threat-toctou',
      filePath: targetFile,
      fileName: 'mutated_threat.exe',
      fileSize: mutatedContent.length,
      sha256: initialHash, // Prior scan hash does not match current disk bytes
      threatName: 'Trojan.Mutated',
      riskScore: 95,
      severity: 'critical',
      verdict: 'BLOCK',
      evidenceFactors: ['TOCTOU_PAYLOAD'],
      detectedAt: Date.now(),
      quarantined: false
    };

    await expect(quarantine.isolateFile(threat)).rejects.toThrow(/TOCTOU_DETECTED/);

    // Manifest must contain 0 entries
    expect(quarantine.listQuarantine().length).toBe(0);
  });

  it('F: verifies restored file can be verified and decrypted without hash corruption', async () => {
    const payload = Buffer.from('4d5a90000300000004000000ffff0000RestoreIntegrityCheck', 'utf8');
    const payloadHash = computeSha256(payload);
    const targetFile = path.join(workDir, 'restore_me.exe');
    fs.writeFileSync(targetFile, payload);

    const threat: DetectedThreat = {
      id: 'threat-restore-test',
      filePath: targetFile,
      fileName: 'restore_me.exe',
      fileSize: payload.length,
      sha256: payloadHash,
      threatName: 'Trojan.RestoreTest',
      riskScore: 95,
      severity: 'critical',
      verdict: 'BLOCK',
      evidenceFactors: ['RESTORE_TEST'],
      detectedAt: Date.now(),
      quarantined: false
    };

    const item = await quarantine.isolateFile(threat);
    expect(item.sha256).toBe(payloadHash);

    const restoreDir = path.join(workDir, 'restored');
    fs.mkdirSync(restoreDir, { recursive: true });
    const restoredPath = await quarantine.restoreItem(item.quarantineId, {
      customDestinationDir: restoreDir
    });

    const restoredBytes = fs.readFileSync(restoredPath);
    expect(computeSha256(restoredBytes)).toBe(payloadHash);
  });
});
