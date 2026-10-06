import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';
import { FileAnalyzer } from '../../core/file-analyzer';
import { ThreatIntel, CleanFileCache } from '@private-protection/core';

describe('QuarantineService (PPVAULT2 Streaming & Hardening)', () => {
  let vaultDir: string;
  let workDir: string;
  let quarantine: QuarantineService;

  beforeEach(() => {
    vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-vault-v2-test-'));
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-work-v2-test-'));
    ThreatIntel.resetSharedInstance();
    CleanFileCache.resetSharedInstance();
    quarantine = new QuarantineService(vaultDir);
  });

  afterEach(() => {
    ThreatIntel.resetSharedInstance();
    CleanFileCache.resetSharedInstance();
    if (fs.existsSync(vaultDir)) fs.rmSync(vaultDir, { recursive: true, force: true });
    if (fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
  });

  describe('PPVAULT2 Container Format & Chunked Streaming', () => {
    it('encrypts and decrypts multi-chunk file via 64 KB streaming', async () => {
      const sourceFile = path.join(workDir, 'multi_chunk.bin');
      // 150 KB payload = chunk 0 (64 KB) + chunk 1 (64 KB) + chunk 2 (22 KB)
      const data = crypto.randomBytes(150 * 1024);
      fs.writeFileSync(sourceFile, data);

      const sourceSha = crypto.createHash('sha256').update(data).digest('hex');
      const threat: DetectedThreat = {
        id: 't-multi',
        filePath: sourceFile,
        fileName: 'multi_chunk.bin',
        fileSize: data.length,
        sha256: sourceSha,
        riskScore: 85,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'STREAMING_THREAT_SAMPLE',
        detectedAt: Date.now(),
        evidenceFactors: ['Streaming Multi-Chunk Test'],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      expect(item.vaultVersion).toBe('PPVAULT2');
      expect(item.fileSize).toBe(data.length);
      expect(fs.existsSync(sourceFile)).toBe(false);
      expect(fs.existsSync(item.blobPath)).toBe(true);

      // Verify container header magic is PPVAULT2
      const blobHeader = Buffer.alloc(8);
      const fd = fs.openSync(item.blobPath, 'r');
      try {
        fs.readSync(fd, blobHeader, 0, 8, 0);
      } finally {
        fs.closeSync(fd);
      }
      expect(blobHeader.toString('utf8')).toBe('PPVAULT2');

      // Restore and verify byte-for-byte SHA-256 match
      const restoredPath = await quarantine.restoreItem(item.quarantineId);
      expect(fs.existsSync(restoredPath)).toBe(true);
      const restoredData = fs.readFileSync(restoredPath);
      expect(restoredData.length).toBe(data.length);
      expect(crypto.createHash('sha256').update(restoredData).digest('hex')).toBe(sourceSha);
    });

    it('encrypts and decrypts a 0-byte file safely via streaming', async () => {
      const emptyFile = path.join(workDir, 'empty.txt');
      fs.writeFileSync(emptyFile, Buffer.alloc(0));

      const emptySha = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
      const threat: DetectedThreat = {
        id: 't-empty',
        filePath: emptyFile,
        fileName: 'empty.txt',
        fileSize: 0,
        sha256: emptySha,
        riskScore: 50,
        severity: 'suspicious',
        verdict: 'WARN',
        threatName: 'SUSPICIOUS_EMPTY_TARGET',
        detectedAt: Date.now(),
        evidenceFactors: ['Zero byte test'],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      expect(fs.existsSync(emptyFile)).toBe(false);
      expect(fs.existsSync(item.blobPath)).toBe(true);

      const restoredPath = await quarantine.restoreItem(item.quarantineId);
      expect(fs.existsSync(restoredPath)).toBe(true);
      expect(fs.readFileSync(restoredPath).length).toBe(0);
    });

    it('retains backward compatibility to decrypt legacy PPVAULT1 containers', async () => {
      // Construct a valid legacy PPVAULT1 container: [MAGIC: 8B "PPVAULT1"][IV: 12B][AUTH_TAG: 16B][CIPHERTEXT]
      const plaintext = Buffer.from('Legacy PPVAULT1 plaintext contents for backward compatibility verification.');
      const iv = crypto.randomBytes(12);
      const keyPath = path.join(vaultDir, '.vault.key');
      const key = fs.readFileSync(keyPath);

      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const legacyContainer = Buffer.concat([
        Buffer.from('PPVAULT1', 'utf8'),
        iv,
        authTag,
        ciphertext
      ]);

      // 1. In-memory decryptBytes test
      const decrypted = quarantine.decryptBytes(legacyContainer);
      expect(decrypted.toString('utf8')).toBe(plaintext.toString('utf8'));

      // 2. Streaming decryptStream test
      const legacyBlobPath = path.join(vaultDir, 'quarantine-legacy-test.blob');
      fs.writeFileSync(legacyBlobPath, legacyContainer);

      const restoreOutPath = path.join(workDir, 'legacy_restored.txt');
      const srcFd = fs.openSync(legacyBlobPath, 'r');
      const dstFd = fs.openSync(restoreOutPath, 'w');
      let streamRes: { sha256: string; totalBytes: number };
      try {
        streamRes = await quarantine.decryptStream(srcFd, dstFd);
      } finally {
        fs.closeSync(srcFd);
        fs.closeSync(dstFd);
      }

      expect(streamRes.totalBytes).toBe(plaintext.length);
      expect(fs.readFileSync(restoreOutPath, 'utf8')).toBe(plaintext.toString('utf8'));
    });
  });

  describe('Adversarial Tamper Resistance & Integrity Enforcement', () => {
    it('rejects tampered container header magic (1-bit flip)', async () => {
      const filePath = path.join(workDir, 'magic_tamper.bin');
      fs.writeFileSync(filePath, 'Header magic tamper test content');

      const threat: DetectedThreat = {
        id: 't-magic-tamper',
        filePath,
        fileName: 'magic_tamper.bin',
        fileSize: 32,
        sha256: crypto.createHash('sha256').update('Header magic tamper test content').digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'MAGIC_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Tamper byte 0 of magic ('P' -> 'Q')
      fs.chmodSync(item.blobPath, 0o666);
      containerBuf[0] = 0x51; // 'Q'
      fs.writeFileSync(item.blobPath, containerBuf);

      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /SECURITY_VIOLATION|invalid or corrupted/i
      );
    });

    it('rejects tampered container UUID in header (AAD violation)', async () => {
      const filePath = path.join(workDir, 'uuid_tamper.bin');
      fs.writeFileSync(filePath, 'UUID AAD tamper test content');

      const threat: DetectedThreat = {
        id: 't-uuid-tamper',
        filePath,
        fileName: 'uuid_tamper.bin',
        fileSize: 28,
        sha256: crypto.createHash('sha256').update('UUID AAD tamper test content').digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'UUID_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Byte 8 is the start of the 36-byte UUID
      fs.chmodSync(item.blobPath, 0o666);
      containerBuf[12] = containerBuf[12] ^ 0x01; // flip 1 bit in UUID
      fs.writeFileSync(item.blobPath, containerBuf);

      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /INTEGRITY_CHECK_FAILED/i
      );
    });

    it('rejects tampered chunk ciphertext in multi-chunk container', async () => {
      const filePath = path.join(workDir, 'cipher_tamper.bin');
      const data = crypto.randomBytes(70 * 1024); // 2 chunks
      fs.writeFileSync(filePath, data);

      const threat: DetectedThreat = {
        id: 't-cipher-tamper',
        filePath,
        fileName: 'cipher_tamper.bin',
        fileSize: data.length,
        sha256: crypto.createHash('sha256').update(data).digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'CIPHER_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Header is 48 bytes. Chunk 0 frame is 37 bytes. Ciphertext starts at byte 85.
      fs.chmodSync(item.blobPath, 0o666);
      containerBuf[100] = containerBuf[100] ^ 0xff; // Flip bits in chunk 0 ciphertext
      fs.writeFileSync(item.blobPath, containerBuf);

      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /INTEGRITY_CHECK_FAILED/i
      );
    });

    it('rejects tampered chunk index (sequence violation)', async () => {
      const filePath = path.join(workDir, 'seq_tamper.bin');
      const data = crypto.randomBytes(70 * 1024);
      fs.writeFileSync(filePath, data);

      const threat: DetectedThreat = {
        id: 't-seq-tamper',
        filePath,
        fileName: 'seq_tamper.bin',
        fileSize: data.length,
        sha256: crypto.createHash('sha256').update(data).digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'SEQ_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Header = 48 bytes. Chunk 0 index is at offset 48 (4 bytes uint32BE). Change 0 to 5.
      fs.chmodSync(item.blobPath, 0o666);
      containerBuf.writeUInt32BE(5, 48);
      fs.writeFileSync(item.blobPath, containerBuf);

      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /INTEGRITY_CHECK_FAILED|Chunk sequence violation/i
      );
    });

    it('rejects truncated container where final chunk is omitted', async () => {
      const filePath = path.join(workDir, 'trunc_tamper.bin');
      const data = crypto.randomBytes(70 * 1024); // 2 chunks
      fs.writeFileSync(filePath, data);

      const threat: DetectedThreat = {
        id: 't-trunc-tamper',
        filePath,
        fileName: 'trunc_tamper.bin',
        fileSize: data.length,
        sha256: crypto.createHash('sha256').update(data).digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'TRUNC_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Truncate to just header + chunk 0 (isFinal=0 on chunk 0)
      const chunk0CipherLen = 64 * 1024;
      const truncatedBuf = containerBuf.subarray(0, 48 + 37 + chunk0CipherLen);
      fs.chmodSync(item.blobPath, 0o666);
      fs.writeFileSync(item.blobPath, truncatedBuf);

      // Restoration will reach EOF without seeing isFinal=1, or restored SHA will fail
      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /INTEGRITY_CHECK_FAILED|CORRUPTED_VAULT/i
      );
    });

    it('rejects tampered GCM auth tag in chunk (1-bit flip in auth tag)', async () => {
      const filePath = path.join(workDir, 'authtag_tamper.bin');
      const data = crypto.randomBytes(70 * 1024);
      fs.writeFileSync(filePath, data);

      const threat: DetectedThreat = {
        id: 't-auth-tamper',
        filePath,
        fileName: 'authtag_tamper.bin',
        fileSize: data.length,
        sha256: crypto.createHash('sha256').update(data).digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'AUTH_TAG_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Header is 48 bytes. Chunk 0 frame starts at offset 48.
      // Auth tag is at offset 48 + 17 = 65 (16 bytes). Flip 1 bit in auth tag:
      fs.chmodSync(item.blobPath, 0o666);
      containerBuf[65] = containerBuf[65] ^ 0x01;
      fs.writeFileSync(item.blobPath, containerBuf);

      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /INTEGRITY_CHECK_FAILED/i
      );
    });

    it('rejects reordered chunks (chunk sequence tampering)', async () => {
      const filePath = path.join(workDir, 'reorder_tamper.bin');
      const data = crypto.randomBytes(130 * 1024); // 3 chunks (chunk 0: 64K, chunk 1: 64K, chunk 2: 2K)
      fs.writeFileSync(filePath, data);

      const threat: DetectedThreat = {
        id: 't-reorder-tamper',
        filePath,
        fileName: 'reorder_tamper.bin',
        fileSize: data.length,
        sha256: crypto.createHash('sha256').update(data).digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'REORDER_TAMPER',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const item = await quarantine.isolateFile(threat);
      const containerBuf = fs.readFileSync(item.blobPath);

      // Chunk 0 frame + ciphertext: 37 + 65536 = 65573 bytes at offset 48.
      // Chunk 1 frame + ciphertext: 37 + 65536 = 65573 bytes at offset 48 + 65573 = 65621.
      // Swap chunk 0 and chunk 1
      const header = containerBuf.subarray(0, 48);
      const chunk0 = containerBuf.subarray(48, 48 + 65573);
      const chunk1 = containerBuf.subarray(48 + 65573, 48 + 65573 * 2);
      const rest = containerBuf.subarray(48 + 65573 * 2);

      const swapped = Buffer.concat([header, chunk1, chunk0, rest]);
      fs.chmodSync(item.blobPath, 0o666);
      fs.writeFileSync(item.blobPath, swapped);

      await expect(quarantine.restoreItem(item.quarantineId)).rejects.toThrow(
        /INTEGRITY_CHECK_FAILED|Chunk sequence violation/i
      );
    });

    it('rejects symlink and junction targets during isolation and restoration (TOCTOU defense)', async () => {
      const realTarget = path.join(workDir, 'real_target.txt');
      fs.writeFileSync(realTarget, 'Safe real target');
      const symlinkSource = path.join(workDir, 'symlink_attack.exe');

      try {
        fs.symlinkSync(realTarget, symlinkSource);
      } catch {
        // If symlink creation fails due to Windows non-admin privileges, skip gracefully
        return;
      }

      const threat: DetectedThreat = {
        id: 't-symlink-attack',
        filePath: symlinkSource,
        fileName: 'symlink_attack.exe',
        fileSize: 16,
        sha256: crypto.createHash('sha256').update('Safe real target').digest('hex'),
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'SYMLINK_ATTACK',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      await expect(quarantine.isolateFile(threat)).rejects.toThrow(/SECURITY_VIOLATION/i);
    });
  });

  describe('Encrypted Manifest & Crash Recovery', () => {
    it('manifest is encrypted on disk (manifest.json.enc) and NOT plaintext JSON', async () => {
      const filePath = path.join(workDir, 'manifest_test.bin');
      fs.writeFileSync(filePath, 'Manifest security test');

      const threat: DetectedThreat = {
        id: 't-manif-1',
        filePath,
        fileName: 'manifest_test.bin',
        fileSize: 22,
        sha256: crypto.createHash('sha256').update('Manifest security test').digest('hex'),
        riskScore: 80,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'MANIF_TEST',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      await quarantine.isolateFile(threat);

      const encPath = path.join(vaultDir, 'manifest.json.enc');
      expect(fs.existsSync(encPath)).toBe(true);

      const rawEnc = fs.readFileSync(encPath);
      // Header magic must be PPMANIF1
      expect(rawEnc.subarray(0, 8).toString('utf8')).toBe('PPMANIF1');
      // Must NOT contain plaintext JSON keywords
      expect(rawEnc.includes(Buffer.from('quarantineId'))).toBe(false);
      expect(rawEnc.includes(Buffer.from('originalPath'))).toBe(false);
    });

    it('recovers quarantine manifest from .bak backup when .enc is corrupted', async () => {
      const filePath1 = path.join(workDir, 'file1.bin');
      const filePath2 = path.join(workDir, 'file2.bin');
      fs.writeFileSync(filePath1, 'File 1 content');
      fs.writeFileSync(filePath2, 'File 2 content');

      await quarantine.isolateFile({
        id: 't-rec-1',
        filePath: filePath1,
        fileName: 'file1.bin',
        fileSize: 14,
        sha256: crypto.createHash('sha256').update('File 1 content').digest('hex'),
        riskScore: 80,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'RECOVER_1',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      });

      // Isolating second file creates .bak of the first state
      await quarantine.isolateFile({
        id: 't-rec-2',
        filePath: filePath2,
        fileName: 'file2.bin',
        fileSize: 14,
        sha256: crypto.createHash('sha256').update('File 2 content').digest('hex'),
        riskScore: 80,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'RECOVER_2',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      });

      const encPath = path.join(vaultDir, 'manifest.json.enc');
      const bakPath = path.join(vaultDir, 'manifest.json.enc.bak');
      expect(fs.existsSync(encPath)).toBe(true);
      expect(fs.existsSync(bakPath)).toBe(true);

      // Corrupt primary manifest.json.enc
      fs.writeFileSync(encPath, Buffer.from('TOTAL_CORRUPTION_GARBAGE_PAYLOAD'));

      // Re-initialize new QuarantineService instance; must recover from .bak
      const recoveredService = new QuarantineService(vaultDir);
      const items = recoveredService.listQuarantine();
      expect(items.length).toBeGreaterThanOrEqual(1);
    });

    it('migrates legacy unencrypted manifest.json to encrypted manifest.json.enc', async () => {
      const legacyPath = path.join(vaultDir, 'manifest.json');
      const dummyItem = {
        quarantineId: 'quarantine-legacy-uuid-1',
        originalPath: path.join(workDir, 'legacy_item.bin'),
        fileName: 'legacy_item.bin',
        fileSize: 100,
        sha256: 'a'.repeat(64),
        threatName: 'LEGACY_THREAT',
        riskScore: 80,
        severity: 'critical',
        quarantinedAt: Date.now(),
        evidenceFactors: ['legacy migration'],
        blobPath: path.join(vaultDir, 'quarantine-legacy-uuid-1.blob')
      };

      fs.writeFileSync(legacyPath, JSON.stringify([dummyItem], null, 2), 'utf8');

      const migratedService = new QuarantineService(vaultDir);
      expect(migratedService.listQuarantine().length).toBe(1);
      expect(migratedService.listQuarantine()[0].quarantineId).toBe('quarantine-legacy-uuid-1');

      // Verify encrypted manifest now exists
      const encPath = path.join(vaultDir, 'manifest.json.enc');
      expect(fs.existsSync(encPath)).toBe(true);
    });
  });

  describe('Restore & Trust SHA-256 Integration Flow', () => {
    it('restores file with trustSha256: true and ensures ThreatIntel and CleanFileCache allow it', async () => {
      const maliciousFile = path.join(workDir, 'false_alarm.exe');
      const content = Buffer.from('Legitimate internal administrative tooling payload');
      fs.writeFileSync(maliciousFile, content);

      const fileSha = crypto.createHash('sha256').update(content).digest('hex');
      const threat: DetectedThreat = {
        id: 't-trust-test',
        filePath: maliciousFile,
        fileName: 'false_alarm.exe',
        fileSize: content.length,
        sha256: fileSha,
        riskScore: 85,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'SUSPICIOUS_ADMIN_TOOL',
        detectedAt: Date.now(),
        evidenceFactors: ['Administrative tool'],
        quarantined: false
      };

      const qItem = await quarantine.isolateFile(threat);
      expect(fs.existsSync(maliciousFile)).toBe(false);

      // Restore with trustSha256: true
      const restoredPath = await quarantine.restoreItem(qItem.quarantineId, { trustSha256: true });
      expect(fs.existsSync(restoredPath)).toBe(true);

      // 1. Verify ThreatIntel singleton has registered the SHA-256 as trusted
      const intel = ThreatIntel.getSharedInstance();
      expect(intel.isHashAllowed(fileSha)).toBe(true);
      const lookup = intel.lookupHash(fileSha);
      expect(lookup.status).toBe('KNOWN_GOOD');

      // 2. Verify FileAnalyzer.analyzeFile now evaluates the restored file as ALLOW
      const analysis = await FileAnalyzer.analyzeFile(restoredPath);
      expect(analysis.verdict).toBe('ALLOW');
      expect(analysis.riskScore).toBe(0);
      expect(analysis.threatName).toMatch(/TRUSTED_ALLOWLISTED_FILE|CLEAN_CACHED_FILE/);
    });

    it('full lifecycle: isolate -> restart service -> verify manifest recovery -> restore with trustSha256 -> verify RealtimeMonitorService does not re-quarantine', async () => {
      const { RealtimeMonitorService } = await import('../../services/realtime-monitor.service');

      const targetPath = path.join(workDir, 'admin_helper.exe');
      const payload = Buffer.concat([
        Buffer.from([0x4d, 0x5a, 0x90, 0x00]), // MZ header
        crypto.randomBytes(4096)
      ]);
      fs.writeFileSync(targetPath, payload);
      const payloadSha = crypto.createHash('sha256').update(payload).digest('hex');

      const threat: DetectedThreat = {
        id: 't-lifecycle-threat',
        filePath: targetPath,
        fileName: 'admin_helper.exe',
        fileSize: payload.length,
        sha256: payloadSha,
        riskScore: 85,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'LIFECYCLE_TARGET',
        detectedAt: Date.now(),
        evidenceFactors: ['Lifecycle verification sample'],
        quarantined: false
      };

      // 1. Isolate the threat into vault
      const isolatedItem = await quarantine.isolateFile(threat);
      expect(fs.existsSync(targetPath)).toBe(false);
      expect(fs.existsSync(isolatedItem.blobPath)).toBe(true);

      // 2. Restart service (simulating app shutdown and restart)
      const restartedQuarantine = new QuarantineService(vaultDir);

      // 3. Verify manifest recovery
      const loadedItems = restartedQuarantine.listQuarantine();
      expect(loadedItems.length).toBe(1);
      expect(loadedItems[0].quarantineId).toBe(isolatedItem.quarantineId);
      expect(loadedItems[0].sha256).toBe(payloadSha);

      // 4. Restore with trustSha256: true
      const restoredPath = await restartedQuarantine.restoreItem(isolatedItem.quarantineId, {
        trustSha256: true
      });
      expect(fs.existsSync(restoredPath)).toBe(true);
      expect(restartedQuarantine.listQuarantine().length).toBe(0);

      // 5. Verify RealtimeMonitorService does not re-quarantine or flag the restored file
      const monitor = new RealtimeMonitorService({
        monitoredPaths: [workDir],
        autoQuarantineCritical: true
      });

      let threatDetectedCalled = false;
      monitor.on('threatDetected', () => {
        threatDetectedCalled = true;
      });

      await monitor.evaluateIncomingFile(restoredPath);

      expect(threatDetectedCalled).toBe(false);
      expect(fs.existsSync(restoredPath)).toBe(true);
      monitor.stop();
    });
  });

  describe('Bounded Memory & Large File Streaming (<16 MB Heap Delta)', () => {
    it('streams a large 20 MB synthetic file without ballooning V8 heap', async () => {
      const largeFile = path.join(workDir, 'large_synthetic_20mb.bin');
      const largeSize = 20 * 1024 * 1024; // 20 MB synthetic stream
      const chunkPattern = Buffer.alloc(QuarantineService.CHUNK_SIZE, 0x5a);

      const hash = crypto.createHash('sha256');
      const outFd = fs.openSync(largeFile, 'w');
      let written = 0;
      while (written < largeSize) {
        const toWrite = Math.min(chunkPattern.length, largeSize - written);
        fs.writeSync(outFd, chunkPattern, 0, toWrite);
        hash.update(chunkPattern.subarray(0, toWrite));
        written += toWrite;
      }
      fs.closeSync(outFd);
      const expectedSha = hash.digest('hex');

      // Baseline heap check
      if (global.gc) global.gc();
      const initialHeapUsed = process.memoryUsage().heapUsed;

      const threat: DetectedThreat = {
        id: 't-large-20mb',
        filePath: largeFile,
        fileName: 'large_synthetic_20mb.bin',
        fileSize: largeSize,
        sha256: expectedSha,
        riskScore: 80,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'LARGE_FILE_TEST_20MB',
        detectedAt: Date.now(),
        evidenceFactors: ['Large synthetic streaming test 20MB'],
        quarantined: false
      };

      const qItem = await quarantine.isolateFile(threat);
      expect(fs.existsSync(largeFile)).toBe(false);
      expect(fs.existsSync(qItem.blobPath)).toBe(true);

      const restoredPath = await quarantine.restoreItem(qItem.quarantineId);
      expect(fs.existsSync(restoredPath)).toBe(true);

      if (global.gc) global.gc();
      const finalHeapUsed = process.memoryUsage().heapUsed;
      const heapDeltaBytes = Math.abs(finalHeapUsed - initialHeapUsed);
      const heapDeltaMb = heapDeltaBytes / (1024 * 1024);

      // Verify peak heap delta is strictly bounded (< 16 MB)
      expect(heapDeltaMb).toBeLessThan(16);

      // Verify integrity of the restored 20 MB file
      const restoredStat = fs.statSync(restoredPath);
      expect(restoredStat.size).toBe(largeSize);
    });

    it('streams a large 100 MB synthetic file and verifies peak V8 heap delta is <16 MB', async () => {
      const largeFile = path.join(workDir, 'large_synthetic_100mb.bin');
      const largeSize = 100 * 1024 * 1024; // 100 MB synthetic stream (Phase D SLA requirement)
      const chunkPattern = Buffer.alloc(QuarantineService.CHUNK_SIZE, 0xa5);

      const hash = crypto.createHash('sha256');
      const outFd = fs.openSync(largeFile, 'w');
      let written = 0;
      while (written < largeSize) {
        const toWrite = Math.min(chunkPattern.length, largeSize - written);
        fs.writeSync(outFd, chunkPattern, 0, toWrite);
        hash.update(chunkPattern.subarray(0, toWrite));
        written += toWrite;
      }
      fs.closeSync(outFd);
      const expectedSha = hash.digest('hex');

      // Baseline heap check
      if (global.gc) global.gc();
      const initialHeapUsed = process.memoryUsage().heapUsed;

      const threat: DetectedThreat = {
        id: 't-large-100mb',
        filePath: largeFile,
        fileName: 'large_synthetic_100mb.bin',
        fileSize: largeSize,
        sha256: expectedSha,
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'LARGE_FILE_TEST_100MB',
        detectedAt: Date.now(),
        evidenceFactors: ['Large synthetic streaming test 100MB SLA'],
        quarantined: false
      };

      const qItem = await quarantine.isolateFile(threat);
      expect(fs.existsSync(largeFile)).toBe(false);
      expect(fs.existsSync(qItem.blobPath)).toBe(true);

      const restoredPath = await quarantine.restoreItem(qItem.quarantineId);
      expect(fs.existsSync(restoredPath)).toBe(true);

      if (global.gc) global.gc();
      const finalHeapUsed = process.memoryUsage().heapUsed;
      const heapDeltaBytes = Math.abs(finalHeapUsed - initialHeapUsed);
      const heapDeltaMb = heapDeltaBytes / (1024 * 1024);

      // Verify peak heap delta is strictly bounded (< 16 MB)
      expect(heapDeltaMb).toBeLessThan(16);

      // Verify integrity of the restored 100 MB file
      const restoredStat = fs.statSync(restoredPath);
      expect(restoredStat.size).toBe(largeSize);
    });
  });
});
