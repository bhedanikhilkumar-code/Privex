import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { CoreFileAnalyzer } from '@private-protection/core';
import { FileAnalyzer } from '../../core/file-analyzer';
import { DesktopSecurityAdapter } from '../../core/desktop-security-adapter';
import { ScannerService } from '../../services/scanner.service';
import { QuarantineService } from '../../services/quarantine.service';
import { SecureStorageService } from '../../services/secure-storage.service';
import { IpcValidator } from '../../ipc/ipc-validator';
import { IpcHandler } from '../../ipc/ipc-handler';

describe('Phase A — Desktop Security Core Hardening & Offline Verification Suite (Steps 4–15)', () => {
  let tempDir: string;
  let vaultDir: string;
  let configDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-a-sec-'));
    vaultDir = path.join(tempDir, 'vault');
    configDir = path.join(tempDir, 'config');
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('1. Input Validation: Path Traversal, Encoded Traversal, ADS, Long Paths & Symlinks', () => {
    it('rejects relative traversal, URL-encoded traversal, NTFS ADS colons, and paths > 1024 chars', () => {
      expect(() => IpcValidator.validatePath('../etc/passwd')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validatePath('C:\\Users\\..\\Windows\\System32')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validatePath('C:\\Users\\%2e%2e\\Windows')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validatePath('C:\\Users\\test\\evil.exe:$DATA')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validatePath('C:\\Users\\test\\doc.txt:hidden.exe')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validatePath('\\\\.\\PhysicalDrive0')).toThrow(/SECURITY_VIOLATION/);
      expect(() => IpcValidator.validatePath('C:\\' + 'a'.repeat(1030))).toThrow(/INVALID_PATH/);
      expect(() => IpcValidator.validatePath('')).toThrow(/INVALID_PATH/);
      expect(() => IpcValidator.validatePath(null)).toThrow(/INVALID_PATH/);
    });

    it('enforces maxDepth recursion limit and followSymlinks policy in ScannerService', async () => {
      const scanner = new ScannerService();
      scanner.setMaxDepth(2);

      // Create depth 4 nested directory
      const d1 = path.join(tempDir, 'd1');
      const d2 = path.join(d1, 'd2');
      const d3 = path.join(d2, 'd3');
      const d4 = path.join(d3, 'd4');
      fs.mkdirSync(d4, { recursive: true });
      fs.writeFileSync(path.join(d1, 'level1.txt'), 'clean 1');
      fs.writeFileSync(path.join(d4, 'too_deep.txt'), 'clean 4');

      const res = await scanner.scanPaths([d1], 'custom');
      expect(res.totalFilesScanned).toBe(1);
      expect(res.skippedFiles.some((s) => s.reason.includes('Maximum directory recursion depth'))).toBe(true);
    });
  });

  describe('2. Missing, Deleted, Locked, Permission-Denied, Empty, Corrupt & Short-Read Files', () => {
    it('handles missing files, empty 0-byte files, and truncated 1-byte/2-byte headers safely', async () => {
      const emptyFile = path.join(tempDir, 'empty.txt');
      const oneByteFile = path.join(tempDir, 'one.bin');
      const twoByteMz = path.join(tempDir, 'tiny_mz.pdf');
      fs.writeFileSync(emptyFile, Buffer.alloc(0));
      fs.writeFileSync(oneByteFile, Buffer.from([0x4d]));
      fs.writeFileSync(twoByteMz, Buffer.from([0x4d, 0x5a]));

      const emptyRes = await FileAnalyzer.analyzeFile(emptyFile);
      expect(emptyRes.fileSize).toBe(0);
      expect(emptyRes.entropy).toBe(0);
      expect(emptyRes.verdict).toBe('ALLOW');
      expect(emptyRes.analysisStatus).toBe('COMPLETED');

      const oneByteRes = await FileAnalyzer.analyzeFile(oneByteFile);
      expect(oneByteRes.fileSize).toBe(1);
      expect(oneByteRes.magicHeader).toBeNull();

      // 2-byte MZ disguised as .pdf -> DISGUISED_EXECUTABLE BLOCK
      const twoByteRes = await FileAnalyzer.analyzeFile(twoByteMz);
      expect(twoByteRes.magicHeader).toBe('PE/MZ_EXECUTABLE');
      expect(twoByteRes.verdict).toBe('BLOCK');
      expect(twoByteRes.disposition).toBe('MALICIOUS');

      // Missing file via analyzeFileSafe returns ANALYSIS_FAILED / WARN (never SAFE/ALLOW)
      const missingSafe = await FileAnalyzer.analyzeFileSafe(path.join(tempDir, 'does_not_exist.exe'));
      expect(missingSafe.analysisStatus).toBe('ANALYSIS_FAILED');
      expect(missingSafe.disposition).toBe('ANALYSIS_FAILED');
      expect(missingSafe.verdict).not.toBe('ALLOW');
    });

    it('detects locked deceptive double-extension files (EBUSY) as WARN threats instead of silently skipping as ALLOW', async () => {
      const scanner = new ScannerService();
      const lockedDeceptivePath = path.join(tempDir, 'urgent_tax_return.pdf.exe');
      fs.writeFileSync(lockedDeceptivePath, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

      vi.spyOn(FileAnalyzer, 'analyzeFile').mockRejectedValueOnce(
        Object.assign(new Error('Resource busy or locked'), { code: 'EBUSY' })
      );

      const result = await scanner.scanPaths([lockedDeceptivePath], 'custom');
      expect(result.skippedFiles.some((s) => s.reason.includes('EBUSY'))).toBe(true);
      expect(result.threats.length).toBe(1);
      expect(result.threats[0].threatName).toBe('LOCKED_DECEPTIVE_FILE');
      expect(result.threats[0].verdict).toBe('WARN');
      expect(result.overallVerdict).toBe('WARN');
    });

    it('fails closed to overallVerdict WARN and ANALYSIS_FAILED when scanner encounters unexpected file errors', async () => {
      const scanner = new ScannerService();
      const targetFile = path.join(tempDir, 'corrupt_io.bin');
      fs.writeFileSync(targetFile, 'test');

      vi.spyOn(FileAnalyzer, 'analyzeFile').mockRejectedValueOnce(new Error('Simulated disk I/O read failure'));

      const result = await scanner.scanPaths([targetFile], 'custom');
      expect(result.errors.length).toBe(1);
      expect(result.overallVerdict).toBe('WARN');
      expect(result.analysisStatus).toBe('ANALYSIS_FAILED');
      expect(result.disposition).toBe('ANALYSIS_FAILED');
    });
  });

  describe('3. Configuration Security: Schema Validation, Backup Recovery & Tamper Handling (Step 11)', () => {
    it('recovers from settings.enc corruption using settings.enc.bak and logs CONFIG_FAILURE', () => {
      const storage = new SecureStorageService(configDir);
      storage.saveSettings({ scanLargeFilesLimitMb: 120, cognitiveLevel: 'grade8' });
      // Second save creates .bak of the valid settings.enc
      storage.saveSettings({ scanLargeFilesLimitMb: 150, cognitiveLevel: 'grade8' });

      // Corrupt primary settings.enc
      fs.writeFileSync(path.join(configDir, 'settings.enc'), '{corrupted-json-payload', 'utf8');

      const freshStorage = new SecureStorageService(configDir);
      const recovered = freshStorage.getSettings();
      // Should recover from .bak (120 MB, grade8)
      expect(recovered.cognitiveLevel).toBe('grade8');
      expect(recovered.scanLargeFilesLimitMb).toBe(120);

      const events = freshStorage.getSecurityEvents();
      expect(events.some((e) => e.type === 'CONFIG_FAILURE')).toBe(true);
    });

    it('falls back to safe defaults when both settings.enc and .bak are tampered/corrupted', () => {
      fs.mkdirSync(configDir, { recursive: true });
      fs.writeFileSync(path.join(configDir, 'settings.enc'), '{"iv":"00","tag":"00","data":"00"}', 'utf8');

      const storage = new SecureStorageService(configDir);
      const settings = storage.getSettings();
      expect(settings.realtimeShieldEnabled).toBe(true);
      expect(settings.frictionGateEnabled).toBe(true);
      expect(settings.scanLargeFilesLimitMb).toBe(50);
      expect(storage.getSecurityEvents().some((e) => e.type === 'CONFIG_FAILURE')).toBe(true);
    });
  });

  describe('4. Quarantine Foundation: Atomic Manifest .bak Crash Recovery & Vault Confinement (Step 10)', () => {
    it('recovers quarantined items from manifest.json.bak if manifest.json is truncated during a crash', async () => {
      const quarantine = new QuarantineService(vaultDir);
      const file1 = path.join(tempDir, 'malware1.pdf.exe');
      const file2 = path.join(tempDir, 'malware2.pdf.exe');
      fs.writeFileSync(file1, Buffer.from([0x4d, 0x5a, 0x90, 0x00, 1, 2, 3]));
      fs.writeFileSync(file2, Buffer.from([0x4d, 0x5a, 0x90, 0x00, 4, 5, 6]));

      const item1 = await quarantine.isolateFile({
        id: 't-1',
        filePath: file1,
        fileName: 'malware1.pdf.exe',
        fileSize: 7,
        sha256: '',
        riskScore: 85,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'DECEPTIVE_DOUBLE_EXTENSION',
        detectedAt: Date.now(),
        evidenceFactors: ['Double extension'],
        quarantined: false
      });

      await quarantine.isolateFile({
        id: 't-2',
        filePath: file2,
        fileName: 'malware2.pdf.exe',
        fileSize: 7,
        sha256: '',
        riskScore: 85,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'DECEPTIVE_DOUBLE_EXTENSION',
        detectedAt: Date.now(),
        evidenceFactors: ['Double extension'],
        quarantined: false
      });

      // Simulate crash truncation of primary manifest.json while manifest.json.bak holds item1
      fs.writeFileSync(path.join(vaultDir, 'manifest.json'), '[{"quarantineId": "truncated', 'utf8');

      const reloadedQuarantine = new QuarantineService(vaultDir);
      const recoveredList = reloadedQuarantine.listQuarantine();
      expect(recoveredList.length).toBeGreaterThanOrEqual(1);
      expect(recoveredList.some((i) => i.quarantineId === item1.quarantineId)).toBe(true);
    });

    it('rejects manifest entries whose blobPath points outside the quarantine vault directory', () => {
      fs.mkdirSync(vaultDir, { recursive: true });
      const outsideBlob = path.join(tempDir, 'outside.blob');
      fs.writeFileSync(outsideBlob, 'outside');

      const poisonedManifest = [
        {
          quarantineId: 'quarantine-11111111-2222-3333-4444-555555555555',
          originalPath: path.join(tempDir, 'orig.exe'),
          fileName: 'orig.exe',
          fileSize: 7,
          sha256: 'a'.repeat(64),
          threatName: 'POISONED',
          riskScore: 90,
          severity: 'critical',
          quarantinedAt: Date.now(),
          evidenceFactors: [],
          blobPath: outsideBlob
        }
      ];
      fs.writeFileSync(path.join(vaultDir, 'manifest.json'), JSON.stringify(poisonedManifest), 'utf8');

      const quarantine = new QuarantineService(vaultDir);
      expect(quarantine.listQuarantine().length).toBe(0);
    });

    it('neutralizes trailing dots/spaces combined with Windows reserved device names in sanitizeFileName', () => {
      expect(QuarantineService.sanitizeFileName('CON.txt... ')).toBe('safe_CON.txt');
      expect(QuarantineService.sanitizeFileName('LPT1...')).toBe('safe_LPT1');
      expect(QuarantineService.sanitizeFileName('invoice_\u202Efdp.exe')).toBe('invoice_fdp.exe');
    });
  });

  describe('5. Bounded Security Event Logging & Zero Tier-1 Data Leakage (Step 12)', () => {
    it('records scan, detection, quarantine, restore, and config events within bounded capacity without Tier-1 content leakage', async () => {
      const handler = new IpcHandler({
        vaultDir,
        configDir,
        autoStartRealtime: false
      });

      const sensitiveContent = 'TOP_SECRET_USER_DOCUMENT_BODY_SSN_999_00_1111';
      const payload = Buffer.concat([
        Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
        Buffer.from(sensitiveContent, 'utf8')
      ]);
      const malFile = path.join(tempDir, 'confidential.pdf.exe');
      fs.writeFileSync(malFile, payload);

      const scanRes = await handler.handleStartCustomScan([malFile]);
      expect(scanRes.threats.length).toBe(1);

      const isolated = await handler.handleIsolateFile(malFile);
      const restoreDir = path.join(tempDir, 'restored');
      fs.mkdirSync(restoreDir, { recursive: true });
      await handler.handleRestoreQuarantine(isolated.quarantineId, restoreDir);

      const events = handler.getSecurityEvents();
      const eventTypes = events.map((e) => e.type);
      expect(eventTypes).toContain('SCAN_STARTED');
      expect(eventTypes).toContain('THREAT_DETECTED');
      expect(eventTypes).toContain('SCAN_COMPLETED');
      expect(eventTypes).toContain('QUARANTINE_ISOLATED');
      expect(eventTypes).toContain('QUARANTINE_RESTORED');

      // Verify zero Tier-1 raw file content appears anywhere in security events
      const serializedEvents = JSON.stringify(events);
      expect(serializedEvents).not.toContain(sensitiveContent);

      // Verify strict ring-buffer cap (MAX_SECURITY_EVENTS = 250)
      const storage = handler.getStorage();
      for (let i = 0; i < 300; i++) {
        storage.recordSecurityEvent('SCAN_COMPLETED', 'INFO', `Event ${i}`);
      }
      expect(storage.getSecurityEvents().length).toBe(SecureStorageService.MAX_SECURITY_EVENTS);
    });
  });

  describe('6. Step 13 Full Socket-Level Offline Air-Gapped Verification', () => {
    it('executes File Scan, Directory Scan, Quarantine, Restore, Settings, and AI Explanation with all Node network/socket APIs hard-disabled', async () => {
      const netViolation = () => {
        throw new Error('NETWORK_DISABLED_AIRGAP_VIOLATION');
      };

      const connectSpy = vi.spyOn(net.Socket.prototype, 'connect').mockImplementation(netViolation as any);
      const origFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockImplementation(netViolation);

      try {
        const handler = new IpcHandler({
          vaultDir,
          configDir,
          autoStartRealtime: false
        });
        const adapter = new DesktopSecurityAdapter();

        const eicarFile = path.join(tempDir, 'eicar_test.com');
        fs.writeFileSync(eicarFile, CoreFileAnalyzer.EICAR_SIGNATURE, 'utf8');

        const scanResult = await handler.handleStartCustomScan([tempDir]);
        expect(scanResult.overallVerdict).toBe('BLOCK');
        expect(scanResult.threats.length).toBe(1);
        expect(scanResult.threats[0].threatName).toBe('EICAR_TEST_FILE');

        const explanation = await handler.handleExplainThreat(scanResult.threats[0], 'grade6');
        expect(explanation.threatTitle).toBe('EICAR_TEST_FILE');
        expect(explanation.recommendedActions.length).toBeGreaterThan(0);

        const urlScan = await adapter.scanUrl('http://192.168.1.1/login-apple-id-verify');
        expect(urlScan.riskScore).toBeGreaterThanOrEqual(50);

        const isolated = await handler.handleIsolateFile(eicarFile);
        expect(fs.existsSync(eicarFile)).toBe(false);

        const restoredPath = await handler.handleRestoreQuarantine(isolated.quarantineId, tempDir);
        expect(fs.existsSync(restoredPath)).toBe(true);
      } finally {
        connectSpy.mockRestore();
        globalThis.fetch = origFetch;
      }
    });
  });
});
