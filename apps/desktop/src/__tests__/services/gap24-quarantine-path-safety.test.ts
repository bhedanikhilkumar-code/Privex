import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('GAP-24: Desktop Quarantine Path & Filename Safety Audit', () => {
  let tempBaseDir: string;
  let vaultDir: string;
  let service: QuarantineService;

  beforeEach(() => {
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-gap24-test-'));
    vaultDir = path.join(tempBaseDir, 'quarantine_vault');
    fs.mkdirSync(vaultDir, { recursive: true });
    service = new QuarantineService(vaultDir);
  });

  afterEach(() => {
    try {
      fs.rmSync(tempBaseDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  describe('QuarantineService.sanitizeFileName', () => {
    it('handles normal filenames without alteration', () => {
      expect(QuarantineService.sanitizeFileName('document.pdf')).toBe('document.pdf');
      expect(QuarantineService.sanitizeFileName('report_2026.docx')).toBe('report_2026.docx');
    });

    it('strips directory traversal sequences', () => {
      expect(QuarantineService.sanitizeFileName('../escape.txt')).toBe('escape.txt');
      expect(QuarantineService.sanitizeFileName('../../escape.exe')).toBe('escape.exe');
      expect(QuarantineService.sanitizeFileName('..\\..\\nested\\danger.bat')).toBe('danger.bat');
      expect(QuarantineService.sanitizeFileName('/etc/shadow')).toBe('shadow');
      expect(QuarantineService.sanitizeFileName('C:\\Windows\\System32\\cmd.exe')).toBe('cmd.exe');
      expect(QuarantineService.sanitizeFileName('\\\\remote-server\\share\\exploit.bin')).toBe('exploit.bin');
    });

    it('neutralizes Windows DOS reserved device names', () => {
      expect(QuarantineService.sanitizeFileName('CON')).toBe('safe_CON');
      expect(QuarantineService.sanitizeFileName('con.txt')).toBe('safe_con.txt');
      expect(QuarantineService.sanitizeFileName('PRN')).toBe('safe_PRN');
      expect(QuarantineService.sanitizeFileName('AUX.dat')).toBe('safe_AUX.dat');
      expect(QuarantineService.sanitizeFileName('NUL')).toBe('safe_NUL');
      expect(QuarantineService.sanitizeFileName('com1.log')).toBe('safe_com1.log');
      expect(QuarantineService.sanitizeFileName('lpt3.bin')).toBe('safe_lpt3.bin');
    });

    it('strips null bytes and illegal filesystem characters', () => {
      const sanitized = QuarantineService.sanitizeFileName('mal\0icious<script>:test?.exe');
      expect(sanitized).not.toContain('\0');
      expect(sanitized).not.toContain('<');
      expect(sanitized).not.toContain('>');
      expect(sanitized).not.toContain(':');
      expect(sanitized).not.toContain('?');
    });

    it('handles empty, dots, and non-string inputs safely with timestamped fallback', () => {
      const dot = QuarantineService.sanitizeFileName('.');
      expect(dot.startsWith('quarantined_file_')).toBe(true);

      const dotdot = QuarantineService.sanitizeFileName('..');
      expect(dotdot.startsWith('quarantined_file_')).toBe(true);

      const empty = QuarantineService.sanitizeFileName('');
      expect(empty.startsWith('quarantined_file_')).toBe(true);

      const nullInput = QuarantineService.sanitizeFileName(null as any);
      expect(nullInput.startsWith('quarantined_file_')).toBe(true);
    });
  });

  describe('isolateFile() with malicious threat payloads', () => {
    it('sanitizes threat.fileName in QuarantineItem during isolation', async () => {
      const sampleFile = path.join(tempBaseDir, 'test_malware.exe');
      fs.writeFileSync(sampleFile, 'MZ_PAYLOAD_TEST');

      const threat: DetectedThreat = {
        id: 'threat-1',
        filePath: sampleFile,
        fileName: '../../../../Windows/System32/con.exe',
        fileSize: 15,
        sha256: 'dummy-sha-256',
        threatName: 'Malicious Header',
        riskScore: 90,
        severity: 'critical',
        verdict: 'BLOCK',
        detectedAt: Date.now(),
        quarantined: false,
        evidenceFactors: ['MZ Header']
      };

      const item = await service.isolateFile(threat);
      expect(item.fileName).toBe('safe_con.exe');
      expect(item.fileName).not.toContain('..');
      expect(fs.existsSync(sampleFile)).toBe(false); // Verified unlinked
    });
  });

  describe('restoreItem() path containment defense', () => {
    it('restores strictly inside customDestinationDir even when given malicious fileName in item', async () => {
      const sampleFile = path.join(tempBaseDir, 'threat_to_restore.bin');
      const testContent = Buffer.from('TEST_SECURE_RESTORE_BYTES');
      fs.writeFileSync(sampleFile, testContent);

      const crypto = await import('crypto');
      const realSha = crypto.createHash('sha256').update(testContent).digest('hex');

      const threat: DetectedThreat = {
        id: 'threat-2',
        filePath: sampleFile,
        fileName: '..\\..\\malicious.bin',
        fileSize: testContent.length,
        sha256: realSha,
        threatName: 'Test Threat',
        riskScore: 88,
        severity: 'critical',
        verdict: 'BLOCK',
        detectedAt: Date.now(),
        quarantined: false,
        evidenceFactors: ['Test']
      };

      const item = await service.isolateFile(threat);
      expect(item.fileName).toBe('malicious.bin');

      const restoreDestDir = path.join(tempBaseDir, 'restore_target');
      fs.mkdirSync(restoreDestDir, { recursive: true });

      const restoredPath = await service.restoreItem(item.quarantineId, restoreDestDir);
      expect(restoredPath.startsWith(path.resolve(restoreDestDir))).toBe(true);
      expect(fs.existsSync(restoredPath)).toBe(true);
      expect(fs.readFileSync(restoredPath).toString()).toBe('TEST_SECURE_RESTORE_BYTES');
    });

    it('rejects restoring to protected OS system directories', async () => {
      const item = {
        quarantineId: 'dummy-id',
        originalPath: path.join(tempBaseDir, 'dummy.exe'),
        fileName: 'dummy.exe',
        fileSize: 10,
        sha256: 'dummy',
        threatName: 'test',
        riskScore: 90,
        severity: 'critical',
        quarantinedAt: Date.now(),
        evidenceFactors: [],
        blobPath: path.join(vaultDir, 'dummy.blob')
      };
      (service as any).manifest.set('dummy-id', item);
      fs.writeFileSync(item.blobPath, 'dummy');

      const systemDir = process.platform === 'win32' ? 'C:\\Windows\\System32' : '/etc';
      if (fs.existsSync(systemDir)) {
        await expect(service.restoreItem('dummy-id', systemDir)).rejects.toThrow(/SECURITY_VIOLATION/);
      }
    });
  });
});
