import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { UniversalFileShieldService } from '../../services/universal-file-shield.service';

describe('UniversalFileShieldService', () => {
  let service: UniversalFileShieldService;

  beforeEach(() => {
    service = new UniversalFileShieldService();
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
    vi.restoreAllMocks();
  });

  describe('Fallback / Web Simulation Mode', () => {
    it('returns isNativeBridgeAvailable as false when window.AndroidSecurityBridge is absent', () => {
      expect(service.isNativeBridgeAvailable()).toBe(false);
    });

    it('rejects empty or whitespace file path', async () => {
      await expect(service.inspectFile('')).rejects.toThrow('INVALID_FILE_PATH');
      await expect(service.inspectFile('   ')).rejects.toThrow('INVALID_FILE_PATH');
    });

    it('inspects a clean file path in fallback mode', async () => {
      const report = await service.inspectFile('/storage/emulated/0/Download/document.pdf');
      expect(report.verdict).toBe('ALLOW');
      expect(report.severity).toBe('NONE');
      expect(report.score).toBeLessThanOrEqual(10);
      expect(report.fileIdentity.fileName).toBe('document.pdf');
      expect(report.fileIdentity.fileExtension).toBe('pdf');
      expect(report.fileIdentity.isExecutable).toBe(false);
      expect(report.recommendation).toBe('SAFE_TO_OPEN');
    });

    it('identifies EICAR test signature file in fallback mode', async () => {
      const report = await service.inspectFile('/storage/emulated/0/Download/eicar.com');
      expect(report.verdict).toBe('DANGEROUS');
      expect(report.severity).toBe('CRITICAL');
      expect(report.score).toBeGreaterThanOrEqual(90);
      expect(report.evidence.some(e => e.code === 'EICAR_TEST_PAYLOAD')).toBe(true);
      expect(report.recommendation).toBe('QUARANTINE_OR_DELETE');
    });

    it('identifies deceptive double extension in fallback mode', async () => {
      const report = await service.inspectFile('/storage/emulated/0/Download/invoice.pdf.exe');
      expect(report.verdict).toBe('DANGEROUS');
      expect(report.severity).toBe('CRITICAL');
      expect(report.evidence.some(e => e.code === 'DECEPTIVE_DOUBLE_EXTENSION')).toBe(true);
    });

    it('isolates threat file in fallback quarantine vault', async () => {
      const res = await service.quarantineFile('/storage/emulated/0/Download/eicar.com');
      expect(res.status).toBe('QUARANTINED');
      expect(res.originalDeleted).toBe(true);
      expect(res.quarantinePath).toContain('private_quarantine_vault');
    });
  });

  describe('Native AndroidSecurityBridge Integration', () => {
    it('detects native bridge when methods are present', () => {
      (window as any).AndroidSecurityBridge = {
        inspectFile: vi.fn(),
        inspectFileUri: vi.fn(),
        quarantineFile: vi.fn()
      };
      expect(service.isNativeBridgeAvailable()).toBe(true);
    });

    it('delegates inspectFile call to native bridge and parses result', async () => {
      const mockResult = {
        fileIdentity: {
          uriString: 'file:///data/test.apk',
          fileName: 'test.apk',
          fileExtension: 'apk',
          detectedMimeType: 'application/vnd.android.package-archive',
          sizeBytes: 2048,
          lastModifiedMs: 1600000000000,
          sha256: 'abcd1234efgh',
          sourceCollection: 'DOWNLOADS',
          isExecutable: true
        },
        score: 35,
        verdict: 'CAUTION',
        severity: 'LOW',
        recommendation: 'INFORMATIONAL: Sideloaded package',
        evidence: [
          {
            code: 'SIDELOADED_APK_PACKAGE',
            severity: 'MEDIUM',
            weight: 35,
            description: 'Standalone Android package'
          }
        ],
        timestamp: 1600000000000
      };

      (window as any).AndroidSecurityBridge = {
        inspectFile: vi.fn().mockReturnValue(JSON.stringify(mockResult)),
        inspectFileUri: vi.fn(),
        quarantineFile: vi.fn()
      };

      const result = await service.inspectFile('/data/test.apk');
      expect((window as any).AndroidSecurityBridge.inspectFile).toHaveBeenCalledWith('/data/test.apk');
      expect(result.verdict).toBe('CAUTION');
      expect(result.score).toBe(35);
      expect(result.fileIdentity.fileName).toBe('test.apk');
    });

    it('throws FILE_INSPECTION_ERROR when native bridge returns an error', async () => {
      (window as any).AndroidSecurityBridge = {
        inspectFile: vi.fn().mockReturnValue(JSON.stringify({ error: 'FILE_NOT_FOUND' })),
        inspectFileUri: vi.fn(),
        quarantineFile: vi.fn()
      };

      await expect(service.inspectFile('/nonexistent.bin')).rejects.toThrow('FILE_INSPECTION_ERROR: FILE_NOT_FOUND');
    });

    it('delegates quarantineFile call to native bridge', async () => {
      const mockQuarantine = {
        status: 'QUARANTINED',
        quarantinePath: '/data/user/0/files/vault/threat.bin.quarantined',
        originalDeleted: true,
        timestamp: Date.now()
      };

      (window as any).AndroidSecurityBridge = {
        inspectFile: vi.fn(),
        inspectFileUri: vi.fn(),
        quarantineFile: vi.fn().mockReturnValue(JSON.stringify(mockQuarantine))
      };

      const result = await service.quarantineFile('/data/threat.bin');
      expect(result.status).toBe('QUARANTINED');
      expect(result.originalDeleted).toBe(true);
      expect(result.quarantinePath).toBe('/data/user/0/files/vault/threat.bin.quarantined');
    });
  });
});
