import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DeviceAuditService } from '../../services/device-audit.service';
import { FileScannerService } from '../../services/file-scanner.service';
import { Verdict } from '@private-protection/core';

describe('GAP-18 & GAP-19: Android Real File Scanning and Posture Remediation', () => {
  describe('GAP-19: DeviceAuditService Dynamic Posture vs False Defaults', () => {
    let auditService: DeviceAuditService;

    beforeEach(() => {
      auditService = new DeviceAuditService();
      delete (globalThis as any).window?.AndroidSecurityBridge;
    });

    it('returns overallHealth: UNKNOWN when native bridge is unavailable (no false HEALTHY)', () => {
      const posture = auditService.auditSecurityPosture();
      expect(posture.overallHealth).toBe('UNKNOWN');
      expect(posture.screenLockConfigured).toBe(false);
      expect(posture.recommendations[0]).toContain('Android native security bridge is not detected');
    });

    it('queries window.AndroidSecurityBridge when present and parses healthy posture', () => {
      (globalThis as any).window = (globalThis as any).window || {};
      (globalThis as any).window.AndroidSecurityBridge = {
        getDeviceSecurityPosture: vi.fn().mockReturnValue(JSON.stringify({
          developerOptionsEnabled: false,
          adbDebuggingEnabled: false,
          screenLockConfigured: true,
          mockLocationsEnabled: false,
          unknownSourcesEnabled: false,
          hardwareEncryptionSupported: true,
          overallHealth: 'HEALTHY'
        }))
      };

      const posture = auditService.auditSecurityPosture();
      expect(posture.overallHealth).toBe('HEALTHY');
      expect(posture.screenLockConfigured).toBe(true);
      expect(posture.adbDebuggingEnabled).toBe(false);
    });

    it('queries window.AndroidSecurityBridge and reports RISK when screen lock is disabled', () => {
      (globalThis as any).window = (globalThis as any).window || {};
      (globalThis as any).window.AndroidSecurityBridge = {
        getDeviceSecurityPosture: vi.fn().mockReturnValue(JSON.stringify({
          developerOptionsEnabled: false,
          adbDebuggingEnabled: false,
          screenLockConfigured: false,
          mockLocationsEnabled: false,
          unknownSourcesEnabled: false,
          hardwareEncryptionSupported: true,
          overallHealth: 'RISK'
        }))
      };

      const posture = auditService.auditSecurityPosture();
      expect(posture.overallHealth).toBe('RISK');
      expect(posture.screenLockConfigured).toBe(false);
      expect(posture.recommendations.some(r => r.includes('PIN, pattern, or biometric lock'))).toBe(true);
    });

    it('queries window.AndroidSecurityBridge and reports WARNING when ADB is enabled', () => {
      (globalThis as any).window = (globalThis as any).window || {};
      (globalThis as any).window.AndroidSecurityBridge = {
        getDeviceSecurityPosture: vi.fn().mockReturnValue(JSON.stringify({
          developerOptionsEnabled: true,
          adbDebuggingEnabled: true,
          screenLockConfigured: true,
          mockLocationsEnabled: false,
          unknownSourcesEnabled: false,
          hardwareEncryptionSupported: true,
          overallHealth: 'WARNING'
        }))
      };

      const posture = auditService.auditSecurityPosture();
      expect(posture.overallHealth).toBe('WARNING');
      expect(posture.adbDebuggingEnabled).toBe(true);
      expect(posture.recommendations.some(r => r.includes('Disable USB debugging'))).toBe(true);
    });
  });

  describe('GAP-18: Real File Slicing and Header Inspection', () => {
    let scannerService: FileScannerService;

    beforeEach(() => {
      scannerService = new FileScannerService();
    });

    it('accurately detects disguised executable via header magic bytes', () => {
      // MZ header bytes: 0x4d, 0x5a, 0x90, 0x00...
      const peBytes = [0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
      const result = scannerService.inspectFile({
        name: 'urgent_invoice.pdf.exe',
        sizeBytes: 10240,
        mimeType: 'application/x-msdownload',
        headerBytes: peBytes
      });

      expect(result.verdict).toBe(Verdict.DANGEROUS);
      expect(result.recommendation.action).toBe('BLOCK');
      expect(result.isExecutable).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(85);
      expect(result.evidence.some(e => e.indicator?.includes('pe-executable') || e.name?.toLowerCase().includes('executable') || e.name === 'Deceptive Double Extension')).toBe(true);
    });

    it('accurately verifies safe PDF document header bytes', () => {
      // %PDF-1.5 header: 0x25, 0x50, 0x44, 0x46...
      const pdfBytes = [0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x35];
      const result = scannerService.inspectFile({
        name: 'annual_report.pdf',
        sizeBytes: 20480,
        mimeType: 'application/pdf',
        headerBytes: pdfBytes
      });

      expect(result.verdict).toBe(Verdict.ALLOW);
      expect(result.isExecutable).toBe(false);
      expect(result.score).toBeLessThan(20);
    });

    it('detects Android DEX bytecode header bytes', () => {
      // dex\n035\0: 0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00
      const dexBytes = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00];
      const result = scannerService.inspectFile({
        name: 'classes.dex',
        sizeBytes: 40960,
        mimeType: 'application/vnd.android.dex',
        headerBytes: dexBytes
      });

      expect(result.verdict).toBe(Verdict.SUSPICIOUS);
      expect(result.isExecutable).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(50);
    });
  });
});
