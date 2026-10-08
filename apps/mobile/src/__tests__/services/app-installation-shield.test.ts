import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AppInstallationShieldService } from '../../services/app-installation-shield.service';

describe('AppInstallationShieldService (Phase T2 App Installation Shield)', () => {
  let service: AppInstallationShieldService;

  beforeEach(() => {
    service = new AppInstallationShieldService();
    if (typeof window !== 'undefined') {
      delete (window as any).AndroidSecurityBridge;
    }
  });

  afterEach(() => {
    if (typeof window !== 'undefined') {
      delete (window as any).AndroidSecurityBridge;
    }
  });

  describe('Fallback Mode (When Native Bridge is Absent)', () => {
    it('detects native bridge as unavailable', () => {
      expect(service.isNativeBridgeAvailable()).toBe(false);
    });

    it('validates empty package name input', async () => {
      await expect(service.auditPackage('')).rejects.toThrow('INVALID_PACKAGE_NAME');
      await expect(service.auditPackage('   ')).rejects.toThrow('INVALID_PACKAGE_NAME');
    });

    it('audits a clean package in fallback mode', async () => {
      const report = await service.auditPackage('com.example.calculator');
      expect(report.packageName).toBe('com.example.calculator');
      expect(report.verdict).toBe('ALLOW');
      expect(report.severity).toBe('NONE');
      expect(report.score).toBeLessThan(20);
    });

    it('audits a suspicious package in fallback mode', async () => {
      const report = await service.auditPackage('com.malicious.trojan');
      expect(report.packageName).toBe('com.malicious.trojan');
      expect(report.verdict).toBe('DANGEROUS');
      expect(report.severity).toBe('CRITICAL');
      expect(report.recommendation).toBe('IMMEDIATELY_UNINSTALL');
      expect(report.score).toBeGreaterThanOrEqual(70);
    });

    it('validates empty APK file path input', async () => {
      await expect(service.auditApkFile('')).rejects.toThrow('INVALID_FILE_PATH');
    });

    it('audits an APK file in fallback mode', async () => {
      const cleanApk = await service.auditApkFile('/sdcard/Download/app.apk');
      expect(cleanApk.verdict).toBe('ALLOW');

      const dropperApk = await service.auditApkFile('/sdcard/Download/malicious_dropper.apk');
      expect(dropperApk.verdict).toBe('DANGEROUS');
      expect(dropperApk.apkInspection?.hasSuspiciousPayloads).toBe(true);
    });

    it('simulates uninstall request in fallback mode', async () => {
      const result = await service.requestUninstall('com.example.calculator');
      expect(result).toBe(true);

      const emptyResult = await service.requestUninstall('');
      expect(emptyResult).toBe(false);
    });
  });

  describe('Native AndroidSecurityBridge Mode', () => {
    it('routes auditPackage to window.AndroidSecurityBridge.auditPackage', async () => {
      const mockAudit = vi.fn().mockReturnValue(
        JSON.stringify({
          packageName: 'com.android.target',
          appLabel: 'Target App',
          score: 80,
          verdict: 'DANGEROUS',
          severity: 'CRITICAL',
          recommendation: 'IMMEDIATELY_UNINSTALL',
          isSideloaded: true,
          isSystemApp: false,
          timestamp: 12345
        })
      );

      (window as any).AndroidSecurityBridge = {
        auditPackage: mockAudit
      };

      expect(service.isNativeBridgeAvailable()).toBe(true);

      const report = await service.auditPackage('com.android.target');
      expect(mockAudit).toHaveBeenCalledWith('com.android.target');
      expect(report.packageName).toBe('com.android.target');
      expect(report.verdict).toBe('DANGEROUS');
      expect(report.score).toBe(80);
    });

    it('handles native auditPackage error response', async () => {
      (window as any).AndroidSecurityBridge = {
        auditPackage: vi.fn().mockReturnValue('{"error":"PACKAGE_NOT_FOUND"}')
      };

      await expect(service.auditPackage('com.nonexistent.app')).rejects.toThrow('PACKAGE_AUDIT_ERROR: PACKAGE_NOT_FOUND');
    });

    it('routes auditApkFile to window.AndroidSecurityBridge.auditApkFile', async () => {
      const mockApkAudit = vi.fn().mockReturnValue(
        JSON.stringify({
          packageName: 'com.apk.file',
          appLabel: 'File App',
          score: 10,
          verdict: 'ALLOW',
          severity: 'NONE',
          recommendation: 'SAFE_TO_RUN',
          isSideloaded: true,
          isSystemApp: false,
          timestamp: 12345
        })
      );

      (window as any).AndroidSecurityBridge = {
        auditPackage: vi.fn(),
        auditApkFile: mockApkAudit
      };

      const report = await service.auditApkFile('/sdcard/app.apk');
      expect(mockApkAudit).toHaveBeenCalledWith('/sdcard/app.apk');
      expect(report.verdict).toBe('ALLOW');
    });

    it('routes requestUninstall to window.AndroidSecurityBridge.requestUninstall', async () => {
      const mockUninstall = vi.fn().mockReturnValue(true);

      (window as any).AndroidSecurityBridge = {
        auditPackage: vi.fn(),
        requestUninstall: mockUninstall
      };

      const res = await service.requestUninstall('com.evil.malware');
      expect(mockUninstall).toHaveBeenCalledWith('com.evil.malware');
      expect(res).toBe(true);
    });
  });
});
