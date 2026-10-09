import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MobileQuarantineService } from '../../services/mobile-quarantine.service';

describe('Phase T10: MobileQuarantineService & Remediation', () => {
  let service: MobileQuarantineService;

  beforeEach(() => {
    vi.restoreAllMocks();
    service = new MobileQuarantineService();
    delete (window as any).AndroidSecurityBridge;
  });

  describe('Fallback / Web Mode (No Native Bridge)', () => {
    it('quarantines file and returns truthful isolation result in fallback mode', async () => {
      const result = await service.quarantineFile('/sdcard/Download/threat_sample.apk');
      expect(result).toBeDefined();
      expect(result.status).toBe('QUARANTINED');
      expect(result.isolationState).toBe('ISOLATED');
      expect(result.fileName).toBe('threat_sample.apk');
      expect(result.sha256).toBeDefined();
      expect(result.originalDeleted).toBe(true);
      expect(result.quarantinePath).toContain('ppmvault');
    });

    it('rejects empty or whitespace file path', async () => {
      await expect(service.quarantineFile('')).rejects.toThrow('INVALID_FILE_PATH');
      await expect(service.quarantineFile('   ')).rejects.toThrow('INVALID_FILE_PATH');
    });

    it('returns default empty quarantine list and stats in fallback mode', async () => {
      const items = await service.getQuarantinedItems();
      expect(Array.isArray(items)).toBe(true);
      expect(items.length).toBe(0);

      const stats = await service.getQuarantineStats();
      expect(stats.totalItems).toBe(0);
      expect(stats.isolatedCount).toBe(0);
      expect(stats.vaultDirectory).toContain('private_quarantine_vault');
    });

    it('restores quarantined file in fallback mode', async () => {
      const res = await service.restoreQuarantinedFile('q_test_123', '/sdcard/Download/restored.apk', false, true);
      expect(res.status).toBe('RESTORED');
      expect(res.itemId).toBe('q_test_123');
      expect(res.trusted).toBe(true);
    });

    it('rejects empty item ID on restore', async () => {
      const res = await service.restoreQuarantinedFile('');
      expect(res.status).toBe('FAILED');
      expect(res.error).toContain('INVALID_ITEM_ID');
    });

    it('evaluates package remediation for third-party user app vs system app', async () => {
      const userAppPlan = await service.getPackageRemediationPlan('com.suspicious.game');
      expect(userAppPlan.isSystemApp).toBe(false);
      expect(userAppPlan.status).toBe('USER_APP_ACTIONABLE');
      expect(userAppPlan.canUninstall).toBe(true);
      expect(userAppPlan.recommendedAction).toBe('UNINSTALL');
      expect(userAppPlan.availableActions).toContain('UNINSTALL');

      const sysAppPlan = await service.getPackageRemediationPlan('com.android.systemui');
      expect(sysAppPlan.isSystemApp).toBe(true);
      expect(sysAppPlan.status).toBe('SYSTEM_APP_PROTECTED');
      expect(sysAppPlan.canUninstall).toBe(false);
      expect(sysAppPlan.recommendedAction).toBe('INSPECT_PERMISSIONS');
    });

    it('handles delete and uninstall in fallback mode', async () => {
      const deleted = await service.deleteQuarantinedItem('q_123');
      expect(deleted).toBe(true);

      const uninstalled = await service.requestUninstall('com.test.app');
      expect(uninstalled).toBe(true);

      const opened = await service.openPackageDetails('com.test.app');
      expect(opened).toBe(true);
    });
  });

  describe('Native Android Security Bridge Integration', () => {
    it('calls native quarantineFile and parses structured response', async () => {
      (window as any).AndroidSecurityBridge = {
        quarantineFile: vi.fn().mockReturnValue(JSON.stringify({
          status: 'SOURCE_REMAINS',
          isolationState: 'SOURCE_REMAINS',
          itemId: 'q_native_001',
          fileName: 'malware.apk',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          originalDeleted: false,
          warning: 'Vault copy secured, but original removal denied.',
          timestamp: 1700000000000
        }))
      };

      const result = await service.quarantineFile('/data/local/tmp/malware.apk');
      expect(result.status).toBe('SOURCE_REMAINS');
      expect(result.originalDeleted).toBe(false);
      expect(result.warning).toContain('Vault copy secured');
      expect((window as any).AndroidSecurityBridge.quarantineFile).toHaveBeenCalledWith('/data/local/tmp/malware.apk');
    });

    it('fetches quarantined items and stats from native bridge', async () => {
      (window as any).AndroidSecurityBridge = {
        getQuarantinedItems: vi.fn().mockReturnValue(JSON.stringify([
          {
            id: 'q_1',
            fileName: 'eicar.com',
            sha256: '275a021b...',
            fileSizeBytes: 68,
            state: 'ISOLATED',
            quarantineTimestamp: 1700000000000
          }
        ])),
        getQuarantineStats: vi.fn().mockReturnValue(JSON.stringify({
          totalItems: 1,
          isolatedCount: 1,
          sourceRemainsCount: 0,
          restoredCount: 0,
          totalProtectedBytes: 68,
          vaultDirectory: '/app/files/vault'
        }))
      };

      const items = await service.getQuarantinedItems();
      expect(items.length).toBe(1);
      expect(items[0].fileName).toBe('eicar.com');

      const stats = await service.getQuarantineStats();
      expect(stats.totalItems).toBe(1);
      expect(stats.isolatedCount).toBe(1);
    });

    it('calls native restoreQuarantinedFile and handles verification outcome', async () => {
      (window as any).AndroidSecurityBridge = {
        restoreQuarantinedFile: vi.fn().mockReturnValue(JSON.stringify({
          status: 'RESTORED',
          itemId: 'q_1',
          restoredPath: '/sdcard/Download/eicar.com',
          trusted: true
        }))
      };

      const res = await service.restoreQuarantinedFile('q_1', '/sdcard/Download/eicar.com', false, true);
      expect(res.status).toBe('RESTORED');
      expect(res.trusted).toBe(true);
      expect((window as any).AndroidSecurityBridge.restoreQuarantinedFile).toHaveBeenCalledWith(
        'q_1',
        '/sdcard/Download/eicar.com',
        false,
        true
      );
    });

    it('queries native getPackageRemediationPlan and handles bridge response', async () => {
      (window as any).AndroidSecurityBridge = {
        getPackageRemediationPlan: vi.fn().mockReturnValue(JSON.stringify({
          packageName: 'com.malicious.app',
          appLabel: 'Fake Flash Player',
          isSystemApp: false,
          status: 'USER_APP_ACTIONABLE',
          canUninstall: true,
          recommendedAction: 'UNINSTALL',
          availableActions: ['UNINSTALL', 'APP_DETAILS'],
          explanation: 'Android requires user confirmation.'
        }))
      };

      const plan = await service.getPackageRemediationPlan('com.malicious.app');
      expect(plan.appLabel).toBe('Fake Flash Player');
      expect(plan.canUninstall).toBe(true);
      expect(plan.recommendedAction).toBe('UNINSTALL');
    });
  });
});
