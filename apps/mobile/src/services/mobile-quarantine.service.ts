import {
  QuarantineResult,
  QuarantineRecordDTO,
  QuarantineVaultStatsDTO,
  QuarantineRestoreResultDTO,
  PackageRemediationPlanDTO
} from '../types/mobile.types';

/**
 * MobileQuarantineService (Phase T10):
 *
 * TypeScript service bridging secure app-private quarantine vault operations,
 * encrypted restoration workflows, integrity verification, and installed-app
 * remediation between the mobile UI and native AndroidSecurityBridge.
 */
export class MobileQuarantineService {

  public isNativeBridgeAvailable(): boolean {
    return (
      typeof window !== 'undefined' &&
      !!window.AndroidSecurityBridge
    );
  }

  /**
   * Quarantines a suspicious or dangerous file into the app-private encrypted vault.
   */
  public async quarantineFile(filePath: string): Promise<QuarantineResult> {
    if (!filePath || !filePath.trim()) {
      throw new Error('INVALID_FILE_PATH: File path cannot be empty');
    }

    if (this.isNativeBridgeAvailable()) {
      try {
        const raw = window.AndroidSecurityBridge!.quarantineFile!(filePath.trim());
        const parsed = JSON.parse(raw);
        return parsed as QuarantineResult;
      } catch (err: any) {
        return {
          status: 'FAILED',
          error: `NATIVE_BRIDGE_FAILURE: ${err?.message || err}`,
          timestamp: Date.now()
        };
      }
    }

    // In-memory mock for web / testing
    const fileName = filePath.split(/[/\\]/).pop() || 'sample_threat.bin';
    return {
      status: 'QUARANTINED',
      isolationState: 'ISOLATED',
      itemId: `q_mock_${Date.now()}`,
      fileName,
      sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      quarantinePath: `/data/user/0/com.privateprotection.mobile/files/private_quarantine_vault/${fileName}.ppmvault`,
      originalDeleted: true,
      timestamp: Date.now()
    };
  }

  /**
   * Retrieves all quarantined items currently recorded in the vault manifest.
   */
  public async getQuarantinedItems(): Promise<QuarantineRecordDTO[]> {
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.getQuarantinedItems === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.getQuarantinedItems();
        return JSON.parse(raw) as QuarantineRecordDTO[];
      } catch (err) {
        console.error('Failed to parse quarantined items from bridge:', err);
        return [];
      }
    }

    // Return empty list or mock item in test environment
    return [];
  }

  /**
   * Retrieves aggregate statistics from the quarantine vault.
   */
  public async getQuarantineStats(): Promise<QuarantineVaultStatsDTO> {
    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.getQuarantineStats === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.getQuarantineStats();
        return JSON.parse(raw) as QuarantineVaultStatsDTO;
      } catch (err) {
        console.error('Failed to parse vault stats from bridge:', err);
      }
    }

    return {
      totalItems: 0,
      isolatedCount: 0,
      sourceRemainsCount: 0,
      restoredCount: 0,
      totalProtectedBytes: 0,
      vaultDirectory: '/data/user/0/com.privateprotection.mobile/files/private_quarantine_vault'
    };
  }

  /**
   * Restores a quarantined file to a target destination with cryptographic verification.
   */
  public async restoreQuarantinedFile(
    itemId: string,
    destinationPath?: string,
    overwrite: boolean = false,
    trustSha256: boolean = false
  ): Promise<QuarantineRestoreResultDTO> {
    if (!itemId || !itemId.trim()) {
      return {
        status: 'FAILED',
        error: 'INVALID_ITEM_ID: Quarantine item ID is required.'
      };
    }

    const dest = destinationPath || `/sdcard/Download/restored_${Date.now()}.bin`;

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.restoreQuarantinedFile === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.restoreQuarantinedFile(
          itemId.trim(),
          dest,
          overwrite,
          trustSha256
        );
        return JSON.parse(raw) as QuarantineRestoreResultDTO;
      } catch (err: any) {
        return {
          status: 'FAILED',
          error: `RESTORE_FAILED: ${err?.message || err}`
        };
      }
    }

    // Web mock
    return {
      status: 'RESTORED',
      itemId,
      restoredPath: dest,
      trusted: trustSha256
    };
  }

  /**
   * Permanently deletes a quarantined item and its encrypted blob from disk.
   */
  public async deleteQuarantinedItem(itemId: string): Promise<boolean> {
    if (!itemId || !itemId.trim()) return false;

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.deleteQuarantinedItem === 'function') {
      try {
        return window.AndroidSecurityBridge.deleteQuarantinedItem(itemId.trim());
      } catch (err) {
        console.error('Failed to delete quarantined item via bridge:', err);
        return false;
      }
    }

    return true;
  }

  /**
   * Evaluates structured, truthful remediation options for an installed package.
   */
  public async getPackageRemediationPlan(packageName: string): Promise<PackageRemediationPlanDTO> {
    if (!packageName || !packageName.trim()) {
      return {
        packageName: '',
        isSystemApp: false,
        status: 'NOT_INSTALLED',
        canUninstall: false,
        recommendedAction: 'NO_ACTION',
        availableActions: [],
        explanation: 'Invalid package name provided.'
      };
    }

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.getPackageRemediationPlan === 'function') {
      try {
        const raw = window.AndroidSecurityBridge.getPackageRemediationPlan(packageName.trim());
        return JSON.parse(raw) as PackageRemediationPlanDTO;
      } catch (err: any) {
        return {
          packageName,
          isSystemApp: false,
          status: 'NOT_INSTALLED',
          canUninstall: false,
          recommendedAction: 'ERROR',
          availableActions: [],
          explanation: `Remediation evaluation error: ${err?.message || err}`
        };
      }
    }

    const isSystem = packageName.startsWith('com.android.') || packageName === 'android';
    return {
      packageName,
      isSystemApp: isSystem,
      status: isSystem ? 'SYSTEM_APP_PROTECTED' : 'USER_APP_ACTIONABLE',
      canUninstall: !isSystem,
      recommendedAction: isSystem ? 'INSPECT_PERMISSIONS' : 'UNINSTALL',
      availableActions: isSystem ? ['APP_DETAILS'] : ['UNINSTALL', 'APP_DETAILS'],
      explanation: isSystem
        ? 'Core Android system packages cannot be uninstalled by third-party apps.'
        : 'Android requires user confirmation to uninstall apps. Launching uninstaller.'
    };
  }

  /**
   * Launches the OS uninstall confirmation dialog for a package.
   */
  public async requestUninstall(packageName: string): Promise<boolean> {
    if (!packageName || !packageName.trim()) return false;

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.requestUninstall === 'function') {
      try {
        return window.AndroidSecurityBridge.requestUninstall(packageName.trim());
      } catch (err) {
        console.error('Failed to trigger uninstall via bridge:', err);
        return false;
      }
    }
    return true;
  }

  /**
   * Opens the Android Application Details screen in System Settings.
   */
  public async openPackageDetails(packageName: string): Promise<boolean> {
    if (!packageName || !packageName.trim()) return false;

    if (this.isNativeBridgeAvailable() && typeof window.AndroidSecurityBridge?.openPackageDetails === 'function') {
      try {
        return window.AndroidSecurityBridge.openPackageDetails(packageName.trim());
      } catch (err) {
        console.error('Failed to open package details via bridge:', err);
        return false;
      }
    }
    return true;
  }
}
