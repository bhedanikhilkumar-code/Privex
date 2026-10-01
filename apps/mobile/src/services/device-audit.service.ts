import { DeviceSecurityPosture } from '../types/mobile.types';

export interface DeviceSystemSettings {
  developerOptionsEnabled?: boolean;
  adbDebuggingEnabled?: boolean;
  screenLockConfigured?: boolean;
  mockLocationsEnabled?: boolean;
  unknownSourcesEnabled?: boolean;
}

export class DeviceAuditService {
  /**
   * Conducts an on-device security configuration audit.
   * This is NOT an "antivirus" scan of third-party apps; it inspects platform security settings.
   */
  public auditSecurityPosture(systemSettings?: DeviceSystemSettings): DeviceSecurityPosture {
    const devOptions = systemSettings?.developerOptionsEnabled ?? false;
    const adb = systemSettings?.adbDebuggingEnabled ?? false;
    const screenLock = systemSettings?.screenLockConfigured ?? true;
    const mockLocations = systemSettings?.mockLocationsEnabled ?? false;
    const unknownSources = systemSettings?.unknownSourcesEnabled ?? false;

    const recommendations: string[] = [];

    if (!screenLock) {
      recommendations.push('Configure a secure PIN, pattern, or biometric lock to protect physical device access.');
    }
    if (adb) {
      recommendations.push('Disable USB debugging (ADB) when not actively developing to prevent unauthorized computer access.');
    }
    if (unknownSources) {
      recommendations.push('Disable installation from unknown sources to protect against unverified sideloaded apps.');
    }
    if (devOptions && !adb) {
      recommendations.push('Developer options are enabled. Consider disabling them when not in use.');
    }
    if (mockLocations) {
      recommendations.push('Mock location provider is active. Ensure location spoofing is intentional.');
    }

    let overallHealth: 'HEALTHY' | 'WARNING' | 'RISK' = 'HEALTHY';
    if (!screenLock || (adb && unknownSources)) {
      overallHealth = 'RISK';
    } else if (adb || unknownSources || mockLocations || devOptions) {
      overallHealth = 'WARNING';
    }

    if (recommendations.length === 0) {
      recommendations.push('Device configuration adheres to recommended Android security baselines.');
    }

    return {
      developerOptionsEnabled: devOptions,
      adbDebuggingEnabled: adb,
      screenLockConfigured: screenLock,
      mockLocationsEnabled: mockLocations,
      unknownSourcesEnabled: unknownSources,
      overallHealth,
      recommendations,
      lastCheckedTimestamp: Date.now()
    };
  }
}
