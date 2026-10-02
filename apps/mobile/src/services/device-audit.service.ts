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
    // 1. If explicit settings provided (e.g. in test suite or config), evaluate them directly
    if (systemSettings) {
      const devOptions = systemSettings.developerOptionsEnabled ?? false;
      const adb = systemSettings.adbDebuggingEnabled ?? false;
      const screenLock = systemSettings.screenLockConfigured ?? false;
      const mockLocations = systemSettings.mockLocationsEnabled ?? false;
      const unknownSources = systemSettings.unknownSourcesEnabled ?? false;

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

    // 2. Query Native Android Bridge if present (GAP-19)
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.getDeviceSecurityPosture) {
      try {
        const rawJson = (window as any).AndroidSecurityBridge.getDeviceSecurityPosture();
        const parsed = JSON.parse(rawJson);

        const devOptions = Boolean(parsed.developerOptionsEnabled);
        const adb = Boolean(parsed.adbDebuggingEnabled);
        const screenLock = Boolean(parsed.screenLockConfigured);
        const mockLocations = Boolean(parsed.mockLocationsEnabled);
        const unknownSources = Boolean(parsed.unknownSourcesEnabled);

        const recommendations: string[] = [];
        if (!screenLock) {
          recommendations.push('Configure a secure PIN, pattern, or biometric lock to protect physical device access.');
        }
        if (adb) {
          recommendations.push('Disable USB debugging (ADB) when not actively developing to prevent unauthorized computer access.');
        }
        if (devOptions && !adb) {
          recommendations.push('Developer options are enabled. Consider disabling them when not in use.');
        }

        let overallHealth: 'HEALTHY' | 'WARNING' | 'RISK' = 'HEALTHY';
        if (!screenLock) {
          overallHealth = 'RISK';
        } else if (adb || devOptions) {
          overallHealth = 'WARNING';
        }

        if (recommendations.length === 0) {
          recommendations.push('Device configuration adheres to verified Android security baselines.');
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
      } catch {
        // Fall through to UNKNOWN
      }
    }

    // 3. Fallback when running outside native Android bridge: Return UNKNOWN (never false HEALTHY)
    return {
      developerOptionsEnabled: false,
      adbDebuggingEnabled: false,
      screenLockConfigured: false,
      mockLocationsEnabled: false,
      unknownSourcesEnabled: false,
      overallHealth: 'UNKNOWN',
      recommendations: [
        'Android native security bridge is not detected. Device configuration audit requires native runtime execution.'
      ],
      lastCheckedTimestamp: Date.now()
    };
  }
}
