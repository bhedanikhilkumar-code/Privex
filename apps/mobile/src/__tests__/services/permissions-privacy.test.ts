import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PermissionsPrivacyService } from '../../services/permissions-privacy.service';
import type { PermissionsPrivacyReportDTO } from '../../types/mobile.types';

describe('PermissionsPrivacyService', () => {
  let service: PermissionsPrivacyService;

  beforeEach(() => {
    service = PermissionsPrivacyService.getInstance();
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
    vi.restoreAllMocks();
  });

  it('returns truthful fallback permissions report when native bridge is absent', async () => {
    const report = await service.getPermissionsPrivacyReport();
    expect(report).toBeDefined();

    // 1. Storage
    expect(report.storage.status).toBe('LIMITED');
    expect(report.storage.mechanism).toBe('MEDIASTORE');
    expect(report.storage.scopedStorageEnforced).toBe(true);
    expect(report.storage.persistedSafTreesCount).toBe(0);

    // 2. Notifications
    expect(report.notifications.areNotificationsEnabled).toBe(true);
    expect(report.notifications.runtimePermission).toBe('GRANTED');
    expect(report.notifications.alertDeliveryDisclaimer).toContain('delivery depends on device Do Not Disturb');

    // 3. VPN / Web Shield
    expect(report.vpnWebShield.serviceState).toBe('STOPPED');
    expect(report.vpnWebShield.isVpnActive).toBe(false);
    expect(report.vpnWebShield.privacyGuarantee).toContain('100% on-device DNS filter');

    // 4. Install Source
    expect(report.installSource.isPreInstallInterceptionSupported).toBe(false);
    expect(report.installSource.privilegeTruth).toContain('standard Android application sandbox');

    // 5. Background Scanning
    expect(report.backgroundScanning.status).toBe('MONITORING_ACTIVE');
    expect(report.backgroundScanning.restrictionsNotice).toContain('battery savers');

    // 6. Battery Optimization
    expect(report.batteryOptimization.isExemptionMandatory).toBe(false);
    expect(report.batteryOptimization.status).toBe('OPTIMIZATION_ENFORCED');

    // 7. Telemetry
    expect(report.telemetry.isTelemetryImplemented).toBe(false);
    expect(report.telemetry.isTelemetryActive).toBe(false);
    expect(report.telemetry.status).toBe('NO_TELEMETRY_EXISTS');
    expect(report.telemetry.userPayloadsCollected).toBe(0);

    // 8. Threat Database
    expect(report.threatDatabase.activeSequence).toBe(100);
    expect(report.threatDatabase.staleness).toBe('FRESH');
    expect(report.threatDatabase.isCryptographicallyVerified).toBe(true);
  });

  it('parses verified report from native bridge when available', async () => {
    const mockReport: PermissionsPrivacyReportDTO = {
      storage: {
        status: 'GRANTED_SAF',
        mechanism: 'SAF_AND_MEDIASTORE',
        persistedSafTreesCount: 2,
        scopedStorageEnforced: true,
        safTrees: [{ uri: 'content://tree/downloads', readable: true }],
        accessibleScope: 'Public Downloads and SAF trees.',
        inaccessibleScope: 'Private app sandboxes.'
      },
      notifications: {
        runtimePermission: 'GRANTED',
        areNotificationsEnabled: true,
        dependentFeatures: 'All threat warnings.',
        alertDeliveryDisclaimer: 'Disclaimer.'
      },
      vpnWebShield: {
        serviceState: 'ACTIVE',
        isVpnActive: true,
        isConsentRequired: false,
        isAnotherVpnActive: false,
        totalDnsQueries: 142,
        blockedDnsQueries: 3,
        lastThreatTimestamp: 1000,
        vpnCoexistenceExplanation: 'Coexistence notice.',
        privacyGuarantee: '100% local.'
      },
      installSource: {
        installerPackage: 'com.android.vending',
        isPreInstallInterceptionSupported: false,
        scopeExplanation: 'Audits post-commit.',
        privilegeTruth: 'Third-party sandbox.'
      },
      backgroundScanning: {
        isDownloadObserverActive: true,
        lastEventTimestamp: 2000,
        lastReconciliationTimestamp: 1500,
        eventsProcessed: 12,
        threatsDetected: 1,
        status: 'MONITORING_ACTIVE',
        restrictionsNotice: 'OEM restrictions.'
      },
      batteryOptimization: {
        isIgnoringBatteryOptimizations: true,
        status: 'OPTIMIZATION_EXEMPTED',
        explanation: 'Exempted.',
        isExemptionMandatory: false
      },
      telemetry: {
        isTelemetryImplemented: false,
        isTelemetryActive: false,
        userPayloadsCollected: 0,
        remoteEndpointsConfigured: 'NONE',
        status: 'NO_TELEMETRY_EXISTS',
        explanation: 'Zero collection.'
      },
      threatDatabase: {
        activeSequence: 1002,
        recordCount: 50,
        lastUpdatedTimestamp: Date.now(),
        ageDays: 1,
        staleness: 'FRESH',
        feedSource: 'verified_ota',
        isCryptographicallyVerified: true,
        verificationMechanism: 'Ed25519'
      },
      timestamp: 3000
    };

    (window as any).AndroidSecurityBridge = {
      getPermissionsPrivacyReport: vi.fn().mockReturnValue(JSON.stringify(mockReport))
    };

    const report = await service.getPermissionsPrivacyReport();
    expect(report.storage.status).toBe('GRANTED_SAF');
    expect(report.storage.persistedSafTreesCount).toBe(2);
    expect(report.vpnWebShield.serviceState).toBe('ACTIVE');
    expect(report.vpnWebShield.totalDnsQueries).toBe(142);
    expect(report.batteryOptimization.status).toBe('OPTIMIZATION_EXEMPTED');
  });

  it('delegates openNotificationSettings to native bridge', () => {
    const fn = vi.fn().mockReturnValue(true);
    (window as any).AndroidSecurityBridge = {
      openAppNotificationSettings: fn
    };

    const result = service.openNotificationSettings();
    expect(result).toBe(true);
    expect(fn).toHaveBeenCalledOnce();
  });

  it('delegates openAppDetailsSettings to native bridge', () => {
    const fn = vi.fn().mockReturnValue(true);
    (window as any).AndroidSecurityBridge = {
      openAppDetailsSettings: fn
    };

    const result = service.openAppDetailsSettings();
    expect(result).toBe(true);
    expect(fn).toHaveBeenCalledOnce();
  });

  it('delegates openBatteryOptimizationSettings to native bridge', () => {
    const fn = vi.fn().mockReturnValue(true);
    (window as any).AndroidSecurityBridge = {
      openBatteryOptimizationSettings: fn
    };

    const result = service.openBatteryOptimizationSettings();
    expect(result).toBe(true);
    expect(fn).toHaveBeenCalledOnce();
  });

  it('gracefully handles missing bridge on settings launches', () => {
    expect(service.openNotificationSettings()).toBe(false);
    expect(service.openAppDetailsSettings()).toBe(false);
    expect(service.openBatteryOptimizationSettings()).toBe(false);
  });
});
