import { describe, it, expect } from 'vitest';
import { DeviceAuditService } from '../../services/device-audit.service';

describe('DeviceAuditService (Security Posture Baseline)', () => {
  const service = new DeviceAuditService();

  it('audits a hardened device and reports HEALTHY baseline', () => {
    const posture = service.auditSecurityPosture({
      developerOptionsEnabled: false,
      adbDebuggingEnabled: false,
      screenLockConfigured: true,
      mockLocationsEnabled: false,
      unknownSourcesEnabled: false
    });

    expect(posture.overallHealth).toBe('HEALTHY');
    expect(posture.recommendations).toContain('Device configuration adheres to recommended Android security baselines.');
  });

  it('flags unconfigured screen lock as a RISK condition', () => {
    const posture = service.auditSecurityPosture({
      screenLockConfigured: false
    });

    expect(posture.overallHealth).toBe('RISK');
    expect(posture.recommendations.some((r) => r.includes('secure PIN, pattern, or biometric'))).toBe(true);
  });

  it('flags active USB debugging as a WARNING condition', () => {
    const posture = service.auditSecurityPosture({
      screenLockConfigured: true,
      adbDebuggingEnabled: true
    });

    expect(posture.overallHealth).toBe('WARNING');
    expect(posture.recommendations.some((r) => r.includes('USB debugging'))).toBe(true);
  });

  it('flags unknown sources combined with adb as high RISK', () => {
    const posture = service.auditSecurityPosture({
      screenLockConfigured: true,
      adbDebuggingEnabled: true,
      unknownSourcesEnabled: true
    });

    expect(posture.overallHealth).toBe('RISK');
  });
});
