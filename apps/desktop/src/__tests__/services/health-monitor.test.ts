import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { HealthMonitorService } from '../../services/health-monitor.service';
import { AuditLoggerService } from '../../services/audit-logger.service';
import { TamperDetectorService } from '../../services/tamper-detector.service';
import { WatchdogService } from '../../services/watchdog.service';

describe('HealthMonitorService Unit Tests', () => {
  let tempDir: string;
  let auditLogger: AuditLoggerService;
  let watchdog: WatchdogService;
  let tamperDetector: TamperDetectorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'health-monitor-test-'));
    auditLogger = new AuditLoggerService({ configDir: tempDir });
    tamperDetector = new TamperDetectorService({ configDir: tempDir, auditLogger });
    watchdog = new WatchdogService({ auditLogger });
  });

  afterEach(() => {
    watchdog?.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  it('evaluates overallState as HEALTHY when all monitored subsystems are nominal', () => {
    const healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector
    });

    const report = healthMonitor.evaluateHealth();
    expect(report.overallState).toBe('HEALTHY');
    expect(report.issues.length).toBe(0);
    expect(report.recommendedRemediations.length).toBe(0);
    expect(report.subsystems.length).toBeGreaterThanOrEqual(4);
  });

  it('evaluates overallState as DEGRADED when Safe Minimal Mode is active on Watchdog', async () => {
    const healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector
    });

    // Simulate isolated component causing Safe Minimal Mode
    watchdog.registerComponent({
      name: 'FaultyService',
      checkHealth: () => false
    });

    // Cause 3 failures to trigger circuit breaker
    await watchdog.executeHeartbeat();
    await watchdog.executeHeartbeat();
    await watchdog.executeHeartbeat();

    // After circuit breaker
    const report = healthMonitor.evaluateHealth();
    expect(report.overallState).toBe('DEGRADED');
    expect(report.issues.some(i => i.includes('Safe Minimal Mode') || i.includes('circuit breaker'))).toBe(true);
    expect(report.recommendedRemediations.some(r => r.actionId === 'RESET_WATCHDOG_ISOLATIONS')).toBe(true);
  });

  it('evaluates overallState as CRITICAL when tamper is detected in configuration or storage', () => {
    // Corrupt settings file to induce tamper
    const settingsPath = path.join(tempDir, 'settings.enc');
    fs.writeFileSync(settingsPath, '{"tampered": true}');

    const healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector
    });

    const report = healthMonitor.evaluateHealth();
    expect(report.overallState).toBe('CRITICAL');
    expect(report.issues.some(i => i.includes('compromised') || i.includes('Tamper'))).toBe(true);
    expect(report.recommendedRemediations.some(r => r.actionId === 'RESTORE_SAFE_DEFAULTS')).toBe(true);
  });

  it('evaluates overallState as WARNING when real-time shield is snoozed', () => {
    watchdog.snoozeShield(60000);

    const healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector
    });

    const report = healthMonitor.evaluateHealth();
    expect(report.overallState).toBe('WARNING');
    const wdSub = report.subsystems.find(s => s.name === 'Watchdog');
    expect(wdSub?.state).toBe('WARNING');
    expect(wdSub?.message).toContain('snoozed');
  });

  it('enforces precedence where CRITICAL overrides DEGRADED and WARNING', () => {
    // 1. Snooze watchdog -> WARNING
    watchdog.snoozeShield(60000);

    // 2. Corrupt audit log on disk -> CRITICAL
    auditLogger.log({
      category: 'SCAN',
      severity: 'INFO',
      action: 'SCAN_EVT',
      actor: 'Tester',
      targetSummary: 'Test target'
    });
    const logPath = path.join(tempDir, 'audit.log.enc');
    fs.writeFileSync(logPath, 'corrupted data\n');

    const healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector
    });

    const report = healthMonitor.evaluateHealth();
    expect(report.overallState).toBe('CRITICAL');
  });
});
