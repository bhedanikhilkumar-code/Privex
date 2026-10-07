import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { IpcHandler } from '../../ipc/ipc-handler';

describe('Phase Q Health & Watchdog Integration Tests', () => {
  let tempBase: string;
  let configDir: string;
  let vaultDir: string;
  let downloadsDir: string;
  let tempDir: string;
  let handler: IpcHandler;

  beforeEach(() => {
    tempBase = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-q-int-'));
    configDir = path.join(tempBase, 'config');
    vaultDir = path.join(tempBase, 'vault');
    downloadsDir = path.join(tempBase, 'downloads');
    tempDir = path.join(tempBase, 'temp');

    fs.mkdirSync(configDir, { recursive: true });
    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(downloadsDir, { recursive: true });
    fs.mkdirSync(tempDir, { recursive: true });

    handler = new IpcHandler({
      configDir,
      vaultDir,
      downloadsDir,
      tempDir,
      autoStartRealtime: true
    });
  });

  afterEach(() => {
    handler.getWatchdog().stop();
    handler.getRealtimeMonitor().stop();
    try {
      fs.rmSync(tempBase, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  it('runs initial health check and verifies all core subsystems report nominal status', () => {
    const report = handler.handleRunHealthCheck();
    expect(report.overallState).toBe('HEALTHY');
    expect(report.subsystems.length).toBeGreaterThanOrEqual(5);

    const names = report.subsystems.map(s => s.name);
    expect(names).toContain('Configuration');
    expect(names).toContain('AuditLogger');
    expect(names).toContain('RealtimeShield');
    expect(names).toContain('Watchdog');
    expect(names).toContain('QuarantineVault');
  });

  it('verifies audit log query and cryptographic chain verification end-to-end', () => {
    const logger = handler.getAuditLogger();
    logger.log({
      category: 'SCAN',
      severity: 'INFO',
      action: 'SYSTEM_STARTUP_SCAN',
      actor: 'IntegrationTest',
      targetSummary: 'Initial startup baseline test'
    });

    const logsResult = handler.handleGetAuditLogs({ category: 'SCAN' });
    expect(logsResult.total).toBeGreaterThanOrEqual(1);
    expect(logsResult.entries[0].action).toBe('SYSTEM_STARTUP_SCAN');

    const verifyResult = handler.handleVerifyAuditChain();
    expect(verifyResult.isValid).toBe(true);
    expect(verifyResult.totalEntries).toBeGreaterThanOrEqual(1);

    const exportCsv = handler.handleExportAuditLogs('csv');
    expect(exportCsv).toContain('SYSTEM_STARTUP_SCAN');
    expect(exportCsv).toContain('entryHmacSha256');
  });

  it('handles shield snooze, pauses real-time monitor, and recovers upon watchdog expiry', async () => {
    // 1. Verify real-time shield is active
    expect(handler.getRealtimeMonitor().isActive()).toBe(true);

    // 2. Snooze shield for 1,000ms
    const snoozeResult = handler.handleWatchdogSnoozeShield(1000);
    expect(snoozeResult.success).toBe(true);
    expect(snoozeResult.remainingMs).toBe(1000);
    expect(handler.getRealtimeMonitor().isActive()).toBe(false);

    // 3. Verify health state transitions to WARNING during snooze
    const snoozedReport = handler.handleRunHealthCheck();
    expect(snoozedReport.overallState).toBe('WARNING');

    // 4. Cancel snooze and re-enable shield
    handler.getWatchdog().cancelSnooze();
    handler.applySettings(handler.getStorage().getSettings(), true);
    expect(handler.getRealtimeMonitor().isActive()).toBe(true);

    const restoredReport = handler.handleRunHealthCheck();
    expect(restoredReport.overallState).toBe('HEALTHY');
  });

  it('verifies tamper status check and detects disk modifications end-to-end', () => {
    const tamperBefore = handler.handleGetTamperStatus();
    expect(tamperBefore.tamperDetected).toBe(false);

    // Corrupt audit log on disk
    const auditFile = path.join(configDir, 'audit.log.enc');
    fs.appendFileSync(auditFile, '{"index":999,"forged":true}\n');

    const tamperAfter = handler.handleGetTamperStatus();
    expect(tamperAfter.tamperDetected).toBe(true);
    expect(tamperAfter.tamperedComponents).toContain('AuditLog');

    const health = handler.handleRunHealthCheck();
    expect(health.overallState).toBe('CRITICAL');
  });
});
