import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { WatchdogService } from '../../services/watchdog.service';
import { AuditLoggerService } from '../../services/audit-logger.service';

describe('Phase S Category 08 — Crash Recovery & Watchdog Subsystem', () => {
  let tempDir: string;
  let auditLogger: AuditLoggerService;
  let watchdog: WatchdogService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-s-watchdog-'));
    auditLogger = new AuditLoggerService({ configDir: tempDir });
  });

  afterEach(() => {
    watchdog?.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('detects realtime watcher failure, executes self-healing recovery, and logs audit record', async () => {
    let failureCount = 0;
    let recoveryExecuted = false;

    watchdog = new WatchdogService({
      auditLogger,
      heartbeatIntervalMs: 50
    });

    watchdog.registerComponent({
      name: 'RealtimeWatcherEngine',
      checkHealth: () => {
        if (failureCount === 0) {
          failureCount++;
          return false; // simulate crash on first heartbeat check
        }
        return true;
      },
      recover: () => {
        recoveryExecuted = true;
        return true; // recovery succeeds
      }
    });

    await watchdog.executeHeartbeat();

    expect(recoveryExecuted).toBe(true);
    const status = watchdog.getStatus();
    expect(status.monitoredComponents[0].status).toBe('HEALTHY');
    expect(status.monitoredComponents[0].failureCount).toBe(1);

    const auditQuery = auditLogger.query({ category: 'WATCHDOG' });
    const recoveryLog = auditQuery.entries.find(e => e.action === 'WATCHDOG_RECOVERY');
    expect(recoveryLog).toBeDefined();
    expect(recoveryLog?.severity).toBe('WARN');
  });

  it('triggers Circuit Breaker and transitions system to Safe Minimal Mode upon crash loop', async () => {
    watchdog = new WatchdogService({
      auditLogger,
      circuitBreakerThreshold: 3,
      circuitBreakerWindowMs: 60000
    });

    watchdog.registerComponent({
      name: 'FlappingScannerWorker',
      checkHealth: () => false, // always unhealthy
      recover: () => false // recovery fails
    });

    // Execute 3 failed heartbeats to trip circuit breaker
    await watchdog.executeHeartbeat();
    await watchdog.executeHeartbeat();
    await watchdog.executeHeartbeat();

    const status = watchdog.getStatus();
    expect(status.safeMinimalMode).toBe(true);
    expect(status.monitoredComponents[0].status).toBe('ISOLATED');
    expect(status.monitoredComponents[0].failureCount).toBe(3);

    const auditQuery = auditLogger.query({ category: 'WATCHDOG' });
    const cbLog = auditQuery.entries.find(e => e.action === 'WATCHDOG_CIRCUIT_BREAKER_TRIGGERED');
    expect(cbLog).toBeDefined();
    expect(cbLog?.severity).toBe('CRITICAL');
  });

  it('executes shield snooze auto-re-enable upon snooze duration expiration', async () => {
    vi.useFakeTimers();
    try {
      let shieldReEnabled = false;
      let mockTime = 1000;

      watchdog = new WatchdogService({
        auditLogger,
        clock: () => mockTime,
        onShieldReEnable: () => {
          shieldReEnabled = true;
        }
      });

      // Start a 1000ms snooze
      watchdog.snoozeShield(1000);
      const status = watchdog.getStatus();
      expect(status.shieldSnoozeActive).toBe(true);
      expect(status.shieldSnoozeRemainingMs).toBe(1000);

      // Advance timers and time
      mockTime += 1500;
      await vi.advanceTimersByTimeAsync(1500);

      expect(shieldReEnabled).toBe(true);
      const finalStatus = watchdog.getStatus();
      expect(finalStatus.shieldSnoozeActive).toBe(false);

      const auditQuery = auditLogger.query({ category: 'WATCHDOG' });
      const snoozeLog = auditQuery.entries.find(e => e.action === 'SHIELD_AUTO_REENABLED');
      expect(snoozeLog).toBeDefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
