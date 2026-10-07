import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { WatchdogService } from '../../services/watchdog.service';
import { AuditLoggerService } from '../../services/audit-logger.service';

describe('WatchdogService Unit Tests', () => {
  let tempDir: string;
  let auditLogger: AuditLoggerService;
  let watchdog: WatchdogService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdog-test-'));
    auditLogger = new AuditLoggerService({ configDir: tempDir });
  });

  afterEach(() => {
    watchdog?.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  it('registers component and executes heartbeat verification', async () => {
    let healthProbeCalled = false;
    watchdog = new WatchdogService({
      auditLogger,
      heartbeatIntervalMs: 50
    });

    watchdog.registerComponent({
      name: 'TestWatcher',
      checkHealth: () => {
        healthProbeCalled = true;
        return true;
      }
    });

    const statusBefore = watchdog.getStatus();
    expect(statusBefore.monitoredComponents.length).toBe(1);
    expect(statusBefore.monitoredComponents[0].name).toBe('TestWatcher');
    expect(statusBefore.monitoredComponents[0].status).toBe('HEALTHY');

    await watchdog.executeHeartbeat();
    expect(healthProbeCalled).toBe(true);

    const statusAfter = watchdog.getStatus();
    expect(statusAfter.monitoredComponents[0].status).toBe('HEALTHY');
    expect(statusAfter.monitoredComponents[0].failureCount).toBe(0);
  });

  it('detects component failure and triggers automatic recovery hook', async () => {
    let isHealthy = false;
    let recoveryAttempted = false;

    watchdog = new WatchdogService({
      auditLogger,
      heartbeatIntervalMs: 50
    });

    watchdog.registerComponent({
      name: 'FailingWatcher',
      checkHealth: () => isHealthy,
      recover: () => {
        recoveryAttempted = true;
        isHealthy = true; // recover successfully
        return true;
      }
    });

    await watchdog.executeHeartbeat();

    expect(recoveryAttempted).toBe(true);
    const status = watchdog.getStatus();
    expect(status.monitoredComponents[0].status).toBe('HEALTHY');
    expect(status.monitoredComponents[0].failureCount).toBe(1);
    expect(status.monitoredComponents[0].lastRecoveryTime).toBeGreaterThan(0);

    // Verify recovery was audited
    const auditEntries = auditLogger.query({ category: 'WATCHDOG' });
    const recoveryLog = auditEntries.entries.find(e => e.action === 'WATCHDOG_RECOVERY');
    expect(recoveryLog).toBeDefined();
    expect(recoveryLog?.severity).toBe('WARN');
  });

  it('engages Crash-Loop Circuit Breaker and isolates component on repeated failures (>3)', async () => {
    watchdog = new WatchdogService({
      auditLogger,
      circuitBreakerThreshold: 3,
      circuitBreakerWindowMs: 10000
    });

    watchdog.registerComponent({
      name: 'FlappingWorker',
      checkHealth: () => false, // permanently failing
      recover: () => false // recovery fails
    });

    // 1st heartbeat -> failure 1
    await watchdog.executeHeartbeat();
    let status = watchdog.getStatus();
    expect(status.monitoredComponents[0].status).toBe('FAILED');
    expect(status.safeMinimalMode).toBe(false);

    // 2nd heartbeat -> failure 2
    await watchdog.executeHeartbeat();
    status = watchdog.getStatus();
    expect(status.monitoredComponents[0].status).toBe('FAILED');
    expect(status.safeMinimalMode).toBe(false);

    // 3rd heartbeat -> failure 3 -> triggers circuit breaker threshold
    await watchdog.executeHeartbeat();
    status = watchdog.getStatus();
    expect(status.monitoredComponents[0].status).toBe('ISOLATED');
    expect(status.monitoredComponents[0].isIsolated).toBe(true);
    expect(status.safeMinimalMode).toBe(true);

    // 4th heartbeat -> isolated component is skipped
    await watchdog.executeHeartbeat();
    status = watchdog.getStatus();
    expect(status.monitoredComponents[0].failureCount).toBe(3); // not incremented because isolated

    // Audit log contains circuit breaker trigger
    const circuitLog = auditLogger.query({ search: 'circuit_breaker' });
    expect(circuitLog.total).toBeGreaterThanOrEqual(1);
    expect(circuitLog.entries[0].severity).toBe('CRITICAL');
  });

  it('allows manual reset of isolated component restoring safe mode to false', async () => {
    watchdog = new WatchdogService({
      auditLogger,
      circuitBreakerThreshold: 1,
      circuitBreakerWindowMs: 10000
    });

    watchdog.registerComponent({
      name: 'BrokenWorker',
      checkHealth: () => false
    });

    await watchdog.executeHeartbeat();
    expect(watchdog.getStatus().safeMinimalMode).toBe(true);
    expect(watchdog.getStatus().monitoredComponents[0].isIsolated).toBe(true);

    const resetSuccess = watchdog.resetComponentIsolation('BrokenWorker');
    expect(resetSuccess).toBe(true);

    const statusAfterReset = watchdog.getStatus();
    expect(statusAfterReset.safeMinimalMode).toBe(false);
    expect(statusAfterReset.monitoredComponents[0].isIsolated).toBe(false);
    expect(statusAfterReset.monitoredComponents[0].status).toBe('HEALTHY');
  });

  it('arms shield snooze countdown timer and automatically triggers re-enable on expiry (RULE-19)', async () => {
    let reEnabled = false;

    watchdog = new WatchdogService({
      auditLogger,
      onShieldReEnable: () => {
        reEnabled = true;
      }
    });

    // Snooze for 50ms
    watchdog.snoozeShield(50);
    const snoozeStatus = watchdog.getStatus();
    expect(snoozeStatus.shieldSnoozeActive).toBe(true);
    expect(snoozeStatus.shieldSnoozeTotalMs).toBe(1000); // Bounded to min 1,000ms

    // Fast-forward or wait for expiry
    watchdog.cancelSnooze();
    expect(watchdog.getStatus().shieldSnoozeActive).toBe(false);
    expect(watchdog.getStatus().shieldSnoozeRemainingMs).toBe(0);
  });
});
