import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { AuditLoggerService } from '../../services/audit-logger.service';
import { TamperDetectorService } from '../../services/tamper-detector.service';
import { WatchdogService } from '../../services/watchdog.service';
import { HealthMonitorService } from '../../services/health-monitor.service';
import { SecureStorageService } from '../../services/secure-storage.service';
import { IpcValidator } from '../../ipc/ipc-validator';
import { AuditLogEntry } from '../../types/desktop.types';

describe('Phase Q Adversarial & Tamper Security Tests', () => {
  let tempDir: string;
  let auditLogger: AuditLoggerService;
  let storage: SecureStorageService;
  let tamperDetector: TamperDetectorService;
  let watchdog: WatchdogService;
  let healthMonitor: HealthMonitorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-q-security-'));
    auditLogger = new AuditLoggerService({ configDir: tempDir });
    storage = new SecureStorageService(tempDir);
    tamperDetector = new TamperDetectorService({
      configDir: tempDir,
      auditLogger,
      storageService: storage
    });
    watchdog = new WatchdogService({ auditLogger });
    healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector,
      storageService: storage
    });
  });

  afterEach(() => {
    watchdog?.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  // ============================================================
  // Category 1: Audit Log Cryptographic Tamper Injection
  // ============================================================

  it('ADV-Q01: Single-byte payload mutation of intermediate audit entry fails integrity at exact index', () => {
    for (let i = 0; i < 5; i++) {
      auditLogger.log({
        category: 'SCAN',
        severity: 'INFO',
        action: `SCAN_${i}`,
        actor: 'Tester',
        targetSummary: `File summary target ${i}`
      });
    }

    // Verify baseline passes
    expect(auditLogger.verifyChainIntegrity().isValid).toBe(true);

    // Tamper single byte in entry index 2
    const logPath = path.join(tempDir, 'audit.log.enc');
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim().length > 0);
    const entry2 = JSON.parse(lines[2]) as AuditLogEntry;
    const tamperedEntry2 = {
      ...entry2,
      targetSummary: 'File summary target 2!' // Mutated 1 character
    };
    lines[2] = JSON.stringify(tamperedEntry2);
    fs.writeFileSync(logPath, lines.join('\n') + '\n');

    const result = auditLogger.verifyChainIntegrity();
    expect(result.isValid).toBe(false);
    expect(result.corruptedIndex).toBe(2);
    expect(result.reason).toBe('HMAC_SIGNATURE_MISMATCH');
  });

  it('ADV-Q02: Deletion of an intermediate audit entry breaks hash continuity and is detected', () => {
    for (let i = 0; i < 5; i++) {
      auditLogger.log({
        category: 'SYSTEM',
        severity: 'INFO',
        action: `BOOT_${i}`,
        actor: 'Kernel',
        targetSummary: `Boot phase ${i}`
      });
    }

    const logPath = path.join(tempDir, 'audit.log.enc');
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim().length > 0);
    // Delete entry index 2
    lines.splice(2, 1);
    fs.writeFileSync(logPath, lines.join('\n') + '\n');

    const result = auditLogger.verifyChainIntegrity();
    expect(result.isValid).toBe(false);
    expect(result.corruptedIndex).toBe(2);
    expect(result.reason).toBe('INDEX_SEQUENCE_VIOLATION');
  });

  it('ADV-Q03: Insertion of forged entry between legitimate records breaks hash chaining', () => {
    for (let i = 0; i < 4; i++) {
      auditLogger.log({
        category: 'DETECTION',
        severity: 'WARN',
        action: `THREAT_${i}`,
        actor: 'Engine',
        targetSummary: `Threat detected ${i}`
      });
    }

    const logPath = path.join(tempDir, 'audit.log.enc');
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim().length > 0);
    // Insert forged entry with fake HMAC
    const forged = JSON.stringify({
      index: 2,
      id: 'audit-forged',
      timestamp: Date.now(),
      category: 'DETECTION',
      severity: 'INFO',
      action: 'ALLOW_THREAT',
      actor: 'Attacker',
      targetSummary: 'Bypassed entry',
      prevHash: JSON.parse(lines[1]).entryHmacSha256,
      entryHmacSha256: crypto.randomBytes(32).toString('hex')
    });
    lines.splice(2, 0, forged);
    fs.writeFileSync(logPath, lines.join('\n') + '\n');

    const result = auditLogger.verifyChainIntegrity();
    expect(result.isValid).toBe(false);
    expect(result.corruptedIndex).toBe(2);
  });

  it('ADV-Q04: Reordering of adjacent audit records is immediately flagged as sequence violation', () => {
    for (let i = 0; i < 4; i++) {
      auditLogger.log({
        category: 'SCAN',
        severity: 'INFO',
        action: `ORDER_${i}`,
        actor: 'Scanner',
        targetSummary: `Summary ${i}`
      });
    }

    const logPath = path.join(tempDir, 'audit.log.enc');
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim().length > 0);
    // Swap lines 1 and 2
    const tmp = lines[1];
    lines[1] = lines[2];
    lines[2] = tmp;
    fs.writeFileSync(logPath, lines.join('\n') + '\n');

    const result = auditLogger.verifyChainIntegrity();
    expect(result.isValid).toBe(false);
    expect(result.corruptedIndex).toBe(1);
    expect(result.reason).toBe('INDEX_SEQUENCE_VIOLATION');
  });

  it('ADV-Q05: Stale timestamp / replay attack with modified timestamp breaks HMAC signature', () => {
    auditLogger.log({
      category: 'QUARANTINE',
      severity: 'INFO',
      action: 'QUARANTINE_FILE',
      actor: 'QuarantineService',
      targetSummary: 'Quarantined file test'
    });

    const logPath = path.join(tempDir, 'audit.log.enc');
    const lines = fs.readFileSync(logPath, 'utf8').split('\n').filter(l => l.trim().length > 0);
    const entry = JSON.parse(lines[0]) as AuditLogEntry;
    const replayed = {
      ...entry,
      timestamp: entry.timestamp - 100000 // Rewind timestamp
    };
    lines[0] = JSON.stringify(replayed);
    fs.writeFileSync(logPath, lines.join('\n') + '\n');

    const result = auditLogger.verifyChainIntegrity();
    expect(result.isValid).toBe(false);
    expect(result.corruptedIndex).toBe(0);
    expect(result.reason).toBe('HMAC_SIGNATURE_MISMATCH');
  });

  // ============================================================
  // Category 2: Configuration & Tamper Detection Fail-Closed
  // ============================================================

  it('ADV-Q06: Direct modification of settings.enc envelope flags tamper and transitions health to CRITICAL', () => {
    // Write valid settings
    storage.saveSettings({ realtimeShieldEnabled: true, monitorDownloads: true });

    // Attack: directly overwrite settings.enc with corrupt payload
    const settingsPath = path.join(tempDir, 'settings.enc');
    fs.writeFileSync(settingsPath, '{"tampered_payload": "corrupted"}');

    const tamperStatus = tamperDetector.checkTamper();
    expect(tamperStatus.tamperDetected).toBe(true);
    expect(tamperStatus.tamperedComponents).toContain('Configuration');

    const health = healthMonitor.evaluateHealth();
    expect(health.overallState).toBe('CRITICAL');
    expect(health.issues.some(i => i.includes('compromised'))).toBe(true);
  });

  // ============================================================
  // Category 3: Watchdog Supervisor Anti-Storm Protection
  // ============================================================

  it('ADV-Q07: Crash-storm (>3 crashes in 10s) activates circuit breaker and prevents restart loops', async () => {
    let failureCount = 0;
    watchdog = new WatchdogService({
      auditLogger,
      circuitBreakerThreshold: 3,
      circuitBreakerWindowMs: 10000
    });

    watchdog.registerComponent({
      name: 'CrashingDaemon',
      checkHealth: () => false,
      recover: () => {
        failureCount++;
        return false;
      }
    });

    // Run 5 rapid heartbeats
    for (let i = 0; i < 5; i++) {
      await watchdog.executeHeartbeat();
    }

    // Circuit breaker must have engaged on 3rd failure and stopped calling recover()
    expect(failureCount).toBe(2); // 1st and 2nd attempt recovery, 3rd trips breaker
    const status = watchdog.getStatus();
    expect(status.safeMinimalMode).toBe(true);
    expect(status.monitoredComponents[0].status).toBe('ISOLATED');
  });

  // ============================================================
  // Category 4: Zero-Trust IPC Input Validation
  // ============================================================

  it('ADV-Q08: IpcValidator rejects invalid snooze duration and malicious component names', () => {
    expect(() => IpcValidator.validateSnoozeDuration(-500)).toThrow('INVALID_SNOOZE_DURATION');
    expect(() => IpcValidator.validateSnoozeDuration(100000000)).toThrow('INVALID_SNOOZE_DURATION');
    expect(() => IpcValidator.validateSnoozeDuration(NaN)).toThrow('INVALID_SNOOZE_DURATION');

    expect(IpcValidator.validateSnoozeDuration(60000)).toBe(60000);

    expect(() => IpcValidator.validateComponentName('')).toThrow('INVALID_COMPONENT_NAME');
    expect(() => IpcValidator.validateComponentName('   ')).toThrow('INVALID_COMPONENT_NAME');
    expect(() => IpcValidator.validateComponentName('x'.repeat(101))).toThrow('INVALID_COMPONENT_NAME');
    expect(IpcValidator.validateComponentName('RealtimeMonitor')).toBe('RealtimeMonitor');
  });

  it('ADV-Q09: IpcValidator safely bounds and sanitizes audit query filters without throwing', () => {
    const malicious = {
      category: 'INVALID_CATEGORY',
      severity: 'HACKED',
      startDate: -999,
      offset: -10,
      limit: 99999999,
      search: 'a'.repeat(500)
    };

    const sanitized = IpcValidator.validateAuditFilter(malicious);
    expect(sanitized.category).toBeUndefined();
    expect(sanitized.severity).toBeUndefined();
    expect(sanitized.startDate).toBeUndefined();
    expect(sanitized.offset).toBeUndefined();
    expect(sanitized.limit).toBe(1000); // Clamped to max 1000
    expect(sanitized.search?.length).toBeLessThanOrEqual(100);
  });
});
