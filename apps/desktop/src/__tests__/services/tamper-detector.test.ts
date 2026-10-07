import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { TamperDetectorService } from '../../services/tamper-detector.service';
import { AuditLoggerService } from '../../services/audit-logger.service';

describe('TamperDetectorService Unit Tests', () => {
  let tempDir: string;
  let auditLogger: AuditLoggerService;
  let detector: TamperDetectorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tamper-detector-test-'));
    auditLogger = new AuditLoggerService({ configDir: tempDir });
    detector = new TamperDetectorService({
      configDir: tempDir,
      auditLogger
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  it('reports clean status when baseline files are uncorrupted', () => {
    // Generate valid audit log entries
    auditLogger.log({
      category: 'SYSTEM',
      severity: 'INFO',
      action: 'BOOT_CLEAN',
      actor: 'System',
      targetSummary: 'Initial clean startup'
    });

    const status = detector.checkTamper();
    expect(status.tamperDetected).toBe(false);
    expect(status.tamperedComponents.length).toBe(0);
    expect(status.configIntegrityValid).toBe(true);
    expect(status.auditChainIntegrityValid).toBe(true);
    expect(status.quarantineManifestIntegrityValid).toBe(true);
  });

  it('detects tampering when settings.enc payload envelope is malformed or invalid', () => {
    const settingsPath = path.join(tempDir, 'settings.enc');
    fs.writeFileSync(settingsPath, '{"invalid_json": true, "no_iv": "bad"}');

    const status = detector.checkTamper();
    expect(status.tamperDetected).toBe(true);
    expect(status.tamperedComponents).toContain('Configuration');
    expect(status.configIntegrityValid).toBe(false);
  });

  it('detects tampering when audit.log.enc hash chain is corrupted or modified', () => {
    // Append valid entry
    auditLogger.log({
      category: 'SCAN',
      severity: 'INFO',
      action: 'SCAN_STARTED',
      actor: 'Scanner',
      targetSummary: 'Target folder'
    });

    // Tamper with audit log file directly on disk
    const auditPath = path.join(tempDir, 'audit.log.enc');
    const content = fs.readFileSync(auditPath, 'utf8');
    const tampered = content.replace('Target folder', 'Attacker modified payload');
    fs.writeFileSync(auditPath, tampered);

    const status = detector.checkTamper();
    expect(status.tamperDetected).toBe(true);
    expect(status.tamperedComponents).toContain('AuditLog');
    expect(status.auditChainIntegrityValid).toBe(false);
    expect(status.details.some(d => d.includes('failed'))).toBe(true);
  });

  it('detects tampering when quarantine-manifest.enc envelope is malformed', () => {
    const qDir = path.join(tempDir, 'quarantine');
    fs.mkdirSync(qDir, { recursive: true });
    const manifestPath = path.join(qDir, 'quarantine-manifest.enc');
    fs.writeFileSync(manifestPath, '{"corrupted": true}');

    const status = detector.checkTamper();
    expect(status.tamperDetected).toBe(true);
    expect(status.tamperedComponents).toContain('QuarantineManifest');
    expect(status.quarantineManifestIntegrityValid).toBe(false);
  });
});
