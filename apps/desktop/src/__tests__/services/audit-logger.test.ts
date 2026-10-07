import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AuditLoggerService } from '../../services/audit-logger.service';
import { AuditEventInput } from '../../types/desktop.types';

describe('AuditLoggerService Unit Tests', () => {
  let tempDir: string;
  let service: AuditLoggerService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-logger-test-'));
    service = new AuditLoggerService({ configDir: tempDir });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  it('initializes with empty cache and genesis prevHash', () => {
    expect(service.getCacheSize()).toBe(0);
    expect(service.getLastHash()).toBe(AuditLoggerService.GENESIS_PREV_HASH);
    expect(service.getNextIndex()).toBe(0);
  });

  it('appends records with valid sequential HMAC-SHA256 chaining', () => {
    const entry1 = service.log({
      category: 'SCAN',
      severity: 'INFO',
      action: 'SCAN_STARTED',
      actor: 'ScannerService',
      targetSummary: 'Target folder scan initiated'
    });

    expect(entry1.index).toBe(0);
    expect(entry1.prevHash).toBe(AuditLoggerService.GENESIS_PREV_HASH);
    expect(entry1.entryHmacSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(service.getLastHash()).toBe(entry1.entryHmacSha256);

    const entry2 = service.log({
      category: 'DETECTION',
      severity: 'WARN',
      action: 'THREAT_DETECTED',
      actor: 'FileAnalyzer',
      targetSummary: 'Suspicious script detected',
      riskScore: 75,
      verdict: 'WARN'
    });

    expect(entry2.index).toBe(1);
    expect(entry2.prevHash).toBe(entry1.entryHmacSha256);
    expect(entry2.entryHmacSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(service.getLastHash()).toBe(entry2.entryHmacSha256);

    const verify = service.verifyChainIntegrity();
    expect(verify.isValid).toBe(true);
    expect(verify.totalEntries).toBe(2);
    expect(verify.verifiedEntries).toBe(2);
  });

  it('scrubs PII and Tier-1 content in URLs, tokens, and credentials (RULE-18)', () => {
    const rawAction = 'User accessed https://example.com/login?token=supersecret123&user=admin#section';
    const rawTarget = 'File scanned with Bearer abcdef1234567890 and password="mySecretPassword"';

    const entry = service.log({
      category: 'SYSTEM',
      severity: 'INFO',
      action: rawAction,
      actor: 'TestActor',
      targetSummary: rawTarget,
      metadata: {
        rawUrl: 'http://malicious.org/payload.exe?download_key=xyz999',
        apiKey: 'api_key: secretKey123',
        normalField: 'okValue'
      }
    });

    expect(entry.action).not.toContain('supersecret123');
    expect(entry.action).toContain('https://example.com/login');
    expect(entry.targetSummary).not.toContain('abcdef1234567890');
    expect(entry.targetSummary).not.toContain('mySecretPassword');
    expect(entry.metadata?.rawUrl).not.toContain('xyz999');
    expect(entry.metadata?.apiKey).not.toContain('secretKey123');
    expect(entry.metadata?.normalField).toBe('okValue');
  });

  it('queries entries with filtering by category, severity, search, and pagination', () => {
    for (let i = 0; i < 15; i++) {
      service.log({
        category: i % 2 === 0 ? 'SCAN' : 'QUARANTINE',
        severity: i < 5 ? 'INFO' : i < 10 ? 'WARN' : 'CRITICAL',
        action: `ACTION_${i}`,
        actor: `Actor_${i}`,
        targetSummary: `Target summary file_${i}.txt`
      });
    }

    const all = service.query({ limit: 50 });
    expect(all.total).toBe(15);
    expect(all.entries.length).toBe(15);

    const onlyScan = service.query({ category: 'SCAN' });
    expect(onlyScan.total).toBe(8);

    const onlyCritical = service.query({ severity: 'CRITICAL' });
    expect(onlyCritical.total).toBe(5);

    const searchResult = service.query({ search: 'file_7' });
    expect(searchResult.total).toBe(1);
    expect(searchResult.entries[0].action).toBe('ACTION_7');

    const paginated = service.query({ offset: 5, limit: 5 });
    expect(paginated.offset).toBe(5);
    expect(paginated.limit).toBe(5);
    expect(paginated.entries.length).toBe(5);
  });

  it('exports sanitized logs to valid JSON and CSV formats', () => {
    service.log({
      category: 'SCAN',
      severity: 'INFO',
      action: 'SCAN_COMPLETED',
      actor: 'ScannerService',
      targetSummary: 'Full system scan completed successfully'
    });

    const jsonExport = service.export('json');
    const parsed = JSON.parse(jsonExport);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    expect(parsed[0].action).toBe('SCAN_COMPLETED');

    const csvExport = service.export('csv');
    const lines = csvExport.split('\n');
    expect(lines.length).toBe(2); // Header + 1 row
    expect(lines[0]).toContain('entryHmacSha256');
    expect(lines[1]).toContain('SCAN_COMPLETED');
  });

  it('recovers valid chain prefix when an incomplete/corrupted tail line exists', () => {
    service.log({
      category: 'SYSTEM',
      severity: 'INFO',
      action: 'BOOT_1',
      actor: 'Kernel',
      targetSummary: 'Clean boot 1'
    });

    service.log({
      category: 'SYSTEM',
      severity: 'INFO',
      action: 'BOOT_2',
      actor: 'Kernel',
      targetSummary: 'Clean boot 2'
    });

    // Simulate system crash during 3rd write leaving a partial truncated line
    const logPath = path.join(tempDir, 'audit.log.enc');
    fs.appendFileSync(logPath, '{"index":2,"id":"audit-2","timestamp":123456');

    // Instantiate new service to test startup crash recovery
    const recoveredService = new AuditLoggerService({ configDir: tempDir });
    expect(recoveredService.getCacheSize()).toBe(2);

    const verify = recoveredService.verifyChainIntegrity();
    expect(verify.isValid).toBe(true);
    expect(verify.totalEntries).toBe(2);

    // Can append normally after recovery
    recoveredService.log({
      category: 'SYSTEM',
      severity: 'INFO',
      action: 'BOOT_3_RECOVERED',
      actor: 'Kernel',
      targetSummary: 'Clean boot 3 after recovery'
    });

    expect(recoveredService.verifyChainIntegrity().isValid).toBe(true);
    expect(recoveredService.getCacheSize()).toBe(3);
  });

  it('purges and crypto-shreds all audit logs on demand', () => {
    service.log({
      category: 'SYSTEM',
      severity: 'INFO',
      action: 'EVENT_TO_SHRED',
      actor: 'ShredTester',
      targetSummary: 'Target to be wiped'
    });

    const logPath = path.join(tempDir, 'audit.log.enc');
    expect(fs.existsSync(logPath)).toBe(true);

    service.purgeAllLogs();
    expect(service.getCacheSize()).toBe(0);
    expect(service.getLastHash()).toBe(AuditLoggerService.GENESIS_PREV_HASH);
    expect(fs.existsSync(logPath)).toBe(false);
  });
});
