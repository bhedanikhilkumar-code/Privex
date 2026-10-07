import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { TamperStatus } from '../types/desktop.types';
import { AuditLoggerService } from './audit-logger.service';
import { SecureStorageService } from './secure-storage.service';

export interface TamperDetectorOptions {
  configDir?: string;
  auditLogger?: AuditLoggerService;
  storageService?: SecureStorageService;
  clock?: () => number;
}

export class TamperDetectorService {
  private readonly configDir: string;
  private readonly auditLogger?: AuditLoggerService;
  private readonly storageService?: SecureStorageService;
  private readonly clock: () => number;

  private lastCheckTimestamp: number = 0;
  private cachedStatus: TamperStatus | null = null;

  constructor(options?: TamperDetectorOptions) {
    this.configDir = path.resolve(
      options?.configDir || path.join(os.homedir(), '.private-protection')
    );
    this.auditLogger = options?.auditLogger;
    this.storageService = options?.storageService;
    this.clock = options?.clock || (() => Date.now());
  }

  /**
   * Executes a full tamper check across configuration, audit log, and quarantine storage.
   */
  public checkTamper(): TamperStatus {
    const now = this.clock();
    const tamperedComponents: string[] = [];
    const details: string[] = [];
    let configValid = true;
    let auditValid = true;
    let quarantineValid = true;

    // 1. Check Configuration Integrity (RULE-19)
    const settingsPath = path.join(this.configDir, 'settings.enc');
    if (fs.existsSync(settingsPath)) {
      try {
        const raw = fs.readFileSync(settingsPath, 'utf8');
        const parsed = JSON.parse(raw);
        if (
          !parsed ||
          typeof parsed !== 'object' ||
          typeof parsed.iv !== 'string' ||
          typeof parsed.tag !== 'string' ||
          typeof parsed.data !== 'string' ||
          parsed.iv.length !== 24 || // 12 bytes hex
          parsed.tag.length !== 32 // 16 bytes hex
        ) {
          configValid = false;
          tamperedComponents.push('Configuration');
          details.push('settings.enc envelope structure is invalid or tampered');
        } else if (this.storageService) {
          // Attempt decrypt check
          try {
            this.storageService.getSettings();
          } catch (e) {
            configValid = false;
            tamperedComponents.push('Configuration');
            details.push(`settings.enc failed authentication: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
      } catch (err) {
        configValid = false;
        tamperedComponents.push('Configuration');
        details.push(`settings.enc file is malformed or unreadable: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // 2. Check Audit Chain Integrity (RULE-18)
    if (this.auditLogger) {
      const auditResult = this.auditLogger.verifyChainIntegrity();
      if (!auditResult.isValid) {
        auditValid = false;
        tamperedComponents.push('AuditLog');
        details.push(
          `Audit log hash chain verification failed at index ${auditResult.corruptedIndex}: ${auditResult.reason || 'TAMPER_DETECTED'} (${auditResult.tamperDetails || ''})`
        );
      }
    } else {
      const auditPath = path.join(this.configDir, 'audit.log.enc');
      if (fs.existsSync(auditPath)) {
        try {
          const content = fs.readFileSync(auditPath, 'utf8');
          const lines = content.split('\n').filter(l => l.trim().length > 0);
          for (let i = 0; i < lines.length; i++) {
            const parsed = JSON.parse(lines[i]);
            if (typeof parsed.index !== 'number' || typeof parsed.entryHmacSha256 !== 'string') {
              auditValid = false;
              tamperedComponents.push('AuditLog');
              details.push(`Audit log line ${i} does not conform to HMAC schema`);
              break;
            }
          }
        } catch (err) {
          auditValid = false;
          tamperedComponents.push('AuditLog');
          details.push(`Audit log file read failed: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    // 3. Check Quarantine Manifest Integrity
    const quarantineManifestPath = path.join(this.configDir, 'quarantine', 'quarantine-manifest.enc');
    if (fs.existsSync(quarantineManifestPath)) {
      try {
        const raw = fs.readFileSync(quarantineManifestPath, 'utf8');
        const parsed = JSON.parse(raw);
        if (
          !parsed ||
          typeof parsed !== 'object' ||
          typeof parsed.iv !== 'string' ||
          typeof parsed.tag !== 'string' ||
          typeof parsed.data !== 'string'
        ) {
          quarantineValid = false;
          tamperedComponents.push('QuarantineManifest');
          details.push('quarantine-manifest.enc envelope structure is invalid');
        }
      } catch (err) {
        quarantineValid = false;
        tamperedComponents.push('QuarantineManifest');
        details.push(`Quarantine manifest read error: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const tamperDetected = tamperedComponents.length > 0;

    const status: TamperStatus = {
      tamperDetected,
      tamperedComponents,
      lastTamperCheck: now,
      configIntegrityValid: configValid,
      auditChainIntegrityValid: auditValid,
      quarantineManifestIntegrityValid: quarantineValid,
      details
    };

    this.cachedStatus = status;
    this.lastCheckTimestamp = now;

    // Log tamper detection if observed
    if (tamperDetected && this.auditLogger) {
      try {
        this.auditLogger.log({
          category: 'TAMPER_DETECTION',
          severity: 'CRITICAL',
          action: 'TAMPER_DETECTED',
          actor: 'TamperDetectorService',
          targetSummary: `Tampered components: ${tamperedComponents.join(', ')}`,
          metadata: {
            configValid,
            auditValid,
            quarantineValid,
            issueCount: details.length
          }
        });
      } catch {
        // do not throw if logger is already in error state
      }
    }

    return status;
  }

  public getStatus(): TamperStatus {
    if (!this.cachedStatus || this.clock() - this.lastCheckTimestamp > 5000) {
      return this.checkTamper();
    }
    return this.cachedStatus;
  }
}
