import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {
  DesktopSettings,
  SecurityLogEntry,
  SecurityLogEventType
} from '../types/desktop.types';
import { IpcValidator } from '../ipc/ipc-validator';

export class SecureStorageService {
  private configDir: string;
  private settingsPath: string;
  private securityEventsPath: string;
  private encryptionKey: Buffer;
  private cachedSettings: DesktopSettings | null = null;
  private securityEvents: SecurityLogEntry[] = [];

  public static readonly MAX_SECURITY_EVENTS = 250;
  private static readonly MAX_SUMMARY_LENGTH = 300;
  private static readonly MAX_METADATA_VALUE_LENGTH = 200;

  private static readonly DEFAULT_SETTINGS: DesktopSettings = {
    realtimeShieldEnabled: true,
    monitorDownloads: true,
    monitorTemp: true,
    scanLargeFilesLimitMb: 50,
    entropyDetectionEnabled: true,
    autoQuarantineCritical: false,
    frictionGateEnabled: true,
    cognitiveLevel: 'grade6',
    excludedPaths: []
  };

  constructor(customConfigDir?: string) {
    this.configDir = path.resolve(
      customConfigDir || path.join(os.homedir(), '.private-protection')
    );
    this.settingsPath = path.join(this.configDir, 'settings.enc');
    this.securityEventsPath = path.join(this.configDir, 'security-events.enc');
    this.initStorage();
    this.encryptionKey = this.deriveEncryptionKey();
    this.loadSecurityEvents();
  }

  private initStorage(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
  }

  private writeAtomicFileSync(targetPath: string, content: string | Buffer): void {
    this.initStorage();
    const tmpPath = `${targetPath}.tmp`;
    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
      if (typeof content === 'string') {
        fs.writeFileSync(fd, content, 'utf8');
      } else {
        fs.writeSync(fd, content, 0, content.length, 0);
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, targetPath);
  }

  /**
   * Derives an authenticated AES-256-GCM encryption key using machine-specific identity
   * combined with a persistent cryptographically random salt and 100,000 PBKDF2 iterations.
   */
  private deriveEncryptionKey(): Buffer {
    this.initStorage();
    const saltPath = path.join(this.configDir, '.storage.salt');
    let salt: Buffer | null = null;

    if (fs.existsSync(saltPath)) {
      try {
        const loaded = fs.readFileSync(saltPath);
        if (loaded.length >= 16) {
          salt = loaded;
        }
      } catch {
        salt = null;
      }
    }

    if (!salt) {
      salt = crypto.randomBytes(32);
      this.writeAtomicFileSync(saltPath, salt);
    }

    const machineSecret = `${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}`;
    return crypto.pbkdf2Sync(machineSecret, salt, 100000, 32, 'sha256');
  }

  private encrypt(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return JSON.stringify({
      iv: iv.toString('hex'),
      tag: authTag.toString('hex'),
      data: encrypted.toString('hex')
    });
  }

  private decrypt(payloadStr: string): string {
    const parsed = JSON.parse(payloadStr);
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      typeof parsed.iv !== 'string' ||
      typeof parsed.tag !== 'string' ||
      typeof parsed.data !== 'string'
    ) {
      throw new Error('CORRUPT_ENCRYPTED_PAYLOAD');
    }
    const iv = Buffer.from(parsed.iv, 'hex');
    const authTag = Buffer.from(parsed.tag, 'hex');
    if (iv.length !== 12 || authTag.length !== 16) {
      throw new Error('INVALID_GCM_PARAMETERS');
    }
    const encrypted = Buffer.from(parsed.data, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final('utf8');
  }

  /**
   * Validates and sanitizes raw parsed JSON against DesktopSettings schema.
   * Rejects or replaces any invalid field with safe defaults and flags whether schema errors occurred.
   */
  private sanitizeLoadedSettings(raw: unknown): {
    settings: DesktopSettings;
    hadSchemaErrors: boolean;
  } {
    const defaults: DesktopSettings = {
      ...SecureStorageService.DEFAULT_SETTINGS,
      excludedPaths: [...SecureStorageService.DEFAULT_SETTINGS.excludedPaths]
    };

    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return { settings: defaults, hadSchemaErrors: true };
    }

    const obj = raw as Record<string, unknown>;
    const sanitized: DesktopSettings = { ...defaults };
    let hadSchemaErrors = false;

    const booleanKeys: Array<
      | 'realtimeShieldEnabled'
      | 'monitorDownloads'
      | 'monitorTemp'
      | 'entropyDetectionEnabled'
      | 'autoQuarantineCritical'
      | 'frictionGateEnabled'
    > = [
      'realtimeShieldEnabled',
      'monitorDownloads',
      'monitorTemp',
      'entropyDetectionEnabled',
      'autoQuarantineCritical',
      'frictionGateEnabled'
    ];

    for (const key of booleanKeys) {
      if (obj[key] !== undefined) {
        if (typeof obj[key] === 'boolean') {
          sanitized[key] = obj[key] as boolean;
        } else {
          hadSchemaErrors = true;
        }
      }
    }

    if (obj.scanLargeFilesLimitMb !== undefined) {
      if (
        typeof obj.scanLargeFilesLimitMb === 'number' &&
        Number.isFinite(obj.scanLargeFilesLimitMb) &&
        obj.scanLargeFilesLimitMb >= 1 &&
        obj.scanLargeFilesLimitMb <= 2048
      ) {
        sanitized.scanLargeFilesLimitMb = Math.floor(obj.scanLargeFilesLimitMb);
      } else {
        hadSchemaErrors = true;
      }
    }

    if (obj.cognitiveLevel !== undefined) {
      if (obj.cognitiveLevel === 'grade6' || obj.cognitiveLevel === 'grade8') {
        sanitized.cognitiveLevel = obj.cognitiveLevel;
      } else {
        hadSchemaErrors = true;
      }
    }

    if (obj.excludedPaths !== undefined) {
      if (Array.isArray(obj.excludedPaths) && obj.excludedPaths.length <= 100) {
        const validPaths: string[] = [];
        for (const p of obj.excludedPaths) {
          try {
            validPaths.push(IpcValidator.validatePath(p));
          } catch {
            hadSchemaErrors = true;
          }
        }
        sanitized.excludedPaths = validPaths;
      } else {
        hadSchemaErrors = true;
      }
    }

    return { settings: sanitized, hadSchemaErrors };
  }

  public getSettings(): DesktopSettings {
    if (this.cachedSettings) {
      return {
        ...this.cachedSettings,
        excludedPaths: [...this.cachedSettings.excludedPaths]
      };
    }

    const bakPath = `${this.settingsPath}.bak`;

    if (!fs.existsSync(this.settingsPath) && !fs.existsSync(bakPath)) {
      this.cachedSettings = {
        ...SecureStorageService.DEFAULT_SETTINGS,
        excludedPaths: [...SecureStorageService.DEFAULT_SETTINGS.excludedPaths]
      };
      return {
        ...this.cachedSettings,
        excludedPaths: [...this.cachedSettings.excludedPaths]
      };
    }

    for (const candidatePath of [this.settingsPath, bakPath]) {
      if (!fs.existsSync(candidatePath)) continue;
      try {
        const rawEnc = fs.readFileSync(candidatePath, 'utf8');
        const decrypted = this.decrypt(rawEnc);
        const parsedJson = JSON.parse(decrypted);
        const { settings, hadSchemaErrors } = this.sanitizeLoadedSettings(parsedJson);

        if (hadSchemaErrors) {
          this.recordSecurityEvent(
            'CONFIG_FAILURE',
            'WARN',
            'Malformed configuration fields detected and sanitized to safe defaults.',
            { recoveredFromBackup: candidatePath === bakPath }
          );
        } else if (candidatePath === bakPath) {
          this.recordSecurityEvent(
            'CONFIG_FAILURE',
            'WARN',
            'Primary settings.enc corrupted; recovered configuration from settings.enc.bak.',
            { recoveredFromBackup: true }
          );
        }

        this.cachedSettings = settings;
        if (candidatePath === bakPath || hadSchemaErrors) {
          const reEncrypted = this.encrypt(JSON.stringify(settings));
          this.writeAtomicFileSync(this.settingsPath, reEncrypted);
        }
        return {
          ...settings,
          excludedPaths: [...settings.excludedPaths]
        };
      } catch {
        // Try backup or fall through to safe defaults
      }
    }

    // Both primary and backup failed decryption or JSON parsing -> fail closed to safe defaults
    this.recordSecurityEvent(
      'CONFIG_FAILURE',
      'ERROR',
      'Configuration storage corrupted or tampered with; restored safe default settings.',
      { fallbackApplied: true }
    );
    const defaults: DesktopSettings = {
      ...SecureStorageService.DEFAULT_SETTINGS,
      excludedPaths: [...SecureStorageService.DEFAULT_SETTINGS.excludedPaths]
    };
    this.cachedSettings = defaults;
    return {
      ...defaults,
      excludedPaths: [...defaults.excludedPaths]
    };
  }

  public saveSettings(settings: Partial<DesktopSettings>): void {
    const validatedPatch = IpcValidator.validateSettings(settings);
    const current = this.getSettings();
    const updated: DesktopSettings = {
      ...current,
      ...validatedPatch,
      excludedPaths: validatedPatch.excludedPaths
        ? [...validatedPatch.excludedPaths]
        : [...current.excludedPaths]
    };
    this.cachedSettings = updated;

    const encrypted = this.encrypt(JSON.stringify(updated));
    const bakPath = `${this.settingsPath}.bak`;
    if (fs.existsSync(this.settingsPath)) {
      try {
        const existingRaw = fs.readFileSync(this.settingsPath, 'utf8');
        this.decrypt(existingRaw);
        fs.copyFileSync(this.settingsPath, bakPath);
      } catch {
        // Do not overwrite .bak with a corrupted primary file
      }
    }
    this.writeAtomicFileSync(this.settingsPath, encrypted);
  }

  /**
   * Step 12: Bounded Local Security Event Logging (Privacy-First, Zero Tier-1 Content).
   */
  private loadSecurityEvents(): void {
    this.securityEvents = [];
    if (!fs.existsSync(this.securityEventsPath)) {
      return;
    }
    try {
      const rawEnc = fs.readFileSync(this.securityEventsPath, 'utf8');
      const decrypted = this.decrypt(rawEnc);
      const parsed = JSON.parse(decrypted);
      if (Array.isArray(parsed)) {
        this.securityEvents = parsed.slice(-SecureStorageService.MAX_SECURITY_EVENTS);
      }
    } catch {
      this.securityEvents = [];
    }
  }

  private saveSecurityEvents(): void {
    try {
      const bounded = this.securityEvents.slice(-SecureStorageService.MAX_SECURITY_EVENTS);
      this.securityEvents = bounded;
      const encrypted = this.encrypt(JSON.stringify(bounded));
      this.writeAtomicFileSync(this.securityEventsPath, encrypted);
    } catch {
      // Best-effort local event persistence
    }
  }

  public recordSecurityEvent(
    type: SecurityLogEventType,
    severity: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL',
    summary: string,
    metadata?: Record<string, string | number | boolean>
  ): SecurityLogEntry {
    const cleanSummary = String(summary || '')
      .replace(/[\r\n\0]/g, ' ')
      .slice(0, SecureStorageService.MAX_SUMMARY_LENGTH);

    let cleanMeta: Record<string, string | number | boolean> | undefined;
    if (metadata && typeof metadata === 'object') {
      cleanMeta = {};
      const keys = Object.keys(metadata).slice(0, 16);
      for (const k of keys) {
        const val = metadata[k];
        if (typeof val === 'boolean' || (typeof val === 'number' && Number.isFinite(val))) {
          cleanMeta[k] = val;
        } else if (typeof val === 'string') {
          cleanMeta[k] = val
            .replace(/[\r\n\0]/g, ' ')
            .slice(0, SecureStorageService.MAX_METADATA_VALUE_LENGTH);
        }
      }
    }

    const entry: SecurityLogEntry = {
      eventId: `evt-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      timestamp: Date.now(),
      type,
      severity,
      summary: cleanSummary,
      ...(cleanMeta ? { metadata: cleanMeta } : {})
    };

    this.securityEvents.push(entry);
    if (this.securityEvents.length > SecureStorageService.MAX_SECURITY_EVENTS) {
      this.securityEvents = this.securityEvents.slice(-SecureStorageService.MAX_SECURITY_EVENTS);
    }
    this.saveSecurityEvents();
    return entry;
  }

  public getSecurityEvents(): SecurityLogEntry[] {
    return this.securityEvents.map((e) => ({
      ...e,
      ...(e.metadata ? { metadata: { ...e.metadata } } : {})
    }));
  }

  public clearSecurityEvents(): void {
    this.securityEvents = [];
    this.saveSecurityEvents();
  }

  /**
   * One-click Crypto-Shredder: Zeroes keys in memory and wipes all local configuration, settings, and security logs.
   */
  public purgeAllData(): void {
    this.cachedSettings = null;
    this.securityEvents = [];
    if (this.encryptionKey) {
      this.encryptionKey.fill(0);
    }
    if (fs.existsSync(this.configDir)) {
      try {
        fs.rmSync(this.configDir, { recursive: true, force: true });
      } catch {
        // continue
      }
    }
    this.initStorage();
    this.encryptionKey = this.deriveEncryptionKey();
  }
}
