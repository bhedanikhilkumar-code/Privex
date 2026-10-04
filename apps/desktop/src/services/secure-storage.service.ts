import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { DesktopSettings } from '../types/desktop.types';

export class SecureStorageService {
  private configDir: string;
  private settingsPath: string;
  private encryptionKey: Buffer;

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
    this.configDir = customConfigDir || path.join(os.homedir(), '.private-protection');
    this.settingsPath = path.join(this.configDir, 'settings.enc');
    this.initStorage();
    this.encryptionKey = this.deriveEncryptionKey();
  }

  private initStorage(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Derives an authenticated AES-256-GCM encryption key using machine-specific identity
   * combined with a persistent cryptographically random salt and 100,000 PBKDF2 iterations.
   */
  private deriveEncryptionKey(): Buffer {
    const saltPath = path.join(this.configDir, '.storage.salt');
    let salt: Buffer;

    if (fs.existsSync(saltPath)) {
      try {
        salt = fs.readFileSync(saltPath);
      } catch {
        salt = crypto.randomBytes(32);
        fs.writeFileSync(saltPath, salt, { mode: 0o600 });
      }
    } else {
      salt = crypto.randomBytes(32);
      fs.writeFileSync(saltPath, salt, { mode: 0o600 });
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
    const iv = Buffer.from(parsed.iv, 'hex');
    const authTag = Buffer.from(parsed.tag, 'hex');
    const encrypted = Buffer.from(parsed.data, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final('utf8');
  }

  private cachedSettings: DesktopSettings | null = null;

  public getSettings(): DesktopSettings {
    if (this.cachedSettings) {
      return { ...this.cachedSettings };
    }
    if (!fs.existsSync(this.settingsPath)) {
      this.cachedSettings = { ...SecureStorageService.DEFAULT_SETTINGS };
      return { ...this.cachedSettings };
    }

    try {
      const rawEnc = fs.readFileSync(this.settingsPath, 'utf8');
      const decrypted = this.decrypt(rawEnc);
      const parsed: DesktopSettings = {
        ...SecureStorageService.DEFAULT_SETTINGS,
        ...(JSON.parse(decrypted) as Partial<DesktopSettings>),
      };
      this.cachedSettings = parsed;
      return { ...parsed };
    } catch {
      const defaults: DesktopSettings = { ...SecureStorageService.DEFAULT_SETTINGS };
      this.cachedSettings = defaults;
      return { ...defaults };
    }
  }

  public saveSettings(settings: Partial<DesktopSettings>): void {
    const current = this.getSettings();
    const updated = { ...current, ...settings } as DesktopSettings;
    this.cachedSettings = updated;
    const encrypted = this.encrypt(JSON.stringify(updated));
    fs.writeFileSync(this.settingsPath, encrypted, 'utf8');
  }

  /**
   * One-click Crypto-Shredder: Wipes all local configuration, settings, and metadata.
   */
  public purgeAllData(): void {
    this.cachedSettings = null;
    if (fs.existsSync(this.configDir)) {
      try {
        fs.rmSync(this.configDir, { recursive: true, force: true });
      } catch {
        // continue
      }
    }
    this.initStorage();
  }
}
