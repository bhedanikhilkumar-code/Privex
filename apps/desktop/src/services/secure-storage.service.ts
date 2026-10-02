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
    // Derive machine-specific key for AES-256-GCM encryption
    this.encryptionKey = crypto.createHash('sha256').update(os.hostname() + os.userInfo().username).digest();
    this.initStorage();
  }

  private initStorage(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true });
    }
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

  public getSettings(): DesktopSettings {
    if (!fs.existsSync(this.settingsPath)) {
      return { ...SecureStorageService.DEFAULT_SETTINGS };
    }

    try {
      const rawEnc = fs.readFileSync(this.settingsPath, 'utf8');
      const decrypted = this.decrypt(rawEnc);
      return { ...SecureStorageService.DEFAULT_SETTINGS, ...JSON.parse(decrypted) };
    } catch {
      return { ...SecureStorageService.DEFAULT_SETTINGS };
    }
  }

  public saveSettings(settings: Partial<DesktopSettings>): void {
    const current = this.getSettings();
    const updated = { ...current, ...settings };
    const encrypted = this.encrypt(JSON.stringify(updated));
    fs.writeFileSync(this.settingsPath, encrypted, 'utf8');
  }

  /**
   * One-click Crypto-Shredder: Wipes all local configuration, settings, and metadata.
   */
  public purgeAllData(): void {
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
