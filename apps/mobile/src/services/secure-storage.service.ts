import { MobileSettings, DEFAULT_MOBILE_SETTINGS } from '../types/mobile.types';

export interface ScanHistoryRecord {
  scanId: string;
  targetType: 'URL' | 'TEXT' | 'FILE';
  sanitizedSummary: string; // Truncated domain prefix or generic label
  verdict: string;
  score: number;
  timestamp: number;
}

export class SecureStorageService {
  private static memoryStore: Map<string, string> = new Map();

  public static async getSettings(): Promise<MobileSettings> {
    try {
      const data = this.memoryStore.get('mobile_settings');
      if (data) {
        const parsed = JSON.parse(data);
        return {
          ...DEFAULT_MOBILE_SETTINGS,
          ...parsed,
          allowlistDomains: Array.isArray(parsed.allowlistDomains) ? [...parsed.allowlistDomains] : []
        };
      }
    } catch {
      // Fallback
    }
    return {
      ...DEFAULT_MOBILE_SETTINGS,
      allowlistDomains: []
    };
  }

  public static async saveSettings(settings: Partial<MobileSettings>): Promise<MobileSettings> {
    const current = await this.getSettings();
    const updated = {
      ...current,
      ...settings,
      allowlistDomains: settings.allowlistDomains ? [...settings.allowlistDomains] : [...current.allowlistDomains]
    };
    this.memoryStore.set('mobile_settings', JSON.stringify(updated));
    return updated;
  }

  public static async getScanHistory(): Promise<ScanHistoryRecord[]> {
    try {
      const data = this.memoryStore.get('scan_history');
      if (data) {
        return JSON.parse(data);
      }
    } catch {
      // Fallback
    }
    return [];
  }

  public static async recordScan(record: ScanHistoryRecord): Promise<void> {
    const current = await this.getScanHistory();
    // Keep at most 20 recent records in volatile memory
    const updated = [record, ...current].slice(0, 20);
    this.memoryStore.set('scan_history', JSON.stringify(updated));
  }

  public static async addAllowlistDomain(domain: string): Promise<string[]> {
    const settings = await this.getSettings();
    const clean = domain.trim().toLowerCase();
    if (!settings.allowlistDomains.includes(clean)) {
      const updatedDomains = [...settings.allowlistDomains, clean];
      await this.saveSettings({ ...settings, allowlistDomains: updatedDomains });
      return updatedDomains;
    }
    return settings.allowlistDomains;
  }

  public static async removeAllowlistDomain(domain: string): Promise<string[]> {
    const settings = await this.getSettings();
    const clean = domain.trim().toLowerCase();
    const updatedDomains = settings.allowlistDomains.filter((d) => d !== clean);
    await this.saveSettings({ ...settings, allowlistDomains: updatedDomains });
    return updatedDomains;
  }

  /**
   * Crypto-shredding: Immediately wipes all persisted and in-memory settings, history, and keys.
   */
  public static async purgeAllData(): Promise<void> {
    this.memoryStore.clear();
  }
}
