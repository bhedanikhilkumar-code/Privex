import { ExtensionSettings, DEFAULT_SETTINGS, TabSecurityState, AuditLogEvent } from './types';

export class ExtensionStorage {
  private static memLocal: Map<string, any> = new Map();
  private static memSession: Map<string, any> = new Map();

  private static hasChromeStorage(): boolean {
    return typeof chrome !== 'undefined' && !!chrome.storage;
  }

  public static async getSettings(): Promise<ExtensionSettings> {
    if (this.hasChromeStorage() && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.get(['settings'], (res) => {
          if (chrome.runtime?.lastError || !res.settings) {
            resolve({ ...DEFAULT_SETTINGS });
          } else {
            resolve({ ...DEFAULT_SETTINGS, ...res.settings });
          }
        });
      });
    }

    const localVal = this.memLocal.get('settings');
    return localVal ? { ...DEFAULT_SETTINGS, ...localVal } : { ...DEFAULT_SETTINGS };
  }

  public static async saveSettings(settings: ExtensionSettings): Promise<void> {
    if (this.hasChromeStorage() && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.set({ settings }, () => resolve());
      });
    }
    this.memLocal.set('settings', settings);
  }

  public static async getTabState(tabId: number): Promise<TabSecurityState | null> {
    const key = `tab_${tabId}`;
    if (this.hasChromeStorage() && chrome.storage.session) {
      return new Promise((resolve) => {
        chrome.storage.session.get([key], (res) => {
          resolve(res[key] || null);
        });
      });
    }

    return this.memSession.get(key) || null;
  }

  public static async setTabState(tabId: number, state: TabSecurityState): Promise<void> {
    const key = `tab_${tabId}`;
    if (this.hasChromeStorage() && chrome.storage.session) {
      return new Promise((resolve) => {
        chrome.storage.session.set({ [key]: state }, () => resolve());
      });
    }

    this.memSession.set(key, state);
  }

  public static async clearTabState(tabId: number): Promise<void> {
    const key = `tab_${tabId}`;
    if (this.hasChromeStorage() && chrome.storage.session) {
      return new Promise((resolve) => {
        chrome.storage.session.remove([key], () => resolve());
      });
    }

    this.memSession.delete(key);
  }

  public static async addAuditLog(event: AuditLogEvent): Promise<void> {
    const logs = await this.getAuditLogs();
    // Maintain maximum 100 entries locally with FIFO pruning
    const updated = [event, ...logs].slice(0, 100);

    if (this.hasChromeStorage() && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.set({ auditLogs: updated }, () => resolve());
      });
    }

    this.memLocal.set('auditLogs', updated);
  }

  public static async getAuditLogs(): Promise<AuditLogEvent[]> {
    if (this.hasChromeStorage() && chrome.storage.local) {
      return new Promise((resolve) => {
        chrome.storage.local.get(['auditLogs'], (res) => {
          resolve(res.auditLogs || []);
        });
      });
    }

    return this.memLocal.get('auditLogs') || [];
  }

  public static async clearAllStorage(): Promise<void> {
    if (this.hasChromeStorage()) {
      if (chrome.storage.local) {
        await new Promise<void>((resolve) => chrome.storage.local.clear(() => resolve()));
      }
      if (chrome.storage.session) {
        await new Promise<void>((resolve) => chrome.storage.session.clear(() => resolve()));
      }
    }
    this.memLocal.clear();
    this.memSession.clear();
  }
}
