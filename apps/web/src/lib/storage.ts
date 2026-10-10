import { UserPreferences } from '../scanner/types';

/**
 * CLIENT PREFERENCE STORAGE
 *
 * CONSTITUTIONAL PRIVACY MANDATE:
 * Never stores raw scan inputs (messages, URLs, files, credentials, or scan outputs).
 * Strictly manages only non-sensitive client configuration parameters.
 */

const PREF_KEY = 'private_protection_preferences_v1';

const DEFAULT_PREFERENCES: UserPreferences = {
  cognitiveReadingGrade: 6,
  enableWorkerOffloading: true,
  allowlistDomains: []
};

export class PreferenceStorage {
  private static getStorage(): Storage | null {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
    if (typeof localStorage !== 'undefined') {
      return localStorage;
    }
    return null;
  }

  public static loadPreferences(): UserPreferences {
    const storage = this.getStorage();
    if (!storage) {
      return { ...DEFAULT_PREFERENCES };
    }

    try {
      const raw = storage.getItem(PREF_KEY);
      if (!raw) return { ...DEFAULT_PREFERENCES };
      const parsed = JSON.parse(raw);
      return {
        cognitiveReadingGrade: parsed.cognitiveReadingGrade === 8 ? 8 : 6,
        enableWorkerOffloading: parsed.enableWorkerOffloading !== false,
        allowlistDomains: Array.isArray(parsed.allowlistDomains) ? parsed.allowlistDomains : []
      };
    } catch {
      return { ...DEFAULT_PREFERENCES };
    }
  }

  public static savePreferences(prefs: UserPreferences): boolean {
    const storage = this.getStorage();
    if (!storage) {
      return false;
    }

    try {
      storage.setItem(PREF_KEY, JSON.stringify(prefs));
      return true;
    } catch {
      return false;
    }
  }

  public static clearAllData(): void {
    const storage = this.getStorage();
    if (storage) {
      try {
        storage.removeItem(PREF_KEY);
      } catch {
        // Ignore
      }
    }
  }
}
