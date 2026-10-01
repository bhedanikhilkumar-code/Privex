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
  public static loadPreferences(): UserPreferences {
    if (typeof window === 'undefined' || !window.localStorage) {
      return { ...DEFAULT_PREFERENCES };
    }

    try {
      const raw = window.localStorage.getItem(PREF_KEY);
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
    if (typeof window === 'undefined' || !window.localStorage) {
      return false;
    }

    try {
      window.localStorage.setItem(PREF_KEY, JSON.stringify(prefs));
      return true;
    } catch {
      return false;
    }
  }

  public static clearAllData(): void {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.removeItem(PREF_KEY);
      } catch {
        // Ignore
      }
    }
  }
}
