import { UserPreferences, AppTheme } from '../scanner/types';

/**
 * CLIENT PREFERENCE STORAGE
 *
 * CONSTITUTIONAL PRIVACY MANDATE:
 * Never stores raw scan inputs (messages, URLs, files, credentials, or scan outputs).
 * Strictly manages only non-sensitive client configuration parameters.
 */

const PREF_KEY = 'private_protection_preferences_v1';
const THEME_KEY = 'privex_theme';

const DEFAULT_PREFERENCES: UserPreferences = {
  cognitiveReadingGrade: 6,
  enableWorkerOffloading: true,
  allowlistDomains: [],
  theme: 'light',
  autoContainmentEnabled: true,
  backgroundMonitoringEnabled: true
};

export class PreferenceStorage {
  private static getStorage(): Storage | null {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
    if (typeof localStorage !== 'undefined') {
      return localStorage;
    }
    if (typeof globalThis !== 'undefined' && (globalThis as any).localStorage) {
      return (globalThis as any).localStorage;
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
      const fallbackTheme = (storage.getItem(THEME_KEY) as AppTheme) || 'light';
      if (!raw) {
        return {
          ...DEFAULT_PREFERENCES,
          theme: this.isValidTheme(fallbackTheme) ? fallbackTheme : 'light'
        };
      }
      const parsed = JSON.parse(raw);
      const validTheme: AppTheme = this.isValidTheme(parsed.theme)
        ? parsed.theme
        : this.isValidTheme(fallbackTheme)
          ? fallbackTheme
          : 'light';

      return {
        cognitiveReadingGrade: parsed.cognitiveReadingGrade === 8 ? 8 : 6,
        enableWorkerOffloading: parsed.enableWorkerOffloading !== false,
        allowlistDomains: Array.isArray(parsed.allowlistDomains) ? parsed.allowlistDomains : [],
        theme: validTheme,
        autoContainmentEnabled: parsed.autoContainmentEnabled !== false,
        backgroundMonitoringEnabled: parsed.backgroundMonitoringEnabled !== false
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
      if (prefs.theme) {
        storage.setItem(THEME_KEY, prefs.theme);
      }
      return true;
    } catch {
      return false;
    }
  }

  public static loadTheme(): AppTheme {
    const storage = this.getStorage();
    if (!storage) {
      return 'light';
    }
    const directTheme = storage.getItem(THEME_KEY) as AppTheme;
    if (this.isValidTheme(directTheme)) {
      return directTheme;
    }
    const prefs = this.loadPreferences();
    return prefs.theme || 'light';
  }

  public static saveTheme(theme: AppTheme): void {
    const storage = this.getStorage();
    if (!storage) {
      return;
    }
    try {
      storage.setItem(THEME_KEY, theme);
      const current = this.loadPreferences();
      this.savePreferences({ ...current, theme });
    } catch {
      // Ignore
    }
  }

  public static clearAllData(): void {
    const storage = this.getStorage();
    if (storage) {
      try {
        storage.removeItem(PREF_KEY);
        storage.removeItem(THEME_KEY);
      } catch {
        // Ignore
      }
    }
  }

  private static isValidTheme(theme: unknown): theme is AppTheme {
    return theme === 'light' || theme === 'dark' || theme === 'night';
  }
}
