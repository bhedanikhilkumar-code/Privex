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
  theme: 'light'
};

export class PreferenceStorage {
  public static loadPreferences(): UserPreferences {
    if (typeof window === 'undefined' || !window.localStorage) {
      return { ...DEFAULT_PREFERENCES };
    }

    try {
      const raw = window.localStorage.getItem(PREF_KEY);
      const fallbackTheme = (window.localStorage.getItem(THEME_KEY) as AppTheme) || 'light';
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
        theme: validTheme
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
      if (prefs.theme) {
        window.localStorage.setItem(THEME_KEY, prefs.theme);
      }
      return true;
    } catch {
      return false;
    }
  }

  public static loadTheme(): AppTheme {
    if (typeof window === 'undefined' || !window.localStorage) {
      return 'light';
    }
    const directTheme = window.localStorage.getItem(THEME_KEY) as AppTheme;
    if (this.isValidTheme(directTheme)) {
      return directTheme;
    }
    const prefs = this.loadPreferences();
    return prefs.theme || 'light';
  }

  public static saveTheme(theme: AppTheme): void {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    try {
      window.localStorage.setItem(THEME_KEY, theme);
      const current = this.loadPreferences();
      this.savePreferences({ ...current, theme });
    } catch {
      // Ignore
    }
  }

  public static clearAllData(): void {
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.removeItem(PREF_KEY);
        window.localStorage.removeItem(THEME_KEY);
      } catch {
        // Ignore
      }
    }
  }

  private static isValidTheme(theme: unknown): theme is AppTheme {
    return theme === 'light' || theme === 'dark' || theme === 'night';
  }
}

