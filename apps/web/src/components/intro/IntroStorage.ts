import { INTRO_CONFIG } from './introConfig';

/**
 * INTRO STORAGE CONTROLLER
 *
 * Persistently manages the one-time intro playback flag (`privexIntroSeen`).
 *
 * Rules:
 * - Returns true if previously seen or if storage is blocked/restricted.
 * - Saves flag immediately upon intro completion or skip.
 * - Handles private browsing / blocked storage gracefully without throwing.
 */
export class IntroStorage {
  public static hasSeenIntro(): boolean {
    if (typeof window === 'undefined') {
      return true;
    }

    try {
      if (!window.localStorage) {
        return true;
      }
      return window.localStorage.getItem(INTRO_CONFIG.storageKey) === 'true';
    } catch {
      // In restricted sandboxes or disabled cookies, fail safe:
      // Do NOT repeatedly force the intro on the user.
      return true;
    }
  }

  public static markIntroSeen(): void {
    if (typeof window === 'undefined') {
      return;
    }

    try {
      if (window.localStorage) {
        window.localStorage.setItem(INTRO_CONFIG.storageKey, 'true');
      }
    } catch {
      // Ignore storage write errors gracefully
    }
  }

  public static resetIntro(): void {
    if (typeof window === 'undefined') {
      return;
    }

    try {
      if (window.localStorage) {
        window.localStorage.removeItem(INTRO_CONFIG.storageKey);
      }
    } catch {
      // Ignore
    }
  }
}
