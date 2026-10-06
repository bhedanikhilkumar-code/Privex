import { app, BrowserWindow } from 'electron';

export interface SingleInstanceController {
  hasLock: boolean;
  onSecondInstance?: () => void;
}

export interface SingleInstanceCallbacks {
  onSecondInstanceLaunch?: () => void;
  onSecondaryRejected?: () => void;
}

/**
 * Enforces single-instance protection at the Electron main-process boundary.
 *
 * Guaranteed invariants:
 * 1. Exactly one primary instance can hold the lock and initialize background protection.
 * 2. Any secondary instance fails lock acquisition and quits immediately.
 * 3. Secondary instance never reaches background service, tray, or watcher initialization.
 * 4. When a secondary instance attempts to start, the primary instance restores, shows, and focuses the existing window.
 */
export function setupSingleInstanceProtection(
  electronApp: typeof app = app,
  getMainWindow: () => BrowserWindow | null = () => null,
  callbacks?: SingleInstanceCallbacks
): boolean {
  const hasLock = electronApp.requestSingleInstanceLock();

  if (!hasLock) {
    console.warn('[SINGLE_INSTANCE] Secondary instance detected. Terminating duplicate process.');
    if (callbacks?.onSecondaryRejected) {
      callbacks.onSecondaryRejected();
    }
    electronApp.quit();
    return false;
  }

  electronApp.on('second-instance', (_event, _commandLine, _workingDirectory) => {
    console.info('[SINGLE_INSTANCE] Second instance launch detected. Focusing primary window.');
    const win = getMainWindow();
    if (win && !win.isDestroyed()) {
      if (win.isMinimized()) {
        win.restore();
      }
      if (!win.isVisible()) {
        win.show();
      }
      win.focus();
    }
    if (callbacks?.onSecondInstanceLaunch) {
      callbacks.onSecondInstanceLaunch();
    }
  });

  return true;
}
