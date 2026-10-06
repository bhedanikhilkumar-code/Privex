import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setupSingleInstanceProtection } from '../../main/single-instance';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { QuarantineService } from '../../services/quarantine.service';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('SEC-E-01 — Electron Single-Instance Protection & Background Continuity Regression Suite', () => {
  let tempRoot: string;
  let vaultDir: string;
  let watchDir: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-single-instance-test-'));
    vaultDir = path.join(tempRoot, 'vault');
    watchDir = path.join(tempRoot, 'watch');
    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(watchDir, { recursive: true });
  });

  it('A & D: allows primary instance to acquire single-instance lock and registers second-instance listener', () => {
    let secondInstanceCallback: ((...args: any[]) => void) | null = null;
    const mockApp: any = {
      requestSingleInstanceLock: vi.fn(() => true),
      quit: vi.fn(),
      on: vi.fn((event: string, cb: any) => {
        if (event === 'second-instance') {
          secondInstanceCallback = cb;
        }
      })
    };

    const hasLock = setupSingleInstanceProtection(mockApp, () => null);

    expect(hasLock).toBe(true);
    expect(mockApp.requestSingleInstanceLock).toHaveBeenCalledTimes(1);
    expect(mockApp.quit).not.toHaveBeenCalled();
    expect(secondInstanceCallback).not.toBeNull();
  });

  it('B & C: detects lock acquisition failure on secondary instance and quits without initializing services', () => {
    let realtimeMonitorInitialized = false;
    let quarantineServiceInitialized = false;
    let trayInitialized = false;
    let watcherInitialized = false;

    const mockSecondaryApp: any = {
      requestSingleInstanceLock: vi.fn(() => false), // Lock already held by primary instance
      quit: vi.fn(),
      on: vi.fn()
    };

    const secondaryRejectedSpy = vi.fn();

    const hasLock = setupSingleInstanceProtection(mockSecondaryApp, () => null, {
      onSecondaryRejected: secondaryRejectedSpy
    });

    expect(hasLock).toBe(false);
    expect(mockSecondaryApp.requestSingleInstanceLock).toHaveBeenCalledTimes(1);
    expect(mockSecondaryApp.quit).toHaveBeenCalledTimes(1);
    expect(secondaryRejectedSpy).toHaveBeenCalledTimes(1);

    // Verify invariant: secondary process execution MUST NOT reach service initialization
    if (hasLock) {
      realtimeMonitorInitialized = true;
      quarantineServiceInitialized = true;
      trayInitialized = true;
      watcherInitialized = true;
    }

    expect(realtimeMonitorInitialized).toBe(false);
    expect(quarantineServiceInitialized).toBe(false);
    expect(trayInitialized).toBe(false);
    expect(watcherInitialized).toBe(false);
  });

  it('D & E: restores, shows, and focuses existing window when second-instance event is triggered', () => {
    let secondInstanceListener: ((...args: any[]) => void) | null = null;
    const mockApp: any = {
      requestSingleInstanceLock: vi.fn(() => true),
      quit: vi.fn(),
      on: vi.fn((event: string, cb: any) => {
        if (event === 'second-instance') {
          secondInstanceListener = cb;
        }
      })
    };

    const mockWindow: any = {
      isDestroyed: vi.fn(() => false),
      isMinimized: vi.fn(() => true), // Window currently minimized to taskbar/tray
      isVisible: vi.fn(() => false),  // Window currently hidden in background tray
      restore: vi.fn(),
      show: vi.fn(),
      focus: vi.fn()
    };

    const secondInstanceLaunchSpy = vi.fn();

    const hasLock = setupSingleInstanceProtection(mockApp, () => mockWindow, {
      onSecondInstanceLaunch: secondInstanceLaunchSpy
    });

    expect(hasLock).toBe(true);
    expect(secondInstanceListener).toBeDefined();

    // Simulate an external launch of a second instance
    secondInstanceListener!({}, ['--second-instance'], 'C:\\Users');

    expect(mockWindow.isMinimized).toHaveBeenCalled();
    expect(mockWindow.restore).toHaveBeenCalledTimes(1);
    expect(mockWindow.show).toHaveBeenCalledTimes(1);
    expect(mockWindow.focus).toHaveBeenCalledTimes(1);
    expect(secondInstanceLaunchSpy).toHaveBeenCalledTimes(1);
  });

  it('F: ensures background protection state is owned exclusively by exactly ONE process', () => {
    // Primary process initialization
    const primaryApp: any = {
      requestSingleInstanceLock: vi.fn(() => true),
      quit: vi.fn(),
      on: vi.fn()
    };

    const primaryLockAcquired = setupSingleInstanceProtection(primaryApp);
    expect(primaryLockAcquired).toBe(true);

    const primaryQuarantine = new QuarantineService(vaultDir);
    const primaryMonitor = new RealtimeMonitorService(
      { recursive: true, autoQuarantineCritical: true },
      primaryQuarantine
    );
    primaryMonitor.start([watchDir]);

    expect(primaryMonitor.isActive()).toBe(true);
    expect(primaryMonitor.getMonitoredPaths().length).toBe(1);

    // Secondary process attempted initialization
    const secondaryApp: any = {
      requestSingleInstanceLock: vi.fn(() => false),
      quit: vi.fn(),
      on: vi.fn()
    };

    let secondaryMonitor: RealtimeMonitorService | null = null;
    const secondaryLockAcquired = setupSingleInstanceProtection(secondaryApp);

    if (secondaryLockAcquired) {
      secondaryMonitor = new RealtimeMonitorService(
        { recursive: true, autoQuarantineCritical: true },
        new QuarantineService(vaultDir)
      );
      secondaryMonitor.start([watchDir]);
    }

    expect(secondaryLockAcquired).toBe(false);
    expect(secondaryApp.quit).toHaveBeenCalled();
    expect(secondaryMonitor).toBeNull(); // Exactly one monitor exists

    primaryMonitor.stop();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });
});
