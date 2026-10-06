import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PersistenceMonitorService } from '../../services/persistence-monitor.service';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';

describe('PersistenceMonitorService (Event-Driven & Polling Monitoring)', () => {
  let testDir: string;
  let testStartupDir: string;

  beforeEach(() => {
    testDir = path.join(os.tmpdir(), `pp-monitor-test-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`);
    testStartupDir = path.join(testDir, 'startup');
    fs.mkdirSync(testStartupDir, { recursive: true });
  });

  afterEach(() => {
    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch {}
  });

  it('manages start, status check, and stop lifecycle cleanly', async () => {
    const auditor = new PersistenceAuditorService();
    const monitor = new PersistenceMonitorService(auditor, {
      customDirs: [testStartupDir],
      pollIntervalMs: 1000
    });

    expect(monitor.isMonitoring()).toBe(false);
    await monitor.startMonitoring();
    expect(monitor.isMonitoring()).toBe(true);

    monitor.stopMonitoring();
    expect(monitor.isMonitoring()).toBe(false);
  });

  it('detects newly added and modified persistence entries via snapshot diffing', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    InitialApp    REG_SZ    "C:\\Program Files\\App.exe"
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(null, registryReader);
    const monitor = new PersistenceMonitorService(auditor, {
      customDirs: [testStartupDir],
      enableRegistryPoll: false
    });

    await monitor.startMonitoring();

    // 1. Simulate adding a new entry to the registry
    mockRegistry['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'] += `
    NewWorm    REG_SZ    powershell.exe -enc JABkYXRh...
`;

    const events = await monitor.refreshSnapshot(false);
    expect(events.length).toBe(1);
    expect(events[0].changeType).toBe('ADDED');
    expect(events[0].item.name).toBe('NewWorm');
    expect(events[0].item.isSuspicious).toBe(true);

    monitor.stopMonitoring();
  });

  it('detects removed persistence entries via snapshot diffing', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    AppOne    REG_SZ    "C:\\Program Files\\AppOne.exe"
    AppTwo    REG_SZ    "C:\\Program Files\\AppTwo.exe"
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(null, registryReader);
    const monitor = new PersistenceMonitorService(auditor, {
      customDirs: [testStartupDir],
      enableRegistryPoll: false
    });

    await monitor.startMonitoring();

    // Simulate removing AppTwo
    mockRegistry['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'] = `
    AppOne    REG_SZ    "C:\\Program Files\\AppOne.exe"
`;

    const events = await monitor.refreshSnapshot(false);
    expect(events.length).toBe(1);
    expect(events[0].changeType).toBe('REMOVED');
    expect(events[0].item.name).toBe('AppTwo');

    monitor.stopMonitoring();
  });

  it('enforces token-bucket rate limiting (RULE-15: max 3 events per storm window)', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': ''
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(null, registryReader);
    const monitor = new PersistenceMonitorService(auditor, {
      customDirs: [testStartupDir],
      enableRegistryPoll: false
    });

    await monitor.startMonitoring();

    let emittedCount = 0;
    monitor.on('persistenceChanged', () => {
      emittedCount++;
    });

    // Add 10 rapid entries in a burst
    for (let i = 0; i < 10; i++) {
      mockRegistry['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'] += `
    Item${i}    REG_SZ    "C:\\App${i}.exe"
`;
    }

    await monitor.refreshSnapshot(false);

    // At most 3 events emitted due to token bucket rate limiter
    expect(emittedCount).toBeLessThanOrEqual(3);

    monitor.stopMonitoring();
  });
});
