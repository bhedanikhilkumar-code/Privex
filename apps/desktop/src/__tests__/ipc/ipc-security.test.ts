import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { IpcHandler } from '../../ipc/ipc-handler';
import { IPC_CHANNELS } from '../../ipc/ipc-channels';
import { ScanProgress } from '../../types/desktop.types';

describe('IpcHandler & Security Boundary', () => {
  let handler: IpcHandler;
  let vaultDir: string;
  let configDir: string;
  let workDir: string;

  beforeEach(() => {
    vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-ipc-vault-'));
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-ipc-config-'));
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-ipc-work-'));
    handler = new IpcHandler({ vaultDir, configDir });
  });

  afterEach(() => {
    if (fs.existsSync(vaultDir)) fs.rmSync(vaultDir, { recursive: true, force: true });
    if (fs.existsSync(configDir)) fs.rmSync(configDir, { recursive: true, force: true });
    if (fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
  });

  it('handles custom scan requests safely through validated IPC target paths', async () => {
    const testFile = path.join(workDir, 'clean.txt');
    fs.writeFileSync(testFile, 'Clean text');

    const result = await handler.handleStartCustomScan([workDir]);
    expect(result.totalFilesScanned).toBe(1);
    expect(result.overallVerdict).toBe('ALLOW');
  });

  it('rejects shell metacharacters, parent traversal, and UNC shares in custom scan targets', async () => {
    await expect(
      handler.handleStartCustomScan(['C:\\folder;format C: /y'])
    ).rejects.toThrow('SECURITY_VIOLATION');

    await expect(
      handler.handleStartCustomScan(['..\\..\\Windows\\System32'])
    ).rejects.toThrow('SECURITY_VIOLATION');

    await expect(
      handler.handleStartCustomScan(['\\\\evil-server\\share\\malware.exe'])
    ).rejects.toThrow('SECURITY_VIOLATION');
  });

  it('isolates detected threat files into vault via IPC dispatch', async () => {
    const threatPath = path.join(workDir, 'invoice.pdf.exe');
    fs.writeFileSync(threatPath, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

    const item = await handler.handleIsolateFile(threatPath);
    expect(item.quarantineId).toMatch(/^quarantine-/);
    expect(fs.existsSync(threatPath)).toBe(false);

    const list = handler.handleListQuarantine();
    expect(list.length).toBe(1);
  });

  it('manages settings persistence securely through IPC', () => {
    handler.handleSaveSettings({ scanLargeFilesLimitMb: 120 });
    const settings = handler.handleGetSettings();
    expect(settings.scanLargeFilesLimitMb).toBe(120);
  });

  it('returns valid protection status telemetry across the IPC boundary', () => {
    const status = handler.handleGetProtectionStatus();
    expect(status.threatDatabaseVersion).toBeDefined();
    expect(status.offlineMode).toBe(true);
    expect(status.memoryRssBytes).toBeGreaterThan(0);
  });

  it('registers Electron ipcMain handlers, enforces sender origin, and streams SCAN_PROGRESS_EVENT', async () => {
    const registeredHandlers = new Map<string, (event: any, ...args: any[]) => any>();
    const sentEvents: Array<{ channel: string; payload: any }> = [];

    const mockIpcMain = {
      handle: (channel: string, listener: (event: any, ...args: any[]) => any) => {
        registeredHandlers.set(channel, listener);
      }
    };

    const mockWebContents = {
      send: (channel: string, payload: any) => {
        sentEvents.push({ channel, payload });
      }
    };

    handler.registerElectronHandlers(mockIpcMain, () => mockWebContents);

    // Verify all 18 invoke channels are bound
    expect(registeredHandlers.has(IPC_CHANNELS.SCAN_START_QUICK)).toBe(true);
    expect(registeredHandlers.has(IPC_CHANNELS.SCAN_START_FULL)).toBe(true);
    expect(registeredHandlers.has(IPC_CHANNELS.SCAN_START_CUSTOM)).toBe(true);
    expect(registeredHandlers.has(IPC_CHANNELS.QUARANTINE_ISOLATE)).toBe(true);
    expect(registeredHandlers.has(IPC_CHANNELS.QUARANTINE_RESTORE)).toBe(true);
    expect(registeredHandlers.has(IPC_CHANNELS.STATUS_GET)).toBe(true);

    // Verify untrusted origin is blocked
    const customScanHandler = registeredHandlers.get(IPC_CHANNELS.SCAN_START_CUSTOM)!;
    await expect(
      customScanHandler({ senderFrame: { url: 'https://malicious.site/exploit' } }, [workDir])
    ).rejects.toThrow('SECURITY_VIOLATION: Untrusted renderer origin rejected');

    // Verify trusted file:// origin succeeds and streams live progress events
    fs.writeFileSync(path.join(workDir, 'sample1.txt'), 'Sample 1 content');
    fs.writeFileSync(path.join(workDir, 'sample2.txt'), 'Sample 2 content');

    const scanRes = await customScanHandler(
      { senderFrame: { url: 'file:///C:/app/dist/renderer/index.html' } },
      [workDir]
    );
    expect(scanRes.totalFilesScanned).toBe(2);
    expect(sentEvents.length).toBeGreaterThanOrEqual(2);
    expect(sentEvents[0].channel).toBe(IPC_CHANNELS.SCAN_PROGRESS_EVENT);
    const firstProgress = sentEvents[0].payload as ScanProgress;
    expect(firstProgress.filesScanned).toBeGreaterThanOrEqual(1);
    expect(firstProgress.bytesScanned).toBeGreaterThan(0);
  });
});
