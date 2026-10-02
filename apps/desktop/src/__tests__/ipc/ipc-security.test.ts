import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { IpcHandler } from '../../ipc/ipc-handler';

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

  it('rejects shell metacharacters in custom scan targets with a security violation', async () => {
    await expect(
      handler.handleStartCustomScan(['C:\\folder;format C: /y'])
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
});
