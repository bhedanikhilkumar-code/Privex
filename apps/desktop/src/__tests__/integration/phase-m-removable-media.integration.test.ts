import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { IpcHandler } from '../../ipc/ipc-handler';

function createSyntheticLnk(destPath: string, relativePath: string, args: string, icon: string) {
  const header = Buffer.alloc(76);
  header.writeUInt32LE(0x0000004c, 0);
  Buffer.from([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]).copy(header, 4);
  header.writeUInt32LE(0x08 | 0x20 | 0x40, 0x14); // HasRelativePath | HasArguments | HasIconLocation

  const writeString = (str: string) => {
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16LE(str.length, 0);
    return Buffer.concat([lenBuf, Buffer.from(str, 'ascii')]);
  };

  const buf = Buffer.concat([
    header,
    writeString(relativePath),
    writeString(args),
    writeString(icon)
  ]);

  fs.writeFileSync(destPath, buf);
}

describe('Phase M Integration — Removable Media E2E Lifecycle Suite', () => {
  let tempRoot: string;
  let vaultDir: string;
  let configDir: string;
  let usbMountDir: string;
  let ipcHandler: IpcHandler;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-m-integ-'));
    vaultDir = path.join(tempRoot, 'vault');
    configDir = path.join(tempRoot, 'config');
    usbMountDir = path.join(tempRoot, 'usb_mount');

    fs.mkdirSync(vaultDir, { recursive: true });
    fs.mkdirSync(configDir, { recursive: true });
    fs.mkdirSync(usbMountDir, { recursive: true });

    ipcHandler = new IpcHandler({
      vaultDir,
      configDir
    });
  });

  afterEach(() => {
    try {
      ipcHandler.getRemovableMediaService().stopMonitoring();
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('INTEG-M-01: executes full E2E malicious USB mount -> root triage -> threat detection -> notification', async () => {
    // 1. Seed malicious USB root contents
    fs.writeFileSync(
      path.join(usbMountDir, 'autorun.inf'),
      '[autorun]\r\nopen=wscript.exe //e:vbs worm.vbs\r\naction=Open USB Drive\r\nicon=shell32.dll,4',
      'utf-8'
    );

    fs.writeFileSync(
      path.join(usbMountDir, 'worm.vbs'),
      'WScript.Echo "malicious USB worm script payload"',
      'utf-8'
    );

    createSyntheticLnk(
      path.join(usbMountDir, 'Documents.lnk'),
      'cmd.exe',
      '/c start worm.vbs',
      '%SystemRoot%\\system32\\shell32.dll,3'
    );

    // Create a mock folder 'Documents' so the shortcut worm deception pattern is matched
    fs.mkdirSync(path.join(usbMountDir, 'Documents'), { recursive: true });

    // 2. Perform Removable Media Scan via IpcHandler
    const scanResult = await ipcHandler.handleScanRemovableMedia(usbMountDir);

    expect(scanResult.threatsFound).toBeGreaterThanOrEqual(2);
    expect(scanResult.verdict).toBe('BLOCK');
    expect(scanResult.severity).toBe('critical');
    expect(scanResult.riskScore).toBeGreaterThanOrEqual(85);
    expect(scanResult.autorun?.isSuspicious).toBe(true);
    expect(scanResult.shortcutWorms.length).toBeGreaterThanOrEqual(1);

    // 3. Verify notifications dispatched
    const notifications = ipcHandler.handleGetNotifications();
    expect(notifications.length).toBeGreaterThanOrEqual(1);
    expect(notifications[0].category).toBe('SECURITY_ALERT');

    // 4. Verify security log records the event
    const events = ipcHandler.getSecurityEvents();
    const threatEvent = events.find((e) => e.type === 'THREAT_DETECTED');
    expect(threatEvent).toBeDefined();
  });

  it('INTEG-M-02: executes clean USB mount with benign files -> root triage -> 100% ALLOW verdict', async () => {
    // 1. Seed clean USB contents
    fs.writeFileSync(path.join(usbMountDir, 'family_photo.jpg'), 'fake jpg header bytes', 'utf-8');
    fs.writeFileSync(path.join(usbMountDir, 'notes.txt'), 'Meeting notes and reminders.', 'utf-8');
    fs.writeFileSync(path.join(usbMountDir, 'budget.xlsx'), 'fake xlsx bytes', 'utf-8');

    // 2. Perform scan
    const scanResult = await ipcHandler.handleScanRemovableMedia(usbMountDir);

    expect(scanResult.threatsFound).toBe(0);
    expect(scanResult.verdict).toBe('ALLOW');
    expect(scanResult.severity).toBe('safe');
    expect(scanResult.riskScore).toBe(0);
    expect(scanResult.threats.length).toBe(0);
  });
});
