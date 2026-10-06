// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import { IpcHandler } from '../../ipc/ipc-handler';
import { createDesktopSecurityApi } from '../../preload/preload';
import { App } from '../../renderer/App';
import { ScanProgress } from '../../types/desktop.types';

function sha256Buffer(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

describe('Desktop Native Runtime End-to-End Integration (GAP-04 / PP-017 / PS-05.4)', () => {
  let tempRoot: string;
  let vaultDir: string;
  let configDir: string;
  let scanDir: string;
  let handler: IpcHandler;
  let rendererEmitter: EventEmitter;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-desktop-e2e-'));
    vaultDir = path.join(tempRoot, 'vault');
    configDir = path.join(tempRoot, 'config');
    scanDir = path.join(tempRoot, 'scan-fixture');
    fs.mkdirSync(path.join(scanDir, 'nested', 'deep'), { recursive: true });

    handler = new IpcHandler({ vaultDir, configDir });
    rendererEmitter = new EventEmitter();

    const ipcMainHandlers = new Map<string, (event: any, ...args: any[]) => any>();
    const mockIpcMain = {
      handle: (channel: string, listener: (event: any, ...args: any[]) => any) => {
        ipcMainHandlers.set(channel, listener);
      }
    };
    const mockWebContents = {
      send: (channel: string, ...args: any[]) => {
        rendererEmitter.emit(channel, {}, ...args);
      }
    };

    handler.registerElectronHandlers(mockIpcMain, () => mockWebContents);

    const mockIpcRenderer = {
      invoke: async (channel: string, ...args: any[]) => {
        const fn = ipcMainHandlers.get(channel);
        if (!fn) throw new Error(`Unregistered IPC channel: ${channel}`);
        return fn({ senderFrame: { url: 'file:///C:/app/dist/renderer/index.html' } }, ...args);
      },
      on: (channel: string, listener: (...args: any[]) => void) => {
        rendererEmitter.on(channel, listener);
      },
      removeListener: (channel: string, listener: (...args: any[]) => void) => {
        rendererEmitter.removeListener(channel, listener);
      }
    };

    window.desktopSecurity = createDesktopSecurityApi(mockIpcRenderer);
  });

  afterEach(() => {
    delete window.desktopSecurity;
    if (fs.existsSync(tempRoot)) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('starts App UI with zero fake file counts (0 files analyzed initially)', () => {
    render(React.createElement(App));
    expect(screen.getByText('System Protection Overview')).toBeDefined();
    expect(screen.getByText('FILES ANALYZED')).toBeDefined();
    // Initial count must be 0, never a hardcoded fake number like 142
    expect(screen.queryByText('142')).toBeNull();
  });

  it('executes a real filesystem scan across nested folders, emits live progress, and detects threats', async () => {
    fs.writeFileSync(path.join(scanDir, 'document.txt'), 'Clean project documentation file.\n');
    fs.writeFileSync(path.join(scanDir, 'nested', 'notes.md'), '# Release Notes\nAll checks green.\n');
    fs.writeFileSync(path.join(scanDir, 'nested', 'deep', 'config.json'), '{"safe":true}');

    const suspiciousPath = path.join(scanDir, 'nested', 'urgent_tax_refund.pdf.exe');
    const mzPayload = Buffer.concat([
      Buffer.from('4d5a90000300000004000000ffff0000', 'hex'),
      Buffer.from('powershell.exe -EncodedCommand VirtualAlloc WriteProcessMemory Mimikatz', 'ascii')
    ]);
    fs.writeFileSync(suspiciousPath, mzPayload);

    const receivedProgress: ScanProgress[] = [];
    const unsubscribe = window.desktopSecurity!.onScanProgress((p) => {
      receivedProgress.push(p);
    });

    const result = await window.desktopSecurity!.startCustomScan([scanDir]);
    unsubscribe();

    expect(result.status).toBe('completed');
    expect(result.totalFilesScanned).toBe(4);
    expect(result.threats.length).toBe(1);
    expect(result.threats[0].fileName).toBe('urgent_tax_refund.pdf.exe');
    expect(result.threats[0].severity).toBe('critical');
    expect(result.threats[0].sha256).toBe(sha256Buffer(mzPayload));

    // Verify genuine live progress events were streamed during the scan
    expect(receivedProgress.length).toBe(4);
    expect(receivedProgress[3].filesScanned).toBe(4);
    expect(receivedProgress[3].bytesScanned).toBeGreaterThan(0);
    expect(receivedProgress[3].scanSpeedFilesPerSec).toBeGreaterThan(0);
  });

  it('supports real mid-scan cancellation via window.desktopSecurity.cancelScan()', async () => {
    for (let i = 0; i < 25; i++) {
      fs.writeFileSync(path.join(scanDir, `file-${i}.txt`), `Content block ${i}`);
    }

    const unsubscribe = window.desktopSecurity!.onScanProgress((p) => {
      if (p.filesScanned >= 2) {
        window.desktopSecurity!.cancelScan();
      }
    });

    const result = await window.desktopSecurity!.startFullScan(scanDir);
    unsubscribe();

    expect(result.status).toBe('cancelled');
    expect(result.totalFilesScanned).toBeLessThan(25);
  });

  it('executes full AES-256-GCM quarantine isolation, verification of PPVAULT1 header, restore, and permanent delete', async () => {
    const suspiciousPath = path.join(scanDir, 'invoice_overdue.docx.exe');
    const originalBytes = Buffer.concat([
      Buffer.from('4d5a90000300000004000000ffff0000', 'hex'),
      Buffer.from('CreateRemoteThread vssadmin delete shadows /all /quiet', 'ascii')
    ]);
    const originalHash = sha256Buffer(originalBytes);
    fs.writeFileSync(suspiciousPath, originalBytes);

    // 1. Isolate file into encrypted quarantine vault
    const qItem = await window.desktopSecurity!.isolateFile(suspiciousPath);
    expect(fs.existsSync(suspiciousPath)).toBe(false);
    expect(fs.existsSync(qItem.blobPath)).toBe(true);

    // Verify vault file is encrypted with PPVAULT2 or PPVAULT1 header and does not contain raw MZ header at byte 0
    const vaultBlob = fs.readFileSync(qItem.blobPath);
    expect(['PPVAULT1', 'PPVAULT2']).toContain(vaultBlob.subarray(0, 8).toString('ascii'));

    const listed = await window.desktopSecurity!.listQuarantine();
    expect(listed.length).toBe(1);
    expect(listed[0].quarantineId).toBe(qItem.quarantineId);

    // 2. Restore file back to original path and verify SHA-256 integrity
    const restoredPath = await window.desktopSecurity!.restoreQuarantine(qItem.quarantineId);
    expect(restoredPath).toBe(suspiciousPath);
    expect(fs.existsSync(suspiciousPath)).toBe(true);
    expect(sha256Buffer(fs.readFileSync(suspiciousPath))).toBe(originalHash);
    expect((await window.desktopSecurity!.listQuarantine()).length).toBe(0);

    // 3. Isolate again and permanently shred
    const qItem2 = await window.desktopSecurity!.isolateFile(suspiciousPath);
    await window.desktopSecurity!.deleteQuarantine(qItem2.quarantineId);
    expect(fs.existsSync(qItem2.blobPath)).toBe(false);
    expect(fs.existsSync(suspiciousPath)).toBe(false);
    expect((await window.desktopSecurity!.listQuarantine()).length).toBe(0);
  });
});
