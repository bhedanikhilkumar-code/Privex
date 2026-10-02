// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawnSync } from 'child_process';
import { EventEmitter } from 'events';
import { CoreFileAnalyzer, DetectionPipeline, InputType } from '@private-protection/core';
import {
  IPC_CHANNELS,
  IPC_INVOKE_CHANNELS,
  IPC_EVENT_CHANNELS
} from '../../ipc/ipc-channels';
import { IpcHandler } from '../../ipc/ipc-handler';
import { IpcValidator } from '../../ipc/ipc-validator';
import { createDesktopSecurityApi } from '../../preload/preload';
import { App } from '../../renderer/App';
import { DesktopSettings, RealtimeThreatEvent } from '../../types/desktop.types';

describe('Phase 11 Remediation Suite (GAP-13, GAP-14, GAP-15, GAP-16, GAP-08 & Native Electron E2E)', () => {
  let tempRoot: string;
  let vaultDir: string;
  let configDir: string;
  let scanDir: string;
  let handler: IpcHandler;
  let rendererEmitter: EventEmitter;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase11-remediation-'));
    vaultDir = path.join(tempRoot, 'vault');
    configDir = path.join(tempRoot, 'config');
    scanDir = path.join(tempRoot, 'scan-fixture');
    fs.mkdirSync(scanDir, { recursive: true });

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
    handler.getRealtimeMonitor().stop();
    delete window.desktopSecurity;
    if (fs.existsSync(tempRoot)) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  // ============================================================
  // GAP-13: IPC CHANNEL SEPARATION & PRELOAD SCHEMA VALIDATION
  // ============================================================
  it('GAP-13: enforces strict separation between IPC_INVOKE_CHANNELS and IPC_EVENT_CHANNELS and validates event payloads', () => {
    expect(IPC_CHANNELS.REALTIME_THREAT_EVENT).toBe('desktop:realtime:threat-event');
    expect(IPC_EVENT_CHANNELS).toContain(IPC_CHANNELS.SCAN_PROGRESS_EVENT);
    expect(IPC_EVENT_CHANNELS).toContain(IPC_CHANNELS.REALTIME_THREAT_EVENT);

    // Event push channels must never appear in IPC_INVOKE_CHANNELS
    for (const eventChannel of IPC_EVENT_CHANNELS) {
      expect(IPC_INVOKE_CHANNELS).not.toContain(eventChannel);
    }

    // Verify preload ignores malformed event payloads
    const validEvents: RealtimeThreatEvent[] = [];
    const unsubscribe = window.desktopSecurity!.onRealtimeThreat((evt) => {
      validEvents.push(evt);
    });

    // Emit invalid/malformed payload -> must be rejected by preload schema check
    rendererEmitter.emit(IPC_CHANNELS.REALTIME_THREAT_EVENT, {}, { malformed: true });
    expect(validEvents.length).toBe(0);
    unsubscribe();
  });

  // ============================================================
  // GAP-14: REAL-TIME THREAT PIPELINE, AUTO-QUARANTINE & UI ALERT
  // ============================================================
  it('GAP-14: routes real-time threat from RealtimeMonitorService -> IpcHandler -> Preload -> UI alert banner and auto-quarantines when autoQuarantineCritical=true', async () => {
    render(React.createElement(App));

    const receivedEvents: RealtimeThreatEvent[] = [];
    const unsubscribe = window.desktopSecurity!.onRealtimeThreat((evt) => {
      receivedEvents.push(evt);
    });

    // Enable autoQuarantineCritical
    const currentSettings = await window.desktopSecurity!.getSettings();
    await window.desktopSecurity!.saveSettings({
      ...currentSettings,
      realtimeShieldEnabled: true,
      autoQuarantineCritical: true
    });

    // Start monitoring scanDir
    handler.getRealtimeMonitor().start([scanDir]);

    // Drop a critical double-extension PE executable into watched directory
    const droppedPath = path.join(scanDir, 'invoice_urgent.pdf.exe');
    const mzPayload = Buffer.concat([
      Buffer.from('4d5a90000300000004000000ffff0000', 'hex'),
      Buffer.from('powershell.exe -EncodedCommand VirtualAlloc WriteProcessMemory', 'ascii')
    ]);
    fs.writeFileSync(droppedPath, mzPayload);

    await act(async () => {
      await handler.getRealtimeMonitor().evaluateIncomingFile(droppedPath);
    });

    await waitFor(() => {
      expect(receivedEvents.length).toBe(1);
    });

    expect(receivedEvents[0].actionTaken).toBe('AUTO_QUARANTINED');
    expect(receivedEvents[0].threat.verdict).toBe('BLOCK');
    expect(receivedEvents[0].threat.quarantined).toBe(true);
    expect(receivedEvents[0].quarantineItem).toBeDefined();
    // File must be removed from original path on disk and vaulted
    expect(fs.existsSync(droppedPath)).toBe(false);
    expect(fs.existsSync(receivedEvents[0].quarantineItem!.blobPath)).toBe(true);

    // UI Alert Banner must be rendered in App.tsx
    const alertBanner = await screen.findByTestId('realtime-threat-alert');
    expect(alertBanner).toBeDefined();
    expect(alertBanner.textContent).toContain('invoice_urgent.pdf.exe');
    expect(alertBanner.textContent).toContain('ACTION TAKEN: AUTO_QUARANTINED');

    unsubscribe();
  });

  it('GAP-14: emits ALERTED without unlinking file when autoQuarantineCritical=false', async () => {
    const receivedEvents: RealtimeThreatEvent[] = [];
    const unsubscribe = window.desktopSecurity!.onRealtimeThreat((evt) => {
      receivedEvents.push(evt);
    });

    const currentSettings = await window.desktopSecurity!.getSettings();
    await window.desktopSecurity!.saveSettings({
      ...currentSettings,
      realtimeShieldEnabled: true,
      autoQuarantineCritical: false
    });

    handler.getRealtimeMonitor().start([scanDir]);

    const droppedPath = path.join(scanDir, 'unquarantined_dropper.pdf.exe');
    const mzPayload = Buffer.concat([
      Buffer.from('4d5a90000300000004000000ffff0000', 'hex'),
      Buffer.from('CreateRemoteThread VirtualAllocEx', 'ascii')
    ]);
    fs.writeFileSync(droppedPath, mzPayload);

    await handler.getRealtimeMonitor().evaluateIncomingFile(droppedPath);

    await waitFor(() => {
      expect(receivedEvents.length).toBe(1);
    });

    expect(receivedEvents[0].actionTaken).toBe('ALERTED');
    expect(receivedEvents[0].threat.quarantined).toBe(false);
    // Original file remains on disk until user clicks Quarantine
    expect(fs.existsSync(droppedPath)).toBe(true);
    unsubscribe();
  });

  // ============================================================
  // GAP-15: SETTINGS VALIDATION, PERSISTENCE & RUNTIME ENFORCEMENT
  // ============================================================
  it('GAP-15: enforces scanLargeFilesLimitMb, entropyDetectionEnabled, excludedPaths, monitorDownloads/monitorTemp, and persists settings across restart', async () => {
    // 1. Create a high-entropy 8KB packed executable (packed_tool.exe: score 25 INFORM when entropyDetectionEnabled=false, score 55 WARN when entropyDetectionEnabled=true)
    const highEntropyPath = path.join(scanDir, 'packed_tool.exe');
    const randomBytes = Buffer.alloc(8192);
    for (let i = 0; i < 8192; i++) {
      randomBytes[i] = i & 0xff;
    }
    randomBytes[0] = 0x4d; // 'M'
    randomBytes[1] = 0x5a; // 'Z'
    fs.writeFileSync(highEntropyPath, randomBytes);

    // 2. Create a 2MB file to test scanLargeFilesLimitMb=1
    const largeFilePath = path.join(scanDir, 'large_archive.dat');
    fs.writeFileSync(largeFilePath, Buffer.alloc(2 * 1024 * 1024, 0x41));

    // 3. Create an excluded subdirectory with a malicious executable
    const excludedSubdir = path.join(scanDir, 'excluded-folder');
    fs.mkdirSync(excludedSubdir, { recursive: true });
    const excludedMalwarePath = path.join(excludedSubdir, 'ignored.pdf.exe');
    fs.writeFileSync(excludedMalwarePath, Buffer.from('4d5a900003000000', 'hex'));

    // Save settings: disable entropy detection, set max file size to 1MB, exclude `excludedSubdir`, disable realtime shield
    const customSettings: DesktopSettings = {
      realtimeShieldEnabled: false,
      monitorDownloads: false,
      monitorTemp: false,
      scanLargeFilesLimitMb: 1,
      entropyDetectionEnabled: false,
      autoQuarantineCritical: false,
      frictionGateEnabled: true,
      cognitiveLevel: 'grade6',
      excludedPaths: [excludedSubdir]
    };

    await window.desktopSecurity!.saveSettings(customSettings);
    const saved = await window.desktopSecurity!.getSettings();
    expect(saved.entropyDetectionEnabled).toBe(false);
    expect(saved.scanLargeFilesLimitMb).toBe(1);
    expect(handler.getRealtimeMonitor().isActive()).toBe(false);
    expect(handler.getRealtimeMonitor().getMonitoredPaths().length).toBe(0);

    // Scan with entropyDetectionEnabled=false, limit=1MB, excludedPaths=[excludedSubdir]
    const scan1 = await window.desktopSecurity!.startCustomScan([scanDir]);
    // Neither the excluded malware nor the high-entropy packed executable should be flagged, and the 2MB file should be skipped
    expect(scan1.threats.length).toBe(0);
    expect(scan1.skippedFiles.length).toBeGreaterThanOrEqual(1);

    // Now enable entropyDetectionEnabled=true and clear excludedPaths
    await window.desktopSecurity!.saveSettings({
      ...customSettings,
      entropyDetectionEnabled: true,
      excludedPaths: []
    });

    const scan2 = await window.desktopSecurity!.startCustomScan([scanDir]);
    const threatNames = scan2.threats.map((t) => t.fileName);
    expect(threatNames).toContain('packed_tool.exe');
    expect(threatNames).toContain('ignored.pdf.exe');

    // Verify persistence across service restart by instantiating a fresh IpcHandler on the same configDir
    const restartedHandler = new IpcHandler({ vaultDir, configDir });
    const persisted = restartedHandler.handleGetSettings();
    expect(persisted.entropyDetectionEnabled).toBe(true);
    expect(persisted.scanLargeFilesLimitMb).toBe(1);
    expect(persisted.cognitiveLevel).toBe('grade6');
    restartedHandler.getRealtimeMonitor().stop();
  });

  // ============================================================
  // GAP-16: BENIGN FILE QUARANTINE SAFETY & SYSTEM PATH DEFENSE
  // ============================================================
  it('GAP-16: refuses to quarantine benign ALLOW files and preserves them untouched on disk', async () => {
    const benignPath = path.join(scanDir, 'important_notes.txt');
    const benignContent = 'Quarterly financial summary — completely safe plain text.\n';
    fs.writeFileSync(benignPath, benignContent);

    await expect(window.desktopSecurity!.isolateFile(benignPath)).rejects.toThrow(
      /QUARANTINE_POLICY_REJECTED/
    );

    // Benign file MUST still exist on disk with identical content and zero vault entries
    expect(fs.existsSync(benignPath)).toBe(true);
    expect(fs.readFileSync(benignPath, 'utf-8')).toBe(benignContent);
    expect((await window.desktopSecurity!.listQuarantine()).length).toBe(0);
  });

  it('GAP-16: refuses to quarantine low/INFORM files (e.g. standard signed-like PE without high risk) and blocks protected OS paths and missing files', async () => {
    // 1. Standard single-extension .exe with low entropy (riskScore=25, severity='low', verdict='INFORM')
    const normalExePath = path.join(scanDir, 'standard_app.exe');
    fs.writeFileSync(
      normalExePath,
      Buffer.concat([Buffer.from('4d5a9000', 'hex'), Buffer.alloc(256, 0x20)])
    );

    await expect(window.desktopSecurity!.isolateFile(normalExePath)).rejects.toThrow(
      /QUARANTINE_POLICY_REJECTED/
    );
    expect(fs.existsSync(normalExePath)).toBe(true);

    // 2. Missing file -> FILE_NOT_FOUND
    await expect(
      window.desktopSecurity!.isolateFile(path.join(scanDir, 'nonexistent.exe'))
    ).rejects.toThrow(/FILE_NOT_FOUND/);

    // 3. Path traversal -> SECURITY_VIOLATION
    await expect(
      window.desktopSecurity!.isolateFile('..\\..\\Windows\\System32\\cmd.exe')
    ).rejects.toThrow(/SECURITY_VIOLATION/);

    // 4. Protected OS System Path check
    expect(IpcValidator.isProtectedSystemPath('C:\\Windows\\System32\\cmd.exe')).toBe(true);
    expect(IpcValidator.isProtectedSystemPath('C:\\Program Files\\App\\app.exe')).toBe(true);
    expect(IpcValidator.isProtectedSystemPath('/etc/passwd')).toBe(true);
  });

  // ============================================================
  // GAP-08: CANONICAL CORE FILE ANALYSIS CONSISTENCY
  // ============================================================
  it('GAP-08: produces consistent canonical security verdicts across CoreFileAnalyzer, DetectionPipeline, and Desktop', async () => {
    const pipeline = new DetectionPipeline();

    const sampleName = 'tax_return_2026.pdf.exe';
    const sampleBytes = new Uint8Array(
      Buffer.concat([
        Buffer.from('4d5a90000300000004000000ffff0000', 'hex'),
        Buffer.from('powershell.exe -EncodedCommand VirtualAlloc', 'ascii')
      ])
    );

    const coreDirect = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: sampleName,
        fileSize: sampleBytes.byteLength,
        headerBytes: sampleBytes
      },
      { platformProfile: 'desktop' }
    );
    const pipelineRes = pipeline.scanFile(
      {
        fileName: sampleName,
        fileSize: sampleBytes.byteLength,
        headerBytes: sampleBytes
      },
      { platformProfile: 'desktop' }
    );
    const scanDispatchRes = await pipeline.scan({
      inputType: InputType.FILE,
      payload: sampleBytes,
      metadata: {
        fileName: sampleName,
        fileSize: String(sampleBytes.byteLength)
      }
    });

    expect(coreDirect.desktopVerdict).toBe('BLOCK');
    expect(coreDirect.isExecutable).toBe(true);
    expect(coreDirect.isDeceptiveExtension).toBe(true);
    expect(pipelineRes.verdict).toBe('DANGEROUS');
    expect(scanDispatchRes.verdict).toBe('DANGEROUS');
    expect(pipelineRes.riskScore).toBe(coreDirect.riskScore);
  });

  // ============================================================
  // REAL ELECTRON NATIVE RUNTIME E2E VERIFICATION (--headless-verify)
  // ============================================================
  it(
    'executes the real Electron binary in --headless-verify mode and verifies all Phase 11 Remediation invariants',
    () => {
      const electronBinary = require('electron') as string;
      const mainBundle = path.resolve(__dirname, '../../../dist/main/electron-main.cjs');
      expect(fs.existsSync(mainBundle)).toBe(true);

      const proc = spawnSync(electronBinary, [mainBundle, '--headless-verify'], {
        encoding: 'utf-8',
        timeout: 45000
      });

      const combinedOutput = `${proc.stdout || ''}\n${proc.stderr || ''}`;
      const match = combinedOutput.match(/\[ELECTRON_E2E_PROOF\]\s*(\{.*\})/);
      expect(match).not.toBeNull();

      const proof = JSON.parse(match![1]);
      expect(proof.bridgeAvailable).toBe(true);
      expect(proof.nodeIntegrationDisabled).toBe(true);
      expect(proof.benignQuarantineRejected).toBe(true);
      expect(proof.safeFilePreservedOnDisk).toBe(true);
      expect(proof.restoredFileVerifiedOnDisk).toBe(true);
      expect(proof.realtimeEventsCount).toBeGreaterThanOrEqual(1);
      expect(proof.firstRealtimeEvent.actionTaken).toBe('AUTO_QUARANTINED');
      expect(proof.droppedThreatAutoQuarantinedFromDisk).toBe(true);
      expect(proof.alertBannerRendered).toBe(true);
    },
    60000
  );
});
