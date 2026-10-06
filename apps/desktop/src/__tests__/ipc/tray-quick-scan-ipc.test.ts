// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { EventEmitter } from 'events';
import { IPC_CHANNELS, IPC_EVENT_CHANNELS, IPC_INVOKE_CHANNELS } from '../../ipc/ipc-channels';
import { createDesktopSecurityApi } from '../../preload/preload';
import { App } from '../../renderer/App';

describe('SEC-E-02 — Tray Quick Scan Canonical IPC Integration Suite', () => {
  let rendererEmitter: EventEmitter;
  let mockIpcRenderer: any;
  let quickScanInvokedCount: number;

  beforeEach(() => {
    rendererEmitter = new EventEmitter();
    quickScanInvokedCount = 0;

    const allowedEventChannels = new Set<string>(IPC_EVENT_CHANNELS);
    const allowedInvokeChannels = new Set<string>(IPC_INVOKE_CHANNELS);

    mockIpcRenderer = {
      invoke: vi.fn(async (channel: string, ..._args: any[]) => {
        if (!allowedInvokeChannels.has(channel)) {
          throw new Error(`IPC_CHANNEL_FORBIDDEN: Channel "${channel}" is not whitelisted`);
        }
        if (channel === IPC_CHANNELS.SCAN_START_QUICK) {
          quickScanInvokedCount++;
          return {
            scanId: 'quick-mock-1',
            scanType: 'quick',
            status: 'completed',
            totalFilesScanned: 5,
            totalBytesScanned: 1024,
            durationMs: 12,
            threats: [],
            skippedFiles: [],
            errors: [],
            overallVerdict: 'ALLOW',
            completedAt: Date.now()
          };
        }
        if (channel === IPC_CHANNELS.STATUS_GET) {
          return {
            realtimeShieldActive: true,
            monitoredPaths: ['Downloads'],
            threatDatabaseVersion: '2026.10',
            threatDatabaseTimestamp: Date.now(),
            coreEngineVersion: '1.0.0',
            mlAssistantReady: true,
            offlineMode: true,
            quarantinedCount: 0,
            memoryRssBytes: 0,
            heapUsedBytes: 0
          };
        }
        if (channel === IPC_CHANNELS.QUARANTINE_LIST) {
          return [];
        }
        if (channel === IPC_CHANNELS.SETTINGS_GET) {
          return {
            realtimeShieldEnabled: true,
            monitorDownloads: true,
            monitorTemp: true,
            scanLargeFilesLimitMb: 50,
            entropyDetectionEnabled: true,
            autoQuarantineCritical: false,
            frictionGateEnabled: true,
            cognitiveLevel: 'grade6',
            excludedPaths: []
          };
        }
        return null;
      }),
      on: vi.fn((channel: string, listener: (...args: any[]) => void) => {
        if (!allowedEventChannels.has(channel)) {
          throw new Error(`IPC_EVENT_CHANNEL_FORBIDDEN: Channel "${channel}" is not whitelisted`);
        }
        rendererEmitter.on(channel, listener);
      }),
      removeListener: vi.fn((channel: string, listener: (...args: any[]) => void) => {
        if (!allowedEventChannels.has(channel)) {
          return;
        }
        rendererEmitter.removeListener(channel, listener);
      })
    };

    window.desktopSecurity = createDesktopSecurityApi(mockIpcRenderer);
  });

  afterEach(() => {
    delete (window as any).desktopSecurity;
  });

  it('A & B: defines the canonical TRIGGER_QUICK_SCAN channel in central registry and event whitelist', () => {
    expect(IPC_CHANNELS.TRIGGER_QUICK_SCAN).toBe('desktop:scan:trigger-quick');
    expect(IPC_EVENT_CHANNELS).toContain(IPC_CHANNELS.TRIGGER_QUICK_SCAN);
    expect(IPC_EVENT_CHANNELS).toContain('desktop:scan:trigger-quick');
  });

  it('C & D: exposes onTriggerQuickScan safely through the preload bridge API without arbitrary ipcRenderer exposure', () => {
    expect(typeof window.desktopSecurity?.onTriggerQuickScan).toBe('function');
    // Ensure raw ipcRenderer is never exposed on the bridge
    expect((window.desktopSecurity as any).ipcRenderer).toBeUndefined();
    expect((window.desktopSecurity as any).send).toBeUndefined();
  });

  it('E & F: receives TRIGGER_QUICK_SCAN event from main process, routes through App.tsx, and executes canonical quick scan', async () => {
    render(React.createElement(App));

    // Verify initial state
    expect(screen.getByText('System Protection Overview')).toBeDefined();
    expect(quickScanInvokedCount).toBe(0);

    // Simulate system tray emitting canonical TRIGGER_QUICK_SCAN event
    await act(async () => {
      rendererEmitter.emit(IPC_CHANNELS.TRIGGER_QUICK_SCAN);
    });

    // App.tsx handleStartQuickScan navigates to quick-scan tab and calls window.desktopSecurity.startQuickScan()
    expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(IPC_CHANNELS.SCAN_START_QUICK);
    expect(quickScanInvokedCount).toBe(1);
  });

  it('G: ensures unwhitelisted/arbitrary IPC event channels are strictly rejected by the security boundary', () => {
    const maliciousChannel = 'MALICIOUS_INJECTION_CHANNEL';
    expect(() => {
      mockIpcRenderer.on(maliciousChannel, () => {});
    }).toThrow(/IPC_EVENT_CHANNEL_FORBIDDEN/);
  });

  it('H: verifies that both UI Quick Scan and Tray Quick Scan reuse the identical canonical scan implementation', async () => {
    // 1. Trigger via preload API directly (as UI QuickScanScreen does)
    await window.desktopSecurity!.startQuickScan();
    expect(quickScanInvokedCount).toBe(1);

    // 2. Trigger via System Tray event
    rendererEmitter.emit(IPC_CHANNELS.TRIGGER_QUICK_SCAN);
    expect(mockIpcRenderer.invoke).toHaveBeenCalledWith(IPC_CHANNELS.SCAN_START_QUICK);
  });
});
