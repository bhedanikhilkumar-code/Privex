import { describe, it, expect, afterEach } from 'vitest';
import * as child_process from 'child_process';
import { WindowsProcessEventSource } from '../../services/windows-process-event-source';
import { ProcessMonitorService } from '../../services/process-monitor.service';
import { ProcessCreationEvent } from '../../types/desktop.types';

/**
 * Windows Native Integration Test Suite (Phase F — SEC-F-02 Real OS Event Path)
 *
 * Requirements:
 * 1. Exercises the REAL production WindowsProcessEventSource against the OS.
 * 2. Proves behavior under both Elevated (live Win32_ProcessStartTrace capture)
 *    and Standard User (truthful Access Denied failure & degraded polling fallback).
 * 3. Never uses synthetic MockProcessEventSource.emitEvent() as proof.
 */
describe('WindowsProcessEventSource (Real Windows OS Integration Suite)', () => {
  let eventSource: WindowsProcessEventSource | undefined;
  let monitor: ProcessMonitorService | undefined;

  afterEach(async () => {
    if (eventSource) {
      await eventSource.dispose();
      eventSource = undefined;
    }
    if (monitor) {
      await monitor.stop();
      monitor = undefined;
    }
  });

  const isWindows = process.platform === 'win32';

  function isElevated(): boolean {
    if (!isWindows) return false;
    try {
      const out = child_process.execSync('whoami /groups', { encoding: 'utf-8', timeout: 5000 });
      return out.includes('S-1-16-12288') || (out.includes('S-1-5-32-544') && !out.includes('Group used for deny only'));
    } catch {
      return false;
    }
  }

  it.skipIf(!isWindows)(
    'exercises the real production event source and verifies Windows privilege & event lifecycle',
    async () => {
      const elevated = isElevated();

      if (elevated) {
        console.log('[INTEGRATION] Running in ELEVATED mode: verifying live OS Win32_ProcessStartTrace capture...');

        eventSource = new WindowsProcessEventSource();
        let capturedEvent: ProcessCreationEvent | undefined;

        // Step 1 & 2: Start real production source and register callback atomically
        await eventSource.start((ev) => {
          capturedEvent = ev;
        });

        expect(eventSource.getStatus().state).toBe('ACTIVE');
        expect(eventSource.getStatus().sourceName).toBe('WMI_TRACE');

        // Step 4 & 5: Launch a real short-lived child process (lives ~15-30ms)
        const child = child_process.spawn('cmd.exe', ['/c', 'exit 0'], {
          windowsHide: true,
          stdio: 'ignore'
        });
        const targetPid = child.pid!;
        expect(targetPid).toBeGreaterThan(0);

        // Wait for child process to exit completely
        await new Promise<void>((resolve) => {
          child.on('exit', () => resolve());
        });

        // Step 6: Wait for actual OS event from Windows kernel trace provider
        const timeoutMs = 8000;
        const startWait = Date.now();
        while (!capturedEvent && Date.now() - startWait < timeoutMs) {
          await new Promise((r) => setTimeout(r, 50));
        }

        // Step 7: Verify real event metadata received from Windows
        expect(capturedEvent).toBeDefined();
        expect(capturedEvent?.pid).toBe(targetPid);
        expect(capturedEvent?.processName.toLowerCase()).toBe('cmd.exe');
        expect(capturedEvent?.ppid).toBe(process.pid);
        expect(capturedEvent?.creationTime).toBeGreaterThan(0);
        expect(capturedEvent?.timestamp).toBeGreaterThan(0);
        expect(capturedEvent?.eventId).toContain(`evt:${targetPid}:`);

        // Step 8: Confirm event was received even though the process has already exited
        expect(child.exitCode !== null || child.killed).toBe(true);
      } else {
        console.log('[INTEGRATION] Running in STANDARD USER mode: verifying truthful access denial & graceful fallback...');

        // Step 1: Real production event source must truthfully reject when unprivileged
        eventSource = new WindowsProcessEventSource();
        await expect(eventSource.start()).rejects.toThrow(/Access denied|requires Administrator/);
        expect(eventSource.getStatus().state).toBe('ERROR');
        expect(eventSource.getStatus().lastError).toMatch(/Access denied/i);

        // Step 2: ProcessMonitorService must handle this startup failure truthfully
        monitor = new ProcessMonitorService({
          eventSource: new WindowsProcessEventSource()
        });

        await monitor.start();
        const health = monitor.getHealth();

        // Must report DEGRADED, isContinuous = false, eventSource = POLLING_FALLBACK (no false RUNNING)
        expect(health.status).toBe('DEGRADED');
        expect(health.isContinuous).toBe(false);
        expect(health.eventSource).toBe('POLLING_FALLBACK');
        expect(health.lastError).toContain('Access denied');
        expect(health.lastError).toContain('Win32_ProcessStartTrace requires Administrator privileges');
      }
    },
    60000
  );
});
