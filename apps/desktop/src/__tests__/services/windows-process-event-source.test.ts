import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import { WindowsProcessEventSource } from '../../services/windows-process-event-source';
import { ProcessCreationEvent } from '../../types/desktop.types';

describe('WindowsProcessEventSource (Phase F — SEC-F-02 Windows Native Event Subscription)', () => {
  function createMockSpawn() {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const child = new EventEmitter() as any;

    child.stdout = stdout;
    child.stderr = stderr;
    child.stdin = new PassThrough();
    child.kill = vi.fn((_sig) => {
      child.emit('exit', 0);
    });

    const spawnProvider = vi.fn(() => child);
    return { child, stdout, stderr, spawnProvider };
  }

  it('transitions to ACTIVE and resolves start() when PP_WMI_READY is emitted', async () => {
    const { stdout, spawnProvider } = createMockSpawn();
    const source = new WindowsProcessEventSource({ spawnProvider });

    const startPromise = source.start();

    // Child writes PP_WMI_READY to stdout
    stdout.write('PP_WMI_READY\n');

    await startPromise;

    expect(source.getStatus().state).toBe('ACTIVE');
    expect(source.getStatus().sourceName).toBe('WMI_TRACE');

    await source.stop();
    expect(source.getStatus().state).toBe('STOPPED');
  });

  it('normalizes inbound JSON line with numeric epoch creation timestamp from Win32_ProcessStartTrace', async () => {
    const { stdout, spawnProvider } = createMockSpawn();
    const source = new WindowsProcessEventSource({ spawnProvider });

    let capturedEvent: ProcessCreationEvent | undefined;
    const startPromise = source.start((ev) => {
      capturedEvent = ev;
    });
    stdout.write('PP_WMI_READY\n');
    await startPromise;

    const eventJson = JSON.stringify({
      pid: 4321,
      ppid: 1234,
      name: 'powershell.exe',
      path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      cmd: 'powershell.exe -ep bypass',
      creation: 1760000000000
    });

    stdout.write(eventJson + '\n');

    expect(capturedEvent).toBeDefined();
    expect(capturedEvent?.pid).toBe(4321);
    expect(capturedEvent?.ppid).toBe(1234);
    expect(capturedEvent?.processName).toBe('powershell.exe');
    expect(capturedEvent?.executablePath).toBe('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    expect(capturedEvent?.commandLine).toBe('powershell.exe -ep bypass');
    expect(capturedEvent?.creationTime).toBe(1760000000000);
    expect(capturedEvent?.eventId).toBe('evt:4321:1760000000000:powershell.exe');
    expect(source.getStatus().eventsObserved).toBe(1);

    await source.stop();
  });

  it('buffers events that arrive before consumer callback is registered and flushes in order (zero loss)', async () => {
    const { stdout, spawnProvider } = createMockSpawn();
    const source = new WindowsProcessEventSource({ spawnProvider });

    const startPromise = source.start();
    stdout.write('PP_WMI_READY\n');
    await startPromise;

    // Send events BEFORE registering onProcessCreated
    const event1 = JSON.stringify({ pid: 101, name: 'proc1.exe', creation: 1000 });
    const event2 = JSON.stringify({ pid: 102, name: 'proc2.exe', creation: 2000 });
    stdout.write(event1 + '\n');
    stdout.write(event2 + '\n');

    const received: ProcessCreationEvent[] = [];
    // Consumer callback registered afterwards
    source.onProcessCreated((ev) => {
      received.push(ev);
    });

    expect(received.length).toBe(2);
    expect(received[0].pid).toBe(101);
    expect(received[1].pid).toBe(102);

    await source.stop();
  });

  it('rejects start() and transitions to ERROR when PP_WMI_INIT_ERROR is emitted on stderr', async () => {
    const { stderr, spawnProvider } = createMockSpawn();
    const source = new WindowsProcessEventSource({ spawnProvider });

    const startPromise = source.start();
    stderr.write('PP_WMI_INIT_ERROR: Access denied (Win32_ProcessStartTrace requires Administrator privileges or Performance Log Users group membership)\n');

    await expect(startPromise).rejects.toThrow('WMI event watcher init failed');
    expect(source.getStatus().state).toBe('ERROR');
    expect(source.getStatus().lastError).toContain('Access denied');
  });

  it('safely ignores malformed JSON without crashing the watcher stream', async () => {
    const { stdout, spawnProvider } = createMockSpawn();
    const source = new WindowsProcessEventSource({ spawnProvider });

    const startPromise = source.start();
    stdout.write('PP_WMI_READY\n');
    await startPromise;

    let malformedCaught = false;
    source.on('malformedEvent', () => {
      malformedCaught = true;
    });

    // Send malformed line
    stdout.write('{ corrupt json content ...\n');

    expect(malformedCaught).toBe(true);
    expect(source.getStatus().state).toBe('ACTIVE');

    await source.stop();
  });

  it('disposes resources and kills child process cleanly on stop()', async () => {
    const { child, stdout, spawnProvider } = createMockSpawn();
    const source = new WindowsProcessEventSource({ spawnProvider });

    const startPromise = source.start();
    stdout.write('PP_WMI_READY\n');
    await startPromise;

    await source.dispose();

    expect(source.getStatus().state).toBe('STOPPED');
    expect(child.kill).toHaveBeenCalled();
  });
});
