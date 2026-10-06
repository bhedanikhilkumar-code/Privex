import { EventEmitter } from 'events';
import * as child_process from 'child_process';
import * as readline from 'readline';
import {
  IProcessEventSource,
  ProcessCreationEvent,
  ProcessEventSourceStatus
} from '../types/desktop.types';

export interface WindowsProcessEventSourceOptions {
  /** Custom spawn provider (useful for unit tests or mocking) */
  readonly spawnProvider?: (command: string, args: string[]) => child_process.ChildProcess;
  /** WMI query event polling interval in seconds (default: 0.25) */
  readonly wmiPollingIntervalSec?: number;
  /** Maximum consecutive restart attempts before entering ERROR state (default: 3) */
  readonly maxRestartAttempts?: number;
}

/**
 * WindowsProcessEventSource (Phase F — SEC-F-02 Primary Event Source)
 *
 * Implements genuine, continuous Windows process-creation event subscription
 * using WMI __InstanceCreationEvent of Win32_Process.
 *
 * ARCHITECTURAL DESIGN & JUSTIFICATION:
 * 1. User-Mode Immunity: Unlike ETW kernel sessions or Win32_ProcessStartTrace which
 *    require SeSecurityPrivilege / local elevation (Access Denied for standard users),
 *    WMI __InstanceCreationEvent operates cleanly within standard user integrity.
 * 2. Event-Driven Stdio Stream: Runs as an isolated background PowerShell process streaming
 *    real-time newline-delimited JSON objects over stdout without blocking the Node event loop.
 * 3. Zero-Allocation Fast-Path: Normalizes OS events immediately into ProcessCreationEvent
 *    with deterministic instance keys: evt:${pid}:${creationTime}:${processName}.
 * 4. 100% Offline Air-Gapped: Zero network sockets, zero remote telemetry, local OS queries only.
 */
export class WindowsProcessEventSource extends EventEmitter implements IProcessEventSource {
  private readonly spawnProvider?: (command: string, args: string[]) => child_process.ChildProcess;
  private readonly wmiPollingIntervalSec: number;
  private readonly maxRestartAttempts: number;

  private state: 'INITIALIZING' | 'ACTIVE' | 'ERROR' | 'STOPPED' = 'STOPPED';
  private lastError?: string;
  private eventsObserved = 0;
  private consecutiveRestarts = 0;
  private isExplicitlyStopped = true;

  private childProcess?: child_process.ChildProcess;
  private readlineInterface?: readline.Interface;
  private processCreatedCallback?: (event: ProcessCreationEvent) => void;
  private stableRunTimer?: NodeJS.Timeout;

  constructor(options?: WindowsProcessEventSourceOptions) {
    super();
    this.spawnProvider = options?.spawnProvider;
    this.wmiPollingIntervalSec = options?.wmiPollingIntervalSec ?? 0.25;
    this.maxRestartAttempts = options?.maxRestartAttempts ?? 3;
  }

  public getStatus(): ProcessEventSourceStatus {
    return {
      state: this.state,
      sourceName: 'WMI_EVENT_SUBSCRIPTION',
      lastError: this.lastError,
      eventsObserved: this.eventsObserved
    };
  }

  public onProcessCreated(callback: (event: ProcessCreationEvent) => void): void {
    this.processCreatedCallback = callback;
  }

  /**
   * Starts the Windows process creation event subscription.
   * Resolves only after the background worker emits confirmation of active subscription.
   */
  public async start(): Promise<void> {
    if (this.state === 'ACTIVE') return;

    this.isExplicitlyStopped = false;
    this.state = 'INITIALIZING';
    this.lastError = undefined;

    return new Promise<void>((resolve, reject) => {
      let resolved = false;

      const onReady = () => {
        if (!resolved) {
          resolved = true;
          this.state = 'ACTIVE';
          this.consecutiveRestarts = 0;
          this.emit('active');
          // Reset consecutive restart counter after 60s of stable operation
          this.stableRunTimer = setTimeout(() => {
            this.consecutiveRestarts = 0;
          }, 60000);
          resolve();
        }
      };

      const onError = (err: Error) => {
        if (!resolved) {
          resolved = true;
          this.state = 'ERROR';
          this.lastError = err.message;
          reject(err);
        }
      };

      try {
        this.spawnEventWatcher(onReady, onError);
      } catch (err: any) {
        onError(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  /**
   * Stops the Windows process creation event subscription and frees all handles.
   */
  public async stop(): Promise<void> {
    this.isExplicitlyStopped = true;
    this.state = 'STOPPED';

    if (this.stableRunTimer) {
      clearTimeout(this.stableRunTimer);
      this.stableRunTimer = undefined;
    }

    if (this.readlineInterface) {
      this.readlineInterface.close();
      this.readlineInterface = undefined;
    }

    if (this.childProcess) {
      const child = this.childProcess;
      this.childProcess = undefined;

      try {
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.stdin?.destroy();
        child.kill('SIGTERM');
      } catch {
        // Safe kill
      }
    }

    this.emit('stopped');
  }

  public async dispose(): Promise<void> {
    await this.stop();
    this.processCreatedCallback = undefined;
    this.removeAllListeners();
  }

  /**
   * Spawns the underlying background PowerShell process hosting the WMI ManagementEventWatcher.
   */
  private spawnEventWatcher(onReady: () => void, onInitError: (err: Error) => void): void {
    const wmiInterval = this.wmiPollingIntervalSec.toFixed(2);
    const powershellScript = `
$ErrorActionPreference = 'Stop'
try {
  $query = New-Object System.Management.WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN ${wmiInterval} WHERE TargetInstance ISA 'Win32_Process'")
  $watcher = New-Object System.Management.ManagementEventWatcher($query)
  $watcher.Start()
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  [Console]::WriteLine('PP_WMI_READY')
  while ($true) {
    try {
      $eventObj = $watcher.WaitForNextEvent()
      $target = $eventObj.TargetInstance
      if ($target) {
        $data = [PSCustomObject]@{
          pid = [int]$target.ProcessId
          ppid = [int]$target.ParentProcessId
          name = [string]$target.Name
          path = [string]$target.ExecutablePath
          cmd = [string]$target.CommandLine
          creation = [string]$target.CreationDate
        }
        [Console]::WriteLine(($data | ConvertTo-Json -Compress))
      }
    } catch [System.Threading.ThreadAbortException] {
      break
    } catch {
      [Console]::Error.WriteLine('ERR: ' + $_.Exception.Message)
    }
  }
} catch {
  [Console]::Error.WriteLine('PP_WMI_INIT_ERROR: ' + $_.Exception.Message)
  exit 1
} finally {
  if ($watcher) {
    try { $watcher.Stop(); $watcher.Dispose() } catch {}
  }
}
`.trim();

    const spawnFn =
      this.spawnProvider ||
      ((cmd: string, args: string[]) => {
        return child_process.spawn(cmd, args, {
          windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe']
        });
      });

    const child = spawnFn('powershell', [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      powershellScript
    ]);

    this.childProcess = child;

    if (!child.stdout) {
      onInitError(new Error('Failed to acquire stdout stream from PowerShell event watcher'));
      return;
    }

    const rl = readline.createInterface({
      input: child.stdout,
      terminal: false
    });
    this.readlineInterface = rl;

    rl.on('line', (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      if (trimmed === 'PP_WMI_READY') {
        onReady();
        return;
      }

      if (trimmed.startsWith('{')) {
        this.handleEventLine(trimmed);
      }
    });

    if (child.stderr) {
      const rlErr = readline.createInterface({
        input: child.stderr,
        terminal: false
      });
      rlErr.on('line', (errLine: string) => {
        const trimmedErr = errLine.trim();
        if (trimmedErr.startsWith('PP_WMI_INIT_ERROR:')) {
          const errMsg = trimmedErr.replace('PP_WMI_INIT_ERROR:', '').trim();
          onInitError(new Error(`WMI event watcher init failed: ${errMsg}`));
        } else if (trimmedErr.startsWith('ERR:')) {
          this.emit('diagnostic', trimmedErr);
        }
      });
    }

    child.on('error', (err: Error) => {
      if (!this.isExplicitlyStopped) {
        this.lastError = err.message;
        onInitError(err);
        this.handleUnexpectedExit();
      }
    });

    child.on('exit', (code: number | null) => {
      if (!this.isExplicitlyStopped) {
        this.lastError = `PowerShell event watcher exited unexpectedly with code ${code}`;
        this.handleUnexpectedExit();
      }
    });
  }

  /**
   * Safely deserializes and normalizes an event JSON line into a ProcessCreationEvent.
   */
  private handleEventLine(rawJson: string): void {
    try {
      const parsed = JSON.parse(rawJson);
      if (!parsed || typeof parsed.pid !== 'number' || !parsed.name) {
        return;
      }

      const pid = parsed.pid;
      const ppid = typeof parsed.ppid === 'number' && parsed.ppid > 0 ? parsed.ppid : undefined;
      const processName = String(parsed.name);
      const executablePath = parsed.path ? String(parsed.path) : undefined;
      const commandLine = parsed.cmd ? String(parsed.cmd) : undefined;
      const creationTime = this.parseDmtfDate(parsed.creation);

      // Deterministic event identity bound to process instance
      const eventId = `evt:${pid}:${creationTime}:${processName.toLowerCase()}`;

      const event: ProcessCreationEvent = {
        eventId,
        pid,
        ppid,
        processName,
        executablePath,
        commandLine,
        creationTime,
        timestamp: Date.now()
      };

      this.eventsObserved++;
      if (this.processCreatedCallback) {
        this.processCreatedCallback(event);
      }
      this.emit('processCreated', event);
    } catch (err: any) {
      this.emit('malformedEvent', { rawJson, error: err?.message });
    }
  }

  /**
   * Parses DMTF datetime strings: YYYYMMDDHHMMSS.mmmmmm+UUU
   */
  private parseDmtfDate(dmtf?: string): number {
    if (!dmtf || typeof dmtf !== 'string') return Date.now();

    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d{3,6})([+-]\d{3})?$/.exec(dmtf.trim());
    if (!match) return Date.now();

    const [, year, month, day, hour, min, sec, micro, offset] = match;
    const ms = parseInt(micro.substring(0, 3), 10);
    const dateUtc = Date.UTC(
      parseInt(year, 10),
      parseInt(month, 10) - 1,
      parseInt(day, 10),
      parseInt(hour, 10),
      parseInt(min, 10),
      parseInt(sec, 10),
      ms
    );

    if (offset) {
      const offsetMinutes = parseInt(offset, 10);
      return dateUtc - offsetMinutes * 60 * 1000;
    }

    return dateUtc;
  }

  /**
   * Recovers from unexpected child process termination with bounded restart attempts.
   */
  private handleUnexpectedExit(): void {
    if (this.isExplicitlyStopped) return;

    if (this.consecutiveRestarts < this.maxRestartAttempts) {
      this.consecutiveRestarts++;
      const backoffMs = Math.min(1000 * Math.pow(2, this.consecutiveRestarts - 1), 8000);

      setTimeout(() => {
        if (!this.isExplicitlyStopped) {
          this.start().catch((err) => {
            this.state = 'ERROR';
            this.lastError = `Restart failed: ${err.message}`;
            this.emit('error', err);
          });
        }
      }, backoffMs);
    } else {
      this.state = 'ERROR';
      this.emit('error', new Error(this.lastError || 'Max restart attempts exceeded for event watcher'));
    }
  }
}
