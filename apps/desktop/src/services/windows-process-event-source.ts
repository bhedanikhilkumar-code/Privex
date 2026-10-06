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
  /** Custom WMI WqlEventQuery (default: 'SELECT * FROM Win32_ProcessStartTrace') */
  readonly wmiQuery?: string;
  /** Maximum consecutive restart attempts before entering ERROR state (default: 3) */
  readonly maxRestartAttempts?: number;
}

/**
 * WindowsProcessEventSource (Phase F — SEC-F-02 Primary Event Source)
 *
 * Implements genuine, continuous Windows process-creation event subscription
 * using Microsoft's Win32_ProcessStartTrace extrinsic event class.
 *
 * ARCHITECTURAL DESIGN & JUSTIFICATION:
 * 1. True Event Semantics: Uses Win32_ProcessStartTrace (subclass of Win32_ProcessTrace
 *    in ROOT/CIMV2). Subscribes directly to push notifications from the Windows kernel
 *    ETW trace provider without any polling interval (NO 'WITHIN' polling loop).
 * 2. Short-Lived Process Capture: Because notifications are event-driven rather than
 *    interval-polled, process starts are captured immediately upon creation.
 * 3. Privilege Model & Environmental Constraints:
 *    - Win32_ProcessStartTrace requires Administrator privileges or membership in the
 *      local 'Performance Log Users' group.
 *    - In an unprivileged standard user context, Windows WMI throws 'Access denied'.
 *    - When access is denied, start() fails truthfully so ProcessMonitorService degrades
 *      cleanly to POLLING_FALLBACK with truthful health diagnostics (no false RUNNING).
 * 4. Startup Buffering (Zero Event Loss): Internally buffers inbound process creation
 *    events until the consumer registers onProcessCreated() or start(callback),
 *    closing the startup race window at the event source boundary.
 * 5. 100% Offline Air-Gapped: Zero network sockets, zero remote telemetry, local OS queries only.
 */
export class WindowsProcessEventSource extends EventEmitter implements IProcessEventSource {
  private readonly spawnProvider?: (command: string, args: string[]) => child_process.ChildProcess;
  private readonly wmiQuery: string;
  private readonly maxRestartAttempts: number;

  private state: 'INITIALIZING' | 'ACTIVE' | 'ERROR' | 'STOPPED' = 'STOPPED';
  private lastError?: string;
  private eventsObserved = 0;
  private consecutiveRestarts = 0;
  private isExplicitlyStopped = true;

  private childProcess?: child_process.ChildProcess;
  private readlineInterface?: readline.Interface;
  private processCreatedCallback?: (event: ProcessCreationEvent) => void;
  private readonly startupBuffer: ProcessCreationEvent[] = [];
  private readonly MAX_STARTUP_BUFFER = 1000;
  private stableRunTimer?: NodeJS.Timeout;

  constructor(options?: WindowsProcessEventSourceOptions) {
    super();
    this.spawnProvider = options?.spawnProvider;
    this.wmiQuery = options?.wmiQuery ?? 'SELECT * FROM Win32_ProcessStartTrace';
    this.maxRestartAttempts = options?.maxRestartAttempts ?? 3;
  }

  public getStatus(): ProcessEventSourceStatus {
    return {
      state: this.state,
      sourceName: 'WMI_TRACE',
      lastError: this.lastError,
      eventsObserved: this.eventsObserved
    };
  }

  public onProcessCreated(callback: (event: ProcessCreationEvent) => void): void {
    this.processCreatedCallback = callback;
    this.flushStartupBuffer();
  }

  /**
   * Starts the Windows process creation event subscription.
   * Resolves only after the background worker emits confirmation of active subscription.
   * If callback is provided, registers it atomically before activating the OS subscription.
   */
  public async start(callback?: (event: ProcessCreationEvent) => void): Promise<void> {
    if (callback) {
      this.onProcessCreated(callback);
    }
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
          this.flushStartupBuffer();
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
          if (this.childProcess) {
            try {
              this.childProcess.kill('SIGTERM');
            } catch {}
          }
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
    this.startupBuffer.length = 0;

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

  private flushStartupBuffer(): void {
    if (!this.processCreatedCallback) return;
    while (this.startupBuffer.length > 0) {
      const buffered = this.startupBuffer.shift()!;
      this.processCreatedCallback(buffered);
    }
  }

  /**
   * Spawns the underlying background PowerShell process hosting the WMI ManagementEventWatcher.
   */
  private spawnEventWatcher(onReady: () => void, onInitError: (err: Error) => void): void {
    const escapedQuery = this.wmiQuery.replace(/'/g, "''");
    const powershellScript = `
$ErrorActionPreference = 'Stop'
try {
  $query = New-Object System.Management.WqlEventQuery('${escapedQuery}')
  $watcher = New-Object System.Management.ManagementEventWatcher($query)
  $watcher.Start()
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  [Console]::WriteLine('PP_WMI_READY')
  while ($true) {
    try {
      $eventObj = $watcher.WaitForNextEvent()
      if (-not $eventObj) { continue }

      # Support both extrinsic (Win32_ProcessStartTrace) and intrinsic (__InstanceCreationEvent)
      $target = if ($eventObj.TargetInstance) { $eventObj.TargetInstance } else { $eventObj }

      $pidVal = 0
      if ($target.ProcessId) { $pidVal = [int]$target.ProcessId }
      elseif ($target.ProcessID) { $pidVal = [int]$target.ProcessID }

      $ppidVal = 0
      if ($target.ParentProcessId) { $ppidVal = [int]$target.ParentProcessId }
      elseif ($target.ParentProcessID) { $ppidVal = [int]$target.ParentProcessID }

      $nameVal = [string]$target.ProcessName
      if (-not $nameVal -and $target.Name) { $nameVal = [string]$target.Name }

      $creationVal = $null
      if ($eventObj.TIME_CREATED) {
        try {
          $creationVal = [DateTimeOffset]::FromFileTime([Int64]$eventObj.TIME_CREATED).ToUnixTimeMilliseconds()
        } catch {
          $creationVal = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        }
      } elseif ($target.CreationDate) {
        $creationVal = [string]$target.CreationDate
      }

      $pathVal = if ($target.ExecutablePath) { [string]$target.ExecutablePath } else { $null }
      $cmdVal = if ($target.CommandLine) { [string]$target.CommandLine } else { $null }

      # If path or command-line is missing (standard in Win32_ProcessStartTrace), attempt instant local enrichment
      if ((-not $pathVal -or -not $cmdVal) -and $pidVal -gt 0) {
        try {
          $p = Get-CimInstance Win32_Process -Filter "ProcessId = $pidVal" -ErrorAction SilentlyContinue
          if ($p) {
            if (-not $pathVal) { $pathVal = [string]$p.ExecutablePath }
            if (-not $cmdVal) { $cmdVal = [string]$p.CommandLine }
          }
        } catch {}
      }

      $data = [PSCustomObject]@{
        pid = $pidVal
        ppid = $ppidVal
        name = $nameVal
        path = $pathVal
        cmd = $cmdVal
        creation = $creationVal
      }
      [Console]::WriteLine(($data | ConvertTo-Json -Compress))
    } catch [System.Threading.ThreadAbortException] {
      break
    } catch {
      [Console]::Error.WriteLine('ERR: ' + $_.Exception.Message)
    }
  }
} catch {
  $errMsg = $_.Exception.Message
  if ($errMsg -match 'Access denied') {
    [Console]::Error.WriteLine('PP_WMI_INIT_ERROR: Access denied (Win32_ProcessStartTrace requires Administrator privileges or Performance Log Users group membership)')
  } else {
    [Console]::Error.WriteLine('PP_WMI_INIT_ERROR: ' + $errMsg)
  }
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
        if (this.state === 'INITIALIZING') {
          onInitError(err);
        } else if (this.state === 'ACTIVE') {
          this.handleUnexpectedExit();
        }
      }
    });

    child.on('exit', (code: number | null) => {
      if (!this.isExplicitlyStopped && this.state === 'ACTIVE') {
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
      const creationTime = this.parseCreationTime(parsed.creation);

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
        this.flushStartupBuffer();
        this.processCreatedCallback(event);
      } else {
        if (this.startupBuffer.length < this.MAX_STARTUP_BUFFER) {
          this.startupBuffer.push(event);
        }
      }
      this.emit('processCreated', event);
    } catch (err: any) {
      this.emit('malformedEvent', { rawJson, error: err?.message });
    }
  }

  /**
   * Parses creation time which can be numeric epoch ms, numeric string, or DMTF string.
   */
  private parseCreationTime(creation?: any): number {
    if (typeof creation === 'number' && Number.isFinite(creation) && creation > 0) {
      return creation;
    }
    if (typeof creation === 'string') {
      const num = Number(creation);
      if (!isNaN(num) && num > 1000000000000) {
        return num;
      }
      return this.parseDmtfDate(creation);
    }
    return Date.now();
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
    if (this.isExplicitlyStopped || this.state !== 'ACTIVE') return;

    if (this.consecutiveRestarts < this.maxRestartAttempts) {
      this.consecutiveRestarts++;
      const backoffMs = Math.min(1000 * Math.pow(2, this.consecutiveRestarts - 1), 8000);

      setTimeout(() => {
        if (!this.isExplicitlyStopped) {
          this.start().catch((err) => {
            this.state = 'ERROR';
            this.lastError = `Restart failed: ${err.message}`;
            if (this.listenerCount('error') > 0) {
              this.emit('error', err);
            }
          });
        }
      }, backoffMs);
    } else {
      this.state = 'ERROR';
      if (this.listenerCount('error') > 0) {
        this.emit('error', new Error(this.lastError || 'Max restart attempts exceeded for event watcher'));
      }
    }
  }
}
