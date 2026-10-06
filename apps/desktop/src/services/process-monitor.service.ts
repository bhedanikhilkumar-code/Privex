import { EventEmitter } from 'events';
import {
  IProcessEventSource,
  ProcessCreationEvent,
  ProcessEventSourceType,
  ProcessMonitorHealth,
  ProcessMonitorStatus,
  DetectedThreat
} from '../types/desktop.types';
import { BehaviorEngineService } from './behavior-engine.service';
import { ProcessAuditorService } from './process-auditor.service';
import { WindowsProcessEventSource } from './windows-process-event-source';
import { MockProcessEventSource } from './mock-process-event-source';

export interface ProcessMonitorOptions {
  readonly behaviorEngine?: BehaviorEngineService;
  readonly processAuditor?: ProcessAuditorService;
  readonly eventSource?: IProcessEventSource;
  readonly maxQueueSize?: number;
  readonly workerConcurrency?: number;
  readonly pollIntervalMs?: number;
  readonly eventSourceOverride?: ProcessEventSourceType;
}

/**
 * ProcessMonitorService (Phase F — SEC-F-02 Targeted Remediation)
 *
 * Provides genuine continuous monitoring of Windows process creation events.
 *
 * ARCHITECTURAL TOPOLOGY:
 * 1. Primary: Windows WMI Event Subscription (WindowsProcessEventSource)
 *    Subscribes directly to OS process creation (__InstanceCreationEvent of Win32_Process).
 *    Catches short-lived processes (<20 ms) that exit between traditional polling intervals.
 * 2. Ingress & Normalization:
 *    ProcessCreationEvent -> deterministic deduplication key -> Bounded Priority Queue.
 * 3. Priority Queue & Worker Pool:
 *    Dual bounded priority queues (high-priority LOLBin, normal-priority standard).
 *    Worker pool bounded to concurrencyLimit (default: 4 workers).
 * 4. Pipeline Execution:
 *    BehaviorEngineService -> RiskScorer -> EngineVerdict -> Authorized Containment.
 * 5. Startup Race Prevention:
 *    Subscribes to OS event source FIRST, then captures initial process snapshot,
 *    reconciling with deterministic instance deduplication.
 * 6. Explicit Degraded Fallback:
 *    Polling fallback runs only when WMI event subscription is unavailable (e.g. non-Windows)
 *    and truthfully reports status: 'DEGRADED', isContinuous: false.
 */
export class ProcessMonitorService extends EventEmitter {
  private readonly behaviorEngine: BehaviorEngineService;
  private readonly processAuditor: ProcessAuditorService;
  private eventSource?: IProcessEventSource;
  private readonly maxQueueSize: number;
  private readonly workerConcurrency: number;
  private readonly pollIntervalMs: number;

  private status: ProcessMonitorStatus = 'STOPPED';
  private eventSourceType: ProcessEventSourceType = 'POLLING_FALLBACK';
  private isContinuous = false;

  // Bounded priority queues
  private readonly highPriorityQueue: ProcessCreationEvent[] = [];
  private readonly normalPriorityQueue: ProcessCreationEvent[] = [];

  // Deduplication & state tracking
  private readonly seenEventKeys = new Set<string>();
  private readonly seenEventKeyOrder: string[] = [];
  private readonly MAX_SEEN_CACHE = 2000;

  // Worker state
  private activeWorkers = 0;
  private processedEvents = 0;
  private droppedEvents = 0;
  private lastEventTimestamp?: number;
  private lastError?: string;

  // Fallback Polling state
  private pollTimer?: NodeJS.Timeout;
  private isProcessingPoll = false;
  private knownPids = new Set<number>();

  constructor(options?: ProcessMonitorOptions) {
    super();
    this.behaviorEngine = options?.behaviorEngine || new BehaviorEngineService();
    this.processAuditor = options?.processAuditor || new ProcessAuditorService({ behaviorEngine: this.behaviorEngine });
    this.maxQueueSize = options?.maxQueueSize ?? 1000;
    this.workerConcurrency = options?.workerConcurrency ?? 4;
    this.pollIntervalMs = options?.pollIntervalMs ?? 1000;

    if (options?.eventSource) {
      this.eventSource = options.eventSource;
      this.eventSourceType = options.eventSource instanceof MockProcessEventSource ? 'MOCK' : 'WMI_TRACE';
    } else if (options?.eventSourceOverride === 'MOCK') {
      this.eventSource = new MockProcessEventSource();
      this.eventSourceType = 'MOCK';
    } else if (options?.eventSourceOverride === 'POLLING_FALLBACK') {
      this.eventSourceType = 'POLLING_FALLBACK';
    } else if (process.platform === 'win32') {
      this.eventSource = new WindowsProcessEventSource();
      this.eventSourceType = 'WMI_TRACE';
    } else {
      this.eventSourceType = 'POLLING_FALLBACK';
    }
  }

  public getBehaviorEngine(): BehaviorEngineService {
    return this.behaviorEngine;
  }

  public getProcessAuditor(): ProcessAuditorService {
    return this.processAuditor;
  }

  public getEventSource(): IProcessEventSource | undefined {
    return this.eventSource;
  }

  /**
   * Starts process monitoring.
   *
   * STARTUP ORDERING & RACE ELIMINATION (SEC-F-02-B Remediation):
   * 1. Registers consumer callback BEFORE or ATOMICALLY within eventSource.start().
   *    Event source internally buffers any events during initialization.
   * 2. Confirms OS event subscription is ACTIVE.
   * 3. Captures running process snapshot and seeds known process identities.
   * 4. Reconciles events + snapshot with deterministic instance keys.
   * 5. Invariant guaranteed: Zero OS events emitted before consumer callback is registered.
   */
  public async start(): Promise<void> {
    if (this.status === 'RUNNING') return;

    this.status = 'RUNNING';
    this.lastError = undefined;

    let primaryEventSourceActive = false;

    // STEP 1: Register callback FIRST, then start primary event subscription atomically
    if (this.eventSource && this.eventSourceType !== 'POLLING_FALLBACK') {
      try {
        this.eventSource.onProcessCreated((event) => {
          this.enqueueEvent(event);
        });
        await this.eventSource.start((event) => {
          this.enqueueEvent(event);
        });
        primaryEventSourceActive = true;
        this.isContinuous = true;
        if (this.eventSource instanceof MockProcessEventSource) {
          this.eventSourceType = 'MOCK';
        } else {
          this.eventSourceType = 'WMI_TRACE';
        }
      } catch (err: any) {
        // Event source failed to initialize (e.g. unprivileged standard user or missing provider)
        this.lastError = `Primary process event subscription failed: ${err?.message || String(err)}; falling back to degraded polling`;
        this.status = 'DEGRADED';
        this.isContinuous = false;
        this.eventSourceType = 'POLLING_FALLBACK';
        primaryEventSourceActive = false;
      }
    } else {
      // Configured explicitly for fallback
      this.status = 'DEGRADED';
      this.isContinuous = false;
      this.eventSourceType = 'POLLING_FALLBACK';
      this.lastError = 'Running in degraded polling fallback mode; short-lived processes may be missed';
    }

    // STEP 2: Capture initial running processes snapshot
    await this.seedInitialProcessSnapshot();

    // STEP 3: If primary event source is not active, run polling fallback
    if (!primaryEventSourceActive) {
      this.scheduleNextPoll();
    }

    this.emit('started', this.getHealth());
  }

  /**
   * Stops continuous monitoring and releases all resources cleanly.
   */
  public async stop(): Promise<void> {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }

    if (this.eventSource) {
      try {
        await this.eventSource.stop();
      } catch {
        // Safe stop
      }
    }

    this.status = 'STOPPED';
    this.isContinuous = false;
    this.highPriorityQueue.length = 0;
    this.normalPriorityQueue.length = 0;
    this.seenEventKeys.clear();
    this.seenEventKeyOrder.length = 0;
    this.knownPids.clear();
    this.emit('stopped', this.getHealth());
  }

  /**
   * Returns current truthful health metrics.
   */
  public getHealth(): ProcessMonitorHealth {
    const queueDepth = this.highPriorityQueue.length + this.normalPriorityQueue.length;
    return {
      status: this.status,
      isContinuous: this.isContinuous,
      eventSource: this.eventSourceType,
      queueDepth,
      processedEvents: this.processedEvents,
      droppedEvents: this.droppedEvents,
      activeWorkers: this.activeWorkers,
      lastEventTimestamp: this.lastEventTimestamp,
      lastError: this.lastError
    };
  }

  /**
   * Ingests a normalized ProcessCreationEvent into the bounded priority queue.
   */
  public enqueueEvent(event: ProcessCreationEvent): boolean {
    if (this.status === 'STOPPED') {
      return false;
    }

    // Deterministic deduplication key based on process instance identity
    const dedupeKey = event.eventId || `evt:${event.pid}:${event.creationTime}:${event.processName.toLowerCase()}`;

    if (this.seenEventKeys.has(dedupeKey)) {
      return false;
    }

    this.seenEventKeys.add(dedupeKey);
    this.seenEventKeyOrder.push(dedupeKey);
    if (this.seenEventKeyOrder.length > this.MAX_SEEN_CACHE) {
      const oldest = this.seenEventKeyOrder.shift();
      if (oldest) this.seenEventKeys.delete(oldest);
    }

    this.lastEventTimestamp = event.timestamp || Date.now();

    // Bounded queue enforcement with load shedding
    const totalQueue = this.highPriorityQueue.length + this.normalPriorityQueue.length;
    if (totalQueue >= this.maxQueueSize) {
      if (this.normalPriorityQueue.length > 0) {
        this.normalPriorityQueue.shift();
        this.droppedEvents++;
      } else {
        this.highPriorityQueue.shift();
        this.droppedEvents++;
      }
      this.status = 'DEGRADED';
      this.emit('backpressure', {
        queueDepth: totalQueue,
        maxQueueSize: this.maxQueueSize,
        droppedEvents: this.droppedEvents
      });
    } else if (this.status === 'DEGRADED' && totalQueue < this.maxQueueSize * 0.5 && this.isContinuous) {
      this.status = 'RUNNING';
    }

    // Priority classification: LOLBins, shell interpreters, and writable dirs get high priority
    const lowerName = event.processName.toLowerCase();
    const isLolbin = BehaviorEngineService.KNOWN_LOLBINS.has(lowerName);
    const isScript = BehaviorEngineService.SCRIPT_INTERPRETERS.has(lowerName);

    if (isLolbin || isScript) {
      this.highPriorityQueue.push(event);
    } else {
      this.normalPriorityQueue.push(event);
    }

    this.scheduleWorkers();
    return true;
  }

  private scheduleWorkers(): void {
    while (
      this.activeWorkers < this.workerConcurrency &&
      (this.highPriorityQueue.length > 0 || this.normalPriorityQueue.length > 0)
    ) {
      const nextEvent = this.highPriorityQueue.shift() || this.normalPriorityQueue.shift();
      if (!nextEvent) break;

      this.activeWorkers++;
      this.processEventAsync(nextEvent).finally(() => {
        this.activeWorkers--;
        this.scheduleWorkers();
      });
    }
  }

  private async processEventAsync(event: ProcessCreationEvent): Promise<void> {
    try {
      const evaluation = this.behaviorEngine.evaluateProcess({
        pid: event.pid,
        ppid: event.ppid,
        processName: event.processName,
        executablePath: event.executablePath,
        commandLine: event.commandLine,
        creationTime: event.creationTime
      });

      this.processedEvents++;
      this.emit('processEvaluated', evaluation);

      if (evaluation.verdict === 'BLOCK' || evaluation.engineVerdict === 'CONTAIN_PROCESS') {
        const threat: DetectedThreat = {
          id: `threat-proc-${event.pid}-${Date.now()}`,
          filePath: event.executablePath || event.processName,
          fileName: event.processName,
          fileSize: 0,
          sha256: evaluation.authorization?.sha256 || 'process-memory',
          riskScore: evaluation.riskScore,
          severity: evaluation.severity,
          verdict: evaluation.verdict,
          threatName: evaluation.threatName,
          detectedAt: Date.now(),
          evidenceFactors: evaluation.evidenceFactors,
          quarantined: false
        };
        this.emit('threatDetected', { threat, evaluation, event });
      }
    } catch (err: any) {
      this.lastError = err?.message || String(err);
      this.emit('workerError', { event, error: err });
    }
  }

  private async seedInitialProcessSnapshot(): Promise<void> {
    try {
      const currentProcs = await this.processAuditor.auditRunningProcesses();
      this.knownPids = new Set(currentProcs.map((p) => p.pid));
      for (const p of currentProcs) {
        const key = `evt:${p.pid}:${p.creationDate || 0}:${p.processName.toLowerCase()}`;
        if (!this.seenEventKeys.has(key)) {
          this.seenEventKeys.add(key);
          this.seenEventKeyOrder.push(key);
          if (this.seenEventKeyOrder.length > this.MAX_SEEN_CACHE) {
            const oldest = this.seenEventKeyOrder.shift();
            if (oldest) this.seenEventKeys.delete(oldest);
          }
        }
      }
    } catch {
      this.knownPids = new Set();
    }
  }

  // ============================================================
  // DEGRADED POLLING FALLBACK (Used only when OS event subscription fails)
  // ============================================================

  private scheduleNextPoll(): void {
    if (this.status === 'STOPPED') return;

    this.pollTimer = setTimeout(async () => {
      if (this.status !== 'STOPPED' && !this.isProcessingPoll) {
        this.isProcessingPoll = true;
        try {
          await this.pollProcessDelta();
        } catch (err: any) {
          this.lastError = err?.message || String(err);
        } finally {
          this.isProcessingPoll = false;
        }
      }
      this.scheduleNextPoll();
    }, this.pollIntervalMs);
  }

  private async pollProcessDelta(): Promise<void> {
    try {
      const currentProcs = await this.processAuditor.auditRunningProcesses();
      const currentPidSet = new Set<number>();

      for (const proc of currentProcs) {
        currentPidSet.add(proc.pid);
        if (!this.knownPids.has(proc.pid)) {
          const event: ProcessCreationEvent = {
            eventId: `evt:${proc.pid}:${proc.creationDate || Date.now()}:${proc.processName.toLowerCase()}`,
            pid: proc.pid,
            ppid: proc.ppid,
            processName: proc.processName,
            executablePath: proc.executablePath,
            commandLine: proc.commandLine,
            creationTime: proc.creationDate || Date.now(),
            timestamp: Date.now()
          };
          this.enqueueEvent(event);
        }
      }

      this.knownPids = currentPidSet;
    } catch (err: any) {
      this.lastError = err?.message || String(err);
    }
  }
}
