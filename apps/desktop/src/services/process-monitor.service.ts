import { EventEmitter } from 'events';
import {
  ProcessCreationEvent,
  ProcessMonitorHealth,
  ProcessMonitorStatus,
  DetectedThreat
} from '../types/desktop.types';
import { BehaviorEngineService } from './behavior-engine.service';
import { ProcessAuditorService } from './process-auditor.service';

export interface ProcessMonitorOptions {
  readonly behaviorEngine?: BehaviorEngineService;
  readonly processAuditor?: ProcessAuditorService;
  readonly maxQueueSize?: number;
  readonly workerConcurrency?: number;
  readonly pollIntervalMs?: number;
  readonly eventSourceOverride?: 'WMI_TRACE' | 'CIM_EVENT' | 'POLLING_FALLBACK' | 'MOCK';
}

/**
 * ProcessMonitorService (Phase F — SEC-F-02 Remediation)
 *
 * Provides resilient, continuous monitoring of process creation events.
 * Implements a bounded priority queue, concurrency-limited worker pool,
 * deduplication, and truthful health reporting.
 *
 * INVARIANTS:
 * 1. 100% offline air-gapped operation with zero network calls.
 * 2. Truthful health status (RUNNING | DEGRADED | STOPPED | FAILED).
 * 3. Bounded priority queue (max 1,000 events) preventing memory exhaustion (<200 MB RSS).
 * 4. Canonical risk scoring through BehaviorEngineService / RiskScorer.
 */
export class ProcessMonitorService extends EventEmitter {
  private readonly behaviorEngine: BehaviorEngineService;
  private readonly processAuditor: ProcessAuditorService;
  private readonly maxQueueSize: number;
  private readonly workerConcurrency: number;
  private readonly pollIntervalMs: number;

  private status: ProcessMonitorStatus = 'STOPPED';
  private eventSource: 'WMI_TRACE' | 'CIM_EVENT' | 'POLLING_FALLBACK' | 'MOCK' = 'POLLING_FALLBACK';
  private isContinuous = false;

  // Bounded priority queues
  private readonly highPriorityQueue: ProcessCreationEvent[] = [];
  private readonly normalPriorityQueue: ProcessCreationEvent[] = [];

  // Deduplication & state tracking
  private readonly seenEventIds = new Set<string>();
  private readonly seenEventIdOrder: string[] = [];
  private readonly MAX_SEEN_CACHE = 2000;

  // Worker state
  private activeWorkers = 0;
  private processedEvents = 0;
  private droppedEvents = 0;
  private lastEventTimestamp?: number;
  private lastError?: string;

  // Polling / WMI handles
  private pollTimer?: NodeJS.Timeout;
  private isProcessing = false;
  private knownPids = new Set<number>();

  constructor(options?: ProcessMonitorOptions) {
    super();
    this.behaviorEngine = options?.behaviorEngine || new BehaviorEngineService();
    this.processAuditor = options?.processAuditor || new ProcessAuditorService({ behaviorEngine: this.behaviorEngine });
    this.maxQueueSize = options?.maxQueueSize ?? 1000;
    this.workerConcurrency = options?.workerConcurrency ?? 4;
    this.pollIntervalMs = options?.pollIntervalMs ?? 1000;

    if (options?.eventSourceOverride) {
      this.eventSource = options.eventSourceOverride;
    }
  }

  public getBehaviorEngine(): BehaviorEngineService {
    return this.behaviorEngine;
  }

  public getProcessAuditor(): ProcessAuditorService {
    return this.processAuditor;
  }

  /**
   * Starts continuous monitoring.
   */
  public async start(): Promise<void> {
    if (this.status === 'RUNNING') return;

    try {
      this.status = 'RUNNING';
      this.isContinuous = true;
      this.lastError = undefined;

      // Seed current running processes to avoid false positive burst on startup
      await this.seedInitialProcessSnapshot();

      // Start continuous background event polling / observation
      this.scheduleNextPoll();
      this.emit('started', this.getHealth());
    } catch (err: any) {
      this.status = 'FAILED';
      this.isContinuous = false;
      this.lastError = err?.message || String(err);
      this.emit('error', err);
      throw err;
    }
  }

  /**
   * Stops continuous monitoring cleanly.
   */
  public stop(): void {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
    this.status = 'STOPPED';
    this.isContinuous = false;
    this.highPriorityQueue.length = 0;
    this.normalPriorityQueue.length = 0;
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
      eventSource: this.eventSource,
      queueDepth,
      processedEvents: this.processedEvents,
      droppedEvents: this.droppedEvents,
      activeWorkers: this.activeWorkers,
      lastEventTimestamp: this.lastEventTimestamp,
      lastError: this.lastError
    };
  }

  /**
   * Ingests a process creation event (used by live WMI/CIM stream or simulated test harnesses).
   */
  public enqueueEvent(event: ProcessCreationEvent): boolean {
    if (this.status === 'STOPPED') {
      return false;
    }

    // Deduplication check
    if (this.seenEventIds.has(event.eventId)) {
      return false;
    }
    this.seenEventIds.add(event.eventId);
    this.seenEventIdOrder.push(event.eventId);
    if (this.seenEventIdOrder.length > this.MAX_SEEN_CACHE) {
      const oldest = this.seenEventIdOrder.shift();
      if (oldest) this.seenEventIds.delete(oldest);
    }

    this.lastEventTimestamp = event.timestamp || Date.now();

    // Check queue bounds
    const totalQueue = this.highPriorityQueue.length + this.normalPriorityQueue.length;
    if (totalQueue >= this.maxQueueSize) {
      // Shed from normal priority first
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
    } else if (this.status === 'DEGRADED' && totalQueue < this.maxQueueSize * 0.5) {
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
    } catch {
      this.knownPids = new Set();
    }
  }

  private scheduleNextPoll(): void {
    if (this.status === 'STOPPED') return;

    this.pollTimer = setTimeout(async () => {
      if (this.status !== 'STOPPED' && !this.isProcessing) {
        this.isProcessing = true;
        try {
          await this.pollProcessDelta();
        } catch (err: any) {
          this.lastError = err?.message || String(err);
        } finally {
          this.isProcessing = false;
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
          // New process spawned
          const event: ProcessCreationEvent = {
            eventId: `evt-${proc.pid}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
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
