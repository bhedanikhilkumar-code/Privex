import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ProcessMonitorService } from '../../services/process-monitor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { MockProcessEventSource } from '../../services/mock-process-event-source';
import { ProcessCreationEvent } from '../../types/desktop.types';

describe('ProcessMonitorService (Phase F — SEC-F-02 Continuous Process Monitor)', () => {
  let behaviorEngine: BehaviorEngineService;
  let processAuditor: ProcessAuditorService;
  let mockEventSource: MockProcessEventSource;
  let monitor: ProcessMonitorService;

  beforeEach(() => {
    behaviorEngine = new BehaviorEngineService({
      maxTrackedProcesses: 500,
      ttlMs: 60000
    });
    processAuditor = new ProcessAuditorService({
      behaviorEngine,
      scanBinaryOnDisk: false,
      processQueryProvider: async () => []
    });
    mockEventSource = new MockProcessEventSource();
    monitor = new ProcessMonitorService({
      behaviorEngine,
      processAuditor,
      eventSource: mockEventSource,
      maxQueueSize: 100,
      workerConcurrency: 2,
      pollIntervalMs: 5000
    });
  });

  afterEach(async () => {
    await monitor.stop();
  });

  describe('1. Lifecycle & Truthful Health Reporting', () => {
    it('reports STOPPED health state before start', () => {
      const health = monitor.getHealth();
      expect(health.status).toBe('STOPPED');
      expect(health.isContinuous).toBe(false);
      expect(health.queueDepth).toBe(0);
      expect(health.processedEvents).toBe(0);
      expect(health.droppedEvents).toBe(0);
      expect(health.eventSource).toBe('MOCK');
    });

    it('transitions to RUNNING and continuous upon start with active event source', async () => {
      await monitor.start();
      const health = monitor.getHealth();
      expect(health.status).toBe('RUNNING');
      expect(health.isContinuous).toBe(true);
      expect(mockEventSource.startCallCount).toBe(1);
    });

    it('transitions to STOPPED and releases handles on stop', async () => {
      await monitor.start();
      await monitor.stop();
      const health = monitor.getHealth();
      expect(health.status).toBe('STOPPED');
      expect(health.isContinuous).toBe(false);
      expect(health.queueDepth).toBe(0);
      expect(mockEventSource.stopCallCount).toBe(1);
    });
  });

  describe('2. Primary Event Source vs Degraded Fallback Policy', () => {
    it('reports DEGRADED when primary event source fails to start and falls back to polling', async () => {
      const failingSource = new MockProcessEventSource();
      failingSource.start = async () => {
        throw new Error('WMI Access Denied');
      };

      const fallbackMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor,
        eventSource: failingSource,
        pollIntervalMs: 2000
      });

      await fallbackMonitor.start();
      const health = fallbackMonitor.getHealth();

      expect(health.status).toBe('DEGRADED');
      expect(health.isContinuous).toBe(false);
      expect(health.eventSource).toBe('POLLING_FALLBACK');
      expect(health.lastError).toContain('falling back to degraded polling');

      await fallbackMonitor.stop();
    });

    it('reports DEGRADED when configured explicitly for polling fallback', async () => {
      const explicitFallbackMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor,
        eventSourceOverride: 'POLLING_FALLBACK',
        pollIntervalMs: 2000
      });

      await explicitFallbackMonitor.start();
      const health = explicitFallbackMonitor.getHealth();

      expect(health.status).toBe('DEGRADED');
      expect(health.isContinuous).toBe(false);
      expect(health.eventSource).toBe('POLLING_FALLBACK');

      await explicitFallbackMonitor.stop();
    });
  });

  describe('3. Startup Race Protection (SEC-F-02-B Remediation)', () => {
    it('subscribes to event source before snapshotting running processes', async () => {
      const order: string[] = [];

      const orderedSource = new MockProcessEventSource();
      const origStart = orderedSource.start.bind(orderedSource);
      orderedSource.start = async (cb) => {
        order.push('EVENT_SOURCE_START');
        return origStart(cb);
      };

      const customAuditor = new ProcessAuditorService({
        behaviorEngine,
        processQueryProvider: async () => {
          order.push('SNAPSHOT_RUNNING_PROCESSES');
          return [];
        }
      });

      const raceProofMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor: customAuditor,
        eventSource: orderedSource
      });

      await raceProofMonitor.start();

      expect(order).toEqual(['EVENT_SOURCE_START', 'SNAPSHOT_RUNNING_PROCESSES']);
      expect(order[0]).toBe('EVENT_SOURCE_START');

      await raceProofMonitor.stop();
    });

    it('adversarially proves zero event loss when an event arrives during activation and snapshotting', async () => {
      // Adversarial test: event generated during event source activation
      const eventDuringActivation: ProcessCreationEvent = {
        eventId: 'evt:7777:1760000000000:evil_spawn.exe',
        pid: 7777,
        ppid: 1000,
        processName: 'evil_spawn.exe',
        executablePath: 'C:\\Users\\Public\\evil_spawn.exe',
        commandLine: 'powershell.exe -w hidden -enc JABv...',
        creationTime: 1760000000000,
        timestamp: Date.now()
      };

      const dangerousWindowSource = new MockProcessEventSource();
      const origStart = dangerousWindowSource.start.bind(dangerousWindowSource);

      // Inbound event arrives WHILE start() is executing (dangerous activation window)
      dangerousWindowSource.start = async (cb) => {
        if (cb) dangerousWindowSource.onProcessCreated(cb);
        dangerousWindowSource.emitEvent(eventDuringActivation);
        return origStart(cb);
      };

      // Snapshot also captures the process
      const customAuditor = new ProcessAuditorService({
        behaviorEngine,
        processQueryProvider: async () => [
          {
            pid: 7777,
            processName: 'evil_spawn.exe',
            executablePath: 'C:\\Users\\Public\\evil_spawn.exe',
            commandLine: 'powershell.exe -w hidden -enc JABv...',
            creationDate: 1760000000000
          }
        ]
      });

      const raceProofMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor: customAuditor,
        eventSource: dangerousWindowSource
      });

      let evaluationCount = 0;
      raceProofMonitor.on('processEvaluated', (ev) => {
        if (ev.pid === 7777) {
          evaluationCount++;
        }
      });

      await raceProofMonitor.start();

      // Wait for async worker queue processing
      await new Promise((r) => setTimeout(r, 60));

      // 1. Activation began
      // 2. Event generated during activation
      // 3. Event was not lost (buffered and enqueued)
      // 4. Event reached ProcessMonitorService
      // 5. Evaluated exactly once (deduplicated against snapshot)
      expect(evaluationCount).toBe(1);

      await raceProofMonitor.stop();
    });
  });

  describe('4. Short-Lived Process Detection (Mandatory Section 13)', () => {
    it('detects short-lived process that exits within 20ms before any polling interval', async () => {
      await monitor.start();

      const evaluatedPromise = new Promise<any>((resolve) => {
        monitor.once('threatDetected', (t) => resolve(t));
      });

      // Simulation:
      // t=0: Monitor is running
      // t=10ms: Process created event arrives from OS event stream
      // t=20ms: Process exits from OS
      const shortLivedEvent: ProcessCreationEvent = {
        eventId: 'evt-shortlived-1',
        pid: 9999,
        ppid: 1000,
        processName: 'vssadmin.exe',
        executablePath: 'C:\\Windows\\System32\\vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet',
        creationTime: Date.now(),
        timestamp: Date.now()
      };

      // Inbound OS event arrives at t=10ms
      mockEventSource.emitEvent(shortLivedEvent);

      // Threat is caught via event stream without needing periodic polling
      const threatData = await evaluatedPromise;
      expect(threatData.event.pid).toBe(9999);
      expect(threatData.threat.threatName).toBe('VSSADMIN_SHADOW_DELETION');
      expect(threatData.evaluation.verdict).toBe('BLOCK');
      expect(threatData.evaluation.engineVerdict).toBe('CONTAIN_PROCESS');
    });
  });

  describe('5. Deterministic Event Deduplication & PID Reuse Preservation', () => {
    beforeEach(async () => {
      await monitor.start();
    });

    it('deduplicates identical process instances based on PID + creationTime + name', () => {
      const now = Date.now();
      const event1: ProcessCreationEvent = {
        eventId: `evt:5001:${now}:notepad.exe`,
        pid: 5001,
        processName: 'notepad.exe',
        creationTime: now,
        timestamp: now
      };

      const eventDuplicate: ProcessCreationEvent = {
        eventId: `evt:5001:${now}:notepad.exe`,
        pid: 5001,
        processName: 'notepad.exe',
        creationTime: now,
        timestamp: now + 50
      };

      expect(monitor.enqueueEvent(event1)).toBe(true);
      expect(monitor.enqueueEvent(eventDuplicate)).toBe(false);
    });

    it('accepts recycled PID when creationTime differs (PID reuse safety)', () => {
      const t1 = 1000000;
      const t2 = 2000000;

      const firstProcess: ProcessCreationEvent = {
        eventId: `evt:6001:${t1}:worker.exe`,
        pid: 6001,
        processName: 'worker.exe',
        creationTime: t1,
        timestamp: t1
      };

      const reusedPidProcess: ProcessCreationEvent = {
        eventId: `evt:6001:${t2}:worker.exe`,
        pid: 6001,
        processName: 'worker.exe',
        creationTime: t2,
        timestamp: t2
      };

      expect(monitor.enqueueEvent(firstProcess)).toBe(true);
      expect(monitor.enqueueEvent(reusedPidProcess)).toBe(true);
    });

    it('deterministically evicts oldest seen entries when cache exceeds MAX_SEEN_CACHE (2,000)', () => {
      // Add first entry
      const firstEvent: ProcessCreationEvent = {
        eventId: 'evt:100:1000:first.exe',
        pid: 100,
        processName: 'first.exe',
        creationTime: 1000,
        timestamp: 1000
      };
      expect(monitor.enqueueEvent(firstEvent)).toBe(true);
      expect(monitor.enqueueEvent(firstEvent)).toBe(false); // Deduplicated

      // Enqueue 2,001 additional distinct events to force LRU eviction of the first
      for (let i = 1; i <= 2001; i++) {
        monitor.enqueueEvent({
          eventId: `evt:${1000 + i}:${2000 + i}:proc_${i}.exe`,
          pid: 1000 + i,
          processName: `proc_${i}.exe`,
          creationTime: 2000 + i,
          timestamp: 2000 + i
        });
      }

      // First event should now have been evicted and can be enqueued again
      expect(monitor.enqueueEvent(firstEvent)).toBe(true);
    });
  });

  describe('6. Bounded Queue & Backpressure Shedding', () => {
    it('sheds normal events when maxQueueSize is exceeded and emits backpressure event', async () => {
      const smallMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor,
        eventSource: new MockProcessEventSource(),
        maxQueueSize: 10,
        workerConcurrency: 1
      });
      await smallMonitor.start();

      let backpressureEmitted = false;
      smallMonitor.on('backpressure', () => {
        backpressureEmitted = true;
      });

      // Flood with 25 normal events
      for (let i = 0; i < 25; i++) {
        smallMonitor.enqueueEvent({
          eventId: `evt-burst-${i}`,
          pid: 3000 + i,
          processName: `worker_${i}.exe`,
          creationTime: Date.now(),
          timestamp: Date.now()
        });
      }

      const health = smallMonitor.getHealth();
      expect(health.droppedEvents).toBeGreaterThan(0);
      expect(health.status).toBe('DEGRADED');
      expect(backpressureEmitted).toBe(true);

      await smallMonitor.stop();
    });
  });

  describe('7. Restart Safety & Idempotency (Section 17)', () => {
    it('supports multiple sequential start/stop cycles cleanly without leaks', async () => {
      expect(monitor.getHealth().status).toBe('STOPPED');

      await monitor.start();
      expect(monitor.getHealth().status).toBe('RUNNING');

      await monitor.stop();
      expect(monitor.getHealth().status).toBe('STOPPED');

      await monitor.start();
      expect(monitor.getHealth().status).toBe('RUNNING');

      await monitor.stop();
      expect(monitor.getHealth().status).toBe('STOPPED');

      await monitor.start();
      expect(monitor.getHealth().status).toBe('RUNNING');

      await monitor.stop();
      expect(monitor.getHealth().status).toBe('STOPPED');
    });

    it('clears and reinitializes state cleanly upon restart', async () => {
      await monitor.start();
      const testEvent: ProcessCreationEvent = {
        eventId: 'evt:999:1234:service.exe',
        pid: 999,
        processName: 'service.exe',
        creationTime: 1234,
        timestamp: Date.now()
      };
      expect(monitor.enqueueEvent(testEvent)).toBe(true);
      expect(monitor.enqueueEvent(testEvent)).toBe(false); // Deduplicated

      await monitor.stop();
      await monitor.start();

      // After restart, state is safely reinitialized so the event is processed fresh
      expect(monitor.enqueueEvent(testEvent)).toBe(true);
    });

    it('handles idempotent start() and stop() calls safely', async () => {
      await monitor.start();
      await monitor.start(); // Idempotent second start
      expect(monitor.getHealth().status).toBe('RUNNING');

      await monitor.stop();
      await monitor.stop(); // Idempotent second stop
      expect(monitor.getHealth().status).toBe('STOPPED');
    });
  });
});
