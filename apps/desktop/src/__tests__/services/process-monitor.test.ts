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
      expect(health.eventSource).toBe('WMI_EVENT_SUBSCRIPTION');
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

  describe('3. Startup Race Protection', () => {
    it('subscribes to event source before snapshotting running processes', async () => {
      const order: string[] = [];

      const orderedSource = new MockProcessEventSource();
      const origStart = orderedSource.start.bind(orderedSource);
      orderedSource.start = async () => {
        order.push('EVENT_SOURCE_START');
        return origStart();
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
