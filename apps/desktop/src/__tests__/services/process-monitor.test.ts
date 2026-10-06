import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ProcessMonitorService } from '../../services/process-monitor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { ProcessCreationEvent } from '../../types/desktop.types';

describe('ProcessMonitorService (Phase F — SEC-F-02 Continuous Process Monitor)', () => {
  let behaviorEngine: BehaviorEngineService;
  let processAuditor: ProcessAuditorService;
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
    monitor = new ProcessMonitorService({
      behaviorEngine,
      processAuditor,
      maxQueueSize: 100,
      workerConcurrency: 2,
      pollIntervalMs: 5000,
      eventSourceOverride: 'MOCK'
    });
  });

  afterEach(() => {
    monitor.stop();
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

    it('transitions to RUNNING and continuous upon start', async () => {
      await monitor.start();
      const health = monitor.getHealth();
      expect(health.status).toBe('RUNNING');
      expect(health.isContinuous).toBe(true);
    });

    it('transitions back to STOPPED and clears queues upon stop', async () => {
      await monitor.start();
      monitor.stop();
      const health = monitor.getHealth();
      expect(health.status).toBe('STOPPED');
      expect(health.isContinuous).toBe(false);
      expect(health.queueDepth).toBe(0);
    });
  });

  describe('2. Event Ingestion, Deduplication & Priority Queuing', () => {
    beforeEach(async () => {
      await monitor.start();
    });

    it('ingests process creation event and evaluates behavior', async () => {
      const evaluatedPromise = new Promise<any>((resolve) => {
        monitor.once('processEvaluated', (ev) => resolve(ev));
      });

      const event: ProcessCreationEvent = {
        eventId: 'evt-101',
        pid: 2001,
        processName: 'calc.exe',
        executablePath: 'C:\\Windows\\System32\\calc.exe',
        commandLine: 'calc.exe',
        creationTime: Date.now(),
        timestamp: Date.now()
      };

      const enqueued = monitor.enqueueEvent(event);
      expect(enqueued).toBe(true);

      const evaluation = await evaluatedPromise;
      expect(evaluation.pid).toBe(2001);
      expect(evaluation.verdict).toBe('ALLOW');
      expect(monitor.getHealth().processedEvents).toBe(1);
    });

    it('deduplicates identical event IDs without redundant evaluation', () => {
      const event: ProcessCreationEvent = {
        eventId: 'evt-dup-1',
        pid: 2002,
        processName: 'notepad.exe',
        creationTime: Date.now(),
        timestamp: Date.now()
      };

      expect(monitor.enqueueEvent(event)).toBe(true);
      expect(monitor.enqueueEvent(event)).toBe(false);
    });

    it('routes LOLBins into high-priority queue', async () => {
      const threatPromise = new Promise<any>((resolve) => {
        monitor.once('threatDetected', (t) => resolve(t));
      });

      const lolbinEvent: ProcessCreationEvent = {
        eventId: 'evt-lolbin-1',
        pid: 2003,
        processName: 'vssadmin.exe',
        executablePath: 'C:\\Windows\\System32\\vssadmin.exe',
        commandLine: 'vssadmin.exe delete shadows /all /quiet',
        creationTime: Date.now(),
        timestamp: Date.now()
      };

      monitor.enqueueEvent(lolbinEvent);

      const threatData = await threatPromise;
      expect(threatData.threat.threatName).toBe('VSSADMIN_SHADOW_DELETION');
      expect(threatData.evaluation.engineVerdict).toBe('CONTAIN_PROCESS');
      expect(threatData.evaluation.authorization).toBeDefined();
    });
  });

  describe('3. Bounded Queue & Backpressure Shedding', () => {
    it('sheds events when maxQueueSize is exceeded and emits backpressure event', async () => {
      const smallMonitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor,
        maxQueueSize: 10,
        workerConcurrency: 1
      });
      await smallMonitor.start();

      let backpressureEmitted = false;
      smallMonitor.on('backpressure', () => {
        backpressureEmitted = true;
      });

      // Flood with 25 events
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

      smallMonitor.stop();
    });
  });

  describe('4. Resource & Memory Bounds', () => {
    it('processes burst within bounded memory footprint (<200 MB)', async () => {
      const memBefore = process.memoryUsage().rss;

      await monitor.start();

      for (let i = 0; i < 200; i++) {
        monitor.enqueueEvent({
          eventId: `evt-mem-${i}`,
          pid: 4000 + i,
          processName: `proc_${i}.exe`,
          commandLine: `proc_${i}.exe --worker`,
          creationTime: Date.now(),
          timestamp: Date.now()
        });
      }

      // Allow queue processing
      await new Promise((r) => setTimeout(r, 200));

      const memAfter = process.memoryUsage().rss;
      const rssMb = (memAfter - memBefore) / (1024 * 1024);

      // Delta should be well within standard 200 MB bound
      expect(rssMb).toBeLessThan(100);
    });
  });
});
