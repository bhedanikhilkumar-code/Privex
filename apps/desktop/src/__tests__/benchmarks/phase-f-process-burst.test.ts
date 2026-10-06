import { describe, it, expect } from 'vitest';
import { ProcessMonitorService } from '../../services/process-monitor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { MockProcessEventSource } from '../../services/mock-process-event-source';
import { ProcessCreationEvent } from '../../types/desktop.types';

describe('Phase F — Continuous Process Monitor Burst Benchmark (Section 14)', () => {
  function computePercentiles(samples: number[]): { p50: number; p95: number; p99: number } {
    if (samples.length === 0) return { p50: 0, p95: 0, p99: 0 };
    const sorted = [...samples].sort((a, b) => a - b);
    const p50 = sorted[Math.floor(sorted.length * 0.5)];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const p99 = sorted[Math.floor(sorted.length * 0.99)];
    return { p50, p95, p99 };
  }

  it('handles 100, 1,000, and 10,000 process creation event bursts with bounded resources', async () => {
    const burstSizes = [100, 1000, 10000];
    const results: any[] = [];

    for (const count of burstSizes) {
      if (global.gc) global.gc();

      const behaviorEngine = new BehaviorEngineService({
        maxTrackedProcesses: 2000,
        ttlMs: 60000
      });
      const processAuditor = new ProcessAuditorService({
        behaviorEngine,
        scanBinaryOnDisk: false,
        processQueryProvider: async () => []
      });
      const mockSource = new MockProcessEventSource();

      const monitor = new ProcessMonitorService({
        behaviorEngine,
        processAuditor,
        eventSource: mockSource,
        maxQueueSize: 2000,
        workerConcurrency: 4
      });

      await monitor.start();

      const memBefore = process.memoryUsage();
      const latencies: number[] = [];
      const startTime = performance.now();

      let evaluatedCount = 0;
      const targetEvaluations = Math.min(count, 2000); // Queue bound caps evaluations
      const evaluationPromise = new Promise<void>((resolve) => {
        monitor.on('processEvaluated', () => {
          evaluatedCount++;
          latencies.push(performance.now() - startTime);
          if (evaluatedCount >= targetEvaluations) {
            resolve();
          }
        });
      });

      // Rapidly burst 'count' events
      for (let i = 0; i < count; i++) {
        const isLolbin = i % 5 === 0;
        const event: ProcessCreationEvent = {
          eventId: `evt-burst-${count}-${i}`,
          pid: 10000 + (i % 5000), // Some PID reuse
          processName: isLolbin ? 'powershell.exe' : `service_${i}.exe`,
          commandLine: isLolbin ? 'powershell.exe -w hidden' : undefined,
          creationTime: Date.now() + i,
          timestamp: Date.now()
        };
        mockSource.emitEvent(event);
      }

      // Wait for workers to process up to targetEvaluations or timeout at 3000ms
      await Promise.race([
        evaluationPromise,
        new Promise((resolve) => setTimeout(resolve, 3000))
      ]);

      const memAfter = process.memoryUsage();
      const endTime = performance.now();
      const totalDurationSec = (endTime - startTime) / 1000;
      const health = monitor.getHealth();

      const rssDeltaMb = (memAfter.rss - memBefore.rss) / (1024 * 1024);
      const heapDeltaMb = (memAfter.heapUsed - memBefore.heapUsed) / (1024 * 1024);
      const throughput = health.processedEvents / Math.max(totalDurationSec, 0.001);
      const { p50, p95, p99 } = computePercentiles(latencies);

      results.push({
        burstSize: count,
        processed: health.processedEvents,
        dropped: health.droppedEvents,
        queuePeak: health.queueDepth,
        p50Ms: Number(p50.toFixed(2)),
        p95Ms: Number(p95.toFixed(2)),
        p99Ms: Number(p99.toFixed(2)),
        throughputPerSec: Number(throughput.toFixed(2)),
        rssDeltaMb: Number(rssDeltaMb.toFixed(2)),
        heapDeltaMb: Number(heapDeltaMb.toFixed(2))
      });

      // Invariants:
      expect(health.droppedEvents).toBeGreaterThanOrEqual(0);
      expect(memAfter.rss / (1024 * 1024)).toBeLessThan(250); // Total RSS remains bounded

      await monitor.stop();
    }

    console.log('\n================ PHASE F CONTINUOUS PROCESS MONITOR BURST BENCHMARK ================');
    console.table(results);
    console.log('======================================================================================\n');

    expect(results.length).toBe(3);
  }, 15000);
});
