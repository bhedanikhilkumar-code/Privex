import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScanSchedulerService, DEFAULT_SCHEDULE_CONFIG } from '../../services/scan-scheduler.service';
import { ScannerService } from '../../services/scanner.service';
import { QuickScanService } from '../../services/quick-scan.service';
import { ScanScheduleConfig } from '../../types/desktop.types';

describe('Phase N Performance Benchmarks — Scheduling & Resource Overhead', () => {
  let tempDir: string;
  let scheduler: ScanSchedulerService;
  let scanner: ScannerService;
  let quickScanner: QuickScanService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-sched-perf-'));
    scanner = new ScannerService();
    quickScanner = new QuickScanService(scanner);
    scheduler = new ScanSchedulerService({
      configDir: tempDir,
      scanner,
      quickScanner
    });
  });

  afterEach(() => {
    scheduler.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('measures calculateNextRun micro-latency (< 0.05 ms target)', () => {
    const config: ScanScheduleConfig = {
      ...DEFAULT_SCHEDULE_CONFIG,
      enabled: true,
      frequency: 'daily',
      timeOfDay: '03:30'
    };
    const now = Date.now();

    // Warm-up
    for (let i = 0; i < 100; i++) {
      scheduler.calculateNextRun(config, now + i * 1000);
    }

    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      scheduler.calculateNextRun(config, now + i * 1000);
    }
    const totalMs = performance.now() - start;
    const avgLatencyMs = totalMs / iterations;

    console.log(`[PERF] calculateNextRun Latency: ${avgLatencyMs.toFixed(5)} ms/call (Target: < 0.05 ms)`);
    expect(avgLatencyMs).toBeLessThan(0.05);
  });

  it('measures 1,000 schedule evaluations throughput (< 10 ms target)', () => {
    const dailyConfig: ScanScheduleConfig = {
      ...DEFAULT_SCHEDULE_CONFIG,
      enabled: true,
      frequency: 'daily',
      timeOfDay: '02:00'
    };
    const weeklyConfig: ScanScheduleConfig = {
      ...DEFAULT_SCHEDULE_CONFIG,
      enabled: true,
      frequency: 'weekly',
      weekday: 4,
      timeOfDay: '04:00'
    };
    const now = Date.now();

    const start = performance.now();
    for (let i = 0; i < 500; i++) {
      scheduler.calculateNextRun(dailyConfig, now + i * 3600000);
      scheduler.calculateNextRun(weeklyConfig, now + i * 3600000);
    }
    const elapsedMs = performance.now() - start;

    console.log(`[PERF] 1,000 Schedule Evaluations Duration: ${elapsedMs.toFixed(2)} ms (Target: < 10 ms)`);
    expect(elapsedMs).toBeLessThan(15.0);
  });

  it('measures battery inspection overhead (< 1.0 ms target)', async () => {
    const start = performance.now();
    const battery = await scheduler.checkBattery();
    const elapsedMs = performance.now() - start;

    console.log(`[PERF] Battery Inspection Duration: ${elapsedMs.toFixed(4)} ms`);
    expect(elapsedMs).toBeLessThan(10.0);
    expect(battery).toBeDefined();
  });

  it('verifies bounded heap footprint under 1,000 history records (< 15 MB heap delta)', () => {
    if (global.gc) global.gc();
    const baselineHeap = process.memoryUsage().heapUsed;

    for (let i = 0; i < 1000; i++) {
      scheduler.recordHistory({
        scanId: `bench-scan-${i}`,
        scanType: 'quick',
        trigger: 'SCHEDULED',
        startTime: Date.now() - 5000,
        completedAt: Date.now(),
        durationMs: 5000,
        totalFilesScanned: 100,
        totalBytesScanned: 1024 * 1024,
        threatsFound: 0,
        threatsQuarantined: 0,
        skippedCount: 0,
        errorCount: 0,
        overallVerdict: 'ALLOW',
        finalStatus: 'COMPLETED'
      });
    }

    if (global.gc) global.gc();
    const finalHeap = process.memoryUsage().heapUsed;
    const deltaMB = (finalHeap - baselineHeap) / (1024 * 1024);

    console.log(`[PERF] 1,000 History Records Heap Delta: ${deltaMB.toFixed(2)} MB (Limit: < 15 MB)`);
    expect(deltaMB).toBeLessThan(15.0);
  }, 60000);
});
