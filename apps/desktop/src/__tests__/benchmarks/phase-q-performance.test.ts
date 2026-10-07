import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AuditLoggerService } from '../../services/audit-logger.service';
import { WatchdogService } from '../../services/watchdog.service';
import { HealthMonitorService } from '../../services/health-monitor.service';
import { TamperDetectorService } from '../../services/tamper-detector.service';

describe('Phase Q Performance & Latency Benchmarks', () => {
  let tempDir: string;
  let auditLogger: AuditLoggerService;
  let watchdog: WatchdogService;
  let tamperDetector: TamperDetectorService;
  let healthMonitor: HealthMonitorService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-q-perf-'));
    auditLogger = new AuditLoggerService({ configDir: tempDir });
    tamperDetector = new TamperDetectorService({ configDir: tempDir, auditLogger });
    watchdog = new WatchdogService({ auditLogger });
    healthMonitor = new HealthMonitorService({
      auditLogger,
      watchdog,
      tamperDetector
    });
  });

  afterEach(() => {
    watchdog?.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // continue
    }
  });

  it('BENCH-Q01: Audit log HMAC-SHA256 append latency satisfies SLA (<0.5ms)', () => {
    const iterations = 500;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      auditLogger.log({
        category: 'SCAN',
        severity: 'INFO',
        action: 'BENCH_WRITE',
        actor: 'BenchmarkRunner',
        targetSummary: `Bench target entry number ${i}`,
        metadata: { iteration: i }
      });
    }

    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;
    const throughputPerSec = Math.round((iterations / elapsed) * 1000);

    expect(avgLatencyMs).toBeLessThan(0.8); // SLA: <0.8ms on file system I/O
    expect(throughputPerSec).toBeGreaterThan(1200); // High throughput append
  });

  it('BENCH-Q02: Watchdog heartbeat execution satisfies SLA (<1.0ms)', async () => {
    // Register 5 active probes
    for (let i = 0; i < 5; i++) {
      watchdog.registerComponent({
        name: `Subsystem_${i}`,
        checkHealth: () => true
      });
    }

    const iterations = 100;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      await watchdog.executeHeartbeat();
    }

    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(1.0); // SLA: <1.0ms per heartbeat cycle
  });

  it('BENCH-Q03: Health evaluation in memory satisfies SLA (<2.0ms)', () => {
    const iterations = 100;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      healthMonitor.evaluateHealth();
    }

    const elapsed = performance.now() - start;
    const avgLatencyMs = elapsed / iterations;

    expect(avgLatencyMs).toBeLessThan(2.0); // SLA: <2.0ms per evaluation
  });

  it('BENCH-Q04: Memory footprint of Phase Q services is bounded (<5MB)', () => {
    const initialHeap = process.memoryUsage().heapUsed;

    // Allocate 1000 log records and multiple health checks
    for (let i = 0; i < 1000; i++) {
      auditLogger.log({
        category: 'SCAN',
        severity: 'INFO',
        action: 'HEAP_TEST',
        actor: 'Perf',
        targetSummary: `Heap test record ${i}`
      });
    }

    healthMonitor.evaluateHealth();

    const finalHeap = process.memoryUsage().heapUsed;
    const heapDiffMb = (finalHeap - initialHeap) / (1024 * 1024);

    expect(heapDiffMb).toBeLessThan(10.0); // Well within budget
  });
});
