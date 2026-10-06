import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { performance } from 'perf_hooks';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { QuarantineService } from '../../services/quarantine.service';

function computeStats(samples: number[]) {
  const sorted = [...samples].sort((a, b) => a - b);
  const min = sorted[0] ?? 0;
  const max = sorted[sorted.length - 1] ?? 0;
  const p50 = sorted[Math.floor(sorted.length * 0.5)] ?? 0;
  const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] ?? 0;
  const p99 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))] ?? 0;
  const avg = sorted.reduce((a, b) => a + b, 0) / (sorted.length || 1);
  return {
    min: Number(min.toFixed(3)),
    p50: Number(p50.toFixed(3)),
    p95: Number(p95.toFixed(3)),
    p99: Number(p99.toFixed(3)),
    max: Number(max.toFixed(3)),
    avg: Number(avg.toFixed(3))
  };
}

describe('Phase E — Real-Time Ingress Latency & Performance Benchmark Suite', () => {
  let workDir: string;
  let watchDir: string;
  let vaultDir: string;
  let monitor: RealtimeMonitorService;
  let quarantine: QuarantineService;

  beforeAll(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-e-bench-'));
    watchDir = path.join(workDir, 'watch');
    vaultDir = path.join(workDir, 'vault');
    fs.mkdirSync(watchDir, { recursive: true });
    fs.mkdirSync(vaultDir, { recursive: true });

    quarantine = new QuarantineService(vaultDir);
    monitor = new RealtimeMonitorService(
      {
        recursive: true,
        debounceMs: 5,
        stabilityCheckMs: 0,
        stabilityRetries: 1,
        autoQuarantineCritical: true,
        maxQueueSize: 5000,
        concurrencyLimit: 4
      },
      quarantine
    );
    monitor.start([watchDir]);
  });

  afterAll(() => {
    monitor.stop();
    if (fs.existsSync(workDir)) {
      try {
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch {
        // Ignore
      }
    }
  });

  it('measures real-time ingress detection & auto-quarantine latency (<50 ms p95 SLA)', async () => {
    const N = 30;
    const ingressLatencies: number[] = [];

    const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000', 'hex');
    const evilPayload = Buffer.from('powershell.exe -EncodedCommand VirtualAlloc Mimikatz', 'ascii');
    const threatBytes = Buffer.concat([mzHeader, evilPayload]);

    for (let i = 0; i < N; i++) {
      const fileName = `bench_download_${i}.pdf.exe`;
      const tempPath = path.join(watchDir, `${fileName}.crdownload`);
      const finalPath = path.join(watchDir, fileName);

      // Simulate partial download write
      fs.writeFileSync(tempPath, threatBytes);

      // Measure time from download completion / rename to threat detected & quarantined
      const start = performance.now();
      const threatPromise = new Promise<void>((resolve) => {
        const handler = (threat: any) => {
          if (threat.fileName === fileName) {
            monitor.off('threatDetected', handler);
            resolve();
          }
        };
        monitor.on('threatDetected', handler);
      });

      // Browser renames .crdownload to final target
      fs.renameSync(tempPath, finalPath);

      await threatPromise;
      const elapsed = performance.now() - start;
      ingressLatencies.push(elapsed);
    }

    const stats = computeStats(ingressLatencies);
    const queueStats = monitor.getQueueStats();
    const totalBenchmarkDurationMs = ingressLatencies.reduce((a, b) => a + b, 0);
    const throughputPerSec = Number((N / (totalBenchmarkDurationMs / 1000)).toFixed(2));
    const memUsage = process.memoryUsage();
    const peakRssMb = Number((memUsage.rss / (1024 * 1024)).toFixed(2));

    console.log('\n================ PHASE E REAL-TIME INGRESS BENCHMARK ================');
    console.log(
      JSON.stringify(
        {
          sampleSize: N,
          ingressLatencyStatsMs: stats,
          throughputFilesPerSec: throughputPerSec,
          peakRssMb,
          queueTelemetry: queueStats,
          slaTargetMs: 50.0,
          p95Compliant: queueStats.p95LatencyMs < 50.0
        },
        null,
        2
      )
    );
    console.log('======================================================================\n');

    // SLA Verification: p95 ingress detection latency must be strictly < 50 ms
    expect(queueStats.p95LatencyMs).toBeLessThan(50.0);
    expect(queueStats.threatsDetectedCount).toBeGreaterThanOrEqual(N);
    expect(queueStats.quarantinedCount).toBeGreaterThanOrEqual(N);
  }, 60000);
});
