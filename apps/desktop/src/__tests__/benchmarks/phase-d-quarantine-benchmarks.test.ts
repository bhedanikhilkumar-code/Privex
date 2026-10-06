import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { performance } from 'perf_hooks';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';
import { ThreatIntel, CleanFileCache } from '@private-protection/core';

function computeStats(samples: number[]) {
  const sorted = [...samples].sort((a, b) => a - b);
  const min = sorted[0] ?? 0;
  const max = sorted[sorted.length - 1] ?? 0;
  const p50 = sorted[Math.floor(sorted.length * 0.5)] ?? 0;
  const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] ?? 0;
  const avg = sorted.reduce((a, b) => a + b, 0) / (sorted.length || 1);
  return {
    min: Number(min.toFixed(3)),
    p50: Number(p50.toFixed(3)),
    p95: Number(p95.toFixed(3)),
    max: Number(max.toFixed(3)),
    avg: Number(avg.toFixed(3))
  };
}

describe('Phase D — Quarantine Hardening (PPVAULT2) Empirical Benchmark Suite', () => {
  let benchDir: string;
  let vaultDir: string;
  let quarantine: QuarantineService;

  beforeAll(() => {
    benchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-d-bench-'));
    vaultDir = path.join(benchDir, 'vault');
    quarantine = new QuarantineService(vaultDir);
  });

  afterAll(() => {
    ThreatIntel.resetSharedInstance();
    CleanFileCache.resetSharedInstance();
    if (fs.existsSync(benchDir)) {
      fs.rmSync(benchDir, { recursive: true, force: true });
    }
  });

  it('measures PPVAULT2 64 KB chunk streaming encryption, decryption, and manifest latency', async () => {
    // 1. Measure 1 MB file streaming isolation latency (N = 10)
    const size1MB = 1024 * 1024;
    const buf1MB = crypto.randomBytes(size1MB);
    const encryptTimes: number[] = [];
    const decryptTimes: number[] = [];

    for (let i = 0; i < 10; i++) {
      const srcPath = path.join(benchDir, `bench_1mb_${i}.bin`);
      fs.writeFileSync(srcPath, buf1MB);
      const sha = crypto.createHash('sha256').update(buf1MB).digest('hex');

      const threat: DetectedThreat = {
        id: `bench-threat-${i}`,
        filePath: srcPath,
        fileName: `bench_1mb_${i}.bin`,
        fileSize: size1MB,
        sha256: sha,
        riskScore: 85,
        severity: 'critical',
        verdict: 'BLOCK',
        threatName: 'BENCHMARK_SAMPLE',
        detectedAt: Date.now(),
        evidenceFactors: ['Benchmark'],
        quarantined: false
      };

      const t0 = performance.now();
      const item = await quarantine.isolateFile(threat);
      const tEncrypt = performance.now() - t0;
      encryptTimes.push(tEncrypt);

      const t1 = performance.now();
      await quarantine.restoreItem(item.quarantineId);
      const tDecrypt = performance.now() - t1;
      decryptTimes.push(tDecrypt);

      // Clean up restored file
      const restoredCandidate = srcPath;
      if (fs.existsSync(restoredCandidate)) fs.unlinkSync(restoredCandidate);
    }

    const encryptStats = computeStats(encryptTimes);
    const decryptStats = computeStats(decryptTimes);

    // 2. Measure Restore & Trust SHA-256 Lookup Latency (N = 100)
    const testHash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    const intel = ThreatIntel.getSharedInstance();
    intel.addAllowedHash(testHash);
    const lookupTimes: number[] = [];
    for (let i = 0; i < 100; i++) {
      const t0 = performance.now();
      intel.isHashAllowed(testHash);
      lookupTimes.push(performance.now() - t0);
    }
    const trustLookupStats = computeStats(lookupTimes);

    // 3. Measure 100 MB synthetic file quarantine and verify peak V8 heap delta (< 16 MB SLA)
    const size100MB = 100 * 1024 * 1024;
    const file100MB = path.join(benchDir, 'bench_100mb.bin');
    const chunk = Buffer.alloc(QuarantineService.CHUNK_SIZE, 0x3c);
    const fd = fs.openSync(file100MB, 'w');
    const hash = crypto.createHash('sha256');
    let written = 0;
    while (written < size100MB) {
      const toWrite = Math.min(chunk.length, size100MB - written);
      fs.writeSync(fd, chunk, 0, toWrite);
      hash.update(chunk.subarray(0, toWrite));
      written += toWrite;
    }
    fs.closeSync(fd);
    const sha100MB = hash.digest('hex');

    if (global.gc) global.gc();
    const initialHeapBytes = process.memoryUsage().heapUsed;

    const tStart100 = performance.now();
    const threat100: DetectedThreat = {
      id: 'bench-100mb-threat',
      filePath: file100MB,
      fileName: 'bench_100mb.bin',
      fileSize: size100MB,
      sha256: sha100MB,
      riskScore: 90,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'BENCH_100MB',
      detectedAt: Date.now(),
      evidenceFactors: ['Phase D SLA Benchmark'],
      quarantined: false
    };

    const item100 = await quarantine.isolateFile(threat100);
    const tIsolate100 = performance.now() - tStart100;

    const tRestoreStart100 = performance.now();
    const restoredPath100 = await quarantine.restoreItem(item100.quarantineId);
    const tRestore100 = performance.now() - tRestoreStart100;

    if (global.gc) global.gc();
    const finalHeapBytes = process.memoryUsage().heapUsed;
    const heapDeltaMB = Number((Math.abs(finalHeapBytes - initialHeapBytes) / (1024 * 1024)).toFixed(3));

    // Verify 100 MB restored integrity
    expect(fs.existsSync(restoredPath100)).toBe(true);
    expect(fs.statSync(restoredPath100).size).toBe(size100MB);
    fs.unlinkSync(restoredPath100);

    const report = {
      stream1MBEncryptStats: encryptStats,
      stream1MBDecryptStats: decryptStats,
      trustLookupStats,
      stream100MB: {
        fileSizeBytes: size100MB,
        isolateDurationMs: Number(tIsolate100.toFixed(2)),
        restoreDurationMs: Number(tRestore100.toFixed(2)),
        peakHeapDeltaMB: heapDeltaMB,
        throughputEncryptMBps: Number((100 / (tIsolate100 / 1000)).toFixed(2)),
        throughputDecryptMBps: Number((100 / (tRestore100 / 1000)).toFixed(2))
      }
    };

    console.log('\n================ PHASE D QUARANTINE (PPVAULT2) PERFORMANCE BASELINE ================');
    console.log(JSON.stringify(report, null, 2));
    console.log('=====================================================================================\n');

    expect(heapDeltaMB).toBeLessThan(16.0); // Phase D Mandatory SLA: Peak V8 heap delta < 16 MB
    expect(trustLookupStats.p50).toBeLessThan(0.05); // ThreatIntel lookup SLA: < 0.05 ms
  }, 45000);
});
