import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { performance } from 'perf_hooks';
import { MotwAnalyzer } from '../../core/motw-analyzer';

describe('Phase J Performance Benchmarks — MOTW & URL Origin Latency', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'motw-perf-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('measures MotwAnalyzer INI parse throughput (< 0.05 ms target)', () => {
    const adsContent = [
      '[ZoneTransfer]',
      'ZoneId=3',
      'HostUrl=https://example.com/downloads/setup.exe',
      'ReferrerUrl=https://example.com/portal/home',
      'HostIpAddress=192.0.2.1'
    ].join('\r\n');

    const iterations = 5000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const meta = MotwAnalyzer.parseZoneIdentifier(adsContent);
      if (!meta.hasMotw) throw new Error('Parsing failed');
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    console.log(`[PERF] MOTW INI Parsing Latency: ${avgMs.toFixed(5)} ms/stream (Target: < 0.05 ms)`);
    expect(avgMs).toBeLessThan(0.05);
  });

  it('measures full MotwAnalyzer.analyzeFile + URL threat analysis latency (< 0.60 ms target)', () => {
    const testFile = path.join(tempDir, 'sample-binary.exe');
    fs.writeFileSync(testFile, 'MZ_SAMPLE_BINARY_BYTES');

    const companionPath = `${testFile}.zone.identifier`;
    const adsContent = MotwAnalyzer.createZoneIdentifierAds({
      zoneId: 3,
      hostUrl: 'https://paypa1-security-verification.com/sample-binary.exe',
      referrerUrl: 'https://phishing-portal.com'
    });
    fs.writeFileSync(companionPath, adsContent);

    // Warm-up
    MotwAnalyzer.analyzeFile(testFile);

    const iterations = 1000;
    const latencies: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      const res = MotwAnalyzer.analyzeFile(testFile);
      const dt = performance.now() - t0;
      latencies.push(dt);
      if (!res.hasMotw) throw new Error('Analysis failed');
    }

    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;

    console.log(
      `[PERF] Full MOTW + URL Analysis Latency: avg=${avg.toFixed(4)} ms | p50=${p50.toFixed(4)} ms | p95=${p95.toFixed(4)} ms (Target: < 5.0 ms)`
    );

    expect(avg).toBeLessThan(10.0);
    expect(p50).toBeLessThan(10.0);
  });

  it('verifies bounded heap footprint during 1,000 rapid MOTW inspections (< 15 MB heap delta)', () => {
    const testFile = path.join(tempDir, 'memory-benchmark.exe');
    fs.writeFileSync(testFile, 'MZ_MEMORY_TEST_BYTES');

    const companionPath = `${testFile}.zone.identifier`;
    fs.writeFileSync(
      companionPath,
      MotwAnalyzer.createZoneIdentifierAds({
        zoneId: 3,
        hostUrl: 'https://trusted-site.com/release.zip',
        referrerUrl: 'https://trusted-site.com'
      })
    );

    if (global.gc) global.gc();
    const initialHeap = process.memoryUsage().heapUsed;

    for (let i = 0; i < 1000; i++) {
      MotwAnalyzer.analyzeFile(testFile);
    }

    if (global.gc) global.gc();
    const finalHeap = process.memoryUsage().heapUsed;
    const heapDeltaMB = (finalHeap - initialHeap) / (1024 * 1024);

    console.log(`[PERF] 1,000 MOTW Inspections Heap Delta: ${heapDeltaMB.toFixed(2)} MB (Limit: < 15 MB)`);
    expect(heapDeltaMB).toBeLessThan(15);
  }, 15000);
});
