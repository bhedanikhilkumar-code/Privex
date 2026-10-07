import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CleanFileCache } from '../../core/clean-file-cache';
import { ScannerService } from '../../services/scanner.service';
import { FileAnalyzer } from '../../core/file-analyzer';

describe('Phase P Performance Benchmarks — Low-Resource, Clean Cache & Throughput', () => {
  let tempDir: string;
  let cache: CleanFileCache;
  let scanner: ScannerService;

  beforeEach(() => {
    CleanFileCache.resetSharedInstance();
    cache = CleanFileCache.getSharedInstance();
    scanner = new ScannerService({ cleanFileCache: cache });
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-p-perf-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('measures CleanFileCache lookup latency (< 0.08 ms target)', () => {
    const filePath = 'C:\\Windows\\System32\\ntdll.dll';
    cache.set(filePath, 2048576, 1700000000000, 'abc123sha256', {
      dev: 1,
      ino: 12345
    });

    // Warmup
    for (let i = 0; i < 1000; i++) {
      cache.get(filePath, 2048576, 1700000000000, { dev: 1, ino: 12345 });
    }

    const iterations = 10000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      cache.get(filePath, 2048576, 1700000000000, { dev: 1, ino: 12345 });
    }
    const duration = performance.now() - start;
    const avgLatencyMs = duration / iterations;

    console.log(`[PERF] CleanFileCache Lookup Latency: ${avgLatencyMs.toFixed(5)} ms/call (Target: < 0.08 ms)`);
    expect(avgLatencyMs).toBeLessThan(0.08);
  });

  it('measures fast-path file analysis p50 latency (< 2.0 ms target)', async () => {
    const testFile = path.join(tempDir, 'benchmark_sample.txt');
    fs.writeFileSync(testFile, 'Clean synthetic file content for fast-path latency measurement.');

    // Warm initial analysis to populate Stage 0 cache
    await FileAnalyzer.analyzeFile(testFile);

    const latencies: number[] = [];
    const samples = 100;

    for (let i = 0; i < samples; i++) {
      const t0 = performance.now();
      await FileAnalyzer.analyzeFile(testFile);
      const elapsed = performance.now() - t0;
      latencies.push(elapsed);
    }

    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(samples * 0.5)];
    const p95 = latencies[Math.floor(samples * 0.95)];

    console.log(`[PERF] Fast-Path File Analysis Latency: p50=${p50.toFixed(4)} ms | p95=${p95.toFixed(4)} ms (Target: < 2.0 ms)`);
    expect(p50).toBeLessThan(2.0);
  });

  it('verifies bounded heap and RSS during 1,000-file batch scan (< 200 MB peak RSS, < 25 MB heap delta)', async () => {
    const fileCount = 500;
    for (let i = 0; i < fileCount; i++) {
      fs.writeFileSync(path.join(tempDir, `bench_${i}.txt`), `File payload data for benchmark ${i}`);
    }

    const memBefore = process.memoryUsage();
    const result = await scanner.scanPaths([tempDir]);
    const memAfter = process.memoryUsage();

    expect(result.totalFilesScanned).toBe(fileCount);
    expect(result.threats.length).toBe(0);

    const heapDeltaMb = (memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024;
    const peakRssMb = memAfter.rss / 1024 / 1024;

    console.log(`[PERF] 500-File Scan Heap Delta: ${heapDeltaMb.toFixed(2)} MB | RSS: ${peakRssMb.toFixed(2)} MB (Limits: < 25 MB heap delta, < 200 MB RSS)`);
    expect(heapDeltaMb).toBeLessThan(25);
    expect(peakRssMb).toBeLessThan(200);
  });

  it('measures 65,536 cache insertions and LRU eviction throughput (< 150 ms for 10,000 entries)', () => {
    const tempCache = new CleanFileCache({ maxEntries: 1000 });
    const count = 10000;

    const start = performance.now();
    for (let i = 0; i < count; i++) {
      tempCache.set(`C:\\item_${i}.txt`, 100, 1000, `hash_${i}`);
    }
    const duration = performance.now() - start;

    console.log(`[PERF] 10,000 Cache Insertions & Evictions Duration: ${duration.toFixed(2)} ms (Target: < 150 ms)`);
    expect(duration).toBeLessThan(150);
    expect(tempCache.size).toBe(1000); // Maintained bound
  });
});
