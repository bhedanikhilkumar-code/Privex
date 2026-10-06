import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { FileAnalyzer } from '../../core/file-analyzer';
import { QuarantineService } from '../../services/quarantine.service';

describe('Phase 7 Desktop Performance & Latency Benchmark', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-benchmark-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('measures real micro-latencies across desktop execution paths', async () => {
    // Prepare test file
    const samplePath = path.join(tempDir, 'benchmark_sample.pdf.exe');
    const sampleBytes = Buffer.concat([
      Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
      crypto.randomBytes(64 * 1024) // 64 KB
    ]);
    fs.writeFileSync(samplePath, sampleBytes);

    const iterations = 30;

    // 1. File Header & Heuristic Analysis
    const headerTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      await FileAnalyzer.analyzeFile(samplePath);
      headerTimes.push(performance.now() - t0);
    }

    // 2. Pure Entropy Calculation
    const entropyTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      FileAnalyzer.calculateEntropy(sampleBytes);
      entropyTimes.push(performance.now() - t0);
    }

    // 3. SHA-256 Hashing
    const hashTimes: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      await FileAnalyzer.computeSha256(samplePath);
      hashTimes.push(performance.now() - t0);
    }

    // 4. Quarantine Vault Isolation
    const vaultDir = path.join(tempDir, 'vault');
    const quarantine = new QuarantineService(vaultDir);
    const quarantineTimes: number[] = [];

    for (let i = 0; i < 10; i++) {
      const iterPath = path.join(tempDir, `iter_${i}.exe`);
      fs.writeFileSync(iterPath, sampleBytes);
      const threat = {
        id: `bench-${i}`,
        filePath: iterPath,
        fileName: `iter_${i}.exe`,
        fileSize: sampleBytes.length,
        sha256: 'mock-hash',
        riskScore: 80,
        severity: 'dangerous' as const,
        verdict: 'BLOCK' as const,
        threatName: 'BENCHMARK',
        detectedAt: Date.now(),
        evidenceFactors: [],
        quarantined: false
      };

      const t0 = performance.now();
      await quarantine.isolateFile(threat);
      quarantineTimes.push(performance.now() - t0);
    }

    const calcP = (arr: number[], percentile: number) => {
      const sorted = [...arr].sort((a, b) => a - b);
      const idx = Math.min(sorted.length - 1, Math.floor((percentile / 100) * sorted.length));
      return Math.round(sorted[idx] * 1000) / 1000;
    };

    const mem = process.memoryUsage();
    const heapUsedMb = Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100;
    const rssMb = Math.round((mem.rss / 1024 / 1024) * 100) / 100;

    console.log('\n================ PHASE 7 DESKTOP LATENCY & PERFORMANCE BENCHMARKS ================');
    console.log(`File Analysis (Full):   p50: ${calcP(headerTimes, 50)} ms | p95: ${calcP(headerTimes, 95)} ms | max: ${calcP(headerTimes, 100)} ms`);
    console.log(`Byte Entropy (64 KB):   p50: ${calcP(entropyTimes, 50)} ms | p95: ${calcP(entropyTimes, 95)} ms | max: ${calcP(entropyTimes, 100)} ms`);
    console.log(`SHA-256 Hashing:        p50: ${calcP(hashTimes, 50)} ms | p95: ${calcP(hashTimes, 95)} ms | max: ${calcP(hashTimes, 100)} ms`);
    console.log(`Quarantine Isolation:   p50: ${calcP(quarantineTimes, 50)} ms | p95: ${calcP(quarantineTimes, 95)} ms | max: ${calcP(quarantineTimes, 100)} ms`);
    console.log('----------------------------------------------------------------------------------');
    console.log(`Memory Footprint:       Heap Used: ${heapUsedMb} MB | RSS: ${rssMb} MB`);
    console.log('==================================================================================\n');

    expect(calcP(headerTimes, 50)).toBeLessThan(100.0);
    expect(heapUsedMb).toBeLessThan(150.0);
  });

  it('R8-F & R8-M: verifies <=64 KB single-open SHA-256 fast-path and in-memory SecureStorageService settings cache', async () => {
    const { SecureStorageService } = await import('../../services/secure-storage.service');
    const smallFilePath = path.join(tempDir, 'small_script.pdf.exe');
    const smallBytes = Buffer.concat([
      Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
      crypto.randomBytes(16 * 1024) // 16 KB (<= 64 KB)
    ]);
    fs.writeFileSync(smallFilePath, smallBytes);

    const expectedSha256 = crypto.createHash('sha256').update(smallBytes).digest('hex');
    const res = await FileAnalyzer.analyzeFile(smallFilePath);
    expect(res.sha256).toBe(expectedSha256);
    expect(res.verdict).toBe('BLOCK');

    // Verify SecureStorageService.getSettings() in-memory cache avoids disk/crypto on repeat reads
    const storage = new SecureStorageService(path.join(tempDir, 'cfg'));
    storage.saveSettings({ scanLargeFilesLimitMb: 75 });
    const t0 = performance.now();
    for (let i = 0; i < 100; i++) {
      const s = storage.getSettings();
      expect(s.scanLargeFilesLimitMb).toBe(75);
    }
    const elapsed100 = performance.now() - t0;
    expect(elapsed100).toBeLessThan(100);
  });
});
