import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { performance, monitorEventLoopDelay } from 'perf_hooks';
import { DetectionPipeline } from '@private-protection/core';
import { FileAnalyzer } from '../../core/file-analyzer';
import { ScannerService } from '../../services/scanner.service';
import { IpcHandler } from '../../ipc/ipc-handler';

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

describe('Phase A — Empirical Performance Baseline Suite (Step 14)', () => {
  let benchDir: string;
  let smallFile1KB: string;
  let mediumFile1MB: string;
  let largeFile25MB: string;
  let dir100Root: string;

  beforeAll(() => {
    benchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-a-bench-'));
    smallFile1KB = path.join(benchDir, 'small_1kb.bin');
    mediumFile1MB = path.join(benchDir, 'medium_1mb.bin');
    largeFile25MB = path.join(benchDir, 'large_25mb.bin');
    dir100Root = path.join(benchDir, 'nested_100');

    fs.writeFileSync(smallFile1KB, crypto.randomBytes(1024));
    fs.writeFileSync(mediumFile1MB, crypto.randomBytes(1024 * 1024));
    fs.writeFileSync(largeFile25MB, crypto.randomBytes(25 * 1024 * 1024));

    // Create 100 files across 10 nested folders
    for (let f = 0; f < 10; f++) {
      const subDir = path.join(dir100Root, `group_${Math.floor(f / 2)}`, `sub_${f}`);
      fs.mkdirSync(subDir, { recursive: true });
      for (let i = 0; i < 10; i++) {
        const idx = f * 10 + i;
        if (idx < 5) {
          // 5 synthetic deceptive executables
          const filePath = path.join(subDir, `invoice_${idx}.pdf.exe`);
          fs.writeFileSync(filePath, Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), Buffer.alloc(2044, 0x41)]));
        } else {
          const filePath = path.join(subDir, `clean_${idx}.txt`);
          fs.writeFileSync(filePath, `Clean benchmark test file #${idx}\n`.repeat(120));
        }
      }
    }
  });

  afterAll(() => {
    if (fs.existsSync(benchDir)) {
      fs.rmSync(benchDir, { recursive: true, force: true });
    }
  });

  it('measures and reports all 8 required Phase A performance baseline metrics', async () => {
    const memBefore = process.memoryUsage();

    // 1. Application / Service Initialization Startup Time
    const tCold0 = performance.now();
    const coldPipeline = new DetectionPipeline();
    expect(coldPipeline).toBeDefined();
    const coldCoreInitMs = Number((performance.now() - tCold0).toFixed(3));

    const serviceInitSamples: number[] = [];
    for (let i = 0; i < 10; i++) {
      const vDir = path.join(benchDir, `v_${i}`);
      const cDir = path.join(benchDir, `c_${i}`);
      const t0 = performance.now();
      const handler = new IpcHandler({ vaultDir: vDir, configDir: cDir, autoStartRealtime: false });
      expect(handler.handleGetProtectionStatus().offlineMode).toBe(true);
      serviceInitSamples.push(performance.now() - t0);
    }
    const serviceInitStats = computeStats(serviceInitSamples);

    // 2. Scanner Startup Overhead
    const scanner = new ScannerService();
    const startupOverheads: number[] = [];
    for (let i = 0; i < 20; i++) {
      let tStarted = 0;
      scanner.once('started', () => {
        tStarted = performance.now();
      });
      const t0 = performance.now();
      await scanner.scanPaths([smallFile1KB], 'custom');
      startupOverheads.push(Math.max(0.001, tStarted - t0));
    }
    const scannerStartupStats = computeStats(startupOverheads);

    // 3. Small-File Scan (1 KB)
    const smallSamples: number[] = [];
    for (let i = 0; i < 30; i++) {
      const t0 = performance.now();
      await FileAnalyzer.analyzeFile(smallFile1KB);
      smallSamples.push(performance.now() - t0);
    }
    const smallStats = computeStats(smallSamples);

    // 4. Medium-File Scan (1 MB)
    const mediumSamples: number[] = [];
    for (let i = 0; i < 15; i++) {
      const t0 = performance.now();
      await FileAnalyzer.analyzeFile(mediumFile1MB);
      mediumSamples.push(performance.now() - t0);
    }
    const mediumStats = computeStats(mediumSamples);

    // 5. Large-File Scan (25 MB)
    const largeSamples: number[] = [];
    const memBefore25MB = process.memoryUsage();
    for (let i = 0; i < 5; i++) {
      const t0 = performance.now();
      const res = await FileAnalyzer.analyzeFile(largeFile25MB);
      expect(res.fileSize).toBe(25 * 1024 * 1024);
      largeSamples.push(performance.now() - t0);
    }
    const memAfter25MB = process.memoryUsage();
    const largeStats = computeStats(largeSamples);

    // 6. Directory Scan (100 files across 10 nested subfolders) + 8. CPU & Event Loop Delay
    const loopDelay = monitorEventLoopDelay({ resolution: 10 });
    loopDelay.enable();
    const cpuStart = process.cpuUsage();
    const wallStart = performance.now();

    const dirSamples: number[] = [];
    let lastDirResult: any;
    for (let i = 0; i < 5; i++) {
      const t0 = performance.now();
      lastDirResult = await scanner.scanPaths([dir100Root], 'custom');
      dirSamples.push(performance.now() - t0);
    }

    const wallElapsedMs = performance.now() - wallStart;
    const cpuDelta = process.cpuUsage(cpuStart);
    loopDelay.disable();

    const dirStats = computeStats(dirSamples);
    expect(lastDirResult.totalFilesScanned).toBe(100);
    expect(lastDirResult.threats.length).toBe(5);

    const memAfterAll = process.memoryUsage();
    const singleCoreCpuPct = Number((((cpuDelta.user + cpuDelta.system) / 1000 / wallElapsedMs) * 100).toFixed(2));
    const systemNormalizedCpuPct = Number((singleCoreCpuPct / os.cpus().length).toFixed(2));

    const report = {
      coldCoreInitMs,
      serviceInitStats,
      scannerStartupStats,
      small1KBStats: smallStats,
      medium1MBStats: mediumStats,
      large25MBStats: largeStats,
      dir100FilesStats: dirStats,
      memory: {
        baselineRssMB: Number((memBefore.rss / 1024 / 1024).toFixed(2)),
        baselineHeapMB: Number((memBefore.heapUsed / 1024 / 1024).toFixed(2)),
        large25MBHeapDeltaMB: Number(((memAfter25MB.heapUsed - memBefore25MB.heapUsed) / 1024 / 1024).toFixed(2)),
        finalRssMB: Number((memAfterAll.rss / 1024 / 1024).toFixed(2)),
        finalHeapMB: Number((memAfterAll.heapUsed / 1024 / 1024).toFixed(2))
      },
      cpuAndEventLoop: {
        userCpuMs: Number((cpuDelta.user / 1000).toFixed(2)),
        systemCpuMs: Number((cpuDelta.system / 1000).toFixed(2)),
        singleCoreCpuPct,
        systemNormalizedCpuPct,
        eventLoopP50Ms: Number((loopDelay.percentile(50) / 1e6).toFixed(2)),
        eventLoopP95Ms: Number((loopDelay.percentile(95) / 1e6).toFixed(2)),
        eventLoopMaxMs: Number((loopDelay.max / 1e6).toFixed(2))
      }
    };

    console.log('\n================ PHASE A PERFORMANCE BASELINE ================\n' + JSON.stringify(report, null, 2) + '\n==============================================================\n');

    expect(smallStats.p50).toBeLessThan(25);
    expect(mediumStats.p50).toBeLessThan(100);
    expect(largeStats.p50).toBeLessThan(1000);
  });
});
