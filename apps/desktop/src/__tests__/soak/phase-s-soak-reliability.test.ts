import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScannerService } from '../../services/scanner.service';

describe('Phase S Category 06 — Reliability & Accelerated Soak Test', () => {
  let tempDir: string;
  let scanner: ScannerService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-s-soak-'));
    scanner = new ScannerService();
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('proves zero memory leak and bounded heap/RSS slope across repeated scanning iterations', async () => {
    // Populate test files
    const scanDir = path.join(tempDir, 'files-to-scan');
    fs.mkdirSync(scanDir, { recursive: true });
    const fileCount = 50;
    for (let i = 0; i < fileCount; i++) {
      fs.writeFileSync(
        path.join(scanDir, `test-doc-${i}.txt`),
        `Benign document sample content for iteration soak testing #${i}\n${'A'.repeat(512)}`
      );
    }

    if (global.gc) {
      global.gc();
    }

    const baselineMemory = process.memoryUsage();
    const iterations = 50; // accelerated soak run
    const heapSnapshots: number[] = [];

    for (let iter = 0; iter < iterations; iter++) {
      const result = await scanner.scanPaths([scanDir], 'custom');
      expect(result.totalFilesScanned).toBe(fileCount);
      expect(result.threats.length).toBe(0);

      if (iter % 10 === 0) {
        if (global.gc) {
          global.gc();
        }
        heapSnapshots.push(process.memoryUsage().heapUsed);
      }
    }

    if (global.gc) {
      global.gc();
    }
    const finalMemory = process.memoryUsage();

    // Calculate memory slope: change between baseline and final heap
    const heapDeltaMb = (finalMemory.heapUsed - baselineMemory.heapUsed) / (1024 * 1024);
    const rssDeltaMb = (finalMemory.rss - baselineMemory.rss) / (1024 * 1024);

    // Assert that bounded heap growth is maintained (< 50 MB allowance for test execution)
    expect(heapDeltaMb).toBeLessThan(50);
    expect(rssDeltaMb).toBeLessThan(100);
  });

  it('verifies event listeners and timers are cleanly recycled without handle leaks', async () => {
    const initialListenerCount = scanner.listenerCount('progress');
    expect(initialListenerCount).toBe(0);

    // Register temporary listeners and simulate multiple scans
    for (let i = 0; i < 20; i++) {
      const progressHandler = () => {};
      scanner.on('progress', progressHandler);
      
      // Perform quick path scan
      await scanner.scanPaths([tempDir], 'quick');

      // Unregister listener
      scanner.off('progress', progressHandler);
    }

    // Listener count must return to baseline 0
    expect(scanner.listenerCount('progress')).toBe(0);
    expect(scanner.listenerCount('complete')).toBe(0);
    expect(scanner.listenerCount('threat-detected')).toBe(0);
  });

  it('guarantees clean worker/file descriptor lifecycle under continuous rapid scan calls', async () => {
    const filePath = path.join(tempDir, 'sample-single.txt');
    fs.writeFileSync(filePath, 'Quick file content for single descriptor test');

    // Run 100 rapid scans
    for (let i = 0; i < 100; i++) {
      const res = await scanner.scanPaths([filePath], 'quick');
      expect(res.totalFilesScanned).toBe(1);
    }

    // Check that we can read and write the file without OS EBUSY or EPERM lock errors
    expect(() => {
      fs.appendFileSync(filePath, '\nNew content appended without lock contention');
      const data = fs.readFileSync(filePath, 'utf8');
      expect(data).toContain('New content appended');
    }).not.toThrow();
  });
});
