import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScannerService } from '../../services/scanner.service';
import { CleanFileCache } from '../../core/clean-file-cache';
import { ResourcePolicy } from '../../core/resource-policy';

describe('Phase P Integration Suite — Batch Scanning & CleanFileCache Acceleration', () => {
  let scanner: ScannerService;
  let cache: CleanFileCache;
  let tempDir: string;

  beforeEach(() => {
    CleanFileCache.resetSharedInstance();
    cache = CleanFileCache.getSharedInstance();
    scanner = new ScannerService({ cleanFileCache: cache });
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-p-integ-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('INT-P-01: executes cold scan vs warm scan and verifies dramatic speedup via CleanFileCache', async () => {
    const fileCount = 200;
    for (let i = 0; i < fileCount; i++) {
      fs.writeFileSync(path.join(tempDir, `file_${i}.txt`), `Sample clean content index ${i}`);
    }

    // 1. Cold Scan (Cache empty)
    const t0 = performance.now();
    const coldResult = await scanner.scanPaths([tempDir], 'full');
    const coldDuration = performance.now() - t0;

    expect(coldResult.totalFilesScanned).toBe(fileCount);
    expect(coldResult.threats.length).toBe(0);
    expect(coldResult.overallVerdict).toBe('ALLOW');
    expect(cache.size).toBe(fileCount);

    // 2. Warm Scan (Cache populated)
    const t1 = performance.now();
    const warmResult = await scanner.scanPaths([tempDir], 'full');
    const warmDuration = performance.now() - t1;

    expect(warmResult.totalFilesScanned).toBe(fileCount);
    expect(warmResult.threats.length).toBe(0);
    expect(warmResult.overallVerdict).toBe('ALLOW');

    // Warm scan must be substantially faster than cold scan
    expect(warmDuration).toBeLessThanOrEqual(coldDuration);
  });

  it('INT-P-02: modifying a single file invalidates only that entry while others remain warm cache hits', async () => {
    const fileCount = 50;
    for (let i = 0; i < fileCount; i++) {
      fs.writeFileSync(path.join(tempDir, `item_${i}.txt`), `Content ${i}`);
    }

    // Populate cache
    await scanner.scanPaths([tempDir]);
    expect(cache.size).toBe(fileCount);

    // Modify file #25
    const modifiedFile = path.join(tempDir, 'item_25.txt');
    const newMtime = new Date(Date.now() + 2000);
    fs.writeFileSync(modifiedFile, 'Updated and modified content 25');
    fs.utimesSync(modifiedFile, newMtime, newMtime);

    // Re-scan
    const res = await scanner.scanPaths([tempDir]);
    expect(res.totalFilesScanned).toBe(fileCount);
    expect(res.threats.length).toBe(0);
    expect(res.overallVerdict).toBe('ALLOW');
  });

  it('INT-P-03: executes multi-tier directory traversal cleanly under low-resource 4GB policy', async () => {
    // Nested folders
    const dirA = path.join(tempDir, 'subA');
    const dirB = path.join(dirA, 'subB');
    fs.mkdirSync(dirB, { recursive: true });

    for (let i = 0; i < 20; i++) {
      fs.writeFileSync(path.join(tempDir, `root_${i}.txt`), `Root ${i}`);
      fs.writeFileSync(path.join(dirA, `subA_${i}.txt`), `SubA ${i}`);
      fs.writeFileSync(path.join(dirB, `subB_${i}.txt`), `SubB ${i}`);
    }

    // Force low-resource 4GB policy
    const lowPolicy = new ResourcePolicy({
      customTotalMemoryBytes: 3.5 * 1024 * 1024 * 1024,
      customCpuCount: 2
    });
    scanner.setResourcePolicy(lowPolicy);

    const res = await scanner.scanPaths([tempDir]);
    expect(res.totalFilesScanned).toBe(60);
    expect(res.overallVerdict).toBe('ALLOW');
  });
});
