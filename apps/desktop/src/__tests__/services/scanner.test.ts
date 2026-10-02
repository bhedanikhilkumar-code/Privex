import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScannerService } from '../../services/scanner.service';

describe('ScannerService (Recursive Filesystem Engine)', () => {
  let scanner: ScannerService;
  let tempDir: string;

  beforeEach(() => {
    scanner = new ScannerService();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-scanner-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('scans a directory recursively and aggregates statistics', async () => {
    // Create nested directory structure with safe files
    const subDirA = path.join(tempDir, 'folderA');
    const subDirB = path.join(subDirA, 'folderB');
    fs.mkdirSync(subDirB, { recursive: true });

    fs.writeFileSync(path.join(tempDir, 'file1.txt'), 'Hello world');
    fs.writeFileSync(path.join(subDirA, 'file2.txt'), 'Hello subfolder');
    fs.writeFileSync(path.join(subDirB, 'file3.txt'), 'Hello nested folder');

    const result = await scanner.scanPaths([tempDir], 'full');
    expect(result.totalFilesScanned).toBe(3);
    expect(result.threats.length).toBe(0);
    expect(result.overallVerdict).toBe('ALLOW');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('detects threats during recursive directory traversal', async () => {
    const threatPath = path.join(tempDir, 'suspicious.pdf.exe');
    fs.writeFileSync(threatPath, Buffer.from([0x4d, 0x5a, 0x90, 0x00])); // PE header disguised as pdf.exe

    const result = await scanner.scanPaths([tempDir], 'custom');
    expect(result.totalFilesScanned).toBe(1);
    expect(result.threats.length).toBe(1);
    expect(result.threats[0].fileName).toBe('suspicious.pdf.exe');
    expect(result.overallVerdict).toBe('BLOCK');
  });

  it('handles symlink loops safely without infinite recursion', async () => {
    const loopDir = path.join(tempDir, 'loopDir');
    fs.mkdirSync(loopDir, { recursive: true });
    fs.writeFileSync(path.join(loopDir, 'inner.txt'), 'content');

    // Create a symlink pointing back to parent directory (circular loop)
    const symlinkPath = path.join(loopDir, 'circularLink');
    try {
      fs.symlinkSync(tempDir, symlinkPath, 'junction');
    } catch {
      // If OS denies symlink creation without elevation, skip symlink creation
      return;
    }

    const result = await scanner.scanPaths([tempDir], 'full');
    expect(result.totalFilesScanned).toBeGreaterThanOrEqual(1);
    expect(result.skippedFiles.some((s) => s.reason.includes('Symlink') || s.reason.includes('loop'))).toBe(true);
  });

  it('supports cancellation token to abort ongoing scans cleanly', async () => {
    // Populate large number of files
    for (let i = 0; i < 20; i++) {
      fs.writeFileSync(path.join(tempDir, `item_${i}.txt`), `Content ${i}`);
    }

    const scanPromise = scanner.scanPaths([tempDir], 'full');
    // Immediately cancel
    scanner.cancelScan();

    const result = await scanPromise;
    expect(scanner.getStatus()).toBe('cancelled');
    expect(result.totalFilesScanned).toBeLessThanOrEqual(20);
  });

  it('supports pause and resume of scan execution', async () => {
    for (let i = 0; i < 15; i++) {
      fs.writeFileSync(path.join(tempDir, `item_${i}.txt`), `Content ${i}`);
    }

    const scanPromise = scanner.scanPaths([tempDir], 'full');
    scanner.pauseScan();
    expect(scanner.getStatus()).toBe('paused');

    // Resume after 20ms
    setTimeout(() => {
      scanner.resumeScan();
    }, 20);

    const result = await scanPromise;
    expect(result.totalFilesScanned).toBe(15);
  });
});
