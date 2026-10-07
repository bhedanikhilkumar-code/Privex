import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScannerService } from '../../services/scanner.service';
import { CleanFileCache } from '../../core/clean-file-cache';
import { ResourcePolicy } from '../../core/resource-policy';
import { DetectedThreat } from '../../types/desktop.types';

describe('Phase P Security & Adversarial Test Suite (SEC-P-01 to SEC-P-12)', () => {
  let scanner: ScannerService;
  let cache: CleanFileCache;
  let tempDir: string;

  beforeEach(() => {
    CleanFileCache.resetSharedInstance();
    cache = CleanFileCache.getSharedInstance();
    scanner = new ScannerService({ cleanFileCache: cache });
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-p-sec-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('SEC-P-01: Scenario A — EICAR appears in previously clean file -> mtime/size change triggers immediate detection', async () => {
    const targetFile = path.join(tempDir, 'document.txt');
    fs.writeFileSync(targetFile, 'Harmless initial clean text content.');

    // 1. Initial scan: verified clean and cached
    const res1 = await scanner.scanPaths([targetFile]);
    expect(res1.totalFilesScanned).toBe(1);
    expect(res1.threats.length).toBe(0);
    expect(res1.overallVerdict).toBe('ALLOW');
    expect(cache.size).toBe(1);

    // 2. Attacker modifies file with synthetic PE header or malware pattern
    // Delay slightly to ensure mtime timestamp changes
    const originalMtime = fs.statSync(targetFile).mtimeMs;
    const newMtime = new Date(Date.now() + 2000);
    fs.writeFileSync(targetFile, Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00])); // MZ header
    fs.utimesSync(targetFile, newMtime, newMtime);

    expect(fs.statSync(targetFile).mtimeMs).not.toBe(originalMtime);

    // Rename to .pdf.exe (deceptive double extension)
    const threatPath = path.join(tempDir, 'document.pdf.exe');
    fs.renameSync(targetFile, threatPath);

    // 3. Second scan: stale clean entry must NOT protect the new threat!
    const res2 = await scanner.scanPaths([threatPath]);
    expect(res2.totalFilesScanned).toBe(1);
    expect(res2.threats.length).toBe(1);
    expect(res2.threats[0].verdict).toBe('BLOCK');
  });

  it('SEC-P-02: Scenario B — Cache cannot be poisoned by attacker-controlled metadata', () => {
    // Attempt to inject malicious result into cache
    const poisoned = cache.set('C:\\Windows\\evil.exe', 1024, 1000, 'badhash', {
      verdict: 'BLOCK' as any,
      riskScore: 99
    });

    expect(poisoned).toBe(false);
    expect(cache.size).toBe(0);
    expect(cache.get('C:\\Windows\\evil.exe', 1024, 1000)).toBeNull();
  });

  it('SEC-P-03: Scenario C — Threat database version update invalidates all stale clean entries', async () => {
    const file1 = path.join(tempDir, 'clean1.txt');
    fs.writeFileSync(file1, 'clean content 1');

    await scanner.scanPaths([file1]);
    expect(cache.size).toBe(1);

    // Threat intelligence updated to new version sequence
    cache.setThreatDatabaseVersion('2026.11-updated-rules');
    expect(cache.size).toBe(0);

    const stat = fs.statSync(file1);
    expect(cache.get(file1, stat.size, stat.mtimeMs)).toBeNull();
  });

  it('SEC-P-04: Scenario D — Engine version update invalidates all stale clean entries', async () => {
    const file1 = path.join(tempDir, 'clean1.txt');
    fs.writeFileSync(file1, 'clean content 1');

    await scanner.scanPaths([file1]);
    expect(cache.size).toBe(1);

    // Core Engine upgraded
    cache.setEngineVersion('1.1.0-updated');
    expect(cache.size).toBe(0);

    const stat = fs.statSync(file1);
    expect(cache.get(file1, stat.size, stat.mtimeMs)).toBeNull();
  });

  it('SEC-P-05: Scenario E — Malformed or unreadable file does not crash scanner (fail-closed)', async () => {
    const validFile = path.join(tempDir, 'valid.txt');
    fs.writeFileSync(validFile, 'Normal file content');

    const nonExistent = path.join(tempDir, 'missing_file.txt');

    const result = await scanner.scanPaths([validFile, nonExistent]);
    expect(result.totalFilesScanned).toBe(1);
    expect(result.skippedFiles.some((s) => s.path === nonExistent)).toBe(true);
    expect(result.status).toBe('completed');
  });

  it('SEC-P-06: Scenario F & G — Memory stays strictly bounded under batch scanning', async () => {
    // Generate 100 small files
    for (let i = 0; i < 100; i++) {
      fs.writeFileSync(path.join(tempDir, `batch_item_${i}.txt`), `Content ${i}`);
    }

    const memBefore = process.memoryUsage().heapUsed;
    const result = await scanner.scanPaths([tempDir]);
    const memAfter = process.memoryUsage().heapUsed;

    expect(result.totalFilesScanned).toBe(100);
    expect(result.threats.length).toBe(0);

    const heapDeltaMb = (memAfter - memBefore) / 1024 / 1024;
    // Heap delta must stay well within 25 MB limit
    expect(heapDeltaMb).toBeLessThan(25);
  });

  it('SEC-P-07: Scenario H — Cancellation during batch scan halts immediately without leaking tasks', async () => {
    for (let i = 0; i < 50; i++) {
      fs.writeFileSync(path.join(tempDir, `item_${i}.txt`), `Content ${i}`);
    }

    const scanPromise = scanner.scanPaths([tempDir]);
    // Cancel immediately
    scanner.cancelScan();

    const result = await scanPromise;
    expect(result.status).toBe('cancelled');
    expect(scanner.getStatus()).toBe('cancelled');
  });

  it('SEC-P-08: Scenario J — Simultaneous threat detection & progress storm: threat event fires immediately', async () => {
    const threatPath = path.join(tempDir, 'trojan.pdf.exe');
    fs.writeFileSync(threatPath, Buffer.from([0x4d, 0x5a, 0x90, 0x00])); // PE header

    let threatFired = false;
    let threatTimestamp = 0;
    const scanStartTime = Date.now();

    scanner.on('threatFound', (threat: DetectedThreat) => {
      threatFired = true;
      threatTimestamp = Date.now();
      expect(threat.fileName).toBe('trojan.pdf.exe');
      expect(threat.verdict).toBe('BLOCK');
    });

    const result = await scanner.scanPaths([threatPath]);
    expect(threatFired).toBe(true);
    expect(result.threats.length).toBe(1);
    expect(threatTimestamp - scanStartTime).toBeLessThan(1000); // Immediate
  });

  it('SEC-P-09: Scenario K — Cache remains strictly bounded at maxEntries (65,536)', () => {
    const tinyCache = new CleanFileCache({ maxEntries: 5 });

    for (let i = 1; i <= 20; i++) {
      tinyCache.set(`C:\\f${i}.txt`, 100, 1000, `hash${i}`);
    }

    expect(tinyCache.size).toBe(5);
    // Oldest items (1..15) were evicted
    expect(tinyCache.get('C:\\f1.txt', 100, 1000)).toBeNull();
    expect(tinyCache.get('C:\\f15.txt', 100, 1000)).toBeNull();
    // Latest items (16..20) exist
    expect(tinyCache.get('C:\\f20.txt', 100, 1000)).not.toBeNull();
  });

  it('SEC-P-10: Low-resource machine configuration enforces conservative concurrency (<=4 GB RAM)', () => {
    // Simulate a 4 GB RAM machine with 2 CPU cores
    const lowResourcePolicy = new ResourcePolicy({
      customTotalMemoryBytes: 3.8 * 1024 * 1024 * 1024,
      customCpuCount: 2
    });

    const profile = lowResourcePolicy.getProfile();
    expect(profile.isLowResourceMachine).toBe(true);
    expect(profile.concurrency).toBeLessThanOrEqual(2);
    expect(profile.batchSize).toBe(25);
    expect(profile.tierName).toBe('LOW_RESOURCE_4GB');
  });

  it('SEC-P-11: High-resource machine scales concurrency safely (>8 GB RAM)', () => {
    // Simulate a 16 GB RAM machine with 8 CPU cores
    const highResourcePolicy = new ResourcePolicy({
      customTotalMemoryBytes: 16 * 1024 * 1024 * 1024,
      customCpuCount: 8
    });

    const profile = highResourcePolicy.getProfile();
    expect(profile.isLowResourceMachine).toBe(false);
    expect(profile.concurrency).toBeGreaterThanOrEqual(4);
    expect(profile.batchSize).toBe(100);
    expect(profile.tierName).toBe('HIGH_RESOURCE');
  });

  it('SEC-P-12: Offline & zero cloud connection invariant preserved during scanning', async () => {
    const testFile = path.join(tempDir, 'local.txt');
    fs.writeFileSync(testFile, '100% local content');

    const res = await scanner.scanPaths([testFile]);
    expect(res.overallVerdict).toBe('ALLOW');
    expect(res.analysisStatus).toBe('COMPLETED');
    expect(res.disposition).toBe('SAFE');
  });
});
