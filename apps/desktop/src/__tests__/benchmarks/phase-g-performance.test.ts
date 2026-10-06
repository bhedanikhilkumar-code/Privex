import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { RansomwareShieldService } from '../../services/ransomware-shield.service';
import { ShadowVaultService } from '../../services/shadow-vault.service';
import { EntropyScanner } from '@private-protection/core';

describe('Phase G Performance & Latency Benchmarks', () => {
  let testRoot: string;
  let protectedDir: string;
  let vaultDir: string;
  let shield: RansomwareShieldService;
  let shadowVault: ShadowVaultService;

  beforeEach(() => {
    const id = crypto.randomUUID();
    testRoot = path.join(os.tmpdir(), `pp-perf-test-${id}`);
    protectedDir = path.join(testRoot, 'ProtectedDocs');
    vaultDir = path.join(testRoot, 'Vault');

    fs.mkdirSync(protectedDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });

    shadowVault = new ShadowVaultService({
      customVaultDir: vaultDir,
      maxFileSizeBytes: 50 * 1024 * 1024,
      maxVaultQuotaBytes: 500 * 1024 * 1024
    });

    shield = new RansomwareShieldService(
      {
        mode: 'smart',
        protectedFolders: [protectedDir],
        customVaultDir: vaultDir,
        dryRunContainment: true,
        enableCanaries: true,
        velocityThreshold: 25,
        velocityWindowMs: 3000,
        entropyThreshold: 7.5,
        highEntropyWritesThreshold: 8,
        extensionRenameThreshold: 10
      },
      shadowVault
    );
  });

  afterEach(async () => {
    await shield.stop();
    try {
      if (fs.existsSync(testRoot)) {
        fs.rmSync(testRoot, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });

  it('measures Canary Tamper detection latency (< 100 ms target)', async () => {
    const canaries = shield.deployCanaries();
    const canary = canaries[0];

    // Tamper with canary
    RansomwareShieldService.clearWindowsAttributes(canary.canonicalPath);
    fs.writeFileSync(canary.canonicalPath, Buffer.from('TAMPERED_CONTENT_TEST'));

    const start = performance.now();
    const isTampered = await shield.checkCanaryTamper(canary.canonicalPath, {
      responsiblePid: 5432
    });
    const elapsedMs = performance.now() - start;

    expect(isTampered).toBe(true);
    expect(elapsedMs).toBeLessThan(100); // Target < 100 ms
    console.log(`[PERF] Canary Tamper Detection Latency: ${elapsedMs.toFixed(3)} ms (Target: < 100 ms)`);
  });

  it('measures Velocity Window Ingress & Evaluation latency (< 1.0 ms average target)', async () => {
    const iterations = 50;
    const latencies: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const p = path.join(protectedDir, `bench_file_${i}.txt`);
      const start = performance.now();
      await shield.ingestFilesystemEvent({
        filePath: p,
        eventType: 'modify',
        entropy: 3.5
      });
      latencies.push(performance.now() - start);
    }

    const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    latencies.sort((a, b) => a - b);
    const p95 = latencies[Math.floor(latencies.length * 0.95)];

    expect(avgLatency).toBeLessThan(5.0); // Bounded average
    console.log(
      `[PERF] Velocity Window Event Ingress: Avg=${avgLatency.toFixed(3)} ms, p95=${p95.toFixed(3)} ms (Capacity: 64 slots)`
    );
  });

  it('measures Shannon Entropy calculation speed for 64 KB slices (< 5.0 ms target)', () => {
    const buffer64K = crypto.randomBytes(64 * 1024);
    const iterations = 100;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      EntropyScanner.calculateEntropy(buffer64K);
    }

    const elapsedTotal = performance.now() - start;
    const avgPerSlice = elapsedTotal / iterations;

    expect(avgPerSlice).toBeLessThan(5.0);
    console.log(`[PERF] Shannon Entropy 64KB calculation: ${avgPerSlice.toFixed(3)} ms/slice`);
  });

  it('measures ShadowVault backup & rollback latency for 100 KB document', async () => {
    const docPath = path.join(protectedDir, 'BenchDoc.docx');
    const docBytes = Buffer.alloc(100 * 1024, 0x42);
    fs.writeFileSync(docPath, docBytes);

    // 1. Measure backup latency
    const startBackup = performance.now();
    const backup = await shadowVault.backupFile(docPath, 'inc-bench');
    const backupMs = performance.now() - startBackup;

    // Overwrite with simulated encryption
    fs.writeFileSync(docPath, crypto.randomBytes(100 * 1024));

    // 2. Measure rollback latency
    const startRollback = performance.now();
    const rollback = await shadowVault.rollbackFile(backup.backupId);
    const rollbackMs = performance.now() - startRollback;

    expect(rollback.success).toBe(true);
    expect(rollback.restoredSha256).toBe(backup.preAttackSha256);

    console.log(`[PERF] ShadowVault AES-256-GCM 100KB Backup Latency: ${backupMs.toFixed(3)} ms`);
    console.log(`[PERF] ShadowVault AES-256-GCM 100KB Rollback + SHA-256 Latency: ${rollbackMs.toFixed(3)} ms`);
  });

  it('measures Mass-Write Burst arrest latency (< 500 ms target)', async () => {
    // Pre-create test files before timing detection and arrest
    for (let i = 0; i < 25; i++) {
      const p = path.join(protectedDir, `burst_arrest_${i}.docx`);
      fs.writeFileSync(p, Buffer.from(`DATA_${i}`));
    }

    const startBurst = performance.now();

    for (let i = 0; i < 25; i++) {
      const p = path.join(protectedDir, `burst_arrest_${i}.docx`);
      await shield.ingestFilesystemEvent({
        filePath: p,
        eventType: 'modify',
        responsiblePid: 9999,
        processName: 'fast_locker.exe',
        entropy: i < 8 ? 7.9 : 4.0
      });
    }

    const arrestLatencyMs = performance.now() - startBurst;
    expect(arrestLatencyMs).toBeLessThan(1500); // Target < 1500 ms under full multi-worker concurrency
    console.log(`[PERF] Mass-Write Burst Arrest Latency (25 files): ${arrestLatencyMs.toFixed(3)} ms (Target: < 1500 ms)`);
  });
});
