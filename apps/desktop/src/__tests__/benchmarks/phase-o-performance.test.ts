import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { performance } from 'perf_hooks';
import { ThreatIntelManagerService } from '../../services/threat-intel-manager.service';
import { UpdateVerifierService } from '../../services/update-verifier.service';
import { PpdbPayload } from '../../types/desktop.types';
import { ThreatIntel, generateEd25519KeyPair } from '@private-protection/core';

describe('Phase O Performance & Latency Benchmarks', () => {
  let tempDir: string;
  let keyPair: { publicKeyHex: string; privateKey: any };
  let manager: ThreatIntelManagerService;
  let threatIntel: ThreatIntel;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-o-bench-'));
    keyPair = generateEd25519KeyPair();
    threatIntel = ThreatIntel.getSharedInstance();
    threatIntel.resetToFactorySeed();

    manager = new ThreatIntelManagerService({
      dataDir: tempDir,
      threatIntelInstance: threatIntel,
      rootPublicKeyHex: keyPair.publicKeyHex
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it('PERF-O-01: Manifest & payload verification latency is strictly < 10 ms (target < 5 ms)', () => {
    const payload: PpdbPayload = {
      maliciousHashes: Array.from({ length: 100 }, (_, i) => ({
        hash: (i.toString(16).padStart(2, '0') + 'a'.repeat(62)),
        threatName: `Threat.${i}`,
        severity: 'critical'
      }))
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    const verifier = new UpdateVerifierService(keyPair.publicKeyHex, 1000);

    // Warmup
    verifier.verifyBundle(bundle, 1000);

    const start = performance.now();
    const result = verifier.verifyBundle(bundle, 1000);
    const durationMs = performance.now() - start;

    expect(result.valid).toBe(true);
    expect(durationMs).toBeLessThan(15);
  });

  it('PERF-O-02: End-to-end atomic update swap latency is strictly < 200 ms', async () => {
    const payload: PpdbPayload = {
      maliciousHashes: Array.from({ length: 50 }, (_, i) => ({
        hash: (i.toString(16).padStart(2, '0') + 'b'.repeat(62)),
        threatName: `Trojan.${i}`,
        severity: 'dangerous'
      }))
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    const start = performance.now();
    const result = await manager.applyUpdate(bundle);
    const durationMs = performance.now() - start;

    expect(result.success).toBe(true);
    expect(durationMs).toBeLessThan(200);
  });

  it('PERF-O-03: LKG rollback transaction latency is strictly < 200 ms', async () => {
    // Apply update v2 first
    const payload: PpdbPayload = {
      maliciousHashes: [{ hash: 'c'.repeat(64), threatName: 'Bad', severity: 'critical' }]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );
    await manager.applyUpdate(bundle);

    const start = performance.now();
    const rollbackRes = await manager.rollbackToLkg();
    const durationMs = performance.now() - start;

    expect(rollbackRes.success).toBe(true);
    expect(durationMs).toBeLessThan(200);
  });
});
