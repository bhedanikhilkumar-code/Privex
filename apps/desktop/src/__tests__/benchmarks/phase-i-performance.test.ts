import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { ExclusionManagerService } from '../../services/exclusion-manager.service';
import { ResponsePolicyEngine } from '../../services/response-policy-engine';

describe('Phase I Benchmarks — Response Ladder & Exclusion Lookup Throughput', () => {
  let tempDir: string;
  let service: ExclusionManagerService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-i-bench-'));
    service = new ExclusionManagerService({
      configDir: tempDir,
      maxExclusions: 5000
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('evaluates ResponsePolicyEngine at > 100,000 evaluations per second', () => {
    const input = {
      riskScore: 85,
      severity: 'dangerous' as const,
      verdict: 'BLOCK' as const,
      threatName: 'Benchmark.Threat'
    };

    const iterations = 50000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      ResponsePolicyEngine.evaluate(input);
    }
    const elapsedMs = performance.now() - start;
    const evalsPerSec = (iterations / elapsedMs) * 1000;

    expect(evalsPerSec).toBeGreaterThan(100000);
  });

  it('performs O(1) hash lookups under 0.01 ms across active exclusions', () => {
    // Populate hash exclusions
    const hashes: string[] = [];
    for (let i = 0; i < 100; i++) {
      const hash = crypto.createHash('sha256').update(`entry-${i}`).digest('hex');
      hashes.push(hash);
      service.addExclusion({
        type: 'HASH',
        value: hash,
        reason: `Benchmark entry ${i}`
      });
    }

    // Verify correctness first
    expect(service.checkHash(hashes[0]).isExcluded).toBe(true);

    const testIterations = 50000;
    let excludedCount = 0;
    const start = performance.now();
    for (let i = 0; i < testIterations; i++) {
      const targetHash = hashes[i % hashes.length];
      const res = service.checkHash(targetHash);
      if (res.isExcluded) {
        excludedCount++;
      }
    }
    const elapsedMs = performance.now() - start;
    const avgLatencyMs = elapsedMs / testIterations;

    expect(excludedCount).toBe(testIterations);
    expect(avgLatencyMs).toBeLessThan(0.01); // Under 0.01 ms (10 microseconds) SLA
  });
});
