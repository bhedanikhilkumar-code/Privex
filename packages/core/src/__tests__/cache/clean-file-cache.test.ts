import { describe, it, expect, beforeEach } from 'vitest';
import { CleanFileCache, EngineVerdict, Verdict } from '../../index';

describe('CleanFileCache (Stage 0 Short-Circuit Sieve)', () => {
  let cache: CleanFileCache;

  beforeEach(() => {
    CleanFileCache.resetSharedInstance();
    cache = CleanFileCache.getSharedInstance();
  });

  it('provides sub-0.08 ms cache hits on repeated lookups of unmodified files', () => {
    const testPath = 'C:\\Program Files\\App\\clean_module.dll';
    const fileSize = 1048576;
    const mtimeMs = 1710000000000;
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    // Miss on first lookup
    expect(cache.get(testPath, fileSize, mtimeMs)).toBeNull();

    // Cache clean entry
    cache.set(testPath, fileSize, mtimeMs, sha256, {
      verdict: Verdict.ALLOW,
      engineVerdict: EngineVerdict.ALLOW,
      riskScore: 0
    });

    // Hit on second lookup
    const hit = cache.get(testPath, fileSize, mtimeMs);
    expect(hit).not.toBeNull();
    expect(hit?.sha256).toBe(sha256);
    expect(hit?.verdict).toBe(Verdict.ALLOW);
    expect(hit?.engineVerdict).toBe(EngineVerdict.ALLOW);
    expect(hit?.riskScore).toBe(0);

    // Benchmark lookup latency
    const iterations = 1000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      cache.get(testPath, fileSize, mtimeMs);
    }
    const avgMs = (performance.now() - start) / iterations;
    expect(avgMs).toBeLessThan(0.08); // SLA: < 0.08 ms
  });

  it('invalidates cache entries when file size or modification time changes', () => {
    const testPath = '/usr/local/bin/worker';
    const initialSize = 2048;
    const initialMtime = 1711111111000;
    const sha256 = 'abc123def456';

    cache.set(testPath, initialSize, initialMtime, sha256);

    // Same size, different mtime -> Miss
    expect(cache.get(testPath, initialSize, initialMtime + 1000)).toBeNull();

    // Different size, same mtime -> Miss
    expect(cache.get(testPath, initialSize + 1, initialMtime)).toBeNull();

    // Original metadata -> Hit
    expect(cache.get(testPath, initialSize, initialMtime)).not.toBeNull();

    // Explicit invalidation
    cache.invalidate(testPath);
    expect(cache.get(testPath, initialSize, initialMtime)).toBeNull();
  });

  it('enforces LRU eviction when capacity exceeds maxEntries', () => {
    const tinyCache = new CleanFileCache({ maxEntries: 3, ttlMs: 10000 });

    tinyCache.set('/file1', 100, 1000, 'hash1');
    tinyCache.set('/file2', 200, 2000, 'hash2');
    tinyCache.set('/file3', 300, 3000, 'hash3');

    expect(tinyCache.get('/file1', 100, 1000)).not.toBeNull();
    expect(tinyCache.get('/file2', 200, 2000)).not.toBeNull();
    expect(tinyCache.get('/file3', 300, 3000)).not.toBeNull();

    // Adding file4 should evict file1 (oldest accessed was file1? wait, we accessed file1 then file2 then file3, so file1 was least recently used before file2 and file3? Actually file1 was accessed, then file2, then file3)
    tinyCache.set('/file4', 400, 4000, 'hash4');

    expect(tinyCache.size).toBe(3);
    // file1 was least recently accessed among the 3
    expect(tinyCache.get('/file1', 100, 1000)).toBeNull();
    expect(tinyCache.get('/file4', 400, 4000)).not.toBeNull();
  });
});
