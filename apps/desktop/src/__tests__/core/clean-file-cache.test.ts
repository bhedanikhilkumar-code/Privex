import { describe, it, expect, beforeEach } from 'vitest';
import { CleanFileCache } from '../../core/clean-file-cache';
import { Verdict, EngineVerdict } from '@private-protection/core';

describe('CleanFileCache (Phase P — 65,536-Entry Stage 0 LRU Sieve)', () => {
  let cache: CleanFileCache;

  beforeEach(() => {
    CleanFileCache.resetSharedInstance();
    cache = new CleanFileCache({ maxEntries: 65536 });
  });

  it('1. performs O(1) cache hits and records clean entries', () => {
    const filePath = 'C:\\Program Files\\App\\clean.dll';
    const recorded = cache.set(filePath, 1024, 1700000000000, 'hash123', {
      dev: 1,
      ino: 100,
      verdict: Verdict.ALLOW,
      engineVerdict: EngineVerdict.ALLOW,
      riskScore: 0
    });

    expect(recorded).toBe(true);
    expect(cache.size).toBe(1);

    const hit = cache.get(filePath, 1024, 1700000000000, { dev: 1, ino: 100 });
    expect(hit).not.toBeNull();
    expect(hit?.sha256).toBe('hash123');
    expect(hit?.verdict).toBe(Verdict.ALLOW);
    expect(hit?.riskScore).toBe(0);
  });

  it('2. returns cache miss when mtimeMs changes', () => {
    const filePath = 'C:\\Program Files\\App\\clean.dll';
    cache.set(filePath, 1024, 1700000000000, 'hash123', { dev: 1, ino: 100 });

    // Modified file (different mtime)
    const miss = cache.get(filePath, 1024, 1700000050000, { dev: 1, ino: 100 });
    expect(miss).toBeNull();
  });

  it('3. returns cache miss when fileSize changes', () => {
    const filePath = 'C:\\Program Files\\App\\clean.dll';
    cache.set(filePath, 1024, 1700000000000, 'hash123', { dev: 1, ino: 100 });

    // Modified file (different size)
    const miss = cache.get(filePath, 2048, 1700000000000, { dev: 1, ino: 100 });
    expect(miss).toBeNull();
  });

  it('4. returns cache miss when dev or ino identity changes', () => {
    const filePath = 'C:\\Program Files\\App\\clean.dll';
    cache.set(filePath, 1024, 1700000000000, 'hash123', { dev: 1, ino: 100 });

    // Replaced or moved file on different device or inode
    expect(cache.get(filePath, 1024, 1700000000000, { dev: 2, ino: 100 })).toBeNull();
    expect(cache.get(filePath, 1024, 1700000000000, { dev: 1, ino: 200 })).toBeNull();
  });

  it('5. invalidates cache when engine version changes', () => {
    const filePath = 'C:\\Program Files\\App\\clean.dll';
    cache.set(filePath, 1024, 1700000000000, 'hash123', { dev: 1, ino: 100 });
    expect(cache.size).toBe(1);

    // Engine version upgraded
    cache.setEngineVersion('2.0.0-upgraded');
    expect(cache.size).toBe(0);
    expect(cache.get(filePath, 1024, 1700000000000, { dev: 1, ino: 100 })).toBeNull();
  });

  it('6. invalidates cache when threat database version changes', () => {
    const filePath = 'C:\\Program Files\\App\\clean.dll';
    cache.set(filePath, 1024, 1700000000000, 'hash123', { dev: 1, ino: 100 });
    expect(cache.size).toBe(1);

    // Threat DB updated
    cache.setThreatDatabaseVersion('2026.11-updated-db');
    expect(cache.size).toBe(0);
    expect(cache.get(filePath, 1024, 1700000000000, { dev: 1, ino: 100 })).toBeNull();
  });

  it('7. strictly refuses to cache non-clean verdicts (BLOCK/WARN/riskScore > 0)', () => {
    const blockPath = 'C:\\Malware\\trojan.exe';
    const warnPath = 'C:\\Suspicious\\script.vbs';
    const scoredPath = 'C:\\Risk\\file.bat';

    const resBlock = cache.set(blockPath, 500, 1700000000000, 'badhash1', {
      verdict: Verdict.DANGEROUS,
      engineVerdict: EngineVerdict.BLOCK,
      riskScore: 90
    });
    const resWarn = cache.set(warnPath, 500, 1700000000000, 'warn1', {
      verdict: Verdict.SUSPICIOUS,
      engineVerdict: EngineVerdict.WARN,
      riskScore: 50
    });
    const resScored = cache.set(scoredPath, 500, 1700000000000, 'score1', {
      verdict: Verdict.ALLOW,
      engineVerdict: EngineVerdict.ALLOW,
      riskScore: 20
    });

    expect(resBlock).toBe(false);
    expect(resWarn).toBe(false);
    expect(resScored).toBe(false);
    expect(cache.size).toBe(0);
  });

  it('8. enforces deterministic LRU eviction when maxEntries bound is reached', () => {
    const smallCache = new CleanFileCache({ maxEntries: 3 });

    smallCache.set('file1.txt', 10, 1000, 'h1');
    smallCache.set('file2.txt', 20, 2000, 'h2');
    smallCache.set('file3.txt', 30, 3000, 'h3');
    expect(smallCache.size).toBe(3);

    // Access file1 to make it most recently used
    smallCache.get('file1.txt', 10, 1000);

    // Insert file4 -> oldest (file2) must be evicted
    smallCache.set('file4.txt', 40, 4000, 'h4');
    expect(smallCache.size).toBe(3);

    expect(smallCache.get('file2.txt', 20, 2000)).toBeNull(); // Evicted!
    expect(smallCache.get('file1.txt', 10, 1000)).not.toBeNull(); // Kept
    expect(smallCache.get('file3.txt', 30, 3000)).not.toBeNull(); // Kept
    expect(smallCache.get('file4.txt', 40, 4000)).not.toBeNull(); // Kept
  });

  it('9. supports per-file and per-directory invalidation', () => {
    cache.set('C:\\folderA\\file1.txt', 10, 1000, 'h1');
    cache.set('C:\\folderA\\file2.txt', 20, 2000, 'h2');
    cache.set('C:\\folderB\\file3.txt', 30, 3000, 'h3');

    // Invalidate single file
    expect(cache.invalidate('C:\\folderA\\file1.txt')).toBe(true);
    expect(cache.get('C:\\folderA\\file1.txt', 10, 1000)).toBeNull();
    expect(cache.get('C:\\folderA\\file2.txt', 20, 2000)).not.toBeNull();

    // Invalidate entire directory
    const removedCount = cache.invalidateByPrefix('C:\\folderA');
    expect(removedCount).toBe(1);
    expect(cache.get('C:\\folderA\\file2.txt', 20, 2000)).toBeNull();
    expect(cache.get('C:\\folderB\\file3.txt', 30, 3000)).not.toBeNull();
  });

  it('10. supports explicit cache bypass (bypassCache: true)', () => {
    cache.set('C:\\file.txt', 10, 1000, 'h1');
    expect(cache.get('C:\\file.txt', 10, 1000)).not.toBeNull();

    // When bypassCache is true, returns null without deleting the entry
    const bypassed = cache.get('C:\\file.txt', 10, 1000, { bypassCache: true });
    expect(bypassed).toBeNull();
    expect(cache.get('C:\\file.txt', 10, 1000)).not.toBeNull();
  });

  it('11. returns accurate telemetry and operation statistics', () => {
    cache.set('C:\\f1.txt', 10, 1000, 'h1');
    cache.get('C:\\f1.txt', 10, 1000); // Hit
    cache.get('C:\\f2.txt', 20, 2000); // Miss

    const stats = cache.getStats();
    expect(stats.size).toBe(1);
    expect(stats.maxEntries).toBe(65536);
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(1);
    expect(stats.sets).toBe(1);
    expect(stats.engineVersion).toBe(CleanFileCache.DEFAULT_ENGINE_VERSION);
    expect(stats.threatDatabaseVersion).toBe(CleanFileCache.DEFAULT_DB_VERSION);
  });
});
