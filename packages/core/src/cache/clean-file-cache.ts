import { EngineVerdict, Verdict } from '../types';

export interface CleanFileCacheEntry {
  readonly path: string;
  readonly fileSize: number;
  readonly mtimeMs: number;
  readonly sha256: string;
  readonly verdict: Verdict;
  readonly engineVerdict: EngineVerdict;
  readonly riskScore: number;
  readonly timestamp: number;
}

export interface CleanFileCacheOptions {
  readonly maxEntries?: number;
  readonly ttlMs?: number;
}

/**
 * Stage 0 CleanFileCache (Phase C / Research Area 01)
 *
 * Provides sub-0.08 ms cache hits for files whose size and modification timestamp
 * have not changed since a clean (ALLOW) verdict was verified.
 * Bounded by an LRU eviction strategy to maintain strict low-memory footprint.
 */
export class CleanFileCache {
  private static instance: CleanFileCache | null = null;

  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly cache: Map<string, CleanFileCacheEntry> = new Map();

  constructor(options?: CleanFileCacheOptions) {
    this.maxEntries = options?.maxEntries ?? 50000;
    this.ttlMs = options?.ttlMs ?? 24 * 60 * 60 * 1000; // 24 hours default TTL
  }

  public static getSharedInstance(): CleanFileCache {
    if (!this.instance) {
      this.instance = new CleanFileCache();
    }
    return this.instance;
  }

  public static resetSharedInstance(): void {
    if (this.instance) {
      this.instance.clear();
      this.instance = null;
    }
  }

  private buildKey(filePath: string, fileSize: number, mtimeMs: number): string {
    const normalizedPath = filePath.toLowerCase().replace(/\\/g, '/');
    return `${normalizedPath}|${fileSize}|${Math.floor(mtimeMs)}`;
  }

  /**
   * Fast O(1) cache lookup (< 0.08 ms target).
   * Returns cached clean entry if valid, unexpired, and metadata matches.
   */
  public get(filePath: string, fileSize: number, mtimeMs: number): CleanFileCacheEntry | null {
    if (!filePath || typeof fileSize !== 'number' || typeof mtimeMs !== 'number') {
      return null;
    }

    const key = this.buildKey(filePath, fileSize, mtimeMs);
    const entry = this.cache.get(key);
    if (!entry) {
      return null;
    }

    // TTL check
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      return null;
    }

    // Refresh LRU order by re-inserting
    this.cache.delete(key);
    this.cache.set(key, entry);

    return entry;
  }

  /**
   * Stores a verified clean file entry in cache.
   * Only ALLOW / SAFE entries should be cached in CleanFileCache.
   */
  public set(
    filePath: string,
    fileSize: number,
    mtimeMs: number,
    sha256: string,
    options?: {
      verdict?: Verdict;
      engineVerdict?: EngineVerdict;
      riskScore?: number;
    }
  ): void {
    if (!filePath || typeof fileSize !== 'number' || typeof mtimeMs !== 'number') {
      return;
    }

    // Never cache anything that is not verified clean.
    if (options?.verdict !== undefined && options.verdict !== Verdict.ALLOW) return;
    if (options?.engineVerdict !== undefined && options.engineVerdict !== EngineVerdict.ALLOW) return;
    if (options?.riskScore !== undefined && options.riskScore > 0) return;

    const key = this.buildKey(filePath, fileSize, mtimeMs);

    // Evict oldest if capacity exceeded
    if (this.cache.size >= this.maxEntries && !this.cache.has(key)) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    const entry: CleanFileCacheEntry = {
      path: filePath,
      fileSize,
      mtimeMs,
      sha256: sha256 || '',
      verdict: options?.verdict ?? Verdict.ALLOW,
      engineVerdict: options?.engineVerdict ?? EngineVerdict.ALLOW,
      riskScore: options?.riskScore ?? 0,
      timestamp: Date.now()
    };

    this.cache.set(key, entry);
  }

  public invalidate(filePath: string): boolean {
    if (!filePath) return false;
    const normalizedPrefix = filePath.toLowerCase().replace(/\\/g, '/');
    let removed = false;

    for (const key of Array.from(this.cache.keys())) {
      if (key.startsWith(normalizedPrefix + '|')) {
        this.cache.delete(key);
        removed = true;
      }
    }

    return removed;
  }

  public clear(): void {
    this.cache.clear();
  }

  /**
   * Convenience alias for set() to record a verified clean file.
   */
  public recordClean(
    filePath: string,
    fileSize: number,
    mtimeMs: number,
    sha256: string,
    options?: {
      verdict?: Verdict;
      engineVerdict?: EngineVerdict;
      riskScore?: number;
    }
  ): void {
    this.set(filePath, fileSize, mtimeMs, sha256, options);
  }

  /**
   * Fast boolean check whether a file is currently cached as clean.
   */
  public isClean(filePath: string, fileSize: number, mtimeMs: number): boolean {
    return this.get(filePath, fileSize, mtimeMs) !== null;
  }

  public get size(): number {
    return this.cache.size;
  }
}
