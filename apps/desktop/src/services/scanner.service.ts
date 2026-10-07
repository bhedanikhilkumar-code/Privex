import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  ScanType,
  ScanStatus,
  ScanProgress,
  ScanResult,
  DetectedThreat,
  SkippedItem,
  ScanErrorItem,
  DesktopSettings
} from '../types/desktop.types';
import { CleanFileCache } from '../core/clean-file-cache';
import { ResourcePolicy } from '../core/resource-policy';
import { ScanProgressThrottler } from '../core/scan-progress-throttler';
import { ScanBatchExecutor } from '../core/scan-batch-executor';

export interface ScanOptions {
  readonly bypassCache?: boolean;
  readonly fileFilter?: (filePath: string) => boolean;
}

/**
 * ScannerService (Phase P — Performance, Worker Pool & Low-Resource Optimization)
 *
 * Production-grade on-demand and filesystem scanning engine.
 *
 * Features:
 * 1. 65,536-entry O(1) LRU Stage 0 CleanFileCache with 6-tuple identity.
 * 2. 20 Hz (50 ms) max IPC progress throttling preventing renderer flooding.
 * 3. Adaptive concurrency & batch sizing scaling to host RAM/CPU (special <= 4 GB tuning).
 * 4. Bounded memory and non-blocking batch execution.
 * 5. Instantaneous threat detection dispatch.
 * 6. Fail-closed error isolation and 100% offline local-only operation.
 */
export class ScannerService extends EventEmitter {
  private currentStatus: ScanStatus = 'idle';
  private currentScanId: string | null = null;
  private currentScanType: ScanType = 'custom';
  private cancelRequested = false;
  private isPaused = false;
  private pauseResolver: (() => void) | null = null;
  private activeStartTime = 0;
  private activeFilesScanned = 0;
  private activeBytesScanned = 0;
  private activeSkippedCount = 0;
  private activeErrorCount = 0;

  public getScanType(): ScanType {
    return this.currentScanType;
  }

  public getActiveStartTime(): number {
    return this.activeStartTime;
  }

  public getActiveSkippedCount(): number {
    return this.activeSkippedCount;
  }

  public getActiveErrorCount(): number {
    return this.activeErrorCount;
  }

  // Dynamic settings enforced at runtime (GAP-15)
  private maxFileSizeBytes = 50 * 1024 * 1024;
  private entropyDetectionEnabled = true;
  private excludedPaths: Set<string> = new Set();
  private maxDepth = 64;
  private followSymlinks = true;

  // Optimization components
  private resourcePolicy: ResourcePolicy;
  private cleanFileCache: CleanFileCache;
  private progressThrottler: ScanProgressThrottler | null = null;

  constructor(options?: {
    resourcePolicy?: ResourcePolicy;
    cleanFileCache?: CleanFileCache;
  }) {
    super();
    this.resourcePolicy = options?.resourcePolicy ?? ResourcePolicy.getSharedInstance();
    this.cleanFileCache = options?.cleanFileCache ?? CleanFileCache.getSharedInstance();
  }

  public getResourcePolicy(): ResourcePolicy {
    return this.resourcePolicy;
  }

  public setResourcePolicy(policy: ResourcePolicy): void {
    if (policy) {
      this.resourcePolicy = policy;
    }
  }

  public getCleanFileCache(): CleanFileCache {
    return this.cleanFileCache;
  }

  public clearCache(): void {
    this.cleanFileCache.clear();
  }

  public invalidateCache(filePath: string): boolean {
    return this.cleanFileCache.invalidate(filePath);
  }

  public setMaxFileSizeBytes(bytes: number): void {
    if (typeof bytes !== 'number' || !Number.isFinite(bytes)) {
      return;
    }
    this.maxFileSizeBytes = Math.max(1024 * 1024, Math.floor(bytes));
  }

  public getMaxFileSizeBytes(): number {
    return this.maxFileSizeBytes;
  }

  public setMaxDepth(depth: number): void {
    if (typeof depth !== 'number' || !Number.isFinite(depth) || depth < 1) {
      return;
    }
    this.maxDepth = Math.min(256, Math.floor(depth));
  }

  public getMaxDepth(): number {
    return this.maxDepth;
  }

  public setFollowSymlinks(follow: boolean): void {
    this.followSymlinks = Boolean(follow);
  }

  public isFollowSymlinksEnabled(): boolean {
    return this.followSymlinks;
  }

  public setEntropyDetectionEnabled(enabled: boolean): void {
    this.entropyDetectionEnabled = Boolean(enabled);
  }

  public isEntropyDetectionEnabled(): boolean {
    return this.entropyDetectionEnabled;
  }

  public setExcludedPaths(paths: string[]): void {
    this.excludedPaths = new Set(
      (paths || [])
        .filter((p): p is string => typeof p === 'string' && p.trim().length > 0 && !p.includes('\0'))
        .map((p) => path.resolve(p))
    );
  }

  public getExcludedPaths(): string[] {
    return Array.from(this.excludedPaths);
  }

  public applySettings(
    settings: Pick<
      DesktopSettings,
      'scanLargeFilesLimitMb' | 'entropyDetectionEnabled' | 'excludedPaths'
    >
  ): void {
    this.setMaxFileSizeBytes(settings.scanLargeFilesLimitMb * 1024 * 1024);
    this.setEntropyDetectionEnabled(settings.entropyDetectionEnabled);
    this.setExcludedPaths(settings.excludedPaths || []);
  }

  public isPathExcluded(targetPath: string): boolean {
    if (!targetPath || typeof targetPath !== 'string') return false;
    const canonical = path.resolve(targetPath);
    for (const rawExcluded of this.excludedPaths) {
      if (!rawExcluded) continue;
      const excluded = path.resolve(rawExcluded);
      if (process.platform === 'win32') {
        const lowerCanon = canonical.toLowerCase();
        const lowerEx = excluded.toLowerCase();
        const prefix = lowerEx.endsWith(path.sep) ? lowerEx : lowerEx + path.sep;
        if (lowerCanon === lowerEx || lowerCanon.startsWith(prefix)) {
          return true;
        }
      } else {
        const prefix = excluded.endsWith(path.sep) ? excluded : excluded + path.sep;
        if (canonical === excluded || canonical.startsWith(prefix)) {
          return true;
        }
      }
    }
    return false;
  }

  public getStatus(): ScanStatus {
    return this.currentStatus;
  }

  public getScanId(): string | null {
    return this.currentScanId;
  }

  public cancelScan(): void {
    if (this.currentStatus === 'running' || this.currentStatus === 'paused') {
      this.cancelRequested = true;
      if (this.isPaused && this.pauseResolver) {
        this.pauseResolver();
        this.pauseResolver = null;
      }
      this.currentStatus = 'cancelled';
      if (this.progressThrottler) {
        this.progressThrottler.flush();
      }
      this.emit('cancelled', { scanId: this.currentScanId });
    }
  }

  public pauseScan(): void {
    if (this.currentStatus === 'running') {
      this.isPaused = true;
      this.currentStatus = 'paused';
      if (this.progressThrottler) {
        this.progressThrottler.flush();
      }
      this.emit('paused', { scanId: this.currentScanId });
    }
  }

  public resumeScan(): void {
    if (this.currentStatus === 'paused') {
      this.isPaused = false;
      this.currentStatus = 'running';
      if (this.pauseResolver) {
        this.pauseResolver();
        this.pauseResolver = null;
      }
      this.emit('resumed', { scanId: this.currentScanId });
    }
  }

  private async checkPauseAndCancel(): Promise<boolean> {
    if (this.cancelRequested) {
      return true;
    }
    if (this.isPaused) {
      await new Promise<void>((resolve) => {
        this.pauseResolver = resolve;
      });
    }
    return this.cancelRequested;
  }

  /**
   * Executes a recursive filesystem scan across target directories with batching,
   * CleanFileCache fast-pathing, adaptive concurrency, and 20 Hz progress rate-limiting.
   */
  public async scanPaths(
    targets: string[],
    scanType: ScanType = 'custom',
    fileFilter?: ((filePath: string) => boolean) | ScanOptions,
    scanOptions?: ScanOptions
  ): Promise<ScanResult> {
    const filterFn = typeof fileFilter === 'function' ? fileFilter : undefined;
    const options: ScanOptions =
      typeof fileFilter === 'object' && fileFilter !== null
        ? fileFilter
        : scanOptions ?? {};

    const scanId = `scan-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    this.currentScanId = scanId;
    this.currentScanType = scanType;
    this.currentStatus = 'running';
    this.cancelRequested = false;
    this.isPaused = false;

    const startTime = Date.now();
    this.activeStartTime = startTime;
    this.activeFilesScanned = 0;
    this.activeBytesScanned = 0;
    this.activeSkippedCount = 0;
    this.activeErrorCount = 0;

    let totalFilesScanned = 0;
    let totalBytesScanned = 0;
    const threats: DetectedThreat[] = [];
    const skippedFiles: SkippedItem[] = [];
    const errors: ScanErrorItem[] = [];

    // Initialize 20 Hz progress throttler
    this.progressThrottler = new ScanProgressThrottler(
      (progress: ScanProgress) => {
        this.emit('progress', progress);
      },
      { intervalMs: 50 }
    );

    // Bounded batch executor
    const batchExecutor = new ScanBatchExecutor({
      scanId,
      scanType,
      maxFileSizeBytes: this.maxFileSizeBytes,
      entropyDetectionEnabled: this.entropyDetectionEnabled,
      bypassCache: options.bypassCache,
      resourcePolicy: this.resourcePolicy,
      progressThrottler: this.progressThrottler,
      isPathExcluded: (p) => this.isPathExcluded(p),
      isCancelled: () => this.cancelRequested,
      isPaused: () => this.isPaused,
      waitForResume: async () => {
        if (this.isPaused) {
          await new Promise<void>((resolve) => {
            this.pauseResolver = resolve;
          });
        }
      },
      onThreatFound: (threat) => {
        this.emit('threatFound', threat);
      },
      onProgress: (progress) => {
        this.emit('progress', progress);
      },
      onFileProcessed: (bytes) => {
        totalBytesScanned += bytes;
        totalFilesScanned++;
        this.activeBytesScanned = totalBytesScanned;
        this.activeFilesScanned = totalFilesScanned;
      }
    });

    const visitedRealPaths = new Set<string>();
    const safeTargets = Array.isArray(targets) ? targets : [];

    this.emit('started', { scanId, scanType, targets: safeTargets });

    for (const target of safeTargets) {
      if (await this.checkPauseAndCancel()) break;

      if (
        typeof target !== 'string' ||
        !target.trim() ||
        target.includes('\0') ||
        target.length > 1024
      ) {
        errors.push({
          path: String(target),
          error: 'INVALID_PATH: Target path is malformed, empty, or exceeds 1024 characters'
        });
        this.activeErrorCount = errors.length;
        continue;
      }

      try {
        const canonicalTarget = path.resolve(target.trim());
        if (this.isPathExcluded(canonicalTarget)) {
          skippedFiles.push({ path: canonicalTarget, reason: 'Excluded by user settings' });
          this.activeSkippedCount = skippedFiles.length;
          continue;
        }

        if (!fs.existsSync(canonicalTarget)) {
          skippedFiles.push({ path: target, reason: 'Path does not exist' });
          this.activeSkippedCount = skippedFiles.length;
          continue;
        }

        const rootStat = await fs.promises.stat(canonicalTarget);
        if (rootStat.isFile()) {
          if (!filterFn || filterFn(canonicalTarget)) {
            await batchExecutor.processFile(canonicalTarget);
          }
        } else if (rootStat.isDirectory()) {
          // Collect directory files in memory-bounded batches
          const collectedBatch: string[] = [];
          const profile = this.resourcePolicy.getProfile();
          const batchSize = profile.batchSize;

          const flushCollectedBatch = async () => {
            if (collectedBatch.length > 0) {
              const toProcess = collectedBatch.splice(0, collectedBatch.length);
              await batchExecutor.execute(toProcess);
            }
          };

          await this.traverseDirectoryStream(
            canonicalTarget,
            visitedRealPaths,
            skippedFiles,
            errors,
            filterFn,
            async (filePath) => {
              collectedBatch.push(filePath);
              if (collectedBatch.length >= batchSize) {
                await flushCollectedBatch();
              }
            },
            0
          );

          // Flush any remaining collected files in the batch
          await flushCollectedBatch();
        }
      } catch (err: any) {
        errors.push({ path: target, error: err.message || 'Unknown traversal error' });
        this.activeErrorCount = errors.length;
      }
    }

    // Flush any pending progress frame before dispatching completed event
    if (this.progressThrottler) {
      this.progressThrottler.flush();
      this.progressThrottler.dispose();
      this.progressThrottler = null;
    }

    const durationMs = Date.now() - startTime;
    this.currentStatus = this.cancelRequested ? 'cancelled' : 'completed';

    // Merge threats, skipped, and errors from batch executor
    const batchResult = await batchExecutor.execute([]);
    threats.push(...batchResult.threats);
    skippedFiles.push(...batchResult.skipped);
    errors.push(...batchResult.errors);

    // Fail-closed overall verdict calculation
    let overallVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' = 'ALLOW';
    if (threats.some((t) => t.verdict === 'BLOCK')) {
      overallVerdict = 'BLOCK';
    } else if (threats.some((t) => t.verdict === 'WARN')) {
      overallVerdict = 'WARN';
    } else if (errors.length > 0) {
      overallVerdict = 'WARN';
    } else if (threats.some((t) => t.verdict === 'INFORM')) {
      overallVerdict = 'INFORM';
    } else if (totalFilesScanned === 0 && skippedFiles.length > 0 && safeTargets.length > 0) {
      overallVerdict = 'INFORM';
    }

    const analysisStatus = errors.length > 0 ? 'ANALYSIS_FAILED' : 'COMPLETED';
    const disposition =
      overallVerdict === 'BLOCK'
        ? 'MALICIOUS'
        : errors.length > 0
        ? 'ANALYSIS_FAILED'
        : overallVerdict === 'WARN' || overallVerdict === 'INFORM'
        ? 'SUSPICIOUS'
        : 'SAFE';

    const result: ScanResult = {
      scanId,
      scanType,
      status: this.currentStatus,
      totalFilesScanned: this.activeFilesScanned,
      totalBytesScanned: this.activeBytesScanned,
      durationMs,
      threats,
      skippedFiles,
      errors,
      overallVerdict,
      analysisStatus,
      disposition,
      completedAt: Date.now()
    };

    this.emit('completed', result);
    return result;
  }

  /**
   * Traverses directories streaming file paths into batch buffer.
   */
  private async traverseDirectoryStream(
    dirPath: string,
    visitedRealPaths: Set<string>,
    skippedFiles: SkippedItem[],
    errors: ScanErrorItem[],
    fileFilter: ((filePath: string) => boolean) | undefined,
    onFileFound: (filePath: string) => Promise<void>,
    currentDepth = 0
  ): Promise<void> {
    if (await this.checkPauseAndCancel()) return;

    if (currentDepth > this.maxDepth) {
      skippedFiles.push({
        path: dirPath,
        reason: `Maximum directory recursion depth (${this.maxDepth}) exceeded`
      });
      this.activeSkippedCount = skippedFiles.length;
      return;
    }

    if (this.isPathExcluded(dirPath)) {
      skippedFiles.push({ path: dirPath, reason: 'Excluded by user settings' });
      this.activeSkippedCount = skippedFiles.length;
      return;
    }

    // Symlink / Junction Cycle Detection
    try {
      const realDirPath = fs.realpathSync(dirPath);
      if (visitedRealPaths.has(realDirPath)) {
        skippedFiles.push({ path: dirPath, reason: 'Symlink recursion cycle avoided' });
        this.activeSkippedCount = skippedFiles.length;
        return;
      }
      visitedRealPaths.add(realDirPath);
    } catch (err: any) {
      skippedFiles.push({ path: dirPath, reason: `Unresolvable realpath: ${err.message}` });
      this.activeSkippedCount = skippedFiles.length;
      return;
    }

    let entries: fs.Dirent[] = [];
    try {
      entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    } catch (err: any) {
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        skippedFiles.push({ path: dirPath, reason: 'Permission denied (access restricted)' });
        this.activeSkippedCount = skippedFiles.length;
      } else {
        errors.push({ path: dirPath, error: err.message || 'Error reading directory' });
        this.activeErrorCount = errors.length;
      }
      return;
    }

    for (const entry of entries) {
      if (await this.checkPauseAndCancel()) return;

      const fullPath = path.join(dirPath, entry.name);

      if (this.isPathExcluded(fullPath)) {
        skippedFiles.push({ path: fullPath, reason: 'Excluded by user settings' });
        this.activeSkippedCount = skippedFiles.length;
        continue;
      }

      try {
        if (entry.isSymbolicLink()) {
          if (!this.followSymlinks) {
            skippedFiles.push({ path: fullPath, reason: 'Symbolic link skipped by policy' });
            this.activeSkippedCount = skippedFiles.length;
            continue;
          }
          try {
            const linkTarget = await fs.promises.realpath(fullPath);
            const targetStat = await fs.promises.stat(linkTarget);
            if (targetStat.isDirectory()) {
              if (visitedRealPaths.has(linkTarget)) {
                skippedFiles.push({ path: fullPath, reason: 'Symlink loop detected' });
                this.activeSkippedCount = skippedFiles.length;
                continue;
              }
              await this.traverseDirectoryStream(
                fullPath,
                visitedRealPaths,
                skippedFiles,
                errors,
                fileFilter,
                onFileFound,
                currentDepth + 1
              );
            } else if (targetStat.isFile()) {
              if (!fileFilter || fileFilter(fullPath)) {
                await onFileFound(fullPath);
              }
            }
          } catch {
            skippedFiles.push({ path: fullPath, reason: 'Broken symlink target' });
            this.activeSkippedCount = skippedFiles.length;
          }
        } else if (entry.isDirectory()) {
          await this.traverseDirectoryStream(
            fullPath,
            visitedRealPaths,
            skippedFiles,
            errors,
            fileFilter,
            onFileFound,
            currentDepth + 1
          );
        } else if (entry.isFile()) {
          if (!fileFilter || fileFilter(fullPath)) {
            await onFileFound(fullPath);
          }
        }
      } catch (err: any) {
        errors.push({ path: fullPath, error: err.message || 'File processing error' });
        this.activeErrorCount = errors.length;
      }
    }
  }
}
