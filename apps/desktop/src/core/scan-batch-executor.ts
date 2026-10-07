import * as fs from 'fs';
import * as path from 'path';
import {
  DetectedThreat,
  SkippedItem,
  ScanErrorItem,
  ScanType,
  ScanStatus,
  ScanProgress
} from '../types/desktop.types';
import { FileAnalyzer } from './file-analyzer';
import { CleanFileCache } from './clean-file-cache';
import { ResourcePolicy } from './resource-policy';
import { ScanProgressThrottler } from './scan-progress-throttler';

export interface ScanBatchExecutorOptions {
  readonly scanId: string;
  readonly scanType: ScanType;
  readonly maxFileSizeBytes: number;
  readonly entropyDetectionEnabled: boolean;
  readonly bypassCache?: boolean;
  readonly resourcePolicy?: ResourcePolicy;
  readonly progressThrottler?: ScanProgressThrottler;
  readonly isPathExcluded: (filePath: string) => boolean;
  readonly isCancelled: () => boolean;
  readonly isPaused: () => boolean;
  readonly waitForResume: () => Promise<void>;
  readonly onThreatFound: (threat: DetectedThreat) => void;
  readonly onProgress: (progress: ScanProgress) => void;
  readonly onFileProcessed: (bytes: number) => void;
}

export interface BatchExecutionResult {
  readonly filesScanned: number;
  readonly bytesScanned: number;
  readonly threats: DetectedThreat[];
  readonly skipped: SkippedItem[];
  readonly errors: ScanErrorItem[];
  readonly status: ScanStatus;
}

/**
 * ScanBatchExecutor (Phase P — P4 & P7)
 *
 * Coordinates non-blocking, memory-bounded, multi-worker batch processing
 * of file analysis pipelines with adaptive concurrency and 20 Hz progress rate-limiting.
 *
 * Guarantees:
 * 1. Files are processed in bounded batches without giant Promise.all allocations.
 * 2. Concurrency adapts to host resources (conservative for <= 4 GB RAM systems).
 * 3. Exact scan accounting is maintained.
 * 4. Cancellation and pause are checked between files and batches.
 * 5. One malformed or locked file never terminates the entire batch scan.
 */
export class ScanBatchExecutor {
  private readonly options: ScanBatchExecutorOptions;
  private readonly resourcePolicy: ResourcePolicy;
  private readonly cache: CleanFileCache;
  private readonly throttler: ScanProgressThrottler;

  private filesScanned = 0;
  private bytesScanned = 0;
  private readonly threats: DetectedThreat[] = [];
  private readonly skipped: SkippedItem[] = [];
  private readonly errors: ScanErrorItem[] = [];
  private readonly startTime = Date.now();

  constructor(options: ScanBatchExecutorOptions) {
    this.options = options;
    this.resourcePolicy = options.resourcePolicy ?? ResourcePolicy.getSharedInstance();
    this.cache = CleanFileCache.getSharedInstance();
    this.throttler =
      options.progressThrottler ??
      new ScanProgressThrottler(options.onProgress, { intervalMs: 50 });
  }

  /**
   * Executes scanning over an array of file paths in adaptive bounded batches.
   */
  public async execute(filePaths: string[]): Promise<BatchExecutionResult> {
    const profile = this.resourcePolicy.getProfile();
    const batchSize = profile.batchSize;
    const concurrency = profile.concurrency;

    for (let i = 0; i < filePaths.length; i += batchSize) {
      if (this.options.isCancelled()) {
        break;
      }
      if (this.options.isPaused()) {
        await this.options.waitForResume();
        if (this.options.isCancelled()) break;
      }

      const currentBatch = filePaths.slice(i, i + batchSize);
      await this.processBatch(currentBatch, concurrency);
    }

    // Flush any pending throttled progress update
    this.throttler.flush();

    return {
      filesScanned: this.filesScanned,
      bytesScanned: this.bytesScanned,
      threats: this.threats,
      skipped: this.skipped,
      errors: this.errors,
      status: this.options.isCancelled() ? 'cancelled' : 'completed'
    };
  }

  /**
   * Processes a single batch with bounded worker concurrency.
   */
  private async processBatch(batch: string[], concurrency: number): Promise<void> {
    const executing = new Set<Promise<void>>();

    for (const filePath of batch) {
      if (this.options.isCancelled()) break;

      const p = this.processFile(filePath).finally(() => {
        executing.delete(p);
      });
      executing.add(p);

      if (executing.size >= concurrency) {
        await Promise.race(executing);
      }
    }

    await Promise.all(executing);
  }

  /**
   * Inspects a single file, checking cache, exclusion, size bounds, and running FileAnalyzer.
   */
  public async processFile(filePath: string): Promise<void> {
    if (this.options.isCancelled()) return;

    if (this.options.isPathExcluded(filePath)) {
      this.skipped.push({ path: filePath, reason: 'Excluded by user settings' });
      return;
    }

    try {
      const stat = await fs.promises.stat(filePath);

      if (!stat.isFile()) {
        return;
      }

      if (stat.size > this.options.maxFileSizeBytes) {
        this.skipped.push({
          path: filePath,
          reason: `File exceeds size limit (${Math.round(stat.size / 1024 / 1024)} MB > ${Math.round(this.options.maxFileSizeBytes / 1024 / 1024)} MB)`
        });
        return;
      }

      // Stage 0: CleanFileCache lookup
      let analysis;
      if (!this.options.bypassCache) {
        const cached = this.cache.get(filePath, stat.size, stat.mtimeMs, {
          dev: stat.dev,
          ino: stat.ino
        });

        if (cached) {
          this.filesScanned++;
          this.bytesScanned += stat.size;
          this.options.onFileProcessed(stat.size);
          this.emitProgress(filePath);
          return;
        }
      }

      analysis = await FileAnalyzer.analyzeFile(filePath, {
        entropyDetectionEnabled: this.options.entropyDetectionEnabled
      });

      this.filesScanned++;
      this.bytesScanned += stat.size;
      this.options.onFileProcessed(stat.size);

      // Threat evaluation
      if (
        analysis.verdict === 'BLOCK' ||
        analysis.verdict === 'WARN' ||
        analysis.riskScore >= 30
      ) {
        const threat: DetectedThreat = {
          id: `threat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          filePath: analysis.filePath,
          fileName: analysis.fileName,
          fileSize: analysis.fileSize,
          sha256: analysis.sha256,
          riskScore: analysis.riskScore,
          severity: analysis.severity,
          verdict: analysis.verdict,
          threatName: analysis.threatName,
          detectedAt: Date.now(),
          evidenceFactors: analysis.evidenceFactors,
          quarantined: false
        };
        this.threats.push(threat);
        this.options.onThreatFound(threat);
      } else if (analysis.verdict === 'ALLOW' && analysis.riskScore === 0) {
        // Populate CleanFileCache for clean files
        this.cache.set(filePath, stat.size, stat.mtimeMs, analysis.sha256, {
          dev: stat.dev,
          ino: stat.ino
        });
      }

      if (analysis.analysisStatus === 'ANALYSIS_FAILED' && analysis.errorReason) {
        this.errors.push({
          path: filePath,
          error: analysis.errorReason
        });
      }

      this.emitProgress(filePath);
    } catch (err: any) {
      if (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EBUSY') {
        this.skipped.push({
          path: filePath,
          reason: `File locked or permission denied (${err.code})`
        });

        // Fail-closed deceptive extension check on locked file
        const fileName = path.basename(filePath);
        const deceptive = FileAnalyzer.checkDeceptiveExtension(fileName);
        if (deceptive.isDeceptive) {
          const lockedThreat: DetectedThreat = {
            id: `threat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            filePath,
            fileName,
            fileSize: 0,
            sha256: '',
            riskScore: 60,
            severity: 'suspicious',
            verdict: 'WARN',
            threatName: 'LOCKED_DECEPTIVE_FILE',
            detectedAt: Date.now(),
            evidenceFactors: [
              `Locked or permission-restricted file (${err.code}) exhibits deceptive extension spoofing`
            ],
            quarantined: false
          };
          this.threats.push(lockedThreat);
          this.options.onThreatFound(lockedThreat);
        }
      } else {
        this.errors.push({
          path: filePath,
          error: err.message || 'File analysis error'
        });
      }
    }
  }

  private emitProgress(currentPath: string): void {
    const elapsedMs = Math.max(1, Date.now() - this.startTime);
    const scanSpeedFilesPerSec =
      Math.round((this.filesScanned / (elapsedMs / 1000)) * 10) / 10;

    const progress: ScanProgress = {
      scanId: this.options.scanId,
      scanType: this.options.scanType,
      status: this.options.isCancelled() ? 'cancelled' : 'running',
      filesScanned: this.filesScanned,
      threatsFound: this.threats.length,
      currentPath,
      bytesScanned: this.bytesScanned,
      skippedCount: this.skipped.length,
      errorCount: this.errors.length,
      startTime: this.startTime,
      elapsedMs,
      scanSpeedFilesPerSec
    };

    this.throttler.push(progress);
  }
}
