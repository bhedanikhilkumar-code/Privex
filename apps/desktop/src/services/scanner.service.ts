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
  ScanErrorItem
} from '../types/desktop.types';
import { FileAnalyzer } from '../core/file-analyzer';

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

  // Maximum file size to inspect full body (50 MB)
  private readonly MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;

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
      this.emit('cancelled', { scanId: this.currentScanId });
    }
  }

  public pauseScan(): void {
    if (this.currentStatus === 'running') {
      this.isPaused = true;
      this.currentStatus = 'paused';
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
   * Executes a recursive filesystem scan across target directories.
   */
  public async scanPaths(
    targets: string[],
    scanType: ScanType = 'custom',
    fileFilter?: (filePath: string) => boolean
  ): Promise<ScanResult> {
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

    // Tracks visited real paths to prevent symlink recursion cycles
    const visitedRealPaths = new Set<string>();

    this.emit('started', { scanId, scanType, targets });

    for (const target of targets) {
      if (await this.checkPauseAndCancel()) break;

      try {
        const canonicalTarget = path.resolve(target);
        if (!fs.existsSync(canonicalTarget)) {
          skippedFiles.push({ path: target, reason: 'Path does not exist' });
          this.activeSkippedCount = skippedFiles.length;
          continue;
        }

        const rootStat = await fs.promises.stat(canonicalTarget);
        if (rootStat.isFile()) {
          await this.processSingleFile(
            canonicalTarget,
            threats,
            skippedFiles,
            errors,
            (bytes) => {
              totalBytesScanned += bytes;
              totalFilesScanned++;
              this.activeBytesScanned = totalBytesScanned;
              this.activeFilesScanned = totalFilesScanned;
            }
          );
        } else if (rootStat.isDirectory()) {
          await this.traverseDirectory(
            canonicalTarget,
            visitedRealPaths,
            threats,
            skippedFiles,
            errors,
            fileFilter,
            (bytes) => {
              totalBytesScanned += bytes;
              totalFilesScanned++;
              this.activeBytesScanned = totalBytesScanned;
              this.activeFilesScanned = totalFilesScanned;
            }
          );
        }
      } catch (err: any) {
        errors.push({ path: target, error: err.message || 'Unknown traversal error' });
        this.activeErrorCount = errors.length;
      }
    }

    const durationMs = Date.now() - startTime;
    this.currentStatus = this.cancelRequested ? 'cancelled' : 'completed';

    let overallVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' = 'ALLOW';
    if (threats.some((t) => t.verdict === 'BLOCK')) {
      overallVerdict = 'BLOCK';
    } else if (threats.some((t) => t.verdict === 'WARN')) {
      overallVerdict = 'WARN';
    } else if (threats.some((t) => t.verdict === 'INFORM')) {
      overallVerdict = 'INFORM';
    }

    const result: ScanResult = {
      scanId,
      scanType,
      status: this.currentStatus,
      totalFilesScanned,
      totalBytesScanned,
      durationMs,
      threats,
      skippedFiles,
      errors,
      overallVerdict,
      completedAt: Date.now()
    };

    this.emit('completed', result);
    return result;
  }

  private async traverseDirectory(
    dirPath: string,
    visitedRealPaths: Set<string>,
    threats: DetectedThreat[],
    skippedFiles: SkippedItem[],
    errors: ScanErrorItem[],
    fileFilter: ((filePath: string) => boolean) | undefined,
    onFileProcessed: (bytes: number) => void
  ): Promise<void> {
    if (await this.checkPauseAndCancel()) return;

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

      try {
        if (entry.isSymbolicLink()) {
          try {
            const linkTarget = await fs.promises.realpath(fullPath);
            const targetStat = await fs.promises.stat(linkTarget);
            if (targetStat.isDirectory()) {
              if (visitedRealPaths.has(linkTarget)) {
                skippedFiles.push({ path: fullPath, reason: 'Symlink loop detected' });
                this.activeSkippedCount = skippedFiles.length;
                continue;
              }
              await this.traverseDirectory(
                fullPath,
                visitedRealPaths,
                threats,
                skippedFiles,
                errors,
                fileFilter,
                onFileProcessed
              );
            } else if (targetStat.isFile()) {
              if (!fileFilter || fileFilter(fullPath)) {
                await this.processSingleFile(fullPath, threats, skippedFiles, errors, onFileProcessed);
              }
            }
          } catch {
            skippedFiles.push({ path: fullPath, reason: 'Broken symlink target' });
            this.activeSkippedCount = skippedFiles.length;
          }
        } else if (entry.isDirectory()) {
          await this.traverseDirectory(
            fullPath,
            visitedRealPaths,
            threats,
            skippedFiles,
            errors,
            fileFilter,
            onFileProcessed
          );
        } else if (entry.isFile()) {
          if (!fileFilter || fileFilter(fullPath)) {
            await this.processSingleFile(fullPath, threats, skippedFiles, errors, onFileProcessed);
          }
        }
      } catch (err: any) {
        errors.push({ path: fullPath, error: err.message || 'File processing error' });
        this.activeErrorCount = errors.length;
      }
    }
  }

  private async processSingleFile(
    filePath: string,
    threats: DetectedThreat[],
    skippedFiles: SkippedItem[],
    errors: ScanErrorItem[],
    onFileProcessed: (bytes: number) => void
  ): Promise<void> {
    try {
      const stat = await fs.promises.stat(filePath);

      if (stat.size > this.MAX_FILE_SIZE_BYTES) {
        skippedFiles.push({ path: filePath, reason: `File exceeds size limit (${Math.round(stat.size / 1024 / 1024)} MB)` });
        this.activeSkippedCount = skippedFiles.length;
        return;
      }

      const analysis = await FileAnalyzer.analyzeFile(filePath);
      onFileProcessed(stat.size);

      if (analysis.verdict === 'BLOCK' || analysis.verdict === 'WARN' || analysis.riskScore >= 30) {
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
        threats.push(threat);
        this.emit('threatFound', threat);
      }

      this.emitProgress(filePath, threats.length);
    } catch (err: any) {
      if (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EBUSY') {
        skippedFiles.push({ path: filePath, reason: `File locked or permission denied (${err.code})` });
        this.activeSkippedCount = skippedFiles.length;
      } else {
        errors.push({ path: filePath, error: err.message || 'File analysis error' });
        this.activeErrorCount = errors.length;
      }
    }
  }

  private emitProgress(currentPath: string, threatsFound: number): void {
    const elapsedMs = Math.max(1, Date.now() - this.activeStartTime);
    const scanSpeedFilesPerSec = Math.round((this.activeFilesScanned / (elapsedMs / 1000)) * 10) / 10;

    const progress: ScanProgress = {
      scanId: this.currentScanId || 'unknown',
      scanType: this.currentScanType,
      status: this.currentStatus,
      filesScanned: this.activeFilesScanned,
      threatsFound,
      currentPath,
      bytesScanned: this.activeBytesScanned,
      skippedCount: this.activeSkippedCount,
      errorCount: this.activeErrorCount,
      startTime: this.activeStartTime,
      elapsedMs,
      scanSpeedFilesPerSec
    };
    this.emit('progress', progress);
  }
}
