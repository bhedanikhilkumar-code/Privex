import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { FileAnalyzer } from '../core/file-analyzer';
import { DetectedThreat } from '../types/desktop.types';

export class RealtimeMonitorService extends EventEmitter {
  private watchers: Map<string, fs.FSWatcher> = new Map();
  private isMonitoring = false;
  private debounceTimers: Map<string, NodeJS.Timeout> = new Map();

  // Transient download extensions to ignore while writing
  private static readonly IGNORED_TRANSIENT_EXTENSIONS = new Set([
    '.crdownload', '.part', '.tmp', '.download', '.swp', '.lock'
  ]);

  public isActive(): boolean {
    return this.isMonitoring;
  }

  public getMonitoredPaths(): string[] {
    return Array.from(this.watchers.keys());
  }

  /**
   * Starts monitoring the provided target directories.
   */
  public start(directories: string[]): void {
    if (this.isMonitoring) {
      this.stop();
    }

    this.isMonitoring = true;

    for (const dir of directories) {
      this.addWatchDirectory(dir);
    }

    this.emit('started', { directories: this.getMonitoredPaths() });
  }

  public stop(): void {
    for (const watcher of this.watchers.values()) {
      try {
        watcher.close();
      } catch {
        // continue
      }
    }
    this.watchers.clear();

    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();

    this.isMonitoring = false;
    this.emit('stopped');
  }

  private addWatchDirectory(dirPath: string): void {
    const canonicalDir = path.resolve(dirPath);
    if (!fs.existsSync(canonicalDir) || this.watchers.has(canonicalDir)) {
      return;
    }

    try {
      const watcher = fs.watch(canonicalDir, { persistent: false }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(canonicalDir, filename);
        this.handleFilesystemEvent(eventType, fullPath);
      });

      this.watchers.set(canonicalDir, watcher);
    } catch (err: any) {
      this.emit('error', { directory: canonicalDir, error: err.message });
    }
  }

  private handleFilesystemEvent(_eventType: string, filePath: string): void {
    const ext = path.extname(filePath).toLowerCase();
    if (RealtimeMonitorService.IGNORED_TRANSIENT_EXTENSIONS.has(ext)) {
      return;
    }

    // Debounce to prevent event storms during multi-block writes
    if (this.debounceTimers.has(filePath)) {
      clearTimeout(this.debounceTimers.get(filePath)!);
    }

    const timer = setTimeout(async () => {
      this.debounceTimers.delete(filePath);
      await this.evaluateIncomingFile(filePath);
    }, 250);

    this.debounceTimers.set(filePath, timer);
  }

  /**
   * Safely inspects the finalized incoming file.
   */
  private async evaluateIncomingFile(filePath: string): Promise<void> {
    if (!fs.existsSync(filePath)) return;

    try {
      const stat = await fs.promises.stat(filePath);
      if (!stat.isFile() || stat.size === 0) return;

      const analysis = await FileAnalyzer.analyzeFile(filePath);

      if (analysis.verdict === 'BLOCK' || analysis.verdict === 'WARN') {
        const threat: DetectedThreat = {
          id: `rt-threat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
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

        this.emit('threatDetected', threat);
      }
    } catch {
      // Ignore transient access or lock errors safely
    }
  }
}
