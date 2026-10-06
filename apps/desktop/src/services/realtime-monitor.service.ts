import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import { FileAnalyzer } from '../core/file-analyzer';
import { DetectedThreat } from '../types/desktop.types';

export class RealtimeMonitorService extends EventEmitter {
  private watchers: Map<string, fs.FSWatcher> = new Map();
  private isMonitoring = false;
  private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
  private inFlightFiles: Set<string> = new Set();
  private recentEvaluations: Map<string, number> = new Map();
  private entropyDetectionEnabled = true;
  private maxFileSizeBytes = 50 * 1024 * 1024;
  private excludedPaths: Set<string> = new Set();

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

  public setEntropyDetectionEnabled(enabled: boolean): void {
    this.entropyDetectionEnabled = Boolean(enabled);
  }

  public isEntropyDetectionEnabled(): boolean {
    return this.entropyDetectionEnabled;
  }

  public setMaxFileSizeBytes(bytes: number): void {
    this.maxFileSizeBytes = Math.max(1024 * 1024, Math.floor(bytes));
  }

  public setExcludedPaths(paths: string[]): void {
    this.excludedPaths = new Set((paths || []).map((p) => path.resolve(p)));
  }

  public isPathExcluded(filePath: string): boolean {
    if (!filePath || typeof filePath !== 'string') return false;
    const canonical = path.resolve(filePath);
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

  /**
   * Starts monitoring the provided target directories.
   */
  public start(directories: string[]): void {
    if (this.isMonitoring) {
      this.stop();
    }

    const validDirs = directories
      .map((d) => path.resolve(d))
      .filter((d) => fs.existsSync(d) && !this.isPathExcluded(d));

    if (validDirs.length === 0) {
      this.isMonitoring = false;
      return;
    }

    this.isMonitoring = true;

    for (const dir of validDirs) {
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
    this.inFlightFiles.clear();
    this.recentEvaluations.clear();

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
      watcher.on('error', () => {
        // Safely ignore runtime directory watcher errors (e.g. directory removed)
      });

      this.watchers.set(canonicalDir, watcher);
    } catch (err: any) {
      this.emit('error', { directory: canonicalDir, error: err.message });
    }
  }

  private handleFilesystemEvent(_eventType: string, filePath: string): void {
    if (!this.isMonitoring || this.isPathExcluded(filePath)) {
      return;
    }

    const canonicalPath = path.resolve(filePath);
    const ext = path.extname(canonicalPath).toLowerCase();
    if (RealtimeMonitorService.IGNORED_TRANSIENT_EXTENSIONS.has(ext)) {
      return;
    }

    // Debounce to prevent event storms during multi-block writes
    if (this.debounceTimers.has(canonicalPath)) {
      clearTimeout(this.debounceTimers.get(canonicalPath)!);
    }

    const timer = setTimeout(async () => {
      this.debounceTimers.delete(canonicalPath);
      await this.evaluateIncomingFile(canonicalPath);
    }, 250);

    this.debounceTimers.set(canonicalPath, timer);
  }

  /**
   * Safely inspects the finalized incoming file.
   */
  public async evaluateIncomingFile(filePath: string): Promise<void> {
    if (!this.isMonitoring || this.isPathExcluded(filePath)) return;
    const canonicalPath = path.resolve(filePath);

    // Cancel any pending debounce timer for this path
    if (this.debounceTimers.has(canonicalPath)) {
      clearTimeout(this.debounceTimers.get(canonicalPath)!);
      this.debounceTimers.delete(canonicalPath);
    }

    if (this.inFlightFiles.has(canonicalPath)) return;
    if (!fs.existsSync(canonicalPath)) return;

    this.inFlightFiles.add(canonicalPath);
    try {
      const stat = await fs.promises.lstat(canonicalPath);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.size === 0 || stat.size > this.maxFileSizeBytes) {
        return;
      }

      const dedupeKey = `${canonicalPath}:${stat.size}:${Math.floor(stat.mtimeMs)}`;
      const now = Date.now();
      const lastEval = this.recentEvaluations.get(dedupeKey);
      if (lastEval && now - lastEval < 1500) {
        return;
      }
      if (this.recentEvaluations.size > 500) {
        for (const [k, ts] of this.recentEvaluations.entries()) {
          if (now - ts >= 1500) {
            this.recentEvaluations.delete(k);
          }
        }
      }
      this.recentEvaluations.set(dedupeKey, now);

      const analysis = await FileAnalyzer.analyzeFile(canonicalPath, {
        entropyDetectionEnabled: this.entropyDetectionEnabled
      });

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
    } finally {
      this.inFlightFiles.delete(canonicalPath);
    }
  }
}
