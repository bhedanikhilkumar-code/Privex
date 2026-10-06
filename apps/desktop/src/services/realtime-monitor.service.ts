import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import { FileAnalyzer } from '../core/file-analyzer';
import {
  DetectedThreat,
  RealtimeMonitorOptions,
  RealtimeQueueStats,
  PendingDownload
} from '../types/desktop.types';
import { QuarantineService } from './quarantine.service';
import { ExclusionManagerService } from './exclusion-manager.service';
import { ResponsePolicyEngine } from './response-policy-engine';

interface QueueItem {
  readonly filePath: string;
  readonly isHighPriority: boolean;
  readonly queuedAt: number;
}

export class RealtimeMonitorService extends EventEmitter {
  private watchers: Map<string, fs.FSWatcher> = new Map();
  private isMonitoring = false;
  private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
  private inFlightFiles: Set<string> = new Set();
  private recentEvaluations: Map<string, number> = new Map();
  private options: Required<RealtimeMonitorOptions>;
  private quarantineService: QuarantineService | null = null;
  private exclusionManager: ExclusionManagerService | null = null;
  private currentExcludedVaultDir: string | null = null;

  // Incomplete / In-progress download tracking (.crdownload, .part, etc.)
  private pendingDownloads: Map<string, PendingDownload> = new Map();

  // Bounded priority event queues
  private highPriorityQueue: QueueItem[] = [];
  private normalPriorityQueue: QueueItem[] = [];
  private queuedPaths: Set<string> = new Set();
  private activeWorkers = 0;

  // Latency ring buffer for accurate p50/p95 reporting
  private readonly latencyBuffer: number[] = [];
  private static readonly MAX_LATENCY_SAMPLES = 1000;

  // Telemetry counters
  private droppedEventsCount = 0;
  private processedCount = 0;
  private threatsDetectedCount = 0;
  private quarantinedCount = 0;

  // Transient download extensions to ignore while actively writing
  public static readonly IGNORED_TRANSIENT_EXTENSIONS = new Set([
    '.crdownload',
    '.part',
    '.tmp',
    '.download',
    '.swp',
    '.lock'
  ]);

  // High-risk executable & script extensions mapped to priority queue
  private static readonly HIGH_RISK_EXTENSIONS = new Set([
    '.exe',
    '.scr',
    '.bat',
    '.cmd',
    '.ps1',
    '.vbs',
    '.dll',
    '.com',
    '.hta',
    '.jar',
    '.msi',
    '.vbe',
    '.wsf',
    '.cpl',
    '.reg',
    '.pif'
  ]);

  constructor(
    options?: RealtimeMonitorOptions,
    quarantineService?: QuarantineService | null,
    exclusionManager?: ExclusionManagerService | null
  ) {
    super();
    this.quarantineService = quarantineService || null;
    this.exclusionManager = exclusionManager || null;

    this.options = {
      recursive: options?.recursive ?? (process.platform === 'win32'),
      maxQueueSize: Math.max(10, options?.maxQueueSize ?? 10000),
      concurrencyLimit: Math.max(1, options?.concurrencyLimit ?? 4),
      stabilityCheckMs: Math.max(0, options?.stabilityCheckMs ?? 15),
      stabilityRetries: Math.max(0, options?.stabilityRetries ?? 3),
      debounceMs: Math.max(0, options?.debounceMs ?? 25),
      autoQuarantineCritical: options?.autoQuarantineCritical ?? false,
      excludedPaths: (options?.excludedPaths || []).map((p) => path.resolve(p)),
      monitoredPaths: options?.monitoredPaths ?? [],
      entropyDetectionEnabled: options?.entropyDetectionEnabled ?? true,
      maxFileSizeBytes: options?.maxFileSizeBytes ?? 50 * 1024 * 1024
    };

    if (quarantineService) {
      this.setQuarantineService(quarantineService);
    }
  }

  public setExclusionManager(manager: ExclusionManagerService | null): void {
    this.exclusionManager = manager;
  }

  public getExclusionManager(): ExclusionManagerService | null {
    return this.exclusionManager;
  }

  // ============================================================
  // DEFAULT ROOTS RESOLUTION (Windows User Locations & Fallbacks)
  // ============================================================

  /**
   * Resolves canonical security-relevant Windows user locations:
   * Downloads, Desktop, Documents, Pictures, %TEMP%, and Startup.
   */
  public static getDefaultMonitoredRoots(): string[] {
    const roots: string[] = [];
    const home = os.homedir();

    const candidates = [
      path.join(home, 'Downloads'),
      path.join(home, 'Desktop'),
      path.join(home, 'Documents'),
      path.join(home, 'Pictures'),
      process.env.TEMP || process.env.TMP || os.tmpdir()
    ];

    // Windows Startup Folder (Roaming AppData)
    if (process.platform === 'win32') {
      const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
      candidates.push(
        path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
      );
    }

    for (const cand of candidates) {
      if (cand && fs.existsSync(cand)) {
        try {
          const canonical = path.resolve(cand);
          const stat = fs.lstatSync(canonical);
          if (stat.isDirectory() && !stat.isSymbolicLink() && !roots.includes(canonical)) {
            roots.push(canonical);
          }
        } catch {
          // Ignore inaccessible candidate
        }
      }
    }

    return roots;
  }

  // ============================================================
  // STATUS & CONFIGURATION GETTERS / SETTERS
  // ============================================================

  public isActive(): boolean {
    return this.isMonitoring;
  }

  public getMonitoredPaths(): string[] {
    return Array.from(this.watchers.keys());
  }

  public setQuarantineService(service: QuarantineService | null): void {
    // 1. Remove previous quarantine vault exclusion if changing services
    if (this.currentExcludedVaultDir) {
      const oldCanonical = this.currentExcludedVaultDir;
      this.options.excludedPaths = this.options.excludedPaths.filter((p) => {
        const canonical = path.resolve(p);
        return process.platform === 'win32'
          ? canonical.toLowerCase() !== oldCanonical.toLowerCase()
          : canonical !== oldCanonical;
      });
      this.currentExcludedVaultDir = null;
    }

    this.quarantineService = service;

    // 2. SEC-E-04: Automatically obtain canonical vaultDir and add to excludedPaths
    if (service && typeof service.getVaultDir === 'function') {
      const canonicalVaultDir = path.resolve(service.getVaultDir());
      this.currentExcludedVaultDir = canonicalVaultDir;

      const alreadyExcluded = this.options.excludedPaths.some((p) => {
        const canonical = path.resolve(p);
        return process.platform === 'win32'
          ? canonical.toLowerCase() === canonicalVaultDir.toLowerCase()
          : canonical === canonicalVaultDir;
      });

      if (!alreadyExcluded) {
        this.options.excludedPaths.push(canonicalVaultDir);
      }
    }
  }

  public setAutoQuarantineCritical(enabled: boolean): void {
    this.options.autoQuarantineCritical = Boolean(enabled);
  }

  public isAutoQuarantineCritical(): boolean {
    return this.options.autoQuarantineCritical;
  }

  public setEntropyDetectionEnabled(enabled: boolean): void {
    this.options.entropyDetectionEnabled = Boolean(enabled);
  }

  public isEntropyDetectionEnabled(): boolean {
    return this.options.entropyDetectionEnabled;
  }

  public setMaxFileSizeBytes(bytes: number): void {
    this.options.maxFileSizeBytes = Math.max(1024 * 1024, Math.floor(bytes));
  }

  public setExcludedPaths(paths: string[]): void {
    this.options.excludedPaths = (paths || []).map((p) => path.resolve(p));
    // Ensure active quarantine vault directory remains excluded
    if (this.currentExcludedVaultDir) {
      const vaultDir = this.currentExcludedVaultDir;
      const hasVault = this.options.excludedPaths.some((p) => {
        const canonical = path.resolve(p);
        return process.platform === 'win32'
          ? canonical.toLowerCase() === vaultDir.toLowerCase()
          : canonical === vaultDir;
      });
      if (!hasVault) {
        this.options.excludedPaths.push(vaultDir);
      }
    }
  }

  public getOptions(): Readonly<Required<RealtimeMonitorOptions>> {
    return { ...this.options };
  }

  public isPathExcluded(filePath: string): boolean {
    if (!filePath || typeof filePath !== 'string') return false;
    if (this.exclusionManager) {
      try {
        const check = this.exclusionManager.checkPath(filePath);
        if (check.isExcluded) return true;
      } catch {
        // Fallback to static path exclusion list
      }
    }
    const canonical = path.resolve(filePath);
    for (const rawExcluded of this.options.excludedPaths) {
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

  // ============================================================
  // LIFECYCLE MANAGEMENT (START / STOP / ADD / REMOVE DIRECTORIES)
  // ============================================================

  /**
   * Starts monitoring the provided target directories.
   * If directories array is empty or omitted, defaults to canonical Windows user roots.
   */
  public start(directories?: string[]): void {
    if (this.isMonitoring) {
      this.stop();
    }

    const targets = directories && directories.length > 0
      ? directories
      : RealtimeMonitorService.getDefaultMonitoredRoots();

    const validDirs = targets
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

    this.highPriorityQueue = [];
    this.normalPriorityQueue = [];
    this.queuedPaths.clear();
    this.inFlightFiles.clear();
    this.recentEvaluations.clear();
    this.pendingDownloads.clear();

    this.isMonitoring = false;
    this.emit('stopped');
  }

  public addDirectory(dirPath: string): boolean {
    if (!dirPath || typeof dirPath !== 'string') return false;
    const canonicalDir = path.resolve(dirPath);
    if (!fs.existsSync(canonicalDir) || this.isPathExcluded(canonicalDir)) {
      return false;
    }
    this.addWatchDirectory(canonicalDir);
    return this.watchers.has(canonicalDir);
  }

  public removeDirectory(dirPath: string): boolean {
    if (!dirPath || typeof dirPath !== 'string') return false;
    const canonicalDir = path.resolve(dirPath);
    const watcher = this.watchers.get(canonicalDir);
    if (watcher) {
      try {
        watcher.close();
      } catch {
        // Ignore
      }
      this.watchers.delete(canonicalDir);
      return true;
    }
    return false;
  }

  private addWatchDirectory(dirPath: string): void {
    const canonicalDir = path.resolve(dirPath);
    if (!fs.existsSync(canonicalDir) || this.watchers.has(canonicalDir)) {
      return;
    }

    // Never watch symlink/junction root to prevent circular loops
    try {
      const lstat = fs.lstatSync(canonicalDir);
      if (lstat.isSymbolicLink() || !lstat.isDirectory()) {
        return;
      }
    } catch {
      return;
    }

    try {
      // Primary: Recursive watching (ReadDirectoryChangesW on Windows)
      const watcher = fs.watch(
        canonicalDir,
        { recursive: this.options.recursive, persistent: false },
        (eventType, filename) => {
          if (!filename) return;
          const fullPath = path.isAbsolute(filename)
            ? filename
            : path.join(canonicalDir, filename);
          this.handleFilesystemEvent(eventType, fullPath);
        }
      );

      watcher.on('error', () => {
        // Safely ignore runtime directory watcher errors (e.g. dir removed)
      });

      this.watchers.set(canonicalDir, watcher);
    } catch (err: any) {
      // Rollback / Fallback strategy: Cleanly fallback to non-recursive watch if recursive fails
      if (this.options.recursive) {
        try {
          const fallbackWatcher = fs.watch(
            canonicalDir,
            { recursive: false, persistent: false },
            (eventType, filename) => {
              if (!filename) return;
              const fullPath = path.isAbsolute(filename)
                ? filename
                : path.join(canonicalDir, filename);
              this.handleFilesystemEvent(eventType, fullPath);
            }
          );
          fallbackWatcher.on('error', () => {});
          this.watchers.set(canonicalDir, fallbackWatcher);
          this.emit('watcherFallback', { directory: canonicalDir, reason: err.message });
          return;
        } catch (fallbackErr: any) {
          this.emit('error', { directory: canonicalDir, error: fallbackErr.message });
        }
      } else {
        this.emit('error', { directory: canonicalDir, error: err.message });
      }
    }
  }

  // ============================================================
  // EVENT INGESTION, DOWNLOAD LIFECYCLE & DEBOUNCE
  // ============================================================

  private handleFilesystemEvent(_eventType: string, filePath: string): void {
    if (!this.isMonitoring || this.isPathExcluded(filePath)) {
      return;
    }

    const canonicalPath = path.resolve(filePath);
    const ext = path.extname(canonicalPath).toLowerCase();

    // 1. Incomplete Download Lifecycle Tracking (.crdownload, .part, .tmp, .download)
    if (RealtimeMonitorService.IGNORED_TRANSIENT_EXTENSIONS.has(ext)) {
      this.trackIncompleteDownload(canonicalPath, ext);
      return; // Do NOT scan partial download fragment prematurely
    }

    // 2. Check if this is the completion / rename of a previously tracked download
    const isCompletedDownload = this.checkAndFinalizeDownload(canonicalPath);

    // 3. Debounce multi-block writes while preserving rapid responsiveness
    if (this.debounceTimers.has(canonicalPath)) {
      clearTimeout(this.debounceTimers.get(canonicalPath)!);
    }

    // Fast path: completed downloads get immediate scheduling (0 ms debounce)
    const effectiveDebounceMs = isCompletedDownload
      ? 0
      : this.options.debounceMs;

    if (effectiveDebounceMs <= 0) {
      this.enqueueFile(canonicalPath, isCompletedDownload);
      return;
    }

    const timer = setTimeout(async () => {
      this.debounceTimers.delete(canonicalPath);
      this.enqueueFile(canonicalPath, isCompletedDownload);
    }, effectiveDebounceMs);

    this.debounceTimers.set(canonicalPath, timer);
  }

  private trackIncompleteDownload(tempPath: string, ext: string): void {
    const targetFinalName = tempPath.substring(0, tempPath.length - ext.length);
    const existing = this.pendingDownloads.get(tempPath);
    const now = Date.now();

    if (existing) {
      existing.lastModifiedAt = now;
    } else {
      this.pendingDownloads.set(tempPath, {
        tempPath,
        targetFinalName,
        firstSeenAt: now,
        lastModifiedAt: now,
        initialSize: 0
      });
      this.emit('downloadDetected', { tempPath, targetFinalName });
    }
  }

  private checkAndFinalizeDownload(finalPath: string): boolean {
    // Check direct target match in pendingDownloads
    for (const [tempPath, pending] of this.pendingDownloads.entries()) {
      if (pending.targetFinalName.toLowerCase() === finalPath.toLowerCase()) {
        this.pendingDownloads.delete(tempPath);
        this.emit('downloadCompleted', { tempPath, finalPath });
        return true;
      }
    }

    // Check if a companion .crdownload / .part existed for this exact base name
    for (const ext of RealtimeMonitorService.IGNORED_TRANSIENT_EXTENSIONS) {
      const candidateTemp = `${finalPath}${ext}`;
      if (this.pendingDownloads.has(candidateTemp)) {
        this.pendingDownloads.delete(candidateTemp);
        this.emit('downloadCompleted', { tempPath: candidateTemp, finalPath });
        return true;
      }
    }

    return false;
  }

  // ============================================================
  // BOUNDED PRIORITY EVENT QUEUE & BACKPRESSURE
  // ============================================================

  public enqueueFile(canonicalPath: string, isCompletedDownload: boolean = false): void {
    if (this.queuedPaths.has(canonicalPath) || this.inFlightFiles.has(canonicalPath)) {
      return; // Deduplicate already queued or evaluating path
    }

    // Determine priority
    const ext = path.extname(canonicalPath).toLowerCase();
    const isDeceptiveDoubleExt = /\.[a-z0-9]{2,4}\.(exe|scr|bat|cmd|ps1|vbs|dll|com|hta|jar|msi)$/i.test(canonicalPath);
    const isHighPriority =
      isCompletedDownload ||
      RealtimeMonitorService.HIGH_RISK_EXTENSIONS.has(ext) ||
      isDeceptiveDoubleExt;

    const totalQueued = this.highPriorityQueue.length + this.normalPriorityQueue.length;

    // Backpressure enforcement (maxQueueSize = 10,000)
    if (totalQueued >= this.options.maxQueueSize) {
      this.droppedEventsCount++;
      // Evict oldest normal-priority item first to make room for high-priority items
      if (this.normalPriorityQueue.length > 0) {
        const evicted = this.normalPriorityQueue.shift();
        if (evicted) {
          this.queuedPaths.delete(evicted.filePath);
          this.emit('backpressure', {
            droppedPath: evicted.filePath,
            queueSize: totalQueued,
            reason: 'QUEUE_OVERFLOW'
          });
        }
      } else {
        // Queue full of high-priority items; drop oldest
        const evicted = this.highPriorityQueue.shift();
        if (evicted) {
          this.queuedPaths.delete(evicted.filePath);
          this.emit('backpressure', {
            droppedPath: evicted.filePath,
            queueSize: totalQueued,
            reason: 'HIGH_PRIORITY_OVERFLOW'
          });
        }
      }
    }

    const item: QueueItem = {
      filePath: canonicalPath,
      isHighPriority,
      queuedAt: Date.now()
    };

    if (isHighPriority) {
      this.highPriorityQueue.push(item);
    } else {
      this.normalPriorityQueue.push(item);
    }
    this.queuedPaths.add(canonicalPath);

    this.scheduleWorkers();
  }

  private scheduleWorkers(): void {
    while (
      this.activeWorkers < this.options.concurrencyLimit &&
      (this.highPriorityQueue.length > 0 || this.normalPriorityQueue.length > 0)
    ) {
      // Pull high priority items first
      const item = this.highPriorityQueue.shift() || this.normalPriorityQueue.shift();
      if (!item) break;

      this.queuedPaths.delete(item.filePath);
      this.activeWorkers++;

      void this.processQueueItem(item.filePath).finally(() => {
        this.activeWorkers--;
        this.scheduleWorkers();
      });
    }
  }

  private async processQueueItem(filePath: string): Promise<void> {
    try {
      await this.evaluateIncomingFile(filePath);
    } catch {
      // Ignore evaluation failures safely
    }
  }

  // ============================================================
  // FILE STABILITY VERIFICATION & DIRECT EVALUATION
  // ============================================================

  /**
   * Verifies that incoming file is accessible, unlinked from writer lock,
   * non-symlink, non-empty, and stable in byte size before scanning.
   */
  private async verifyFileStability(filePath: string): Promise<boolean> {
    for (let attempt = 0; attempt <= this.options.stabilityRetries; attempt++) {
      try {
        if (!fs.existsSync(filePath)) return false;
        const stat1 = await fs.promises.lstat(filePath);

        if (stat1.isSymbolicLink() || !stat1.isFile() || stat1.size === 0) {
          return false;
        }
        if (stat1.size > this.options.maxFileSizeBytes) {
          return false;
        }

        // Test non-exclusive read access to confirm file writer has released handle
        const handle = await fs.promises.open(filePath, 'r');
        await handle.close();

        // Check size stability if configured
        if (this.options.stabilityCheckMs > 0 && attempt < this.options.stabilityRetries) {
          await new Promise((r) => setTimeout(r, this.options.stabilityCheckMs));
          const stat2 = await fs.promises.lstat(filePath);
          if (stat2.size !== stat1.size) {
            continue; // File still growing, retry
          }
        }

        return true;
      } catch (err: any) {
        // Locked by writing process (EBUSY / EPERM / EACCES)
        if (attempt < this.options.stabilityRetries) {
          await new Promise((r) => setTimeout(r, 15));
          continue;
        }
        return false;
      }
    }
    return false;
  }

  /**
   * Safely inspects the finalized incoming file, measures ingress latency,
   * routes through FileAnalyzer (canonical detection engine), and automatically
   * quarantines confirmed threats into PPVAULT2 if configured.
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

    // Stability verification
    const isStable = await this.verifyFileStability(canonicalPath);
    if (!isStable) return;

    this.inFlightFiles.add(canonicalPath);
    const startTime = performance.now();

    try {
      const stat = await fs.promises.lstat(canonicalPath);

      // Inode / Path / Mtime Deduplication
      const dedupeKey = `${canonicalPath}:${stat.size}:${Math.floor(stat.mtimeMs)}`;
      const now = Date.now();
      const lastEval = this.recentEvaluations.get(dedupeKey);
      if (lastEval && now - lastEval < 1500) {
        return;
      }

      // Memory-bounded LRU cleanup for recentEvaluations
      if (this.recentEvaluations.size > 500) {
        for (const [k, ts] of this.recentEvaluations.entries()) {
          if (now - ts >= 1500) {
            this.recentEvaluations.delete(k);
          }
        }
      }
      this.recentEvaluations.set(dedupeKey, now);

      // Route through canonical Core Detection Engine
      const analysis = await FileAnalyzer.analyzeFile(canonicalPath, {
        entropyDetectionEnabled: this.options.entropyDetectionEnabled
      });

      const latencyMs = performance.now() - startTime;
      this.recordLatency(latencyMs);
      this.processedCount++;

      this.emit('fileScanned', {
        filePath: canonicalPath,
        verdict: analysis.verdict,
        riskScore: analysis.riskScore,
        latencyMs
      });

      if (analysis.verdict === 'BLOCK' || analysis.verdict === 'WARN') {
        // Phase I: Evaluate Response Policy Engine
        const responseEval = ResponsePolicyEngine.evaluate({
          riskScore: analysis.riskScore,
          severity: analysis.severity,
          verdict: analysis.verdict,
          confidence: 1.0,
          isProtectedSystemBinary: false
        });

        // Phase I: Check Exclusion Manager for SHA-256 exclusion
        if (this.exclusionManager) {
          const hashCheck = this.exclusionManager.checkHash(analysis.sha256, {
            isRansomware: responseEval.tier === 'RANSOMWARE_BEHAVIOR',
            riskScore: analysis.riskScore,
            verdict: analysis.verdict
          });
          if (hashCheck.isExcluded) {
            this.emit('fileExcluded', {
              filePath: canonicalPath,
              sha256: analysis.sha256,
              reason: hashCheck.reason,
              exclusionId: hashCheck.matchedExclusion?.id
            });
            return;
          }
        }

        const threat: DetectedThreat = {
          id: `rt-threat-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
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

        // Automatic quarantine execution if enabled and policy/verdict warrants isolation
        if (
          this.options.autoQuarantineCritical &&
          this.quarantineService &&
          (analysis.verdict === 'BLOCK' ||
            responseEval.autoQuarantine ||
            responseEval.tier === 'CRITICAL' ||
            responseEval.tier === 'RANSOMWARE_BEHAVIOR')
        ) {
          try {
            const qItem = await this.quarantineService.isolateFile(threat);
            threat.quarantined = true;
            (threat as any).quarantineId = qItem.quarantineId;
            (threat as any).actionTaken = 'AUTO_QUARANTINED';
            this.quarantinedCount++;
          } catch (err: any) {
            (threat as any).quarantineError = err?.message || String(err);
          }
        }

        this.threatsDetectedCount++;
        this.emit('threatDetected', threat);
      }
    } catch {
      // Ignore transient access or locking errors safely
    } finally {
      this.inFlightFiles.delete(canonicalPath);
    }
  }

  // ============================================================
  // TELEMETRY & STATS
  // ============================================================

  private recordLatency(latencyMs: number): void {
    if (this.latencyBuffer.length >= RealtimeMonitorService.MAX_LATENCY_SAMPLES) {
      this.latencyBuffer.shift();
    }
    this.latencyBuffer.push(latencyMs);
  }

  public getQueueStats(): RealtimeQueueStats {
    const latencies = [...this.latencyBuffer].sort((a, b) => a - b);
    const count = latencies.length;
    const avg = count > 0 ? latencies.reduce((a, b) => a + b, 0) / count : 0;
    const p95 = count > 0 ? latencies[Math.min(Math.floor(count * 0.95), count - 1)] : 0;

    return {
      queuedCount: this.highPriorityQueue.length + this.normalPriorityQueue.length,
      inFlightCount: this.inFlightFiles.size,
      processedCount: this.processedCount,
      droppedEventsCount: this.droppedEventsCount,
      threatsDetectedCount: this.threatsDetectedCount,
      quarantinedCount: this.quarantinedCount,
      averageLatencyMs: Number(avg.toFixed(3)),
      p95LatencyMs: Number(p95.toFixed(3))
    };
  }
}
