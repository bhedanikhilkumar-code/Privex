import * as fs from 'fs';
import { EventEmitter } from 'events';
import { PersistenceAuditorService } from './persistence-auditor.service';
import { PersistenceItem, PersistenceChangeEvent } from '../types/desktop.types';

export interface PersistenceMonitorOptions {
  readonly pollIntervalMs?: number;
  readonly debounceMs?: number;
  readonly customDirs?: string[];
  readonly enableRegistryPoll?: boolean;
}

/**
 * Continuous Event-Driven & Polling Persistence Monitor Service (Phase L).
 *
 * Monitors Windows Startup folders via event-driven fs.watch and Registry Run/RunOnce keys
 * via periodic state diffing, with token-bucket storm rate limiting and duplicate suppression.
 */
export class PersistenceMonitorService extends EventEmitter {
  private auditor: PersistenceAuditorService;
  private isRunning: boolean = false;
  private pollIntervalMs: number;
  private debounceMs: number;
  private customDirs?: string[];
  private enableRegistryPoll: boolean;

  private folderWatchers: fs.FSWatcher[] = [];
  private pollTimer: NodeJS.Timeout | null = null;
  private debounceTimers: Map<string, NodeJS.Timeout> = new Map();

  // Snapshot cache mapping canonical ID -> PersistenceItem
  private knownSnapshot: Map<string, PersistenceItem> = new Map();

  // Token-Bucket Storm Rate Limiter (RULE-15: max 3 events per 10-second window)
  private eventTokens: number = 3;
  private maxTokens: number = 3;
  private tokenRefillInterval: NodeJS.Timeout | null = null;

  constructor(auditor?: PersistenceAuditorService, options?: PersistenceMonitorOptions) {
    super();
    this.auditor = auditor || new PersistenceAuditorService();
    this.pollIntervalMs = options?.pollIntervalMs || 10000; // 10 seconds default
    this.debounceMs = options?.debounceMs || 300; // 300 ms debounce
    this.customDirs = options?.customDirs;
    this.enableRegistryPoll = options?.enableRegistryPoll !== false;
  }

  public isMonitoring(): boolean {
    return this.isRunning;
  }

  /**
   * Starts monitoring startup directories and registry keys.
   */
  public async startMonitoring(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    // 1. Initialize baseline snapshot
    await this.refreshSnapshot(true);

    // 2. Start folder watchers
    const dirs = this.auditor.getStartupFolderPaths(this.customDirs);
    for (const dirInfo of dirs) {
      if (fs.existsSync(dirInfo.path)) {
        try {
          const watcher = fs.watch(dirInfo.path, (_eventType, filename) => {
            if (filename) {
              this.handleFolderChangeEvent(dirInfo.path, filename.toString());
            }
          });
          this.folderWatchers.push(watcher);
        } catch {
          // Inaccessible directory ignored safely
        }
      }
    }

    // 3. Start registry poll timer if enabled
    if (this.enableRegistryPoll) {
      this.pollTimer = setInterval(() => {
        if (this.isRunning) {
          this.refreshSnapshot(false).catch(() => {});
        }
      }, this.pollIntervalMs);
    }

    // 4. Token refill timer (refills 1 token every 3.33 seconds, capped at 3)
    this.tokenRefillInterval = setInterval(() => {
      if (this.eventTokens < this.maxTokens) {
        this.eventTokens++;
      }
    }, 3333);
  }

  /**
   * Stops all active watchers, timers, and polling.
   */
  public stopMonitoring(): void {
    this.isRunning = false;

    for (const watcher of this.folderWatchers) {
      try {
        watcher.close();
      } catch {}
    }
    this.folderWatchers = [];

    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }

    if (this.tokenRefillInterval) {
      clearInterval(this.tokenRefillInterval);
      this.tokenRefillInterval = null;
    }

    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();
  }

  /**
   * Debounced handler for directory events.
   */
  private handleFolderChangeEvent(dirPath: string, filename: string): void {
    const key = `${dirPath}:${filename}`;
    if (this.debounceTimers.has(key)) {
      clearTimeout(this.debounceTimers.get(key)!);
    }

    const timer = setTimeout(() => {
      this.debounceTimers.delete(key);
      if (this.isRunning) {
        this.refreshSnapshot(false).catch(() => {});
      }
    }, this.debounceMs);

    this.debounceTimers.set(key, timer);
  }

  /**
   * Refreshes the persistence snapshot and diffs against previous state.
   */
  public async refreshSnapshot(isInitial: boolean = false): Promise<PersistenceChangeEvent[]> {
    const auditResult = await this.auditor.auditStartupLocations({
      customDirs: this.customDirs
    });

    const currentMap = new Map<string, PersistenceItem>();
    for (const item of auditResult.items) {
      currentMap.set(item.id, item);
    }

    const changeEvents: PersistenceChangeEvent[] = [];

    if (!isInitial) {
      // 1. Detect Added and Modified items
      for (const [id, item] of currentMap.entries()) {
        const oldItem = this.knownSnapshot.get(id);
        if (!oldItem) {
          changeEvents.push({
            changeType: 'ADDED',
            item,
            timestamp: Date.now()
          });
        } else if (
          oldItem.rawCommand !== item.rawCommand ||
          oldItem.riskScore !== item.riskScore ||
          oldItem.existsOnDisk !== item.existsOnDisk
        ) {
          changeEvents.push({
            changeType: 'MODIFIED',
            item,
            timestamp: Date.now()
          });
        }
      }

      // 2. Detect Removed items
      for (const [id, oldItem] of this.knownSnapshot.entries()) {
        if (!currentMap.has(id)) {
          changeEvents.push({
            changeType: 'REMOVED',
            item: oldItem,
            timestamp: Date.now()
          });
        }
      }

      // 3. Dispatch events through rate limiter
      for (const change of changeEvents) {
        if (this.eventTokens > 0) {
          this.eventTokens--;
          this.emit('persistenceChanged', change);

          if (change.item.isSuspicious && (change.changeType === 'ADDED' || change.changeType === 'MODIFIED')) {
            this.emit('threatDetected', change.item);
          }
        }
      }
    }

    this.knownSnapshot = currentMap;
    return changeEvents;
  }

  public getKnownSnapshot(): Map<string, PersistenceItem> {
    return new Map(this.knownSnapshot);
  }
}
