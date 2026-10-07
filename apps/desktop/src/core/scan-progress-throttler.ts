import { ScanProgress } from '../types/desktop.types';

export interface ScanProgressThrottlerOptions {
  /**
   * Minimum interval in milliseconds between progress emissions.
   * Default: 50 ms (20 Hz rate cap, as specified in Phase P / phase.md).
   */
  readonly intervalMs?: number;
}

/**
 * Scan Progress IPC Throttler (Phase P — P3)
 *
 * Coalesces high-frequency scan progress updates during rapid scans (e.g. 10,000 files)
 * to a maximum rate of 20 Hz (1 event per 50 ms).
 *
 * Invariants:
 * 1. The first progress event is emitted immediately for instant UI feedback.
 * 2. Subsequent events are coalesced so the renderer is never flooded with IPC messages.
 * 3. Latest scan progress state always wins.
 * 4. flush() guarantees that the final state is always delivered before scan completion.
 * 5. Security threat events are NEVER processed by this throttler and are always instantaneous.
 */
export class ScanProgressThrottler {
  public static readonly DEFAULT_INTERVAL_MS = 50; // 20 Hz cap

  private readonly intervalMs: number;
  private readonly emitCallback: (progress: ScanProgress) => void;
  private lastEmissionTime = 0;
  private pendingProgress: ScanProgress | null = null;
  private flushTimer: NodeJS.Timeout | null = null;
  private emissionCount = 0;
  private suppressedCount = 0;

  constructor(
    emitCallback: (progress: ScanProgress) => void,
    options?: ScanProgressThrottlerOptions
  ) {
    this.emitCallback = emitCallback;
    this.intervalMs = options?.intervalMs ?? ScanProgressThrottler.DEFAULT_INTERVAL_MS;
  }

  /**
   * Pushes a progress update through the rate-limiter.
   */
  public push(progress: ScanProgress): void {
    const now = Date.now();
    const timeSinceLastEmission = now - this.lastEmissionTime;

    // First event or interval elapsed: emit immediately
    if (this.lastEmissionTime === 0 || timeSinceLastEmission >= this.intervalMs) {
      if (this.flushTimer) {
        clearTimeout(this.flushTimer);
        this.flushTimer = null;
      }
      this.pendingProgress = null;
      this.lastEmissionTime = now;
      this.emissionCount++;
      this.emitCallback(progress);
      return;
    }

    // Coalesce: save the latest progress state
    this.pendingProgress = progress;
    this.suppressedCount++;

    // Schedule delayed flush if not already pending
    if (!this.flushTimer) {
      const delay = Math.max(1, this.intervalMs - timeSinceLastEmission);
      this.flushTimer = setTimeout(() => {
        this.flushTimer = null;
        if (this.pendingProgress) {
          const toEmit = this.pendingProgress;
          this.pendingProgress = null;
          this.lastEmissionTime = Date.now();
          this.emissionCount++;
          this.emitCallback(toEmit);
        }
      }, delay);
    }
  }

  /**
   * Flushes any pending progress event immediately (e.g. before scan completion or cancel).
   */
  public flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.pendingProgress) {
      const toEmit = this.pendingProgress;
      this.pendingProgress = null;
      this.lastEmissionTime = Date.now();
      this.emissionCount++;
      this.emitCallback(toEmit);
    }
  }

  /**
   * Cleans up pending timers.
   */
  public dispose(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    this.pendingProgress = null;
  }

  public getEmissionCount(): number {
    return this.emissionCount;
  }

  public getSuppressedCount(): number {
    return this.suppressedCount;
  }
}
