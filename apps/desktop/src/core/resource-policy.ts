import * as os from 'os';

export interface ResourceProfile {
  readonly totalMemoryBytes: number;
  readonly freeMemoryBytes: number;
  readonly cpuCount: number;
  readonly isLowResourceMachine: boolean;
  readonly isMemoryConstrained: boolean;
  readonly concurrency: number;
  readonly batchSize: number;
  readonly maxHeaderSliceBytes: number;
  readonly maxQueueDepth: number;
  readonly tierName: 'LOW_RESOURCE_4GB' | 'MODERATE_RESOURCE_8GB' | 'HIGH_RESOURCE';
}

export interface ResourcePolicyOptions {
  readonly customTotalMemoryBytes?: number;
  readonly customFreeMemoryBytes?: number;
  readonly customCpuCount?: number;
  readonly maxConcurrencyOverride?: number;
}

/**
 * Adaptive Resource & Concurrency Policy (Phase P — P5 & P6)
 *
 * Dynamically determines safe worker concurrency, scan batch sizes, and queue
 * depths based on physical host resources with special tuning for <= 4 GB RAM systems.
 *
 * Constitutional Invariant: Low-resource optimizations ONLY adapt batch sizing
 * and queue concurrency. They NEVER skip, bypass, or weaken any security analyzers.
 */
export class ResourcePolicy {
  public static readonly FOUR_GB_BYTES = 4 * 1024 * 1024 * 1024; // 4,294,967,296 bytes
  public static readonly EIGHT_GB_BYTES = 8 * 1024 * 1024 * 1024; // 8,589,934,592 bytes
  public static readonly MIN_FREE_MEMORY_THRESHOLD = 512 * 1024 * 1024; // 512 MB free threshold

  private static instance: ResourcePolicy | null = null;
  private readonly options?: ResourcePolicyOptions;

  constructor(options?: ResourcePolicyOptions) {
    this.options = options;
  }

  public static getSharedInstance(): ResourcePolicy {
    if (!this.instance) {
      this.instance = new ResourcePolicy();
    }
    return this.instance;
  }

  public static resetSharedInstance(): void {
    this.instance = null;
  }

  /**
   * Resolves current hardware specifications and evaluates the adaptive resource profile.
   */
  public getProfile(): ResourceProfile {
    const totalMemoryBytes = this.options?.customTotalMemoryBytes ?? os.totalmem();
    const freeMemoryBytes = this.options?.customFreeMemoryBytes ?? os.freemem();
    const cpuCount = this.options?.customCpuCount ?? (os.cpus()?.length || 1);

    const isLowResourceMachine = totalMemoryBytes <= ResourcePolicy.FOUR_GB_BYTES;
    const isMemoryConstrained = freeMemoryBytes < ResourcePolicy.MIN_FREE_MEMORY_THRESHOLD;

    let tierName: 'LOW_RESOURCE_4GB' | 'MODERATE_RESOURCE_8GB' | 'HIGH_RESOURCE';
    let concurrency: number;
    let batchSize: number;
    let maxQueueDepth: number;

    if (isLowResourceMachine) {
      tierName = 'LOW_RESOURCE_4GB';
      // Low-resource (<=4 GB RAM): keep worker concurrency strictly bounded (1-2) to avoid memory spikes
      concurrency = isMemoryConstrained || cpuCount <= 2 ? 1 : 2;
      batchSize = 25;
      maxQueueDepth = 2500;
    } else if (totalMemoryBytes <= ResourcePolicy.EIGHT_GB_BYTES) {
      tierName = 'MODERATE_RESOURCE_8GB';
      // Moderate (4-8 GB RAM): conservative multi-threading
      concurrency = Math.min(4, Math.max(2, Math.floor(cpuCount / 2)));
      batchSize = 50;
      maxQueueDepth = 5000;
    } else {
      tierName = 'HIGH_RESOURCE';
      // High-resource (>8 GB RAM): scale up to 8 parallel workers or cpuCount
      concurrency = Math.min(8, Math.max(4, cpuCount));
      batchSize = 100;
      maxQueueDepth = 10000;
    }

    if (this.options?.maxConcurrencyOverride && this.options.maxConcurrencyOverride > 0) {
      concurrency = Math.min(concurrency, this.options.maxConcurrencyOverride);
    }

    return {
      totalMemoryBytes,
      freeMemoryBytes,
      cpuCount,
      isLowResourceMachine,
      isMemoryConstrained,
      concurrency: Math.max(1, concurrency),
      batchSize,
      maxHeaderSliceBytes: 64 * 1024, // 64 KB header read
      maxQueueDepth,
      tierName
    };
  }

  /**
   * Safe helper to execute an array of async tasks with adaptive bounded concurrency.
   */
  public async executeWithConcurrency<T, R>(
    items: T[],
    fn: (item: T, index: number) => Promise<R>,
    onProgressItem?: () => void,
    isCancelled?: () => boolean
  ): Promise<R[]> {
    const profile = this.getProfile();
    const results: R[] = [];
    const executing = new Set<Promise<void>>();

    for (let i = 0; i < items.length; i++) {
      if (isCancelled?.()) {
        break;
      }

      const item = items[i];
      const p = (async () => {
        const res = await fn(item, i);
        results.push(res);
        onProgressItem?.();
      })();

      const promiseWrapper = p.finally(() => {
        executing.delete(promiseWrapper);
      });

      executing.add(promiseWrapper);

      if (executing.size >= profile.concurrency) {
        await Promise.race(executing);
      }
    }

    await Promise.all(executing);
    return results;
  }
}
