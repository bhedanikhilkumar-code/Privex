import {
  SecurityJobDescriptor,
  SecurityJobType,
  CoordinatorStats
} from '../types/mobile.types';

declare global {
  interface Window {
    AndroidSecurityBridge?: {
      submitSecurityJob?: (jobTypeStr: string, metadataJsonStr: string) => string;
      cancelSecurityJob?: (jobId: string, reason: string) => boolean;
      getSecurityJobStatus?: (jobId: string) => string;
      listActiveSecurityJobs?: () => string;
      getCoordinatorStats?: () => string;
      [key: string]: any;
    };
  }
}

/**
 * Client service interface for the Native Android MobileSecurityCoordinator (Phase T1).
 * Communicates with the native coordinator via window.AndroidSecurityBridge when running
 * in native Android WebView, and provides an in-memory fallback when executing in web/tests.
 */
export class NativeSecurityCoordinatorService {
  private inMemoryFallbackJobs: Map<string, SecurityJobDescriptor> = new Map();
  private isFallbackShutdown: boolean = false;

  public isNativeBridgeAvailable(): boolean {
    return (
      typeof window !== 'undefined' &&
      !!window.AndroidSecurityBridge &&
      typeof window.AndroidSecurityBridge.submitSecurityJob === 'function'
    );
  }

  /**
   * Submits a security job to the native coordinator.
   */
  public async submitJob(
    type: SecurityJobType,
    metadata?: Record<string, any>
  ): Promise<SecurityJobDescriptor> {
    if (this.isNativeBridgeAvailable()) {
      try {
        const metaStr = metadata ? JSON.stringify(metadata) : '{}';
        const resStr = window.AndroidSecurityBridge!.submitSecurityJob!(type, metaStr);
        const parsed = JSON.parse(resStr);
        if (parsed.error) {
          throw new Error(`NATIVE_COORDINATOR_ERROR: ${parsed.error}`);
        }
        return parsed as SecurityJobDescriptor;
      } catch (err: any) {
        if (err.message && err.message.startsWith('NATIVE_COORDINATOR_ERROR')) {
          throw err;
        }
        throw new Error(`NATIVE_BRIDGE_FAILURE: ${err?.message || err}`);
      }
    }

    // In-memory fallback for web/test environment
    if (this.isFallbackShutdown) {
      throw new Error('COORDINATOR_SHUTDOWN: Native coordinator service has been shut down');
    }

    const jobId = `fallback-job-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const job: SecurityJobDescriptor = {
      id: jobId,
      type,
      state: 'COMPLETED',
      progress: 1.0,
      createdAtMs: Date.now(),
      startedAtMs: Date.now(),
      completedAtMs: Date.now(),
      metadata: metadata || {},
      result: {
        status: 'FALLBACK_ACKNOWLEDGED',
        jobId,
        type,
        timestamp: Date.now()
      }
    };
    this.inMemoryFallbackJobs.set(jobId, job);
    return job;
  }

  /**
   * Requests cancellation of an active or queued security job.
   */
  public async cancelJob(jobId: string, reason: string = 'User cancelled'): Promise<boolean> {
    if (!jobId) return false;

    if (this.isNativeBridgeAvailable()) {
      try {
        return !!window.AndroidSecurityBridge!.cancelSecurityJob!(jobId, reason);
      } catch {
        return false;
      }
    }

    const job = this.inMemoryFallbackJobs.get(jobId);
    if (!job || job.state === 'COMPLETED' || job.state === 'CANCELLED' || job.state === 'FAILED') {
      return false;
    }
    job.state = 'CANCELLED';
    job.cancellationReason = reason;
    job.completedAtMs = Date.now();
    return true;
  }

  /**
   * Retrieves the current status and result of a security job.
   */
  public async getJobStatus(jobId: string): Promise<SecurityJobDescriptor | null> {
    if (!jobId) return null;

    if (this.isNativeBridgeAvailable()) {
      try {
        const resStr = window.AndroidSecurityBridge!.getSecurityJobStatus!(jobId);
        const parsed = JSON.parse(resStr);
        if (parsed.error === 'JOB_NOT_FOUND') {
          return null;
        }
        if (parsed.error) {
          throw new Error(parsed.error);
        }
        return parsed as SecurityJobDescriptor;
      } catch {
        return null;
      }
    }

    return this.inMemoryFallbackJobs.get(jobId) || null;
  }

  /**
   * Lists all currently active or running security jobs.
   */
  public async listActiveJobs(): Promise<SecurityJobDescriptor[]> {
    if (this.isNativeBridgeAvailable()) {
      try {
        const resStr = window.AndroidSecurityBridge!.listActiveSecurityJobs!();
        return JSON.parse(resStr) as SecurityJobDescriptor[];
      } catch {
        return [];
      }
    }

    return Array.from(this.inMemoryFallbackJobs.values()).filter(
      (j) => j.state === 'QUEUED' || j.state === 'RUNNING' || j.state === 'CANCELLING'
    );
  }

  /**
   * Retrieves runtime statistics from the native coordinator.
   */
  public async getStats(): Promise<CoordinatorStats> {
    if (this.isNativeBridgeAvailable()) {
      try {
        const resStr = window.AndroidSecurityBridge!.getCoordinatorStats!();
        return JSON.parse(resStr) as CoordinatorStats;
      } catch {
        return {
          isShutdown: false,
          isThrottled: false,
          activeJobsCount: 0,
          workerActiveThreads: 0,
          workerPoolSize: 0,
          workerMaxPoolSize: 0,
          workerQueueSize: 0,
          totalPersistedJobs: 0
        };
      }
    }

    return {
      isShutdown: this.isFallbackShutdown,
      isThrottled: false,
      activeJobsCount: Array.from(this.inMemoryFallbackJobs.values()).filter(
        (j) => j.state === 'QUEUED' || j.state === 'RUNNING'
      ).length,
      workerActiveThreads: 0,
      workerPoolSize: 2,
      workerMaxPoolSize: 4,
      workerQueueSize: 0,
      totalPersistedJobs: this.inMemoryFallbackJobs.size
    };
  }

  public shutdownFallback(): void {
    this.isFallbackShutdown = true;
  }
}
