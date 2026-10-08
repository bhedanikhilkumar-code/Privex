import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { NativeSecurityCoordinatorService } from '../../services/native-security-coordinator.service';

describe('NativeSecurityCoordinatorService (Phase T1)', () => {
  let service: NativeSecurityCoordinatorService;

  beforeEach(() => {
    service = new NativeSecurityCoordinatorService();
    // Clean up window bridge mocks
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
  });

  describe('Fallback Mode (When Native Bridge is Absent)', () => {
    it('detects native bridge as unavailable', () => {
      expect(service.isNativeBridgeAvailable()).toBe(false);
    });

    it('submits a security job successfully in fallback mode', async () => {
      const job = await service.submitJob('FILE_SCAN', { filePath: '/sdcard/Download/test.apk' });
      expect(job).toBeDefined();
      expect(job.id).toContain('fallback-job-');
      expect(job.type).toBe('FILE_SCAN');
      expect(job.state).toBe('COMPLETED');
      expect(job.progress).toBe(1.0);
      expect(job.result?.status).toBe('FALLBACK_ACKNOWLEDGED');
    });

    it('retrieves job status in fallback mode', async () => {
      const job = await service.submitJob('URL_SCAN', { url: 'https://example.com' });
      const status = await service.getJobStatus(job.id);
      expect(status).toBeDefined();
      expect(status?.id).toBe(job.id);
      expect(status?.type).toBe('URL_SCAN');
    });

    it('returns null for non-existent job in fallback mode', async () => {
      const status = await service.getJobStatus('non-existent-id');
      expect(status).toBeNull();
    });

    it('retrieves coordinator statistics in fallback mode', async () => {
      await service.submitJob('PACKAGE_AUDIT');
      const stats = await service.getStats();
      expect(stats).toBeDefined();
      expect(stats.isShutdown).toBe(false);
      expect(stats.workerPoolSize).toBe(2);
      expect(stats.totalPersistedJobs).toBeGreaterThanOrEqual(1);
    });

    it('throws error when submitting job after fallback shutdown', async () => {
      service.shutdownFallback();
      await expect(service.submitJob('HEALTH_CHECK')).rejects.toThrow('COORDINATOR_SHUTDOWN');
    });
  });

  describe('Native AndroidSecurityBridge Mode', () => {
    it('routes submitJob to window.AndroidSecurityBridge.submitSecurityJob', async () => {
      const mockSubmit = vi.fn().mockReturnValue(
        JSON.stringify({
          id: 'native-job-123',
          type: 'STORAGE_SCAN',
          state: 'QUEUED',
          progress: 0.0,
          createdAtMs: 1600000000000
        })
      );

      (window as any).AndroidSecurityBridge = {
        submitSecurityJob: mockSubmit
      };

      expect(service.isNativeBridgeAvailable()).toBe(true);

      const job = await service.submitJob('STORAGE_SCAN', { scope: 'USER_DOCS' });
      expect(mockSubmit).toHaveBeenCalledWith(
        'STORAGE_SCAN',
        JSON.stringify({ scope: 'USER_DOCS' })
      );
      expect(job.id).toBe('native-job-123');
      expect(job.state).toBe('QUEUED');
    });

    it('handles native coordinator error response', async () => {
      (window as any).AndroidSecurityBridge = {
        submitSecurityJob: vi.fn().mockReturnValue(
          JSON.stringify({ error: 'METADATA_PAYLOAD_TOO_LARGE' })
        )
      };

      await expect(service.submitJob('FILE_SCAN')).rejects.toThrow('METADATA_PAYLOAD_TOO_LARGE');
    });

    it('routes cancelJob to window.AndroidSecurityBridge.cancelSecurityJob', async () => {
      const mockCancel = vi.fn().mockReturnValue(true);
      (window as any).AndroidSecurityBridge = {
        submitSecurityJob: vi.fn(),
        cancelSecurityJob: mockCancel
      };

      const result = await service.cancelJob('native-job-123', 'User cancel');
      expect(mockCancel).toHaveBeenCalledWith('native-job-123', 'User cancel');
      expect(result).toBe(true);
    });

    it('routes getJobStatus and handles JOB_NOT_FOUND', async () => {
      (window as any).AndroidSecurityBridge = {
        submitSecurityJob: vi.fn(),
        getSecurityJobStatus: vi.fn().mockReturnValue(
          JSON.stringify({ error: 'JOB_NOT_FOUND' })
        )
      };

      const status = await service.getJobStatus('missing-job');
      expect(status).toBeNull();
    });

    it('routes listActiveJobs and parses array', async () => {
      (window as any).AndroidSecurityBridge = {
        submitSecurityJob: vi.fn(),
        listActiveSecurityJobs: vi.fn().mockReturnValue(
          JSON.stringify([
            { id: 'job-1', type: 'DOWNLOAD_INSPECT', state: 'RUNNING', progress: 0.5 }
          ])
        )
      };

      const active = await service.listActiveJobs();
      expect(active).toHaveLength(1);
      expect(active[0].id).toBe('job-1');
      expect(active[0].state).toBe('RUNNING');
    });

    it('routes getStats and parses coordinator statistics', async () => {
      (window as any).AndroidSecurityBridge = {
        submitSecurityJob: vi.fn(),
        getCoordinatorStats: vi.fn().mockReturnValue(
          JSON.stringify({
            isShutdown: false,
            isThrottled: false,
            activeJobsCount: 2,
            workerActiveThreads: 2,
            workerPoolSize: 4,
            workerMaxPoolSize: 4,
            workerQueueSize: 0,
            totalPersistedJobs: 15
          })
        )
      };

      const stats = await service.getStats();
      expect(stats.activeJobsCount).toBe(2);
      expect(stats.workerMaxPoolSize).toBe(4);
      expect(stats.totalPersistedJobs).toBe(15);
    });
  });
});
