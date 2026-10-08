import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RealtimeDownloadProtectionService } from '../../services/realtime-download-protection.service';

describe('RealtimeDownloadProtectionService (Phase T5)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
  });

  it('starts and stops real-time download protection in web simulation mode', async () => {
    const started = await RealtimeDownloadProtectionService.startProtection();
    expect(started).toBe(true);

    const statusActive = await RealtimeDownloadProtectionService.getStatus();
    expect(statusActive.isMonitoringActive).toBe(true);
    expect(statusActive.isPreOpenInterceptionSupported).toBe(false);
    expect(statusActive.platformLimitationNotice).toContain('System-wide pre-open interception is not supported');

    const stopped = await RealtimeDownloadProtectionService.stopProtection();
    expect(stopped).toBe(true);

    const statusInactive = await RealtimeDownloadProtectionService.getStatus();
    expect(statusInactive.isMonitoringActive).toBe(false);
  });

  it('executes catch-up reconciliation in fallback mode', async () => {
    const report = await RealtimeDownloadProtectionService.reconcileCatchUp();
    expect(report.discovered).toBeGreaterThanOrEqual(0);
    expect(report.rescanned).toBeGreaterThanOrEqual(0);
    expect(report.skipped).toBeGreaterThanOrEqual(0);
    expect(report.threatsFound).toBe(0);
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('delegates to native AndroidSecurityBridge when available', async () => {
    const mockBridge = {
      startRealtimeDownloadProtection: vi.fn().mockReturnValue(true),
      stopRealtimeDownloadProtection: vi.fn().mockReturnValue(true),
      getRealtimeDownloadProtectionStatus: vi.fn().mockReturnValue(
        JSON.stringify({
          isMonitoringActive: true,
          lastEventTimestamp: 1700000000000,
          lastReconciliationTimestamp: 1700000000000,
          eventsProcessed: 42,
          threatsDetected: 1,
          deduplicatorStats: { cachedEntries: 42, maxCapacity: 5000 },
          cleanCacheCount: 40,
          isPreOpenInterceptionSupported: false,
          platformLimitationNotice:
            'Private Protection scans supported downloads as soon as Android makes the file available for inspection.'
        })
      ),
      reconcileDownloadCatchUp: vi.fn().mockReturnValue(
        JSON.stringify({
          discovered: 8,
          rescanned: 2,
          skipped: 6,
          threatsFound: 0,
          durationMs: 45,
          timestamp: 1700000000000
        })
      )
    };

    (window as any).AndroidSecurityBridge = mockBridge;

    const started = await RealtimeDownloadProtectionService.startProtection();
    expect(started).toBe(true);
    expect(mockBridge.startRealtimeDownloadProtection).toHaveBeenCalledTimes(1);

    const status = await RealtimeDownloadProtectionService.getStatus();
    expect(status.isMonitoringActive).toBe(true);
    expect(status.eventsProcessed).toBe(42);
    expect(status.threatsDetected).toBe(1);
    expect(status.isPreOpenInterceptionSupported).toBe(false);
    expect(mockBridge.getRealtimeDownloadProtectionStatus).toHaveBeenCalledTimes(1);

    const catchUp = await RealtimeDownloadProtectionService.reconcileCatchUp();
    expect(catchUp.discovered).toBe(8);
    expect(catchUp.skipped).toBe(6);
    expect(mockBridge.reconcileDownloadCatchUp).toHaveBeenCalledTimes(1);

    const stopped = await RealtimeDownloadProtectionService.stopProtection();
    expect(stopped).toBe(true);
    expect(mockBridge.stopRealtimeDownloadProtection).toHaveBeenCalledTimes(1);
  });

  it('truthfully refuses to claim impossible Android system privileges', async () => {
    const status = await RealtimeDownloadProtectionService.getStatus();
    expect(status.isPreOpenInterceptionSupported).toBe(false);
    expect(status.platformLimitationNotice).not.toContain('always blocks malware before it can run');
  });
});
