import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AdaptiveProtectionService } from '../../services/adaptive-protection.service';
import { AdaptiveResourceStatusDTO } from '../../types/mobile.types';

describe('Phase T12: AdaptiveProtectionService', () => {
  let service: AdaptiveProtectionService;

  beforeEach(() => {
    service = AdaptiveProtectionService.getInstance();
    delete (window as any).AndroidSecurityBridge;
  });

  afterEach(() => {
    delete (window as any).AndroidSecurityBridge;
    vi.restoreAllMocks();
  });

  it('provides truthful fallback in browser / testing environment without native bridge', async () => {
    const status = await service.getAdaptiveStatus();

    expect(status.resourceMode).toBe('NORMAL');
    expect(status.batteryPercentage).toBe(100);
    expect(status.isCharging).toBe(true);
    expect(status.thermalStatus).toBe('UNAVAILABLE');
    expect(status.isThermalSupported).toBe(false);
    expect(status.streamingBufferSize).toBe(65536);
    expect(status.canExecuteScheduledDeepScan).toBe(true);
    expect(status.disclaimer).toContain('physical Android runtime');
  });

  it('delegates to native bridge getAdaptiveResourceStatus when available', async () => {
    const mockNativeDTO: AdaptiveResourceStatusDTO = {
      resourceMode: 'BATTERY_SAVER',
      batteryPercentage: 14,
      isCharging: false,
      thermalStatus: 'NONE',
      isThermalSupported: true,
      isLowMemory: false,
      isForegroundHeavy: false,
      streamingBufferSize: 65536,
      canExecuteScheduledDeepScan: false,
      transitionReason: 'Battery below 20% discharging',
      disclaimer: 'Native test disclaimer'
    };

    (window as any).AndroidSecurityBridge = {
      getAdaptiveResourceStatus: vi.fn().mockReturnValue(JSON.stringify(mockNativeDTO))
    };

    const status = await service.getAdaptiveStatus();
    expect((window as any).AndroidSecurityBridge.getAdaptiveResourceStatus).toHaveBeenCalled();
    expect(status.resourceMode).toBe('BATTERY_SAVER');
    expect(status.batteryPercentage).toBe(14);
    expect(status.canExecuteScheduledDeepScan).toBe(false);
  });

  it('handles bridge json errors safely and returns mock fallback', async () => {
    (window as any).AndroidSecurityBridge = {
      getAdaptiveResourceStatus: vi.fn().mockReturnValue('{"error":"SERVICE_UNAVAILABLE"}')
    };

    const status = await service.getAdaptiveStatus();
    expect(status.resourceMode).toBe('NORMAL');
  });

  it('delegates setForegroundHeavyWorkload to native bridge', async () => {
    const mockSetForeground = vi.fn().mockReturnValue(true);
    (window as any).AndroidSecurityBridge = {
      getAdaptiveResourceStatus: vi.fn(),
      setForegroundHeavyWorkload: mockSetForeground
    };

    const res = await service.setForegroundHeavy(true);
    expect(res).toBe(true);
    expect(mockSetForeground).toHaveBeenCalledWith(true);
  });

  it('delegates triggerScheduledDeepScan to native bridge and receives deferred status under pressure', async () => {
    const mockDeferredJob = {
      id: 'job_deferred_123',
      type: 'STORAGE_SCAN',
      state: 'DEFERRED',
      progress: 0,
      createdAtMs: Date.now(),
      startedAtMs: 0,
      completedAtMs: 0,
      metadata: { isScheduled: true, scanMode: 'FULL_ACCESSIBLE_SCAN' },
      cancellationReason: 'Deferred due to adaptive resource constraints: Battery below 20%'
    };

    (window as any).AndroidSecurityBridge = {
      getAdaptiveResourceStatus: vi.fn(),
      triggerScheduledDeepScan: vi.fn().mockReturnValue(JSON.stringify(mockDeferredJob))
    };

    const job = await service.triggerScheduledDeepScan();
    expect(job.id).toBe('job_deferred_123');
    expect(job.state).toBe('DEFERRED');
    expect(job.cancellationReason).toContain('Deferred due to adaptive');
  });

  it('returns mock scheduled scan job when native bridge is unavailable', async () => {
    const job = await service.triggerScheduledDeepScan();
    expect(job.id).toContain('mock_sched_');
    expect(job.type).toBe('STORAGE_SCAN');
    expect(job.state).toBe('COMPLETED');
  });
});
