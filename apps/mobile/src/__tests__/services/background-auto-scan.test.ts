import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { BackgroundAutoScanService } from '../../services/background-auto-scan.service';
import { SecureStorageService } from '../../services/secure-storage.service';

describe('BackgroundAutoScanService', () => {
  beforeEach(async () => {
    BackgroundAutoScanService.resetInstance();
    await SecureStorageService.purgeAllData();
  });

  afterEach(() => {
    BackgroundAutoScanService.resetInstance();
  });

  it('initializes as singleton with default secure status', () => {
    const service = BackgroundAutoScanService.getInstance();
    const status = service.getStatus();
    expect(status.isEnabled).toBe(true);
    expect(status.lastScanVerdict).toBe('SECURE');
    expect(status.totalScansCount).toBeGreaterThanOrEqual(0);
  });

  it('executes a scan cycle and notifies subscribers', async () => {
    const service = BackgroundAutoScanService.getInstance();
    const updates: any[] = [];
    const unsubscribe = service.subscribe((status) => {
      updates.push(status);
    });

    const result = await service.executeScanCycle();
    expect(result.lastScanTimestamp).toBeDefined();
    expect(result.totalScansCount).toBeGreaterThanOrEqual(1);
    expect(updates.length).toBeGreaterThanOrEqual(2);

    unsubscribe();
  });

  it('can enable and disable auto-scan', async () => {
    const service = BackgroundAutoScanService.getInstance();
    await service.setEnabled(false);
    expect(service.getStatus().isEnabled).toBe(false);
    expect(service.getStatus().isRunning).toBe(false);

    await service.setEnabled(true);
    expect(service.getStatus().isEnabled).toBe(true);
    expect(service.getStatus().isRunning).toBe(true);
  });

  it('updates scan interval safely', async () => {
    const service = BackgroundAutoScanService.getInstance();
    await service.setInterval(45);
    expect(service.getStatus().intervalSeconds).toBe(45);

    // Clamps below minimum 10s
    await service.setInterval(3);
    expect(service.getStatus().intervalSeconds).toBe(10);
  });
});
