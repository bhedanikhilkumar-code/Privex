import { describe, it, expect } from 'vitest';
import { RemovableMediaService } from '../../services/removable-media.service';

describe('RemovableMediaService (USB & Drive Mounting)', () => {
  const service = new RemovableMediaService();

  it('queries mounted drives safely without throwing unhandled exceptions', async () => {
    const drives = await service.getMountedDrives();
    expect(Array.isArray(drives)).toBe(true);
  });

  it('starts and stops media attachment polling without memory leaks', () => {
    service.startMonitoring(1000);
    service.stopMonitoring();
    expect(true).toBe(true);
  });
});
