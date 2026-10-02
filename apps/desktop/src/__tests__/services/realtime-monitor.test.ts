import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';

describe('RealtimeMonitorService (Ingress Filesystem Shield)', () => {
  let monitor: RealtimeMonitorService;
  let watchDir: string;

  beforeEach(() => {
    monitor = new RealtimeMonitorService();
    watchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-rt-watch-'));
  });

  afterEach(() => {
    monitor.stop();
    if (fs.existsSync(watchDir)) {
      fs.rmSync(watchDir, { recursive: true, force: true });
    }
  });

  it('starts monitoring target directories and reports active state', () => {
    monitor.start([watchDir]);
    expect(monitor.isActive()).toBe(true);
    expect(monitor.getMonitoredPaths().length).toBe(1);
    expect(monitor.getMonitoredPaths()[0]).toBe(path.resolve(watchDir));

    monitor.stop();
    expect(monitor.isActive()).toBe(false);
    expect(monitor.getMonitoredPaths().length).toBe(0);
  });

  it('ignores transient partial download files without throwing errors', async () => {
    monitor.start([watchDir]);

    let threatFired = false;
    monitor.on('threatDetected', () => {
      threatFired = true;
    });

    // Write incomplete download file
    const partialPath = path.join(watchDir, 'payload.exe.crdownload');
    fs.writeFileSync(partialPath, Buffer.from([0x4d, 0x5a, 0x00, 0x00]));

    // Wait 350ms to exceed debounce
    await new Promise((resolve) => setTimeout(resolve, 350));
    expect(threatFired).toBe(false);
  });
});
