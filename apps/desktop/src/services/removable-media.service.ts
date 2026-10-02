import * as fs from 'fs';
import { EventEmitter } from 'events';
import { RemovableDrive } from '../types/desktop.types';

export class RemovableMediaService extends EventEmitter {
  private knownDrives: Set<string> = new Set();
  private isPolling = false;
  private pollInterval: NodeJS.Timeout | null = null;

  /**
   * Discovers current mounted removable volumes safely.
   */
  public async getMountedDrives(): Promise<RemovableDrive[]> {
    const drives: RemovableDrive[] = [];

    if (process.platform === 'win32') {
      // Check standard drive letters D: through Z:
      const letters = 'DEFGHIJKLMNOPQRSTUVWXYZ';
      for (const char of letters) {
        const drivePath = `${char}:\\`;
        try {
          if (fs.existsSync(drivePath)) {
            drives.push({
              mountPoint: drivePath,
              label: `Removable Disk (${char}:)`,
              totalBytes: 0,
              freeBytes: 0
            });
          }
        } catch {
          // Ignore unready or optical drives
        }
      }
    } else {
      // POSIX /media or /Volumes
      const mediaPaths = ['/Volumes', '/media'];
      for (const mediaDir of mediaPaths) {
        if (fs.existsSync(mediaDir)) {
          try {
            const entries = fs.readdirSync(mediaDir);
            for (const entry of entries) {
              drives.push({
                mountPoint: `${mediaDir}/${entry}`,
                label: entry,
                totalBytes: 0,
                freeBytes: 0
              });
            }
          } catch {
            // continue
          }
        }
      }
    }

    return drives;
  }

  /**
   * Starts non-invasive polling for newly attached media.
   * Emits 'driveAttached' when a new drive is discovered.
   */
  public startMonitoring(intervalMs = 3000): void {
    if (this.isPolling) return;
    this.isPolling = true;

    // Initialize known drives
    this.getMountedDrives().then((drives) => {
      this.knownDrives = new Set(drives.map((d) => d.mountPoint));
    });

    this.pollInterval = setInterval(async () => {
      const currentDrives = await this.getMountedDrives();
      for (const drive of currentDrives) {
        if (!this.knownDrives.has(drive.mountPoint)) {
          this.knownDrives.add(drive.mountPoint);
          this.emit('driveAttached', drive);
        }
      }
    }, intervalMs);
  }

  public stopMonitoring(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    this.isPolling = false;
  }
}
