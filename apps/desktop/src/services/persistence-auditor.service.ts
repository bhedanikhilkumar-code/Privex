import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PersistenceItem } from '../types/desktop.types';

export class PersistenceAuditorService {
  /**
   * Audits user startup persistence locations.
   * STRICT INVARIANT: Read-only inspection. Never modifies startup entries.
   */
  public async auditStartupLocations(): Promise<PersistenceItem[]> {
    const items: PersistenceItem[] = [];
    const home = os.homedir();

    // 1. Windows Startup Folder
    if (process.platform === 'win32') {
      const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
      const startupFolder = path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
      await this.auditDirectory(startupFolder, 'startup_folder', items);
    } else {
      // POSIX autostart folder
      const autostart = path.join(home, '.config', 'autostart');
      await this.auditDirectory(autostart, 'startup_folder', items);
    }

    return items;
  }

  private async auditDirectory(
    dirPath: string,
    locationType: 'startup_folder' | 'run_key' | 'scheduled_task',
    items: PersistenceItem[]
  ): Promise<void> {
    if (!fs.existsSync(dirPath)) return;

    try {
      const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        const isSuspicious = this.checkPersistenceEntry(entry.name);

        items.push({
          id: `persist-${Buffer.from(entry.name).toString('hex').substring(0, 8)}`,
          name: entry.name,
          targetPath: fullPath,
          locationType,
          isSuspicious: isSuspicious.suspicious,
          reason: isSuspicious.reason
        });
      }
    } catch {
      // Read errors handled safely
    }
  }

  public checkPersistenceEntry(name: string): { suspicious: boolean; reason?: string } {
    const lower = name.toLowerCase();

    // Deceptive script or executable persistence
    if (lower.endsWith('.vbs') || lower.endsWith('.js') || lower.endsWith('.bat') || lower.endsWith('.cmd')) {
      return {
        suspicious: true,
        reason: 'Automated script configured in startup persistence location'
      };
    }

    const parts = lower.split('.');
    if (parts.length >= 3) {
      return {
        suspicious: true,
        reason: 'Double-extension file in startup persistence'
      };
    }

    return { suspicious: false };
  }
}
