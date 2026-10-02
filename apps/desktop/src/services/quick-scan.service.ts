import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { ScannerService } from './scanner.service';
import { ScanResult } from '../types/desktop.types';

export class QuickScanService {
  private scanner: ScannerService;

  constructor(scanner?: ScannerService) {
    this.scanner = scanner || new ScannerService();
  }

  public getScanner(): ScannerService {
    return this.scanner;
  }

  /**
   * Resolves legitimate high-risk ingress points for a targeted Quick Scan.
   */
  public getQuickScanTargets(): string[] {
    const home = os.homedir();
    const targets: string[] = [];

    // 1. User Downloads
    const downloads = path.join(home, 'Downloads');
    if (fs.existsSync(downloads)) targets.push(downloads);

    // 2. User Temp Directory
    const tmp = os.tmpdir();
    if (fs.existsSync(tmp)) targets.push(tmp);

    // 3. User Desktop
    const desktop = path.join(home, 'Desktop');
    if (fs.existsSync(desktop)) targets.push(desktop);

    // 4. Windows Startup folder (if on Windows)
    if (process.platform === 'win32') {
      const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
      const startup = path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
      if (fs.existsSync(startup)) targets.push(startup);
    } else {
      const autostart = path.join(home, '.config', 'autostart');
      if (fs.existsSync(autostart)) targets.push(autostart);
    }

    return targets;
  }

  /**
   * Runs the Quick Scan targeting executables and double-extension deceptions.
   */
  public async executeQuickScan(customTargets?: string[]): Promise<ScanResult> {
    const targets = customTargets && customTargets.length > 0
      ? customTargets
      : this.getQuickScanTargets();

    const executableExts = new Set([
      '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi', '.pif'
    ]);

    const isTargetFile = (filePath: string) => {
      const fileName = path.basename(filePath).toLowerCase();
      const ext = path.extname(fileName);

      // Inspect if declared executable
      if (executableExts.has(ext)) return true;

      // Inspect if double extension (e.g., invoice.pdf.exe, doc.docx.bat)
      const parts = fileName.split('.');
      if (parts.length >= 3) return true;

      return false;
    };

    return this.scanner.scanPaths(targets, 'quick', isTargetFile);
  }
}
