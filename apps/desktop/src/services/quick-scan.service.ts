import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { CoreFileAnalyzer } from '@private-protection/core';
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
   * Runs the Quick Scan targeting executables, scripts, and double-extension/RTLO deceptions.
   */
  public async executeQuickScan(customTargets?: string[]): Promise<ScanResult> {
    const targets =
      customTargets && customTargets.length > 0
        ? customTargets
        : this.getQuickScanTargets();

    const isTargetFile = (filePath: string) => {
      const rawName = path.basename(filePath);
      const deceptive = CoreFileAnalyzer.checkDeceptiveExtension(rawName);
      if (deceptive.isDeceptive) return true;

      const normalizedName = rawName
        .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
        .replace(/[. ]+$/, '')
        .toLowerCase();
      const ext = path.extname(normalizedName);

      // Inspect if declared executable or script
      if (CoreFileAnalyzer.EXECUTABLE_EXTENSIONS.has(ext)) return true;

      // Inspect if double extension (e.g., invoice.pdf.exe, doc.docx.bat)
      const parts = normalizedName.split('.').filter((p) => p.length > 0);
      if (parts.length >= 3) return true;

      return false;
    };

    return this.scanner.scanPaths(targets, 'quick', isTargetFile);
  }
}
