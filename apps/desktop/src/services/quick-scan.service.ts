import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { CoreFileAnalyzer } from '@private-protection/core';
import { ScannerService } from './scanner.service';
import { ProcessAuditorService } from './process-auditor.service';
import { PersistenceAuditorService } from './persistence-auditor.service';
import { ScanResult } from '../types/desktop.types';

export interface QuickScanOptions {
  readonly scanner?: ScannerService;
  readonly processAuditor?: ProcessAuditorService;
  readonly persistenceAuditor?: PersistenceAuditorService;
}

/**
 * QuickScanService (Phase N Expanded)
 *
 * Implements targeted, rapid threat discovery across high-risk ingress points:
 * 1. User Downloads
 * 2. User/System Temp Directory
 * 3. User Desktop
 * 4. User and System Startup Folders
 * 5. Active user-mode process executable binaries (via ProcessAuditorService)
 * 6. Windows Startup and Persistence registered targets (via PersistenceAuditorService)
 *
 * All discovered targets are safely evaluated through the canonical FileAnalyzer pipeline
 * without executing untrusted binaries or spawning child shells.
 */
export class QuickScanService {
  private scanner: ScannerService;
  private processAuditor?: ProcessAuditorService;
  private persistenceAuditor?: PersistenceAuditorService;

  constructor(optionsOrScanner?: QuickScanOptions | ScannerService) {
    if (optionsOrScanner instanceof ScannerService) {
      this.scanner = optionsOrScanner;
    } else if (optionsOrScanner && typeof optionsOrScanner === 'object') {
      this.scanner = optionsOrScanner.scanner || new ScannerService();
      this.processAuditor = optionsOrScanner.processAuditor;
      this.persistenceAuditor = optionsOrScanner.persistenceAuditor;
    } else {
      this.scanner = new ScannerService();
    }
  }

  public getScanner(): ScannerService {
    return this.scanner;
  }

  public setProcessAuditor(auditor: ProcessAuditorService): void {
    this.processAuditor = auditor;
  }

  public setPersistenceAuditor(auditor: PersistenceAuditorService): void {
    this.persistenceAuditor = auditor;
  }

  /**
   * Resolves legitimate high-risk ingress directory points for a targeted Quick Scan.
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

      const progData = process.env.ProgramData || 'C:\\ProgramData';
      const commonStartup = path.join(progData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
      if (fs.existsSync(commonStartup)) targets.push(commonStartup);
    } else {
      const autostart = path.join(home, '.config', 'autostart');
      if (fs.existsSync(autostart)) targets.push(autostart);
    }

    return targets;
  }

  /**
   * Resolves complete Quick Scan targets including directory ingress points,
   * active process executable binaries, and registered persistence items.
   */
  public async resolveAllQuickScanTargets(customTargets?: string[]): Promise<string[]> {
    const targetSet = new Set<string>();

    // 1. Add base directory targets
    const baseTargets =
      customTargets && customTargets.length > 0
        ? customTargets
        : this.getQuickScanTargets();

    for (const t of baseTargets) {
      if (t && typeof t === 'string' && fs.existsSync(t)) {
        targetSet.add(path.resolve(t));
      }
    }

    // 2. Add Active Process Binaries (Phase N Expansion)
    if (this.processAuditor) {
      try {
        const processes = await this.processAuditor.auditRunningProcesses();
        for (const proc of processes) {
          if (proc.executablePath && typeof proc.executablePath === 'string') {
            const resolved = path.resolve(proc.executablePath);
            if (fs.existsSync(resolved)) {
              try {
                const stat = fs.statSync(resolved);
                if (stat.isFile()) {
                  targetSet.add(resolved);
                }
              } catch {
                // Ignore inaccessible process binary
              }
            }
          }
        }
      } catch {
        // Continue if process auditor encounters permission restriction
      }
    }

    // 3. Add Startup / Persistence Targets (Phase N Expansion)
    if (this.persistenceAuditor) {
      try {
        const persistenceResult = await this.persistenceAuditor.auditStartupLocations();
        for (const item of persistenceResult.items) {
          const candidatePath = item.targetPath || item.executablePath;
          if (candidatePath && typeof candidatePath === 'string') {
            const resolved = path.resolve(candidatePath);
            if (fs.existsSync(resolved)) {
              try {
                const stat = fs.statSync(resolved);
                if (stat.isFile()) {
                  targetSet.add(resolved);
                }
              } catch {
                // Ignore inaccessible persistence file
              }
            }
          }
        }
      } catch {
        // Continue if persistence auditor encounters permission restriction
      }
    }

    return Array.from(targetSet);
  }

  /**
   * Runs the Quick Scan targeting executables, scripts, active process binaries,
   * persistence mechanisms, and double-extension/RTLO deceptions.
   */
  public async executeQuickScan(customTargets?: string[]): Promise<ScanResult> {
    const targets = await this.resolveAllQuickScanTargets(customTargets);

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
