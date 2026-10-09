import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';
import { EventEmitter } from 'events';
import {
  RemovableDrive,
  RemovableDriveScanResult,
  AutorunAnalysisResult,
  ShortcutWormAnalysisResult,
  DetectedThreat,
  ThreatSeverity,
  ThreatVerdict
} from '../types/desktop.types';
import { AutorunParser } from '../core/autorun-parser';
import { LnkParser } from '../core/lnk-parser';
import { FileAnalyzer } from '../core/file-analyzer';
import { IpcValidator } from '../ipc/ipc-validator';

export interface RemovableMediaCommandRunner {
  exec(command: string, args: string[]): Promise<{ stdout: string; stderr: string }>;
}

export class DefaultRemovableMediaCommandRunner implements RemovableMediaCommandRunner {
  public async exec(command: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      child_process.execFile(
        command,
        args,
        {
          timeout: 3000,
          maxBuffer: 2 * 1024 * 1024,
          windowsHide: true
        },
        (err, stdout, stderr) => {
          if (err) {
            reject(err);
          } else {
            resolve({ stdout, stderr });
          }
        }
      );
    });
  }
}

export interface RemovableMediaServiceOptions {
  readonly commandRunner?: RemovableMediaCommandRunner;
  readonly driveProvider?: () => Promise<RemovableDrive[]>;
  readonly autoScanOnMount?: boolean;
}

/**
 * Real Windows Removable Drive & USB Protection Service (Phase M).
 *
 * Implements DRIVE_REMOVABLE (DriveType=2) volume discovery, real capacity reporting,
 * mount attachment monitoring, and high-speed (<200ms) root quick-triage for autorun.inf,
 * binary shortcut worms, and deceptive root executables via the canonical detection pipeline.
 */
export class RemovableMediaService extends EventEmitter {
  private knownDrives: Map<string, RemovableDrive> = new Map();
  private isPolling = false;
  private pollInterval: NodeJS.Timeout | null = null;
  private runner: RemovableMediaCommandRunner;
  private customDriveProvider?: () => Promise<RemovableDrive[]>;
  private autoScanOnMount: boolean;

  private static readonly ROOT_EXECUTABLE_EXTENSIONS = new Set([
    '.exe',
    '.scr',
    '.pif',
    '.com',
    '.bat',
    '.cmd',
    '.vbs',
    '.vbe',
    '.js',
    '.jse',
    '.wsf',
    '.hta',
    '.ps1',
    '.dll',
    '.cpl'
  ]);

  constructor(options?: RemovableMediaServiceOptions) {
    super();
    this.runner = options?.commandRunner || new DefaultRemovableMediaCommandRunner();
    this.customDriveProvider = options?.driveProvider;
    this.autoScanOnMount = options?.autoScanOnMount ?? true;
  }

  /**
   * Discovers current mounted removable volumes accurately.
   * On Windows: Queries Win32_LogicalDisk where DriveType=2 (DRIVE_REMOVABLE).
   * Does NOT treat arbitrary fixed drives (C:, D:) as removable media.
   */
  public async getMountedDrives(): Promise<RemovableDrive[]> {
    if (this.customDriveProvider) {
      return this.customDriveProvider();
    }

    if (process.platform === 'win32' || !(this.runner instanceof DefaultRemovableMediaCommandRunner)) {
      return this.queryWindowsRemovableDrives();
    }

    return this.queryPosixRemovableDrives();
  }

  /**
   * Windows-native Removable Drive Query using WMI / CIM Win32_LogicalDisk.
   */
  private async queryWindowsRemovableDrives(): Promise<RemovableDrive[]> {
    const psScript =
      'Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType,VolumeSerialNumber | ConvertTo-Json -Compress';

    try {
      const { stdout } = await this.runner.exec('powershell', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        psScript
      ]);

      const trimmed = stdout.trim();
      if (!trimmed) {
        return [];
      }

      let parsed: any;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        return [];
      }

      const items = Array.isArray(parsed) ? parsed : [parsed];
      const drives: RemovableDrive[] = [];

      for (const item of items) {
        if (!item || typeof item !== 'object') continue;

        // DriveType: 2 = DRIVE_REMOVABLE (USB, SD cards, Floppy)
        const driveTypeNum = Number(item.DriveType);
        if (driveTypeNum !== 2) {
          continue; // Strict RULE: Ignore Fixed (3), Network (4), CD-ROM (5), RAMDisk (6)
        }

        const deviceId = String(item.DeviceID || '').trim();
        if (!/^[a-zA-Z]:$/.test(deviceId)) {
          continue;
        }

        const mountPoint = `${deviceId.toUpperCase()}\\`;
        const volumeName = item.VolumeName ? String(item.VolumeName).trim() : '';
        const label = volumeName || `Removable Disk (${deviceId.toUpperCase()})`;
        const totalBytes = Number(item.Size) || 0;
        const freeBytes = Number(item.FreeSpace) || 0;
        const fileSystem = item.FileSystem ? String(item.FileSystem).trim() : undefined;
        const volumeSerialNumber = item.VolumeSerialNumber ? String(item.VolumeSerialNumber).trim() : undefined;

        drives.push({
          mountPoint,
          label,
          totalBytes,
          freeBytes,
          driveLetter: deviceId.toUpperCase(),
          driveType: 'REMOVABLE',
          fileSystem,
          isRemovable: true,
          volumeSerialNumber
        });
      }

      return drives;
    } catch {
      // Fallback to safe directory check if PowerShell fails
      return [];
    }
  }

  /**
   * POSIX Removable Drive Query for cross-platform support (/Volumes, /media, /mnt).
   */
  private async queryPosixRemovableDrives(): Promise<RemovableDrive[]> {
    const drives: RemovableDrive[] = [];
    const mediaRoots = ['/Volumes', '/media', path.join(os.homedir(), 'media')];

    for (const root of mediaRoots) {
      if (!fs.existsSync(root)) continue;

      try {
        const entries = await fs.promises.readdir(root, { withFileTypes: true });
        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          const mountPoint = path.join(root, entry.name);

          let totalBytes = 0;
          let freeBytes = 0;
          try {
            if ((fs as any).statfsSync) {
              const stat = (fs as any).statfsSync(mountPoint);
              const bsize = stat.bsize || 4096;
              totalBytes = Number(stat.blocks || 0) * bsize;
              freeBytes = Number(stat.bfree || 0) * bsize;
            }
          } catch {
            // statfs optional
          }

          drives.push({
            mountPoint,
            label: entry.name,
            totalBytes,
            freeBytes,
            driveType: 'REMOVABLE',
            isRemovable: true
          });
        }
      } catch {
        // Read errors handled safely
      }
    }

    return drives;
  }

  /**
   * Starts periodic monitoring for newly attached removable media.
   * Emits 'driveAttached' when a new valid removable volume is connected.
   */
  public startMonitoring(intervalMs = 2000): void {
    if (this.isPolling) return;
    this.isPolling = true;

    // Initialize baseline known drives
    this.getMountedDrives()
      .then((drives) => {
        this.knownDrives.clear();
        for (const d of drives) {
          this.knownDrives.set(path.normalize(d.mountPoint).toLowerCase(), d);
        }
      })
      .catch(() => {
        // Init error handled safely
      });

    this.pollInterval = setInterval(async () => {
      try {
        const currentDrives = await this.getMountedDrives();
        const currentMap = new Map<string, RemovableDrive>();

        for (const drive of currentDrives) {
          const normKey = path.normalize(drive.mountPoint).toLowerCase();
          currentMap.set(normKey, drive);

          if (!this.knownDrives.has(normKey)) {
            // New drive attached
            this.knownDrives.set(normKey, drive);
            this.emit('driveAttached', drive);

            if (this.autoScanOnMount) {
              void this.scanRemovableDriveRoot(drive.mountPoint);
            }
          }
        }

        // Check for detached drives
        for (const [key, known] of this.knownDrives.entries()) {
          if (!currentMap.has(key)) {
            this.knownDrives.delete(key);
            this.emit('driveDetached', known.mountPoint);
          }
        }
      } catch {
        // Polling errors handled safely
      }
    }, intervalMs);
  }

  /**
   * Stops active attachment monitoring.
   */
  public stopMonitoring(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    this.isPolling = false;
  }

  /**
   * High-Speed Quick Triage of Removable Media Root (< 200 ms SLA).
   *
   * Non-recursively inspects:
   * 1. autorun.inf directives
   * 2. Binary .lnk shortcuts and deceptive folder disguises
   * 3. Root executables and scripts
   * 4. Hidden folder replacement worm patterns
   */
  public async scanRemovableDriveRoot(mountPath: string): Promise<RemovableDriveScanResult> {
    const startTime = Date.now();

    // Strict path validation
    const validMount = IpcValidator.validatePath(mountPath);
    if (!fs.existsSync(validMount)) {
      throw new Error(`REMOVABLE_DRIVE_NOT_FOUND: Mount path '${mountPath}' does not exist or is disconnected.`);
    }

    const stat = await fs.promises.stat(validMount);
    if (!stat.isDirectory()) {
      throw new Error(`INVALID_MOUNT_POINT: Mount path '${mountPath}' is not a directory.`);
    }

    const threats: DetectedThreat[] = [];
    const evidenceFactors: string[] = [];
    const shortcutWorms: ShortcutWormAnalysisResult[] = [];
    let autorunResult: AutorunAnalysisResult | undefined;
    let totalRootItemsScanned = 0;

    let entries: fs.Dirent[] = [];
    try {
      entries = await fs.promises.readdir(validMount, { withFileTypes: true });
    } catch (err: any) {
      throw new Error(`READ_DIRECTORY_FAILED: Could not enumerate root of '${mountPath}': ${err?.message}`);
    }

    // Limit to max 50 items for guaranteed < 200 ms SLA on root triage
    const triageEntries = entries.slice(0, 50);
    totalRootItemsScanned = triageEntries.length;

    const directoryNames = new Set<string>();
    for (const ent of triageEntries) {
      if (ent.isDirectory()) {
        directoryNames.add(ent.name.toLowerCase());
      }
    }

    // 1. Inspect autorun.inf if present
    const autorunEntry = triageEntries.find((e) => e.isFile() && e.name.toLowerCase() === 'autorun.inf');
    if (autorunEntry) {
      const autorunPath = path.join(validMount, autorunEntry.name);
      autorunResult = await AutorunParser.parseFile(autorunPath, validMount);

      if (autorunResult.hasAutorun && autorunResult.isSuspicious) {
        evidenceFactors.push(...autorunResult.evidenceFactors);

        const autorunThreat: DetectedThreat = {
          id: `threat-autorun-${Date.now()}`,
          filePath: autorunPath,
          fileName: 'autorun.inf',
          fileSize: (await fs.promises.stat(autorunPath).catch(() => ({ size: 0 }))).size,
          sha256: autorunResult.targetAnalysis?.sha256 || 'autorun-heuristic',
          riskScore: autorunResult.riskScore,
          severity: autorunResult.riskScore >= 85 ? 'critical' : 'suspicious',
          verdict: autorunResult.riskScore >= 85 ? 'BLOCK' : 'WARN',
          threatName: autorunResult.indicators[0] || 'USB_AUTORUN_THREAT',
          detectedAt: Date.now(),
          evidenceFactors: [...autorunResult.evidenceFactors],
          quarantined: false
        };
        threats.push(autorunThreat);
      }
    }

    // 2. Inspect .LNK shortcuts & worm patterns
    const lnkEntries = triageEntries.filter((e) => e.isFile() && e.name.toLowerCase().endsWith('.lnk'));
    for (const lnk of lnkEntries) {
      const lnkPath = path.join(validMount, lnk.name);
      const lnkAnalysis = await LnkParser.parseFile(lnkPath, validMount);
      shortcutWorms.push(lnkAnalysis);

      if (lnkAnalysis.isSuspicious) {
        evidenceFactors.push(...lnkAnalysis.evidenceFactors);

        const lnkThreat: DetectedThreat = {
          id: `threat-lnk-${Date.now()}-${threats.length}`,
          filePath: lnkPath,
          fileName: lnk.name,
          fileSize: (await fs.promises.stat(lnkPath).catch(() => ({ size: 0 }))).size,
          sha256: lnkAnalysis.targetAnalysis?.sha256 || 'lnk-heuristic',
          riskScore: lnkAnalysis.riskScore,
          severity: lnkAnalysis.riskScore >= 85 ? 'critical' : 'suspicious',
          verdict: lnkAnalysis.riskScore >= 85 ? 'BLOCK' : 'WARN',
          threatName: lnkAnalysis.indicators[0] || 'USB_SHORTCUT_WORM',
          detectedAt: Date.now(),
          evidenceFactors: [...lnkAnalysis.evidenceFactors],
          quarantined: false
        };
        threats.push(lnkThreat);
      }

      // Check hidden folder replacement pattern (e.g. folder 'Work' exists + 'Work.lnk' exists)
      const baseLnkName = path.parse(lnk.name).name.toLowerCase();
      if (directoryNames.has(baseLnkName) && lnkAnalysis.isSuspicious) {
        evidenceFactors.push(
          `Shortcut '${lnk.name}' deceptively replaces existing folder '${baseLnkName}' (Shortcut Worm pattern)`
        );
      }
    }

    // 3. Inspect root-level executables and scripts with FileAnalyzer
    const rootExecutables = triageEntries.filter(
      (e) =>
        e.isFile() &&
        RemovableMediaService.ROOT_EXECUTABLE_EXTENSIONS.has(path.extname(e.name).toLowerCase()) &&
        e.name.toLowerCase() !== 'autorun.inf'
    );

    for (const execEnt of rootExecutables) {
      const execPath = path.join(validMount, execEnt.name);
      try {
        const fileAnalysis = await FileAnalyzer.analyzeFile(execPath, {
          entropyDetectionEnabled: true,
          inspectMotw: true,
          inspectEmail: false
        });

        if (fileAnalysis.verdict === 'BLOCK' || fileAnalysis.riskScore >= 70) {
          evidenceFactors.push(
            `Root executable '${execEnt.name}' analyzed as ${fileAnalysis.verdict} (score=${fileAnalysis.riskScore}): ${fileAnalysis.threatName}`
          );

          const execThreat: DetectedThreat = {
            id: `threat-rootexec-${Date.now()}-${threats.length}`,
            filePath: execPath,
            fileName: execEnt.name,
            fileSize: fileAnalysis.fileSize,
            sha256: fileAnalysis.sha256,
            riskScore: fileAnalysis.riskScore,
            severity: fileAnalysis.severity,
            verdict: fileAnalysis.verdict,
            threatName: fileAnalysis.threatName,
            detectedAt: Date.now(),
            evidenceFactors: fileAnalysis.evidenceFactors,
            quarantined: false
          };
          threats.push(execThreat);
        }
      } catch {
        // Individual file analysis error ignored
      }
    }

    // Compute aggregate risk score and verdict
    let maxScore = 0;
    for (const t of threats) {
      if (t.riskScore > maxScore) {
        maxScore = t.riskScore;
      }
    }

    let overallSeverity: ThreatSeverity = 'safe';
    let overallVerdict: ThreatVerdict = 'ALLOW';

    if (maxScore >= 85) {
      overallSeverity = 'critical';
      overallVerdict = 'BLOCK';
    } else if (maxScore >= 70) {
      overallSeverity = 'dangerous';
      overallVerdict = 'BLOCK';
    } else if (maxScore >= 50) {
      overallSeverity = 'suspicious';
      overallVerdict = 'WARN';
    } else if (maxScore > 0) {
      overallSeverity = 'low';
      overallVerdict = 'INFORM';
    }

    const durationMs = Date.now() - startTime;

    const result: RemovableDriveScanResult = {
      mountPoint: validMount,
      scanTimestamp: Date.now(),
      totalRootItemsScanned,
      threatsFound: threats.length,
      riskScore: maxScore,
      severity: overallSeverity,
      verdict: overallVerdict,
      autorun: autorunResult,
      shortcutWorms,
      threats,
      evidenceFactors,
      durationMs
    };

    this.emit('scanCompleted', result);
    return result;
  }
}
