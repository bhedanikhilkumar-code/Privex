import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {
  PersistenceItem,
  PersistenceAuditResult,
  PersistenceRemediationResult,
  PersistenceLocationType,
  ThreatSeverity,
  ThreatVerdict,
  DetectedThreat
} from '../types/desktop.types';
import { PersistenceCommandParser } from '../core/persistence-command-parser';
import { WindowsRegistryReader, RegistryRunEntry } from '../core/windows-registry-reader';
import { LnkParser } from '../core/lnk-parser';
import { FileAnalyzer } from '../core/file-analyzer';
import { IpcValidator } from '../ipc/ipc-validator';
import { QuarantineService } from './quarantine.service';

export interface AuditPersistenceOptions {
  readonly customDirs?: string[];
  readonly customRegistry?: Record<string, string>;
  readonly customEntries?: RegistryRunEntry[];
}

/**
 * Production-Grade Windows Startup & Persistence Protection Service (Phase L).
 *
 * Audits, analyzes, monitors, and remediates Windows startup persistence vectors
 * (Registry Run/RunOnce HKCU/HKLM, User Startup, All-Users Startup) through the
 * canonical detection engine with false-positive protection and RULE-09 OS immunity.
 */
export class PersistenceAuditorService {
  private registryReader: WindowsRegistryReader;
  private quarantineService: QuarantineService | null;
  private cachedItems: Map<string, PersistenceItem> = new Map();
  private lastAuditResult: PersistenceAuditResult | null = null;

  constructor(
    quarantineService?: QuarantineService | null,
    registryReader?: WindowsRegistryReader
  ) {
    this.quarantineService = quarantineService || null;
    this.registryReader = registryReader || new WindowsRegistryReader();
  }

  public setQuarantineService(quarantineService: QuarantineService | null): void {
    this.quarantineService = quarantineService;
  }

  public setRegistryReader(reader: WindowsRegistryReader): void {
    this.registryReader = reader;
  }

  /**
   * Generates a stable, deterministic canonical ID for a persistence entry.
   */
  public static generateCanonicalId(locationType: string, locationPath: string, name: string): string {
    const rawKey = `${locationType}:${locationPath.toLowerCase()}:${name.toLowerCase()}`;
    return `persist-${crypto.createHash('sha256').update(rawKey).digest('hex').substring(0, 16)}`;
  }

  /**
   * Discovers startup folder paths for the current system.
   */
  public getStartupFolderPaths(customDirs?: string[]): Array<{ path: string; type: PersistenceLocationType }> {
    if (customDirs !== undefined) {
      return customDirs.map((d) => ({ path: path.resolve(d), type: 'startup_folder_user' }));
    }

    const folders: Array<{ path: string; type: PersistenceLocationType }> = [];
    const home = os.homedir();

    if (process.platform === 'win32') {
      // 1. Current User Startup Folder
      const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
      const userStartup = path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
      folders.push({ path: userStartup, type: 'startup_folder_user' });

      // 2. All Users / Common Startup Folder
      const programData = process.env.PROGRAMDATA || 'C:\\ProgramData';
      const commonStartup = path.join(programData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
      folders.push({ path: commonStartup, type: 'startup_folder_common' });
    } else {
      // POSIX autostart folder fallback
      const autostart = path.join(home, '.config', 'autostart');
      folders.push({ path: autostart, type: 'startup_folder_user' });
    }

    return folders;
  }

  /**
   * Audits all configured startup persistence locations (Registry + Folders).
   * STRICT INVARIANT: Read-only inspection. Never modifies startup entries during audit.
   */
  public async auditStartupLocations(options?: AuditPersistenceOptions): Promise<PersistenceAuditResult> {
    const startTime = Date.now();
    const items: PersistenceItem[] = [];
    const scanErrors: string[] = [];

    // 1. Audit Windows Registry Run & RunOnce Keys
    if (options?.customRegistry) {
      this.registryReader.setMockRegistry(options.customRegistry);
    }
    if (options?.customEntries) {
      this.registryReader.setMockEntries(options.customEntries);
    }

    try {
      const regEntries = await this.registryReader.readAllRunKeys();
      for (const regEntry of regEntries) {
        try {
          const item = await this.analyzeRegistryEntry(regEntry);
          items.push(item);
        } catch (err) {
          scanErrors.push(`Failed to analyze registry entry '${regEntry.valueName}': ${String(err)}`);
        }
      }
    } catch (err) {
      scanErrors.push(`Registry audit encountered an error: ${String(err)}`);
    }

    // 2. Audit Startup Folders
    const startupDirs = this.getStartupFolderPaths(options?.customDirs);
    for (const dirInfo of startupDirs) {
      if (!fs.existsSync(dirInfo.path)) continue;

      try {
        const folderItems = await this.auditStartupFolder(dirInfo.path, dirInfo.type);
        items.push(...folderItems);
      } catch (err) {
        scanErrors.push(`Failed to audit startup folder '${dirInfo.path}': ${String(err)}`);
      }
    }

    // Update in-memory cache
    this.cachedItems.clear();
    for (const item of items) {
      this.cachedItems.set(item.id, item);
    }

    const threatsFound = items.filter((i) => i.engineVerdict === 'BLOCK').length;
    const suspiciousCount = items.filter((i) => i.isSuspicious).length;
    const cleanCount = items.filter((i) => !i.isSuspicious).length;
    const maxRiskScore = items.reduce((max, i) => Math.max(max, i.riskScore || 0), 0);
    const durationMs = Date.now() - startTime;

    const result: PersistenceAuditResult = {
      timestamp: Date.now(),
      totalEntriesAudited: items.length,
      threatsFound,
      suspiciousCount,
      cleanCount,
      maxRiskScore,
      items,
      durationMs,
      scanErrors: scanErrors.length > 0 ? scanErrors : undefined
    };

    this.lastAuditResult = result;
    return result;
  }

  /**
   * Analyzes a single Registry Run/RunOnce entry safely.
   */
  public async analyzeRegistryEntry(entry: RegistryRunEntry): Promise<PersistenceItem> {
    const isRunOnce = entry.isRunOnce;
    const isWow64 = entry.is64BitView === false || entry.keyPath.toLowerCase().includes('wow6432node');
    let locationType: PersistenceLocationType = 'registry_run_hkcu';

    if (entry.hive === 'HKCU') {
      locationType = isRunOnce ? 'registry_runonce_hkcu' : 'registry_run_hkcu';
    } else {
      if (isWow64) {
        locationType = 'registry_run_wow6432';
      } else {
        locationType = isRunOnce ? 'registry_runonce_hklm' : 'registry_run_hklm';
      }
    }

    const id = PersistenceAuditorService.generateCanonicalId(locationType, entry.fullKey, entry.valueName);
    const parsedCmd = PersistenceCommandParser.parseCommandLine(entry.rawValue);

    const indicators = [...parsedCmd.indicators];
    const evidenceFactors = [...parsedCmd.evidenceFactors];
    let totalRiskScore = parsedCmd.riskContribution;

    let existsOnDisk = false;
    let isAccessible = false;
    let isSystemBinary = false;
    let fileAnalysis: any = undefined;

    if (parsedCmd.executablePath) {
      try {
        // Check for RULE-09 OS System Binary
        if (IpcValidator.isProtectedSystemPath(parsedCmd.executablePath)) {
          isSystemBinary = true;
        }

        if (fs.existsSync(parsedCmd.executablePath)) {
          existsOnDisk = true;
          isAccessible = true;

          // Run canonical FileAnalyzer on target binary
          fileAnalysis = await FileAnalyzer.analyzeFile(parsedCmd.executablePath, {
            entropyDetectionEnabled: true
          });

          if (fileAnalysis.riskScore > 0) {
            totalRiskScore = Math.max(totalRiskScore, fileAnalysis.riskScore);
            indicators.push(...(fileAnalysis.evidenceFactors || []));
            evidenceFactors.push(...(fileAnalysis.evidenceFactors || []));
          }
        } else {
          // Disconnected / Missing binary in persistence
          if (!isSystemBinary) {
            indicators.push('MISSING_PERSISTENCE_TARGET');
            evidenceFactors.push(`Referenced persistence target does not exist on disk: ${parsedCmd.executablePath}`);
          }
        }
      } catch {
        isAccessible = false;
      }
    }

    // Calculate severity and verdict deterministically
    let severity: ThreatSeverity = 'safe';
    let engineVerdict: ThreatVerdict = 'ALLOW';

    if (totalRiskScore >= 75 || indicators.includes('SCRIPT_IN_STARTUP_PERSISTENCE') && totalRiskScore >= 70) {
      severity = 'critical';
      engineVerdict = 'BLOCK';
    } else if (totalRiskScore >= 50) {
      severity = 'dangerous';
      engineVerdict = 'WARN';
    } else if (totalRiskScore >= 25 || parsedCmd.isSuspicious) {
      severity = 'suspicious';
      engineVerdict = 'INFORM';
    } else if (totalRiskScore >= 10) {
      severity = 'low';
      engineVerdict = 'ALLOW';
    }

    // System binary protection override (never BLOCK known system binary)
    if (isSystemBinary && !parsedCmd.isSuspicious) {
      engineVerdict = 'ALLOW';
      severity = 'safe';
      totalRiskScore = 0;
    }

    const isSuspicious = severity !== 'safe' && severity !== 'low';

    return {
      id,
      name: entry.valueName,
      targetPath: parsedCmd.executablePath || entry.rawValue,
      rawCommand: entry.rawValue,
      executablePath: parsedCmd.executablePath,
      arguments: parsedCmd.arguments,
      locationType,
      locationPath: entry.fullKey,
      registryHive: entry.hive,
      registryKey: entry.keyPath,
      valueName: entry.valueName,
      existsOnDisk,
      isAccessible,
      isSystemBinary,
      isSuspicious,
      riskScore: totalRiskScore,
      severity,
      engineVerdict,
      threatName: isSuspicious ? (fileAnalysis?.threatName || 'Suspicious Persistence Entry') : undefined,
      reason: evidenceFactors[0] || (isSuspicious ? 'Suspicious persistence configuration' : undefined),
      indicators,
      evidenceFactors,
      analysisResult: fileAnalysis,
      timestamp: Date.now()
    };
  }

  /**
   * Audits a startup folder safely without following junctions or recursive directories.
   */
  private async auditStartupFolder(
    dirPath: string,
    locationType: PersistenceLocationType
  ): Promise<PersistenceItem[]> {
    const items: PersistenceItem[] = [];
    if (!fs.existsSync(dirPath)) return items;

    const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);

      // Skip subdirectories, symlinks, or directory junctions
      if (entry.isDirectory()) continue;

      let isSymlink = false;
      try {
        const lstat = await fs.promises.lstat(fullPath);
        if (lstat.isSymbolicLink()) {
          isSymlink = true;
        }
      } catch {
        continue;
      }

      const id = PersistenceAuditorService.generateCanonicalId(locationType, dirPath, entry.name);
      const ext = path.extname(entry.name).toLowerCase();
      const isShortcut = ext === '.lnk';

      let totalRiskScore = 0;
      const indicators: string[] = [];
      const evidenceFactors: string[] = [];
      let shortcutDetails: any = undefined;
      let fileAnalysis: any = undefined;

      if (isSymlink) {
        indicators.push('SYMLINK_STARTUP_ENTRY');
        evidenceFactors.push('Startup directory contains symbolic link (potential target hijack)');
        totalRiskScore += 45;
      }

      // 1. If .lnk shortcut: parse binary shell link
      if (isShortcut) {
        shortcutDetails = await LnkParser.parseFile(fullPath);
        if (shortcutDetails.isSuspicious) {
          totalRiskScore += shortcutDetails.riskScore;
          indicators.push(...shortcutDetails.indicators);
          evidenceFactors.push(...shortcutDetails.evidenceFactors);
        }
      }

      // 2. Parse file target with FileAnalyzer
      let existsOnDisk = true;
      let isAccessible = true;
      try {
        fileAnalysis = await FileAnalyzer.analyzeFile(fullPath, {
          entropyDetectionEnabled: true
        });

        if (fileAnalysis.riskScore > 0) {
          totalRiskScore = Math.max(totalRiskScore, fileAnalysis.riskScore);
          indicators.push(...(fileAnalysis.evidenceFactors || []));
          evidenceFactors.push(...(fileAnalysis.evidenceFactors || []));
        }
      } catch {
        isAccessible = false;
      }

      // 3. Heuristic script check
      const scriptCheck = this.checkPersistenceEntry(entry.name);
      if (scriptCheck.suspicious) {
        indicators.push('SCRIPT_IN_STARTUP_FOLDER');
        if (scriptCheck.reason) evidenceFactors.push(scriptCheck.reason);
        totalRiskScore += 35;

        // Inspect script text content for encoded/hidden payload commands
        try {
          const rawText = fs.readFileSync(fullPath, 'utf8').substring(0, 4096);
          const parsedScriptCmd = PersistenceCommandParser.parseCommandLine(rawText);
          if (parsedScriptCmd.isSuspicious) {
            indicators.push(...parsedScriptCmd.indicators);
            evidenceFactors.push(...parsedScriptCmd.evidenceFactors);
            totalRiskScore = Math.max(totalRiskScore, parsedScriptCmd.riskContribution + 30);
          }
        } catch {}
      }

      // Calculate severity and verdict
      let severity: ThreatSeverity = 'safe';
      let engineVerdict: ThreatVerdict = 'ALLOW';

      if (totalRiskScore >= 75) {
        severity = 'critical';
        engineVerdict = 'BLOCK';
      } else if (totalRiskScore >= 50) {
        severity = 'dangerous';
        engineVerdict = 'WARN';
      } else if (totalRiskScore >= 25 || indicators.length > 0) {
        severity = 'suspicious';
        engineVerdict = 'INFORM';
      } else if (totalRiskScore >= 10) {
        severity = 'low';
        engineVerdict = 'ALLOW';
      }

      const isSuspicious = severity !== 'safe' && severity !== 'low';

      items.push({
        id,
        name: entry.name,
        targetPath: fullPath,
        rawCommand: fullPath,
        executablePath: fullPath,
        locationType,
        locationPath: dirPath,
        isShortcut,
        shortcutDetails,
        existsOnDisk,
        isAccessible,
        isSystemBinary: false,
        isSuspicious,
        riskScore: totalRiskScore,
        severity,
        engineVerdict,
        threatName: isSuspicious ? (fileAnalysis?.threatName || 'Suspicious Startup File') : undefined,
        reason: evidenceFactors[0] || (isSuspicious ? 'Suspicious file in startup folder' : undefined),
        indicators,
        evidenceFactors,
        analysisResult: fileAnalysis,
        timestamp: Date.now()
      });
    }

    return items;
  }

  /**
   * Remediates a flagged persistence item safely.
   * - For Registry Run entries: removes ONLY the exact value name from the specific hive/key.
   * - For Startup folder entries: isolates the file into the encrypted PPVAULT2 quarantine.
   */
  public async remediateItem(
    itemId: string,
    _options?: { frictionToken?: string }
  ): Promise<PersistenceRemediationResult> {
    if (!itemId || typeof itemId !== 'string') {
      return {
        success: false,
        itemId: itemId || '',
        message: 'Invalid persistence item ID.',
        locationType: 'custom_persistence'
      };
    }

    const item = this.cachedItems.get(itemId);
    if (!item) {
      return {
        success: false,
        itemId,
        message: `Persistence item '${itemId}' not found in active audit cache. Re-run audit first.`,
        locationType: 'custom_persistence'
      };
    }

    // 1. Registry Run / RunOnce Entry Remediation
    if (item.registryHive && item.registryKey && item.valueName) {
      const is64Bit = !item.locationPath?.toLowerCase().includes('wow6432node');
      const deleteResult = await this.registryReader.deleteRunValue(
        item.registryHive,
        item.registryKey,
        item.valueName,
        { view: is64Bit ? '64' : '32' }
      );

      if (deleteResult.success) {
        this.cachedItems.delete(itemId);
        return {
          success: true,
          itemId,
          message: `Registry persistence value '${item.valueName}' successfully deleted from ${item.registryHive}\\${item.registryKey}.`,
          locationType: item.locationType,
          deletedRegistryValue: `${item.registryHive}\\${item.registryKey}\\${item.valueName}`
        };
      } else {
        return {
          success: false,
          itemId,
          message: deleteResult.message || 'Failed to delete registry persistence value.',
          locationType: item.locationType
        };
      }
    }

    // 2. Startup Folder File Remediation (Quarantine Isolation)
    if (item.targetPath && fs.existsSync(item.targetPath)) {
      // Rule-09 protection
      if (IpcValidator.isProtectedSystemPath(item.targetPath)) {
        return {
          success: false,
          itemId,
          message: 'SECURITY_VIOLATION: Cannot delete or quarantine protected Windows OS system binaries.',
          locationType: item.locationType
        };
      }

      if (this.quarantineService) {
        try {
          const detectedThreat: DetectedThreat = {
            id: item.id,
            filePath: item.targetPath,
            fileName: item.name,
            fileSize: fs.statSync(item.targetPath).size,
            sha256: item.analysisResult?.sha256 || '0'.repeat(64),
            riskScore: item.riskScore || 80,
            severity: item.severity || 'dangerous',
            verdict: (item.engineVerdict as ThreatVerdict) || 'BLOCK',
            threatName: item.threatName || 'Startup.Persistence.Threat',
            detectedAt: Date.now(),
            evidenceFactors: item.evidenceFactors || ['Quarantined from Startup Persistence'],
            quarantined: false
          };

          const qItem = await this.quarantineService.isolateFile(detectedThreat);
          this.cachedItems.delete(itemId);

          return {
            success: true,
            itemId,
            message: `Startup file '${item.name}' safely quarantined into vault (${qItem.quarantineId}).`,
            locationType: item.locationType,
            quarantinedFile: item.targetPath
          };
        } catch (err) {
          return {
            success: false,
            itemId,
            message: `Quarantine failed: ${String(err)}`,
            locationType: item.locationType
          };
        }
      } else {
        // Safe unlink if quarantine service is not injected
        try {
          await fs.promises.unlink(item.targetPath);
          this.cachedItems.delete(itemId);
          return {
            success: true,
            itemId,
            message: `Startup file '${item.name}' removed from startup folder.`,
            locationType: item.locationType,
            quarantinedFile: item.targetPath
          };
        } catch (err) {
          return {
            success: false,
            itemId,
            message: `File deletion failed: ${String(err)}`,
            locationType: item.locationType
          };
        }
      }
    }

    return {
      success: false,
      itemId,
      message: 'Unable to remediate persistence item: unsupported target location or file missing.',
      locationType: item.locationType
    };
  }

  /**
   * Backward-compatible heuristic filename checker for simple script/double-extension tests.
   */
  public checkPersistenceEntry(name: string): { suspicious: boolean; reason?: string } {
    if (!name || typeof name !== 'string') return { suspicious: false };
    const lower = name.toLowerCase();

    // Deceptive script or executable persistence
    if (
      lower.endsWith('.vbs') ||
      lower.endsWith('.js') ||
      lower.endsWith('.bat') ||
      lower.endsWith('.cmd') ||
      lower.endsWith('.ps1') ||
      lower.endsWith('.hta') ||
      lower.endsWith('.scr') ||
      lower.endsWith('.pif')
    ) {
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

  public getLastAuditResult(): PersistenceAuditResult | null {
    return this.lastAuditResult;
  }
}
