import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { IPC_CHANNELS } from './ipc-channels';
import { IpcValidator } from './ipc-validator';
import { ScannerService } from '../services/scanner.service';
import { QuickScanService } from '../services/quick-scan.service';
import { QuarantineService } from '../services/quarantine.service';
import { RealtimeMonitorService } from '../services/realtime-monitor.service';
import { ProcessAuditorService } from '../services/process-auditor.service';
import { PersistenceAuditorService } from '../services/persistence-auditor.service';
import { RemovableMediaService } from '../services/removable-media.service';
import { NetworkMonitorService } from '../services/network-monitor.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { DesktopSecurityAdapter } from '../core/desktop-security-adapter';
import {
  DesktopProtectionStatus,
  DesktopSettings,
  DetectedThreat,
  DesktopAssistantExplanation,
  ScanProgress,
  RealtimeThreatEvent
} from '../types/desktop.types';

export interface IpcHandlerOptions {
  vaultDir?: string;
  configDir?: string;
  downloadsDir?: string;
  tempDir?: string;
  autoStartRealtime?: boolean;
}

export class IpcHandler {
  private scanner: ScannerService;
  private quickScanner: QuickScanService;
  private quarantine: QuarantineService;
  private realtimeMonitor: RealtimeMonitorService;
  private processAuditor: ProcessAuditorService;
  private persistenceAuditor: PersistenceAuditorService;
  private removableMedia: RemovableMediaService;
  private networkMonitor: NetworkMonitorService;
  private storage: SecureStorageService;
  private adapter: DesktopSecurityAdapter;
  private downloadsDir: string;
  private tempDir: string;
  private autoStartRealtime: boolean;
  private getWebContentsFn?: () => { send: (channel: string, ...args: any[]) => void } | null | undefined;

  constructor(options?: IpcHandlerOptions) {
    this.scanner = new ScannerService();
    this.quickScanner = new QuickScanService(this.scanner);
    this.quarantine = new QuarantineService(options?.vaultDir);
    this.realtimeMonitor = new RealtimeMonitorService();
    this.processAuditor = new ProcessAuditorService();
    this.persistenceAuditor = new PersistenceAuditorService();
    this.removableMedia = new RemovableMediaService();
    this.networkMonitor = new NetworkMonitorService();
    this.storage = new SecureStorageService(options?.configDir);
    this.adapter = new DesktopSecurityAdapter();

    this.downloadsDir = options?.downloadsDir || path.join(os.homedir(), 'Downloads');
    this.tempDir = options?.tempDir || os.tmpdir();
    this.autoStartRealtime = options?.autoStartRealtime ?? false;

    // Subscribe to RealtimeMonitorService detections (GAP-14)
    this.realtimeMonitor.on('threatDetected', (threat: DetectedThreat) => {
      void this.handleRealtimeThreatDetected(threat);
    });

    // Apply persisted settings immediately on startup (GAP-15)
    this.applySettings(this.storage.getSettings(), this.autoStartRealtime);
  }

  public getScanner(): ScannerService {
    return this.scanner;
  }

  public getQuarantine(): QuarantineService {
    return this.quarantine;
  }

  public getRealtimeMonitor(): RealtimeMonitorService {
    return this.realtimeMonitor;
  }

  /**
   * Applies DesktopSettings across ScannerService and RealtimeMonitorService at runtime (GAP-15).
   */
  public applySettings(settings: DesktopSettings, updateWatchers = true): void {
    this.scanner.applySettings(settings);

    this.realtimeMonitor.setEntropyDetectionEnabled(settings.entropyDetectionEnabled);
    this.realtimeMonitor.setMaxFileSizeBytes(settings.scanLargeFilesLimitMb * 1024 * 1024);
    this.realtimeMonitor.setExcludedPaths(settings.excludedPaths || []);

    if (!updateWatchers) {
      return;
    }

    if (!settings.realtimeShieldEnabled) {
      this.realtimeMonitor.stop();
      return;
    }

    const watchDirs: string[] = [];
    if (settings.monitorDownloads && fs.existsSync(this.downloadsDir)) {
      watchDirs.push(this.downloadsDir);
    }
    if (settings.monitorTemp && fs.existsSync(this.tempDir)) {
      watchDirs.push(this.tempDir);
    }

    if (watchDirs.length > 0) {
      this.realtimeMonitor.start(watchDirs);
    } else {
      this.realtimeMonitor.stop();
    }
  }

  /**
   * Processes a real-time threat event from RealtimeMonitorService, executes auto-quarantine
   * if policy requires, and dispatches REALTIME_THREAT_EVENT over IPC to the renderer (GAP-14).
   */
  public async handleRealtimeThreatDetected(threat: DetectedThreat): Promise<RealtimeThreatEvent> {
    const settings = this.storage.getSettings();
    const shouldAutoQuarantine =
      settings.autoQuarantineCritical === true &&
      threat.verdict === 'BLOCK' &&
      (threat.severity === 'critical' || threat.severity === 'dangerous');

    let eventPayload: RealtimeThreatEvent;

    if (shouldAutoQuarantine) {
      try {
        const quarantineItem = await this.quarantine.isolateFile(threat);
        eventPayload = {
          threat: { ...threat, quarantined: true },
          actionTaken: 'AUTO_QUARANTINED',
          quarantineItem,
          timestamp: Date.now()
        };
      } catch {
        eventPayload = {
          threat,
          actionTaken: 'ALERTED',
          timestamp: Date.now()
        };
      }
    } else {
      eventPayload = {
        threat,
        actionTaken: 'ALERTED',
        timestamp: Date.now()
      };
    }

    const wc = this.getWebContentsFn?.();
    if (wc) {
      wc.send(IPC_CHANNELS.REALTIME_THREAT_EVENT, eventPayload);
    }

    return eventPayload;
  }

  public async handleStartQuickScan() {
    this.scanner.applySettings(this.storage.getSettings());
    return this.quickScanner.executeQuickScan();
  }

  public async handleStartFullScan(targetPath?: string) {
    this.scanner.applySettings(this.storage.getSettings());
    const root = targetPath ? IpcValidator.validatePath(targetPath) : os.homedir();
    return this.scanner.scanPaths([root], 'full');
  }

  public async handleStartCustomScan(targets: string[]) {
    this.scanner.applySettings(this.storage.getSettings());
    const validated = IpcValidator.validateScanTargets(targets);
    return this.scanner.scanPaths(validated, 'custom');
  }

  public handleCancelScan(): void {
    this.scanner.cancelScan();
  }

  public handlePauseScan(): void {
    this.scanner.pauseScan();
  }

  public handleResumeScan(): void {
    this.scanner.resumeScan();
  }

  public handleListQuarantine() {
    return this.quarantine.listQuarantine();
  }

  /**
   * Validates path, resolves symlinks, analyzes file, and enforces threat policy before quarantine (GAP-16).
   */
  public async handleIsolateFile(filePath: string) {
    const validatedPath = IpcValidator.validatePath(filePath);

    if (!fs.existsSync(validatedPath)) {
      throw new Error(`FILE_NOT_FOUND: Cannot quarantine non-existent file '${validatedPath}'.`);
    }

    const lstat = await fs.promises.lstat(validatedPath);
    if (lstat.isSymbolicLink()) {
      throw new Error('SECURITY_VIOLATION: Quarantining symbolic links is forbidden to prevent target hijacking.');
    }

    if (IpcValidator.isProtectedSystemPath(validatedPath)) {
      throw new Error('SECURITY_VIOLATION: Quarantining protected OS system files is forbidden.');
    }

    const currentSettings = this.storage.getSettings();
    const analysis = await this.adapter.analyzeFile(validatedPath, {
      entropyDetectionEnabled: currentSettings.entropyDetectionEnabled
    });

    // GAP-16 Policy Enforcement: Reject benign ALLOW/INFORM or safe/low severity files
    const isDangerousOrSuspiciousVerdict = analysis.verdict === 'BLOCK' || analysis.verdict === 'WARN';
    const isElevatedSeverity =
      analysis.severity === 'critical' ||
      analysis.severity === 'dangerous' ||
      analysis.severity === 'suspicious';

    if (!isDangerousOrSuspiciousVerdict || !isElevatedSeverity) {
      throw new Error(
        `QUARANTINE_POLICY_REJECTED: Benign or safe files (verdict=${analysis.verdict}, severity=${analysis.severity}) cannot be quarantined.`
      );
    }

    const threat: DetectedThreat = {
      id: `threat-${Date.now()}`,
      filePath: analysis.filePath,
      fileName: analysis.fileName,
      fileSize: analysis.fileSize,
      sha256: analysis.sha256,
      riskScore: analysis.riskScore,
      severity: analysis.severity,
      verdict: analysis.verdict,
      threatName: analysis.threatName,
      detectedAt: Date.now(),
      evidenceFactors: analysis.evidenceFactors,
      quarantined: false
    };
    return this.quarantine.isolateFile(threat);
  }

  public async handleRestoreQuarantine(quarantineId: string, customDir?: string) {
    const validId = IpcValidator.validateId(quarantineId, 'quarantine-');
    const validDest = customDir ? IpcValidator.validatePath(customDir) : undefined;
    return this.quarantine.restoreItem(validId, validDest);
  }

  public async handleDeleteQuarantine(quarantineId: string) {
    const validId = IpcValidator.validateId(quarantineId, 'quarantine-');
    return this.quarantine.permanentDelete(validId);
  }

  public handleGetProtectionStatus(): DesktopProtectionStatus {
    const mem = process.memoryUsage();
    return {
      realtimeShieldActive: this.realtimeMonitor.isActive(),
      monitoredPaths: this.realtimeMonitor.getMonitoredPaths(),
      threatDatabaseVersion: '2026.10-offline-seed',
      threatDatabaseTimestamp: 1760000000000,
      coreEngineVersion: '1.0.0-verified',
      mlAssistantReady: true,
      offlineMode: true,
      quarantinedCount: this.quarantine.listQuarantine().length,
      memoryRssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed
    };
  }

  public handleGetSettings(): DesktopSettings {
    return this.storage.getSettings();
  }

  public handleSaveSettings(settings: Partial<DesktopSettings>): DesktopSettings {
    const validatedPatch = IpcValidator.validateSettings(settings);
    this.storage.saveSettings(validatedPatch);
    const updated = this.storage.getSettings();
    this.applySettings(updated, true);
    return updated;
  }

  public async handleExplainThreat(
    threat: DetectedThreat,
    cognitiveLevel?: 'grade6' | 'grade8'
  ): Promise<DesktopAssistantExplanation> {
    const validThreat = IpcValidator.validateThreatInput(threat);
    const storedLevel = this.storage.getSettings().cognitiveLevel;
    const validLevel = cognitiveLevel
      ? IpcValidator.validateCognitiveLevel(cognitiveLevel)
      : storedLevel;
    return this.adapter.explainThreat(validThreat, validLevel);
  }

  public async handleAuditProcesses() {
    return this.processAuditor.auditRunningProcesses();
  }

  public async handleAuditPersistence() {
    return this.persistenceAuditor.auditStartupLocations();
  }

  public async handleGetRemovableMedia() {
    return this.removableMedia.getMountedDrives();
  }

  public async handleGetNetworkPosture() {
    return this.networkMonitor.getNetworkPosture();
  }

  public handlePrivacyShred(): void {
    this.quarantine.purgeAllQuarantine();
    this.storage.purgeAllData();
    this.applySettings(this.storage.getSettings(), false);
  }

  /**
   * Registers all allowed IPC channels onto an Electron ipcMain instance with origin validation
   * and binds real-time scan progress and threat events to the renderer webContents.
   */
  public registerElectronHandlers(
    ipcMain: {
      handle: (channel: string, listener: (event: any, ...args: any[]) => any) => void;
    },
    getWebContents?: () => { send: (channel: string, ...args: any[]) => void } | null | undefined
  ): void {
    this.getWebContentsFn = getWebContents;

    const verifyOrigin = (event: any) => {
      const senderUrl = event?.senderFrame?.url;
      IpcValidator.validateSenderOrigin(senderUrl);
    };

    // Forward real-time progress events from ScannerService to Renderer
    this.scanner.on('progress', (progress: ScanProgress) => {
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.SCAN_PROGRESS_EVENT, progress);
      }
    });

    ipcMain.handle(IPC_CHANNELS.SCAN_START_QUICK, async (event) => {
      verifyOrigin(event);
      return this.handleStartQuickScan();
    });

    ipcMain.handle(IPC_CHANNELS.SCAN_START_FULL, async (event, rootPath?: string) => {
      verifyOrigin(event);
      return this.handleStartFullScan(rootPath);
    });

    ipcMain.handle(IPC_CHANNELS.SCAN_START_CUSTOM, async (event, targets: string[]) => {
      verifyOrigin(event);
      return this.handleStartCustomScan(targets);
    });

    ipcMain.handle(IPC_CHANNELS.SCAN_CANCEL, (event) => {
      verifyOrigin(event);
      return this.handleCancelScan();
    });

    ipcMain.handle(IPC_CHANNELS.SCAN_PAUSE, (event) => {
      verifyOrigin(event);
      return this.handlePauseScan();
    });

    ipcMain.handle(IPC_CHANNELS.SCAN_RESUME, (event) => {
      verifyOrigin(event);
      return this.handleResumeScan();
    });

    ipcMain.handle(IPC_CHANNELS.QUARANTINE_LIST, (event) => {
      verifyOrigin(event);
      return this.handleListQuarantine();
    });

    ipcMain.handle(IPC_CHANNELS.QUARANTINE_ISOLATE, async (event, filePath: string) => {
      verifyOrigin(event);
      return this.handleIsolateFile(filePath);
    });

    ipcMain.handle(IPC_CHANNELS.QUARANTINE_RESTORE, async (event, quarantineId: string, customDir?: string) => {
      verifyOrigin(event);
      return this.handleRestoreQuarantine(quarantineId, customDir);
    });

    ipcMain.handle(IPC_CHANNELS.QUARANTINE_DELETE, async (event, quarantineId: string) => {
      verifyOrigin(event);
      return this.handleDeleteQuarantine(quarantineId);
    });

    ipcMain.handle(IPC_CHANNELS.STATUS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetProtectionStatus();
    });

    ipcMain.handle(IPC_CHANNELS.SETTINGS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetSettings();
    });

    ipcMain.handle(IPC_CHANNELS.SETTINGS_SAVE, (event, settings: Partial<DesktopSettings>) => {
      verifyOrigin(event);
      return this.handleSaveSettings(settings);
    });

    ipcMain.handle(IPC_CHANNELS.ASSISTANT_EXPLAIN, async (event, threat: DetectedThreat, level?: 'grade6' | 'grade8') => {
      verifyOrigin(event);
      return this.handleExplainThreat(threat, level);
    });

    ipcMain.handle(IPC_CHANNELS.PROCESSES_AUDIT, async (event) => {
      verifyOrigin(event);
      return this.handleAuditProcesses();
    });

    ipcMain.handle(IPC_CHANNELS.PERSISTENCE_AUDIT, async (event) => {
      verifyOrigin(event);
      return this.handleAuditPersistence();
    });

    ipcMain.handle(IPC_CHANNELS.REMOVABLE_MEDIA_GET, async (event) => {
      verifyOrigin(event);
      return this.handleGetRemovableMedia();
    });

    ipcMain.handle(IPC_CHANNELS.NETWORK_POSTURE_GET, async (event) => {
      verifyOrigin(event);
      return this.handleGetNetworkPosture();
    });

    ipcMain.handle(IPC_CHANNELS.PRIVACY_SHRED, (event) => {
      verifyOrigin(event);
      return this.handlePrivacyShred();
    });
  }
}
