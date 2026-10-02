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
  ScanProgress
} from '../types/desktop.types';

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

  constructor(options?: {
    vaultDir?: string;
    configDir?: string;
  }) {
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

  public async handleStartQuickScan() {
    return this.quickScanner.executeQuickScan();
  }

  public async handleStartFullScan(targetPath?: string) {
    const root = targetPath ? IpcValidator.validatePath(targetPath) : os.homedir();
    return this.scanner.scanPaths([root], 'full');
  }

  public async handleStartCustomScan(targets: string[]) {
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

  public async handleIsolateFile(filePath: string) {
    const validatedPath = IpcValidator.validatePath(filePath);
    const analysis = await this.adapter.analyzeFile(validatedPath);
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

  public handleSaveSettings(settings: Partial<DesktopSettings>): void {
    this.storage.saveSettings(settings);
  }

  public async handleExplainThreat(
    threat: DetectedThreat,
    cognitiveLevel: 'grade6' | 'grade8' = 'grade6'
  ): Promise<DesktopAssistantExplanation> {
    const validLevel = IpcValidator.validateCognitiveLevel(cognitiveLevel);
    return this.adapter.explainThreat(threat, validLevel);
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
  }

  /**
   * Registers all allowed IPC channels onto an Electron ipcMain instance with origin validation
   * and binds real-time scan progress events to the renderer webContents.
   */
  public registerElectronHandlers(
    ipcMain: {
      handle: (channel: string, listener: (event: any, ...args: any[]) => any) => void;
    },
    getWebContents?: () => { send: (channel: string, ...args: any[]) => void } | null | undefined
  ): void {
    const verifyOrigin = (event: any) => {
      const senderUrl = event?.senderFrame?.url ?? 'file://local';
      IpcValidator.validateSenderOrigin(senderUrl);
    };

    // Forward real-time progress events from ScannerService to Renderer
    this.scanner.on('progress', (progress: ScanProgress) => {
      const wc = getWebContents?.();
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
