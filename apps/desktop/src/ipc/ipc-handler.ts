import * as os from 'os';
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
  DesktopAssistantExplanation
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
    if (!Array.isArray(targets) || targets.length === 0) {
      throw new Error('INVALID_TARGETS: Must provide at least one target path.');
    }
    const validated = targets.map((t) => IpcValidator.validatePath(t));
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
}
