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
import { ProcessMonitorService } from '../services/process-monitor.service';
import { PersistenceAuditorService } from '../services/persistence-auditor.service';
import { PersistenceMonitorService } from '../services/persistence-monitor.service';
import { RemovableMediaService } from '../services/removable-media.service';
import { NetworkMonitorService } from '../services/network-monitor.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { ShadowVaultService } from '../services/shadow-vault.service';
import { RansomwareShieldService } from '../services/ransomware-shield.service';
import { NotificationService } from '../services/notification.service';
import { ExclusionManagerService } from '../services/exclusion-manager.service';
import { DesktopSecurityAdapter } from '../core/desktop-security-adapter';
import { MotwAnalyzer } from '../core/motw-analyzer';
import { EmailMimeParser } from '../core/email-mime-parser';
import { ScanSchedulerService } from '../services/scan-scheduler.service';
import { ThreatIntelManagerService } from '../services/threat-intel-manager.service';
import { ThreatIntel } from '@private-protection/core';
import {
  DesktopProtectionStatus,
  DesktopSettings,
  DetectedThreat,
  DesktopAssistantExplanation,
  ScanProgress,
  ScanResult,
  RealtimeThreatEvent,
  ContainProcessOptions,
  ProcessMonitorHealth,
  RansomwareShieldStatus,
  TrustedApplication,
  RansomwareIncident,
  IncidentRollbackResult,
  CanaryFileRecord,
  DesktopNotification,
  NotificationInboxState,
  ExclusionItem,
  MotwAnalysisResult,
  EmailAnalysisResult,
  RemovableDrive,
  RemovableDriveScanResult,
  PersistenceItem,
  PersistenceAuditResult,
  PersistenceRemediationResult,
  PersistenceChangeEvent,
  ScanScheduleConfig,
  ScanSchedulerState,
  ScanHistoryRecord,
  UpdateApplyResult,
  UpdateRollbackResult,
  ThreatIntelStatus
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
  private processMonitor: ProcessMonitorService;
  private persistenceAuditor: PersistenceAuditorService;
  private persistenceMonitor: PersistenceMonitorService;
  private removableMedia: RemovableMediaService;
  private networkMonitor: NetworkMonitorService;
  private storage: SecureStorageService;
  private shadowVault: ShadowVaultService;
  private ransomwareShield: RansomwareShieldService;
  private notificationService: NotificationService;
  private exclusionManager: ExclusionManagerService;
  private scanScheduler: ScanSchedulerService;
  private threatIntelManager: ThreatIntelManagerService;
  private adapter: DesktopSecurityAdapter;
  private downloadsDir: string;
  private tempDir: string;
  private autoStartRealtime: boolean;
  private getWebContentsFn?: () => { send: (channel: string, ...args: any[]) => void } | null | undefined;

  constructor(options?: IpcHandlerOptions) {
    this.scanner = new ScannerService();
    this.exclusionManager = new ExclusionManagerService(
      options?.configDir ? { configDir: options.configDir } : undefined
    );
    this.quarantine = new QuarantineService(options?.vaultDir, this.exclusionManager);
    this.realtimeMonitor = new RealtimeMonitorService(
      undefined,
      this.quarantine,
      this.exclusionManager
    );
    this.processAuditor = new ProcessAuditorService();
    this.processMonitor = new ProcessMonitorService({
      processAuditor: this.processAuditor,
      behaviorEngine: this.processAuditor.getBehaviorEngine()
    });
    this.persistenceAuditor = new PersistenceAuditorService(this.quarantine);
    this.persistenceMonitor = new PersistenceMonitorService(this.persistenceAuditor);
    this.quickScanner = new QuickScanService({
      scanner: this.scanner,
      processAuditor: this.processAuditor,
      persistenceAuditor: this.persistenceAuditor
    });
    this.removableMedia = new RemovableMediaService();
    this.networkMonitor = new NetworkMonitorService();
    this.storage = new SecureStorageService(options?.configDir);
    this.shadowVault = new ShadowVaultService(
      options?.vaultDir ? { customVaultDir: path.join(options.vaultDir, 'shadow-vault') } : undefined
    );
    this.ransomwareShield = new RansomwareShieldService(
      undefined,
      this.shadowVault,
      this.processAuditor,
      this.processAuditor.getBehaviorEngine()
    );
    this.notificationService = new NotificationService({
      storageDir: options?.configDir
    });
    this.scanScheduler = new ScanSchedulerService({
      configDir: options?.configDir,
      storage: this.storage,
      scanner: this.scanner,
      quickScanner: this.quickScanner,
      quarantineService: this.quarantine,
      notificationService: this.notificationService,
      processAuditor: this.processAuditor,
      persistenceAuditor: this.persistenceAuditor
    });
    this.threatIntelManager = new ThreatIntelManagerService({
      dataDir: options?.configDir,
      scannerService: this.scanner
    });
    this.adapter = new DesktopSecurityAdapter();

    this.downloadsDir = options?.downloadsDir || path.join(os.homedir(), 'Downloads');
    this.tempDir = options?.tempDir || os.tmpdir();
    this.autoStartRealtime = options?.autoStartRealtime ?? false;

    // Wire ThreatIntelManager events to security log, notifications, and renderer broadcast (Phase O)
    this.threatIntelManager.on('updateApplied', (res: UpdateApplyResult) => {
      const ver = res.version || res.newVersion || 'unknown';
      const seq = res.versionSequence ?? res.newVersionSequence ?? 0;
      this.storage.recordSecurityEvent(
        'CONFIG_UPDATED',
        'INFO',
        `Threat database updated to ${ver} (seq: ${seq})`,
        { version: ver, versionSequence: seq, badCount: res.badCount ?? 0 }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.UPDATE_EVENT, { eventType: 'APPLIED', result: res });
      }
    });

    this.threatIntelManager.on('updateRollback', (res: UpdateRollbackResult) => {
      const restVer = res.restoredVersion || 'seed';
      const restSeq = res.restoredVersionSequence ?? 0;
      this.storage.recordSecurityEvent(
        'CONFIG_UPDATED',
        'WARN',
        `Threat database rolled back to ${restVer} (seq: ${restSeq})`,
        { restoredVersion: restVer, restoredVersionSequence: restSeq }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.UPDATE_EVENT, { eventType: 'ROLLBACK', result: res });
      }
    });

    this.threatIntelManager.on('updateFailed', (err: any) => {
      this.storage.recordSecurityEvent(
        'ENGINE_FAILURE',
        'ERROR',
        `Threat database update failed: ${err?.reason || err?.message || 'Unknown error'}`,
        { code: String(err?.code || 'UNKNOWN'), reason: String(err?.reason || err?.message || 'Unknown error') }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.UPDATE_EVENT, { eventType: 'FAILED', error: err });
      }
    });

    // Wire NotificationService broadcasts to renderer
    this.notificationService.on('notification', (notif: DesktopNotification) => {
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.NOTIFICATION_EVENT, notif);
      }
    });

    // Wire RealtimeMonitor events to NotificationService
    this.realtimeMonitor.on('threatDetected', (threat: DetectedThreat) => {
      this.notificationService.notifySecurityThreat(threat, { source: 'Realtime Protection' });
    });

    // Wire RansomwareShield events to security log, NotificationService, and renderer broadcast
    this.ransomwareShield.on('ransomwareDetected', (incident: RansomwareIncident) => {
      this.storage.recordSecurityEvent(
        'THREAT_DETECTED',
        'CRITICAL',
        `Ransomware incident detected: ${incident.reason}`,
        { incidentId: incident.incidentId, threatType: incident.threatType, riskScore: incident.riskScore }
      );
      this.notificationService.notifyRansomwareIncident(incident);
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.RANSOMWARE_EVENT, incident);
      }
    });

    // Wire RemovableMedia events to security log, notifications, and renderer broadcast (Phase M)
    this.removableMedia.on('driveAttached', (drive: RemovableDrive) => {
      this.storage.recordSecurityEvent(
        'CONFIG_UPDATED',
        'INFO',
        `Removable drive attached: ${drive.label} (${drive.mountPoint})`,
        { mountPoint: drive.mountPoint, label: drive.label, totalBytes: drive.totalBytes }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.MEDIA_DRIVE_ATTACHED, drive);
      }
    });

    this.removableMedia.on('scanCompleted', (res: RemovableDriveScanResult) => {
      if (res.threatsFound > 0) {
        this.storage.recordSecurityEvent(
          'THREAT_DETECTED',
          res.verdict === 'BLOCK' ? 'CRITICAL' : 'WARN',
          `USB root threat detected on ${res.mountPoint}: ${res.threatsFound} threat(s) found`,
          {
            mountPoint: res.mountPoint,
            threatsFound: res.threatsFound,
            riskScore: res.riskScore,
            verdict: res.verdict
          }
        );
        for (const threat of res.threats) {
          this.notificationService.notifySecurityThreat(threat, {
            source: `Removable Media (${path.basename(res.mountPoint)})`
          });
        }
      }
    });

    // Wire PersistenceMonitor events to security log, notifications, and renderer broadcast (Phase L)
    this.persistenceMonitor.on('persistenceChanged', (change: PersistenceChangeEvent) => {
      this.storage.recordSecurityEvent(
        'CONFIG_UPDATED',
        change.item.isSuspicious ? 'WARN' : 'INFO',
        `Startup persistence entry ${change.changeType.toLowerCase()}: ${change.item.name}`,
        { itemId: change.item.id, name: change.item.name, locationType: change.item.locationType, isSuspicious: change.item.isSuspicious }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.PERSISTENCE_CHANGED, change);
      }
    });

    this.persistenceMonitor.on('threatDetected', (item: PersistenceItem) => {
      const detectedThreat: DetectedThreat = {
        id: item.id,
        filePath: item.targetPath,
        fileName: item.name,
        fileSize: 0,
        sha256: item.analysisResult?.sha256 || '0'.repeat(64),
        riskScore: item.riskScore || 80,
        severity: item.severity || 'dangerous',
        verdict: (item.engineVerdict as any) || 'BLOCK',
        threatName: item.threatName || 'Startup.Persistence.Threat',
        detectedAt: Date.now(),
        evidenceFactors: item.evidenceFactors || ['Startup Persistence Threat'],
        quarantined: false
      };
      this.notificationService.notifySecurityThreat(detectedThreat, {
        source: 'Startup & Persistence Protection'
      });
    });

    // Wire ScanSchedulerService events to renderer broadcasts & security log (Phase N)
    this.scanScheduler.on('scheduleUpdated', (state: ScanSchedulerState) => {
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.SCHEDULE_EVENT, { eventType: 'UPDATED', state });
      }
    });

    this.scanScheduler.on('scheduledScanStarted', (info: any) => {
      this.storage.recordSecurityEvent(
        'SCHEDULED_SCAN_TRIGGERED',
        'INFO',
        `Scheduled scan started (${info.scanType}) by trigger: ${info.trigger}`,
        { scanId: info.scanId, trigger: info.trigger, scanType: info.scanType }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.SCHEDULE_EVENT, { eventType: 'STARTED', ...info });
      }
    });

    this.scanScheduler.on('scheduledScanCompleted', (info: any) => {
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.SCHEDULE_EVENT, { eventType: 'COMPLETED', ...info });
      }
    });

    this.scanScheduler.on('scheduledScanDeferred', (info: any) => {
      this.storage.recordSecurityEvent(
        'SCHEDULED_SCAN_DEFERRED',
        'INFO',
        `Scheduled scan deferred: ${info.deferredReason || info.finalStatus}`,
        { scanId: info.scanId, status: info.finalStatus, trigger: info.trigger }
      );
      const wc = this.getWebContentsFn?.();
      if (wc) {
        wc.send(IPC_CHANNELS.SCHEDULE_EVENT, { eventType: 'DEFERRED', ...info });
      }
    });

    // Wire ScannerService lifecycle events into bounded local security log (Step 12)
    this.scanner.on('started', (info: { scanId: string; scanType: string; targets: string[] }) => {
      this.storage.recordSecurityEvent(
        'SCAN_STARTED',
        'INFO',
        `Scan started (${info.scanType})`,
        { scanId: info.scanId, scanType: info.scanType, targetCount: info.targets?.length || 0 }
      );
    });

    this.scanner.on('threatFound', (threat: DetectedThreat) => {
      this.storage.recordSecurityEvent(
        'THREAT_DETECTED',
        threat.verdict === 'BLOCK' ? 'CRITICAL' : 'WARN',
        `Threat detected: ${threat.threatName} (verdict=${threat.verdict}, score=${threat.riskScore})`,
        {
          threatId: threat.id,
          threatName: threat.threatName,
          verdict: threat.verdict,
          riskScore: threat.riskScore,
          sha256: threat.sha256
        }
      );
    });

    this.scanner.on('completed', (res) => {
      if (res.errors && res.errors.length > 0) {
        this.storage.recordSecurityEvent(
          'SCAN_FAILED',
          'WARN',
          `Scan completed with ${res.errors.length} error(s) (${res.scanType})`,
          {
            scanId: res.scanId,
            scanType: res.scanType,
            filesScanned: res.totalFilesScanned,
            threatsFound: res.threats.length,
            errorCount: res.errors.length,
            overallVerdict: res.overallVerdict
          }
        );
      } else {
        this.storage.recordSecurityEvent(
          'SCAN_COMPLETED',
          'INFO',
          `Scan completed (${res.scanType}): ${res.totalFilesScanned} file(s) scanned`,
          {
            scanId: res.scanId,
            scanType: res.scanType,
            filesScanned: res.totalFilesScanned,
            threatsFound: res.threats.length,
            overallVerdict: res.overallVerdict
          }
        );
      }
    });

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

  public getStorage(): SecureStorageService {
    return this.storage;
  }

  public getNotificationService(): NotificationService {
    return this.notificationService;
  }

  public getSecurityEvents() {
    return this.storage.getSecurityEvents();
  }


  /**
   * Applies DesktopSettings across ScannerService and RealtimeMonitorService at runtime (GAP-15).
   */
  public applySettings(settings: DesktopSettings, updateWatchers = true): void {
    this.scanner.applySettings(settings);

    this.realtimeMonitor.setEntropyDetectionEnabled(settings.entropyDetectionEnabled);
    this.realtimeMonitor.setMaxFileSizeBytes(settings.scanLargeFilesLimitMb * 1024 * 1024);
    this.realtimeMonitor.setExcludedPaths(settings.excludedPaths || []);
    this.realtimeMonitor.setAutoQuarantineCritical(Boolean(settings.autoQuarantineCritical));

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
    this.storage.recordSecurityEvent(
      'THREAT_DETECTED',
      threat.verdict === 'BLOCK' ? 'CRITICAL' : 'WARN',
      `Real-time threat detected: ${threat.threatName}`,
      {
        threatId: threat.id,
        threatName: threat.threatName,
        verdict: threat.verdict,
        riskScore: threat.riskScore,
        sha256: threat.sha256
      }
    );

    const settings = this.storage.getSettings();
    const shouldAutoQuarantine =
      settings.autoQuarantineCritical === true &&
      threat.verdict === 'BLOCK' &&
      (threat.severity === 'critical' || threat.severity === 'dangerous');

    let eventPayload: RealtimeThreatEvent;

    if (threat.quarantined) {
      let qItem: any = null;
      if ((threat as any).quarantineId) {
        qItem = this.quarantine.getQuarantinedItem((threat as any).quarantineId);
      }
      eventPayload = {
        threat,
        actionTaken: 'AUTO_QUARANTINED',
        quarantineItem: qItem,
        timestamp: Date.now()
      };
    } else if (shouldAutoQuarantine) {
      try {
        const quarantineItem = await this.quarantine.isolateFile(threat);
        this.storage.recordSecurityEvent(
          'QUARANTINE_ISOLATED',
          'INFO',
          `Auto-quarantined critical threat (${quarantineItem.quarantineId})`,
          {
            quarantineId: quarantineItem.quarantineId,
            threatName: quarantineItem.threatName,
            sha256: quarantineItem.sha256
          }
        );
        eventPayload = {
          threat: { ...threat, quarantined: true },
          actionTaken: 'AUTO_QUARANTINED',
          quarantineItem,
          timestamp: Date.now()
        };
      } catch (err: any) {
        this.storage.recordSecurityEvent(
          'ENGINE_FAILURE',
          'ERROR',
          `Auto-quarantine failed: ${err?.message || 'Unknown error'}`,
          { threatId: threat.id }
        );
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
      this.storage.recordSecurityEvent(
        'SECURITY_VIOLATION',
        'WARN',
        'Blocked attempt to quarantine symbolic link',
        { action: 'quarantine:isolate' }
      );
      throw new Error('SECURITY_VIOLATION: Quarantining symbolic links is forbidden to prevent target hijacking.');
    }

    if (IpcValidator.isProtectedSystemPath(validatedPath)) {
      this.storage.recordSecurityEvent(
        'SECURITY_VIOLATION',
        'WARN',
        'Blocked attempt to quarantine protected OS system file',
        { action: 'quarantine:isolate' }
      );
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
    const item = await this.quarantine.isolateFile(threat);
    this.storage.recordSecurityEvent(
      'QUARANTINE_ISOLATED',
      'INFO',
      `Quarantined threat ${item.threatName} (${item.quarantineId})`,
      {
        quarantineId: item.quarantineId,
        threatName: item.threatName,
        sha256: item.sha256,
        riskScore: item.riskScore
      }
    );
    return item;
  }

  public async handleRestoreQuarantine(quarantineId: string, customDir?: string) {
    const validId = IpcValidator.validateId(quarantineId, 'quarantine-');
    const validDest = customDir ? IpcValidator.validatePath(customDir) : undefined;
    const restoredPath = await this.quarantine.restoreItem(validId, validDest);
    this.storage.recordSecurityEvent(
      'QUARANTINE_RESTORED',
      'INFO',
      `Restored quarantined item ${validId}`,
      { quarantineId: validId }
    );
    return restoredPath;
  }

  public async handleDeleteQuarantine(quarantineId: string) {
    const validId = IpcValidator.validateId(quarantineId, 'quarantine-');
    await this.quarantine.permanentDelete(validId);
    this.storage.recordSecurityEvent(
      'QUARANTINE_DELETED',
      'INFO',
      `Permanently deleted quarantined item ${validId}`,
      { quarantineId: validId }
    );
  }

  public handleGetProtectionStatus(): DesktopProtectionStatus {
    const mem = process.memoryUsage();
    const tiStatus = this.threatIntelManager.getStatus();
    return {
      realtimeShieldActive: this.realtimeMonitor.isActive(),
      monitoredPaths: this.realtimeMonitor.getMonitoredPaths(),
      threatDatabaseVersion: tiStatus.currentVersion || tiStatus.installedVersion,
      threatDatabaseTimestamp: tiStatus.lastUpdatedAt ?? tiStatus.lastUpdated,
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
    this.storage.recordSecurityEvent(
      'CONFIG_UPDATED',
      'INFO',
      'Desktop security configuration updated',
      {
        realtimeShieldEnabled: updated.realtimeShieldEnabled,
        entropyDetectionEnabled: updated.entropyDetectionEnabled,
        scanLargeFilesLimitMb: updated.scanLargeFilesLimitMb
      }
    );
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

  public async handleContainProcess(pid: number, options?: ContainProcessOptions) {
    const validPid = IpcValidator.validateNumber(pid, 0, 9999999);
    const result = await this.processAuditor.containProcess(validPid, options);
    this.storage.recordSecurityEvent(
      'PROCESS_CONTAINED',
      result.success ? 'INFO' : 'WARN',
      `Process containment evaluated for PID ${validPid}: ${result.action} (${result.reason})`,
      { pid: validPid, action: result.action, success: result.success, authorizationId: options?.authorizationId || 'none' }
    );
    return result;
  }

  public handleGetProcessMonitorHealth(): ProcessMonitorHealth {
    return this.processMonitor.getHealth();
  }

  public async handleAuditPersistence(): Promise<PersistenceItem[]> {
    const res = await this.persistenceAuditor.auditStartupLocations();
    return res.items;
  }

  public async handleAuditPersistenceDetailed(): Promise<PersistenceAuditResult> {
    return this.persistenceAuditor.auditStartupLocations();
  }

  public async handleRemediatePersistence(
    itemId: unknown,
    options?: { frictionToken?: string }
  ): Promise<PersistenceRemediationResult> {
    if (!itemId || typeof itemId !== 'string') {
      throw new Error('INVALID_PERSISTENCE_ID: Persistence itemId must be a non-empty string.');
    }

    const result = await this.persistenceAuditor.remediateItem(itemId, options);
    this.storage.recordSecurityEvent(
      'QUARANTINE_ISOLATED',
      result.success ? 'INFO' : 'WARN',
      `Startup persistence remediation evaluated for '${itemId}': ${result.message}`,
      { itemId, success: result.success, locationType: result.locationType }
    );
    return result;
  }

  public async handleGetRemovableMedia() {
    return this.removableMedia.getMountedDrives();
  }

  public async handleGetNetworkPosture() {
    return this.networkMonitor.getNetworkPosture();
  }

  public handlePrivacyShred(): void {
    this.quarantine.purgeAllQuarantine();
    this.shadowVault.purgeAll();
    this.storage.purgeAllData();
    this.applySettings(this.storage.getSettings(), false);
  }

  public getRansomwareShield(): RansomwareShieldService {
    return this.ransomwareShield;
  }

  public getShadowVault(): ShadowVaultService {
    return this.shadowVault;
  }

  public async handleGetRansomwareStatus(): Promise<RansomwareShieldStatus> {
    return this.ransomwareShield.getStatus();
  }

  public async handleGetProtectedFolders(): Promise<string[]> {
    return this.ransomwareShield.getProtectedFolders();
  }

  public async handleAddProtectedFolder(folderPath: string): Promise<string> {
    const validated = IpcValidator.validatePath(folderPath);
    return this.ransomwareShield.addProtectedFolder(validated);
  }

  public async handleRemoveProtectedFolder(folderPath: string): Promise<boolean> {
    const validated = IpcValidator.validatePath(folderPath);
    return this.ransomwareShield.removeProtectedFolder(validated);
  }

  public async handleGetTrustedApps(): Promise<TrustedApplication[]> {
    return this.ransomwareShield.getTrustedApplications();
  }

  public async handleAddTrustedApp(app: {
    path?: string;
    canonicalPath?: string;
    sha256?: string;
    signer?: string;
    name?: string;
  }): Promise<TrustedApplication> {
    return this.ransomwareShield.registerTrustedApplication(app);
  }

  public async handleRemoveTrustedApp(executablePath: string): Promise<boolean> {
    const validated = IpcValidator.validatePath(executablePath);
    return this.ransomwareShield.removeTrustedApplication(validated);
  }

  public async handleGetRansomwareIncidents(): Promise<RansomwareIncident[]> {
    return this.ransomwareShield.getIncidents();
  }

  public async handleRollbackIncident(incidentId: string): Promise<IncidentRollbackResult> {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('INVALID_ARGUMENT: incidentId must be a non-empty string.');
    }
    return this.ransomwareShield.rollbackIncident(incidentId);
  }

  public async handleResetCanaries(): Promise<CanaryFileRecord[]> {
    return this.ransomwareShield.deployCanaries();
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

    ipcMain.handle(IPC_CHANNELS.PROCESS_CONTAIN, async (event, pid: number, options?: any) => {
      verifyOrigin(event);
      return this.handleContainProcess(pid, options);
    });

    ipcMain.handle(IPC_CHANNELS.PROCESS_MONITOR_HEALTH, async (event) => {
      verifyOrigin(event);
      return this.handleGetProcessMonitorHealth();
    });

    ipcMain.handle(IPC_CHANNELS.PERSISTENCE_AUDIT, async (event) => {
      verifyOrigin(event);
      return this.handleAuditPersistence();
    });

    ipcMain.handle(IPC_CHANNELS.PERSISTENCE_REMEDIATE, async (event, itemId: unknown, options?: any) => {
      verifyOrigin(event);
      return this.handleRemediatePersistence(itemId, options);
    });

    ipcMain.handle(IPC_CHANNELS.REMOVABLE_MEDIA_GET, async (event) => {
      verifyOrigin(event);
      return this.handleGetRemovableMedia();
    });

    ipcMain.handle(IPC_CHANNELS.REMOVABLE_MEDIA_SCAN, async (event, mountPath: unknown) => {
      verifyOrigin(event);
      return this.handleScanRemovableMedia(mountPath);
    });

    ipcMain.handle(IPC_CHANNELS.NETWORK_POSTURE_GET, async (event) => {
      verifyOrigin(event);
      return this.handleGetNetworkPosture();
    });

    ipcMain.handle(IPC_CHANNELS.PRIVACY_SHRED, (event) => {
      verifyOrigin(event);
      return this.handlePrivacyShred();
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_STATUS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetRansomwareStatus();
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetProtectedFolders();
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_ADD, async (event, folderPath: string) => {
      verifyOrigin(event);
      return this.handleAddProtectedFolder(folderPath);
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_REMOVE, async (event, folderPath: string) => {
      verifyOrigin(event);
      return this.handleRemoveProtectedFolder(folderPath);
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetTrustedApps();
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_ADD, async (event, app: any) => {
      verifyOrigin(event);
      return this.handleAddTrustedApp(app);
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_REMOVE, async (event, executablePath: string) => {
      verifyOrigin(event);
      return this.handleRemoveTrustedApp(executablePath);
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_INCIDENTS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetRansomwareIncidents();
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_INCIDENT_ROLLBACK, async (event, incidentId: string) => {
      verifyOrigin(event);
      return this.handleRollbackIncident(incidentId);
    });

    ipcMain.handle(IPC_CHANNELS.RANSOMWARE_CANARY_RESET, async (event) => {
      verifyOrigin(event);
      return this.handleResetCanaries();
    });

    // Phase H: Notification System & Inbox Handlers
    ipcMain.handle(IPC_CHANNELS.NOTIFICATIONS_GET, (event, limit?: unknown) => {
      verifyOrigin(event);
      return this.handleGetNotifications(limit);
    });

    ipcMain.handle(IPC_CHANNELS.NOTIFICATIONS_INBOX_STATE_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetNotificationInboxState();
    });

    ipcMain.handle(IPC_CHANNELS.NOTIFICATIONS_MARK_READ, (event, notificationId: unknown) => {
      verifyOrigin(event);
      return this.handleMarkNotificationRead(notificationId);
    });

    ipcMain.handle(IPC_CHANNELS.NOTIFICATIONS_MARK_ALL_READ, (event) => {
      verifyOrigin(event);
      return this.handleMarkAllNotificationsRead();
    });

    ipcMain.handle(IPC_CHANNELS.NOTIFICATIONS_CLEAR_ALL, (event) => {
      verifyOrigin(event);
      return this.handleClearAllNotifications();
    });

    // Phase I: False-Positive Exclusion Handlers
    ipcMain.handle(IPC_CHANNELS.EXCLUSIONS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetExclusions();
    });

    ipcMain.handle(IPC_CHANNELS.EXCLUSION_ADD, (event, input: unknown, frictionToken?: unknown) => {
      verifyOrigin(event);
      return this.handleAddExclusion(input, frictionToken);
    });

    ipcMain.handle(IPC_CHANNELS.EXCLUSION_REMOVE, (event, id: unknown) => {
      verifyOrigin(event);
      return this.handleRemoveExclusion(id);
    });

    ipcMain.handle(IPC_CHANNELS.EXCLUSION_TOGGLE, (event, id: unknown, enabled: unknown) => {
      verifyOrigin(event);
      return this.handleToggleExclusion(id, enabled);
    });

    ipcMain.handle(IPC_CHANNELS.EXCLUSIONS_CLEAR_ALL, (event) => {
      verifyOrigin(event);
      return this.handleClearAllExclusions();
    });

    // Phase J: Web & Download MOTW Handlers
    ipcMain.handle(IPC_CHANNELS.MOTW_ANALYZE_FILE, (event, filePath: unknown) => {
      verifyOrigin(event);
      return this.handleMotwAnalyzeFile(filePath);
    });

    ipcMain.handle(IPC_CHANNELS.WEB_PROTECTION_STATUS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetWebProtectionStatus();
    });

    // Phase K: Practical Email Threat Handlers
    ipcMain.handle(IPC_CHANNELS.EMAIL_ANALYZE_FILE, async (event, filePath: unknown) => {
      verifyOrigin(event);
      return this.handleEmailAnalyzeFile(filePath);
    });

    // Phase N: Scheduled & On-Demand Scan Handlers
    ipcMain.handle(IPC_CHANNELS.SCHEDULE_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetSchedule();
    });

    ipcMain.handle(IPC_CHANNELS.SCHEDULE_SAVE, (event, config: unknown, options?: any) => {
      verifyOrigin(event);
      return this.handleSaveSchedule(config, options);
    });

    ipcMain.handle(IPC_CHANNELS.SCHEDULE_RUN_NOW, async (event, options?: any) => {
      verifyOrigin(event);
      return this.handleRunScheduledScanNow(options);
    });

    ipcMain.handle(IPC_CHANNELS.SCHEDULE_HISTORY_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetScheduleHistory();
    });

    // Phase O: Signed Threat Update Handlers
    ipcMain.handle(IPC_CHANNELS.UPDATE_APPLY_BUNDLE, async (event, input: unknown) => {
      verifyOrigin(event);
      return this.handleApplyUpdateBundle(input);
    });

    ipcMain.handle(IPC_CHANNELS.UPDATE_ROLLBACK_LKG, async (event) => {
      verifyOrigin(event);
      return this.handleRollbackUpdateLkg();
    });

    ipcMain.handle(IPC_CHANNELS.UPDATE_STATUS_GET, (event) => {
      verifyOrigin(event);
      return this.handleGetThreatIntelStatus();
    });
  }

  // ============================================================
  // PHASE H NOTIFICATION HANDLERS
  // ============================================================

  public handleGetNotifications(limit?: unknown): DesktopNotification[] {
    const validLimit = IpcValidator.validateNotificationLimit(limit, 100);
    return this.notificationService.getNotifications(validLimit);
  }

  public handleGetNotificationInboxState(): NotificationInboxState {
    return this.notificationService.getInboxState();
  }

  public handleMarkNotificationRead(notificationId: unknown): boolean {
    const validId = IpcValidator.validateNotificationId(notificationId);
    return this.notificationService.markRead(validId);
  }

  public handleMarkAllNotificationsRead(): number {
    return this.notificationService.markAllRead();
  }

  public handleClearAllNotifications(): void {
    this.notificationService.clearAll();
  }

  // ============================================================
  // PHASE I EXCLUSION HANDLERS
  // ============================================================

  public handleGetExclusions(): ExclusionItem[] {
    return this.exclusionManager.getExclusions();
  }

  public handleAddExclusion(input: unknown, frictionToken?: unknown): ExclusionItem {
    const validatedInput = IpcValidator.validateExclusionInput(input);
    const validatedToken =
      frictionToken !== undefined ? IpcValidator.validateFrictionToken(frictionToken) : undefined;
    const item = this.exclusionManager.addExclusion(validatedInput, validatedToken);
    this.storage.recordSecurityEvent(
      'EXCLUSION_ADDED',
      'INFO',
      `Exclusion added: ${item.type} = ${item.value}`,
      { exclusionId: item.id, type: item.type, value: item.value }
    );
    return item;
  }

  public handleRemoveExclusion(id: unknown): boolean {
    const validId = IpcValidator.validateExclusionId(id);
    const removed = this.exclusionManager.removeExclusion(validId);
    if (removed) {
      this.storage.recordSecurityEvent(
        'EXCLUSION_REMOVED',
        'INFO',
        `Exclusion removed: ${validId}`,
        { exclusionId: validId }
      );
    }
    return removed;
  }

  public handleToggleExclusion(id: unknown, enabled: unknown): boolean {
    const validId = IpcValidator.validateExclusionId(id);
    const validEnabled = Boolean(enabled);
    const updated = this.exclusionManager.toggleExclusion(validId, validEnabled);
    if (updated) {
      this.storage.recordSecurityEvent(
        'EXCLUSION_TOGGLED',
        'INFO',
        `Exclusion ${validId} enabled state set to ${validEnabled}`,
        { exclusionId: validId, enabled: validEnabled }
      );
    }
    return updated !== null;
  }

  public handleClearAllExclusions(): number {
    const clearedCount = this.exclusionManager.clearAll();
    this.storage.recordSecurityEvent(
      'EXCLUSION_CLEARED',
      'INFO',
      `Cleared all exclusions (${clearedCount} items)`,
      { count: clearedCount }
    );
    return clearedCount;
  }

  public getExclusionManager(): ExclusionManagerService {
    return this.exclusionManager;
  }

  // ============================================================
  // PHASE J WEB & MOTW HANDLERS
  // ============================================================

  public handleMotwAnalyzeFile(filePath: unknown): MotwAnalysisResult {
    const validPath = IpcValidator.validatePath(filePath);
    return MotwAnalyzer.analyzeFile(validPath);
  }

  public handleGetWebProtectionStatus(): {
    enabled: boolean;
    motwInspectionEnabled: boolean;
    threatIntelRulesLoaded: number;
    platform: string;
  } {
    return {
      enabled: true,
      motwInspectionEnabled: true,
      threatIntelRulesLoaded: ThreatIntel.getSharedInstance().snapshot().badCount,
      platform: process.platform
    };
  }

  // ============================================================
  // PHASE K EMAIL THREAT HANDLERS
  // ============================================================

  public async handleEmailAnalyzeFile(filePath: unknown): Promise<EmailAnalysisResult> {
    const validPath = IpcValidator.validatePath(filePath);
    return EmailMimeParser.analyzeEmailFile(validPath);
  }

  // ============================================================
  // PHASE M REMOVABLE MEDIA HANDLERS
  // ============================================================

  public async handleScanRemovableMedia(mountPath: unknown): Promise<RemovableDriveScanResult> {
    const validPath = IpcValidator.validatePath(mountPath);
    return this.removableMedia.scanRemovableDriveRoot(validPath);
  }

  public getRemovableMediaService(): RemovableMediaService {
    return this.removableMedia;
  }

  // ============================================================
  // PHASE N SCHEDULED & ON-DEMAND SCAN HANDLERS
  // ============================================================

  public handleGetSchedule(): ScanSchedulerState {
    return this.scanScheduler.getState();
  }

  public handleSaveSchedule(
    rawConfig: unknown,
    options?: { frictionToken?: string }
  ): { success: boolean; config: ScanScheduleConfig; state: ScanSchedulerState } {
    const validated = IpcValidator.validateScheduleConfig(rawConfig);
    if (options?.frictionToken) {
      IpcValidator.validateFrictionToken(options.frictionToken);
    }
    const updated = this.scanScheduler.saveSchedule(validated);
    this.storage.recordSecurityEvent(
      'SCHEDULE_CONFIG_UPDATED',
      'INFO',
      `Scan schedule updated: ${updated.frequency} at ${updated.timeOfDay} (${updated.scanType} scan, enabled=${updated.enabled})`,
      { enabled: updated.enabled, frequency: updated.frequency, timeOfDay: updated.timeOfDay, scanType: updated.scanType }
    );
    return {
      success: true,
      config: updated,
      state: this.scanScheduler.getState()
    };
  }

  public async handleRunScheduledScanNow(options?: { frictionToken?: string }): Promise<ScanResult> {
    if (options?.frictionToken) {
      IpcValidator.validateFrictionToken(options.frictionToken);
    }
    return this.scanScheduler.runNow();
  }

  public handleGetScheduleHistory(): ScanHistoryRecord[] {
    return this.scanScheduler.getHistory();
  }

  public getScanScheduler(): ScanSchedulerService {
    return this.scanScheduler;
  }

  // ============================================================
  // PHASE O THREAT INTEL & SIGNED UPDATE HANDLERS
  // ============================================================

  public async handleApplyUpdateBundle(input: unknown): Promise<UpdateApplyResult> {
    const validated = IpcValidator.validateApplyBundlePayload(input);
    return this.threatIntelManager.applyUpdate(validated);
  }

  public async handleRollbackUpdateLkg(): Promise<UpdateRollbackResult> {
    return this.threatIntelManager.rollbackToLkg();
  }

  public handleGetThreatIntelStatus(): ThreatIntelStatus {
    return this.threatIntelManager.getStatus();
  }

  public getThreatIntelManager(): ThreatIntelManagerService {
    return this.threatIntelManager;
  }
}

