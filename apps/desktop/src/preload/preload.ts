import { IPC_CHANNELS } from '../ipc/ipc-channels';
import {
  ScanResult,
  QuarantineItem,
  DesktopProtectionStatus,
  DesktopSettings,
  DetectedThreat,
  DesktopAssistantExplanation,
  ProcessInfo,
  ProcessContainmentResult,
  PersistenceItem,
  PersistenceRemediationResult,
  PersistenceChangeEvent,
  RemovableDrive,
  ScanProgress,
  RealtimeThreatEvent,
  ContainProcessOptions,
  ProcessMonitorHealth,
  DesktopNotification,
  NotificationInboxState,
  ExclusionItem,
  CreateExclusionInput,
  MotwAnalysisResult,
  EmailAnalysisResult,
  RemovableDriveScanResult,
  ScanScheduleConfig,
  ScanSchedulerState,
  ScanHistoryRecord,
  UpdateApplyResult,
  UpdateRollbackResult,
  ThreatIntelStatus,
  PpdbBundle,
  SystemHealthReport,
  WatchdogStatus,
  AuditVerificationResult,
  TamperStatus,
  AuditLogEntry,
  AuditQueryFilter,
  RansomwareShieldStatus,
  RansomwareIncident,
  TrustedApplication,
  IncidentRollbackResult,
  CanaryFileRecord
} from '../types/desktop.types';
import { NetworkPostureReport } from '../services/network-monitor.service';

export interface DesktopSecurityApi {
  startQuickScan: () => Promise<ScanResult>;
  startFullScan: (rootPath?: string) => Promise<ScanResult>;
  startCustomScan: (targets: string[]) => Promise<ScanResult>;
  cancelScan: () => Promise<void>;
  pauseScan: () => Promise<void>;
  resumeScan: () => Promise<void>;
  onScanProgress: (callback: (progress: ScanProgress) => void) => () => void;
  onRealtimeThreat: (callback: (event: RealtimeThreatEvent) => void) => () => void;
  onTriggerQuickScan: (callback: () => void) => () => void;

  listQuarantine: () => Promise<QuarantineItem[]>;
  isolateFile: (filePath: string) => Promise<QuarantineItem>;
  restoreQuarantine: (quarantineId: string, customDir?: string) => Promise<string>;
  deleteQuarantine: (quarantineId: string) => Promise<void>;

  getProtectionStatus: () => Promise<DesktopProtectionStatus>;
  getSettings: () => Promise<DesktopSettings>;
  saveSettings: (settings: Partial<DesktopSettings>) => Promise<void>;

  explainThreat: (threat: DetectedThreat, level: 'grade6' | 'grade8') => Promise<DesktopAssistantExplanation>;

  auditProcesses: () => Promise<ProcessInfo[]>;
  containProcess: (pid: number, options?: ContainProcessOptions) => Promise<ProcessContainmentResult>;
  getProcessMonitorHealth: () => Promise<ProcessMonitorHealth>;
  auditPersistence: () => Promise<PersistenceItem[]>;
  remediatePersistence: (itemId: string, frictionToken?: string) => Promise<PersistenceRemediationResult>;
  onPersistenceChanged: (callback: (event: PersistenceChangeEvent) => void) => () => void;
  getRemovableMedia: () => Promise<RemovableDrive[]>;
  scanRemovableMedia: (mountPath: string) => Promise<RemovableDriveScanResult>;
  onMediaDriveAttached: (callback: (drive: RemovableDrive) => void) => () => void;
  getNetworkPosture: () => Promise<NetworkPostureReport>;

  privacyShred: () => Promise<void>;

  // Phase H: Notification API
  getNotifications: (limit?: number) => Promise<DesktopNotification[]>;
  getNotificationInboxState: () => Promise<NotificationInboxState>;
  markNotificationRead: (notificationId: string) => Promise<boolean>;
  markAllNotificationsRead: () => Promise<number>;
  clearAllNotifications: () => Promise<void>;
  onNotificationEvent: (callback: (notification: DesktopNotification) => void) => () => void;

  // Phase I: Exclusion API
  getExclusions: () => Promise<ExclusionItem[]>;
  addExclusion: (input: CreateExclusionInput, frictionToken?: string) => Promise<ExclusionItem>;
  removeExclusion: (id: string) => Promise<boolean>;
  toggleExclusion: (id: string, enabled: boolean) => Promise<boolean>;
  clearAllExclusions: () => Promise<number>;

  // Phase J: Web & Download MOTW API
  analyzeMotw: (filePath: string) => Promise<MotwAnalysisResult>;
  getWebProtectionStatus: () => Promise<{
    enabled: boolean;
    motwInspectionEnabled: boolean;
    threatIntelRulesLoaded: number;
    platform: string;
  }>;

  // Phase K: Practical Email (.eml / .msg) Threat API
  analyzeEmail: (filePath: string) => Promise<EmailAnalysisResult>;

  // Phase N: Scheduled & On-Demand Scanning API
  getScanSchedule: () => Promise<ScanSchedulerState>;
  saveScanSchedule: (
    config: ScanScheduleConfig,
    options?: { frictionToken?: string }
  ) => Promise<{ success: boolean; config: ScanScheduleConfig; state: ScanSchedulerState }>;
  runScheduledScanNow: (options?: { frictionToken?: string }) => Promise<ScanResult>;
  getScanHistory: () => Promise<ScanHistoryRecord[]>;
  onScheduleEvent: (callback: (event: any) => void) => () => void;

  // Phase O: Threat Intelligence & Signed Update API
  applyUpdateBundle: (bundleOrPath: string | PpdbBundle) => Promise<UpdateApplyResult>;
  rollbackUpdateLkg: () => Promise<UpdateRollbackResult>;
  getThreatIntelStatus: () => Promise<ThreatIntelStatus>;
  onUpdateEvent: (callback: (event: any) => void) => () => void;

  // Phase G: Ransomware Shield & Shadow Vault API
  getRansomwareStatus: () => Promise<RansomwareShieldStatus>;
  getProtectedFolders: () => Promise<string[]>;
  addProtectedFolder: (folderPath: string) => Promise<string[]>;
  removeProtectedFolder: (folderPath: string) => Promise<string[]>;
  getTrustedApplications: () => Promise<TrustedApplication[]>;
  addTrustedApplication: (app: TrustedApplication) => Promise<TrustedApplication[]>;
  removeTrustedApplication: (executablePath: string) => Promise<TrustedApplication[]>;
  getRansomwareIncidents: () => Promise<RansomwareIncident[]>;
  rollbackRansomwareIncident: (incidentId: string) => Promise<IncidentRollbackResult>;
  resetCanaryTraps: () => Promise<CanaryFileRecord[]>;
  onRansomwareEvent: (callback: (incident: RansomwareIncident) => void) => () => void;

  // Phase Q: Health, Watchdog, Audit Log & Tamper Protection API
  getHealthStatus: () => Promise<SystemHealthReport>;
  runHealthCheck: () => Promise<SystemHealthReport>;
  getWatchdogStatus: () => Promise<WatchdogStatus>;
  snoozeShield: (durationMs: number) => Promise<{ success: boolean; remainingMs: number }>;
  resetWatchdogIsolation: (componentName: string) => Promise<{ success: boolean }>;
  getAuditLogs: (filter?: AuditQueryFilter) => Promise<{ entries: AuditLogEntry[]; total: number; offset: number; limit: number }>;
  verifyAuditChain: () => Promise<AuditVerificationResult>;
  exportAuditLogs: (format: 'json' | 'csv') => Promise<string>;
  getTamperStatus: () => Promise<TamperStatus>;
  onHealthEvent: (callback: (data: unknown) => void) => () => void;
  onWatchdogEvent: (callback: (data: unknown) => void) => () => void;
}

declare global {
  interface Window {
    desktopSecurity?: DesktopSecurityApi;
  }
}

function isValidScanProgress(payload: unknown): payload is ScanProgress {
  if (!payload || typeof payload !== 'object') return false;
  const p = payload as Record<string, unknown>;
  return (
    typeof p.scanId === 'string' &&
    typeof p.filesScanned === 'number' &&
    typeof p.threatsFound === 'number' &&
    typeof p.currentPath === 'string'
  );
}

function isValidRealtimeThreatEvent(payload: unknown): payload is RealtimeThreatEvent {
  if (!payload || typeof payload !== 'object') return false;
  const ev = payload as Record<string, unknown>;
  if (ev.actionTaken !== 'AUTO_QUARANTINED' && ev.actionTaken !== 'ALERTED') return false;
  if (typeof ev.timestamp !== 'number') return false;
  if (!ev.threat || typeof ev.threat !== 'object') return false;
  const t = ev.threat as Record<string, unknown>;
  return (
    typeof t.id === 'string' &&
    typeof t.filePath === 'string' &&
    typeof t.fileName === 'string' &&
    typeof t.riskScore === 'number' &&
    typeof t.verdict === 'string' &&
    typeof t.severity === 'string' &&
    Array.isArray(t.evidenceFactors)
  );
}

function isValidNotification(payload: unknown): payload is DesktopNotification {
  if (!payload || typeof payload !== 'object') return false;
  const n = payload as Record<string, unknown>;
  return (
    typeof n.id === 'string' &&
    typeof n.timestamp === 'number' &&
    typeof n.title === 'string' &&
    typeof n.message === 'string' &&
    typeof n.severity === 'string' &&
    typeof n.category === 'string' &&
    typeof n.isRead === 'boolean'
  );
}

/**
 * Creates the typed API bridge for the renderer process.
 * In production Electron, this is wired via contextBridge.exposeInMainWorld('desktopSecurity', api).
 */
export function createDesktopSecurityApi(ipcRenderer: {
  invoke: (channel: string, ...args: any[]) => Promise<any>;
  on: (channel: string, listener: (...args: any[]) => void) => void;
  removeListener: (channel: string, listener: (...args: any[]) => void) => void;
}): DesktopSecurityApi {
  return {
    startQuickScan: () => ipcRenderer.invoke(IPC_CHANNELS.SCAN_START_QUICK),
    startFullScan: (rootPath) => ipcRenderer.invoke(IPC_CHANNELS.SCAN_START_FULL, rootPath),
    startCustomScan: (targets) => ipcRenderer.invoke(IPC_CHANNELS.SCAN_START_CUSTOM, targets),
    cancelScan: () => ipcRenderer.invoke(IPC_CHANNELS.SCAN_CANCEL),
    pauseScan: () => ipcRenderer.invoke(IPC_CHANNELS.SCAN_PAUSE),
    resumeScan: () => ipcRenderer.invoke(IPC_CHANNELS.SCAN_RESUME),
    onScanProgress: (callback) => {
      const handler = (_event: any, progress: unknown) => {
        if (isValidScanProgress(progress)) {
          callback(progress);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.SCAN_PROGRESS_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.SCAN_PROGRESS_EVENT, handler);
    },
    onRealtimeThreat: (callback) => {
      const handler = (_event: any, threatEvent: unknown) => {
        if (isValidRealtimeThreatEvent(threatEvent)) {
          callback(threatEvent);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.REALTIME_THREAT_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.REALTIME_THREAT_EVENT, handler);
    },
    onTriggerQuickScan: (callback) => {
      const handler = () => {
        callback();
      };
      ipcRenderer.on(IPC_CHANNELS.TRIGGER_QUICK_SCAN, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.TRIGGER_QUICK_SCAN, handler);
    },

    listQuarantine: () => ipcRenderer.invoke(IPC_CHANNELS.QUARANTINE_LIST),
    isolateFile: (filePath) => ipcRenderer.invoke(IPC_CHANNELS.QUARANTINE_ISOLATE, filePath),
    restoreQuarantine: (quarantineId, customDir) =>
      ipcRenderer.invoke(IPC_CHANNELS.QUARANTINE_RESTORE, quarantineId, customDir),
    deleteQuarantine: (quarantineId) => ipcRenderer.invoke(IPC_CHANNELS.QUARANTINE_DELETE, quarantineId),

    getProtectionStatus: () => ipcRenderer.invoke(IPC_CHANNELS.STATUS_GET),
    getSettings: () => ipcRenderer.invoke(IPC_CHANNELS.SETTINGS_GET),
    saveSettings: (settings) => ipcRenderer.invoke(IPC_CHANNELS.SETTINGS_SAVE, settings),

    explainThreat: (threat, level) => ipcRenderer.invoke(IPC_CHANNELS.ASSISTANT_EXPLAIN, threat, level),

    auditProcesses: () => ipcRenderer.invoke(IPC_CHANNELS.PROCESSES_AUDIT),
    containProcess: (pid, options) => ipcRenderer.invoke(IPC_CHANNELS.PROCESS_CONTAIN, pid, options),
    getProcessMonitorHealth: () => ipcRenderer.invoke(IPC_CHANNELS.PROCESS_MONITOR_HEALTH),
    auditPersistence: () => ipcRenderer.invoke(IPC_CHANNELS.PERSISTENCE_AUDIT),
    remediatePersistence: (itemId, frictionToken) =>
      ipcRenderer.invoke(IPC_CHANNELS.PERSISTENCE_REMEDIATE, itemId, { frictionToken }),
    onPersistenceChanged: (callback) => {
      const handler = (_event: any, changeEvent: unknown) => {
        if (changeEvent && typeof changeEvent === 'object' && 'changeType' in changeEvent) {
          callback(changeEvent as PersistenceChangeEvent);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.PERSISTENCE_CHANGED, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.PERSISTENCE_CHANGED, handler);
    },
    getRemovableMedia: () => ipcRenderer.invoke(IPC_CHANNELS.REMOVABLE_MEDIA_GET),
    scanRemovableMedia: (mountPath) =>
      ipcRenderer.invoke(IPC_CHANNELS.REMOVABLE_MEDIA_SCAN, mountPath),
    onMediaDriveAttached: (callback) => {
      const handler = (_event: any, drive: unknown) => {
        if (drive && typeof drive === 'object' && 'mountPoint' in drive) {
          callback(drive as RemovableDrive);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.MEDIA_DRIVE_ATTACHED, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.MEDIA_DRIVE_ATTACHED, handler);
    },
    getNetworkPosture: () => ipcRenderer.invoke(IPC_CHANNELS.NETWORK_POSTURE_GET),

    privacyShred: () => ipcRenderer.invoke(IPC_CHANNELS.PRIVACY_SHRED),

    // Phase H: Notification API
    getNotifications: (limit) => ipcRenderer.invoke(IPC_CHANNELS.NOTIFICATIONS_GET, limit),
    getNotificationInboxState: () => ipcRenderer.invoke(IPC_CHANNELS.NOTIFICATIONS_INBOX_STATE_GET),
    markNotificationRead: (notificationId) =>
      ipcRenderer.invoke(IPC_CHANNELS.NOTIFICATIONS_MARK_READ, notificationId),
    markAllNotificationsRead: () => ipcRenderer.invoke(IPC_CHANNELS.NOTIFICATIONS_MARK_ALL_READ),
    clearAllNotifications: () => ipcRenderer.invoke(IPC_CHANNELS.NOTIFICATIONS_CLEAR_ALL),
    onNotificationEvent: (callback) => {
      const handler = (_event: any, notif: unknown) => {
        if (isValidNotification(notif)) {
          callback(notif);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.NOTIFICATION_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.NOTIFICATION_EVENT, handler);
    },

    // Phase I: Exclusion API
    getExclusions: () => ipcRenderer.invoke(IPC_CHANNELS.EXCLUSIONS_GET),
    addExclusion: (input, frictionToken) =>
      ipcRenderer.invoke(IPC_CHANNELS.EXCLUSION_ADD, input, frictionToken),
    removeExclusion: (id) => ipcRenderer.invoke(IPC_CHANNELS.EXCLUSION_REMOVE, id),
    toggleExclusion: (id, enabled) =>
      ipcRenderer.invoke(IPC_CHANNELS.EXCLUSION_TOGGLE, id, enabled),
    clearAllExclusions: () => ipcRenderer.invoke(IPC_CHANNELS.EXCLUSIONS_CLEAR_ALL),

    // Phase J: Web & Download MOTW API
    analyzeMotw: (filePath) => ipcRenderer.invoke(IPC_CHANNELS.MOTW_ANALYZE_FILE, filePath),
    getWebProtectionStatus: () => ipcRenderer.invoke(IPC_CHANNELS.WEB_PROTECTION_STATUS_GET),

    // Phase K: Practical Email (.eml / .msg) Threat API
    analyzeEmail: (filePath) => ipcRenderer.invoke(IPC_CHANNELS.EMAIL_ANALYZE_FILE, filePath),

    // Phase N: Scheduled & On-Demand Scanning API
    getScanSchedule: () => ipcRenderer.invoke(IPC_CHANNELS.SCHEDULE_GET),
    saveScanSchedule: (config, options) =>
      ipcRenderer.invoke(IPC_CHANNELS.SCHEDULE_SAVE, config, options),
    runScheduledScanNow: (options) =>
      ipcRenderer.invoke(IPC_CHANNELS.SCHEDULE_RUN_NOW, options),
    getScanHistory: () => ipcRenderer.invoke(IPC_CHANNELS.SCHEDULE_HISTORY_GET),
    onScheduleEvent: (callback) => {
      const handler = (_event: any, data: unknown) => {
        if (data && typeof data === 'object') {
          callback(data);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.SCHEDULE_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.SCHEDULE_EVENT, handler);
    },

    // Phase O: Threat Intelligence & Signed Update API
    applyUpdateBundle: (bundleOrPath) =>
      ipcRenderer.invoke(IPC_CHANNELS.UPDATE_APPLY_BUNDLE, bundleOrPath),
    rollbackUpdateLkg: () => ipcRenderer.invoke(IPC_CHANNELS.UPDATE_ROLLBACK_LKG),
    getThreatIntelStatus: () => ipcRenderer.invoke(IPC_CHANNELS.UPDATE_STATUS_GET),
    onUpdateEvent: (callback) => {
      const handler = (_event: any, data: unknown) => {
        if (data && typeof data === 'object') {
          callback(data);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.UPDATE_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.UPDATE_EVENT, handler);
    },

    // Phase G: Ransomware Shield & Shadow Vault API
    getRansomwareStatus: () => ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_STATUS_GET),
    getProtectedFolders: () => ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_GET),
    addProtectedFolder: (folderPath) =>
      ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_ADD, folderPath),
    removeProtectedFolder: (folderPath) =>
      ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_REMOVE, folderPath),
    getTrustedApplications: () => ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_GET),
    addTrustedApplication: (app) =>
      ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_ADD, app),
    removeTrustedApplication: (executablePath) =>
      ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_REMOVE, executablePath),
    getRansomwareIncidents: () => ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_INCIDENTS_GET),
    rollbackRansomwareIncident: (incidentId) =>
      ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_INCIDENT_ROLLBACK, incidentId),
    resetCanaryTraps: () => ipcRenderer.invoke(IPC_CHANNELS.RANSOMWARE_CANARY_RESET),
    onRansomwareEvent: (callback) => {
      const handler = (_event: any, incident: unknown) => {
        if (incident && typeof incident === 'object') {
          callback(incident as RansomwareIncident);
        }
      };
      ipcRenderer.on(IPC_CHANNELS.RANSOMWARE_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.RANSOMWARE_EVENT, handler);
    },

    // Phase Q: Health, Watchdog, Audit Log & Tamper Protection API
    getHealthStatus: () => ipcRenderer.invoke(IPC_CHANNELS.HEALTH_STATUS_GET),
    runHealthCheck: () => ipcRenderer.invoke(IPC_CHANNELS.HEALTH_CHECK_RUN),
    getWatchdogStatus: () => ipcRenderer.invoke(IPC_CHANNELS.WATCHDOG_STATUS_GET),
    snoozeShield: (durationMs) => ipcRenderer.invoke(IPC_CHANNELS.WATCHDOG_SNOOZE_SHIELD, durationMs),
    resetWatchdogIsolation: (componentName) => ipcRenderer.invoke(IPC_CHANNELS.WATCHDOG_RESET_ISOLATION, componentName),
    getAuditLogs: (filter) => ipcRenderer.invoke(IPC_CHANNELS.AUDIT_LOGS_GET, filter),
    verifyAuditChain: () => ipcRenderer.invoke(IPC_CHANNELS.AUDIT_CHAIN_VERIFY),
    exportAuditLogs: (format) => ipcRenderer.invoke(IPC_CHANNELS.AUDIT_EXPORT, format),
    getTamperStatus: () => ipcRenderer.invoke(IPC_CHANNELS.TAMPER_STATUS_GET),
    onHealthEvent: (callback) => {
      const handler = (_event: any, data: unknown) => {
        if (data && typeof data === 'object') callback(data);
      };
      ipcRenderer.on(IPC_CHANNELS.HEALTH_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.HEALTH_EVENT, handler);
    },
    onWatchdogEvent: (callback) => {
      const handler = (_event: any, data: unknown) => {
        if (data && typeof data === 'object') callback(data);
      };
      ipcRenderer.on(IPC_CHANNELS.WATCHDOG_EVENT, handler);
      return () => ipcRenderer.removeListener(IPC_CHANNELS.WATCHDOG_EVENT, handler);
    }
  };
}

