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
  RemovableDrive,
  ScanProgress,
  RealtimeThreatEvent,
  ContainProcessOptions,
  ProcessMonitorHealth,
  DesktopNotification,
  NotificationInboxState
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
  getRemovableMedia: () => Promise<RemovableDrive[]>;
  getNetworkPosture: () => Promise<NetworkPostureReport>;

  privacyShred: () => Promise<void>;

  // Phase H: Notification API
  getNotifications: (limit?: number) => Promise<DesktopNotification[]>;
  getNotificationInboxState: () => Promise<NotificationInboxState>;
  markNotificationRead: (notificationId: string) => Promise<boolean>;
  markAllNotificationsRead: () => Promise<number>;
  clearAllNotifications: () => Promise<void>;
  onNotificationEvent: (callback: (notification: DesktopNotification) => void) => () => void;
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
    getRemovableMedia: () => ipcRenderer.invoke(IPC_CHANNELS.REMOVABLE_MEDIA_GET),
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
    }
  };
}

