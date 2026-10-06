export const IPC_CHANNELS = {
  SCAN_START_QUICK: 'desktop:scan:startQuick',
  SCAN_START_FULL: 'desktop:scan:startFull',
  SCAN_START_CUSTOM: 'desktop:scan:startCustom',
  SCAN_CANCEL: 'desktop:scan:cancel',
  SCAN_PAUSE: 'desktop:scan:pause',
  SCAN_RESUME: 'desktop:scan:resume',
  SCAN_PROGRESS_EVENT: 'desktop:scan:progress',

  REALTIME_THREAT_EVENT: 'desktop:realtime:threat-event',

  QUARANTINE_LIST: 'desktop:quarantine:list',
  QUARANTINE_ISOLATE: 'desktop:quarantine:isolate',
  QUARANTINE_RESTORE: 'desktop:quarantine:restore',
  QUARANTINE_DELETE: 'desktop:quarantine:delete',

  STATUS_GET: 'desktop:status:get',
  SETTINGS_GET: 'desktop:settings:get',
  SETTINGS_SAVE: 'desktop:settings:save',

  ASSISTANT_EXPLAIN: 'desktop:assistant:explain',

  PROCESSES_AUDIT: 'desktop:processes:audit',
  PROCESS_CONTAIN: 'desktop:process:contain',
  PROCESS_MONITOR_HEALTH: 'desktop:processMonitor:health',
  PERSISTENCE_AUDIT: 'desktop:persistence:audit',
  REMOVABLE_MEDIA_GET: 'desktop:removableMedia:get',
  NETWORK_POSTURE_GET: 'desktop:networkPosture:get',

  PRIVACY_SHRED: 'desktop:privacy:shred',

  // System Tray & Background Continuity IPC Events
  TRIGGER_QUICK_SCAN: 'desktop:scan:trigger-quick',

  // Phase G: Ransomware Shield & Shadow Vault IPC Channels
  RANSOMWARE_STATUS_GET: 'desktop:ransomware:statusGet',
  RANSOMWARE_PROTECTED_FOLDERS_GET: 'desktop:ransomware:foldersGet',
  RANSOMWARE_PROTECTED_FOLDERS_ADD: 'desktop:ransomware:foldersAdd',
  RANSOMWARE_PROTECTED_FOLDERS_REMOVE: 'desktop:ransomware:foldersRemove',
  RANSOMWARE_TRUSTED_APPS_GET: 'desktop:ransomware:trustedAppsGet',
  RANSOMWARE_TRUSTED_APPS_ADD: 'desktop:ransomware:trustedAppsAdd',
  RANSOMWARE_TRUSTED_APPS_REMOVE: 'desktop:ransomware:trustedAppsRemove',
  RANSOMWARE_INCIDENTS_GET: 'desktop:ransomware:incidentsGet',
  RANSOMWARE_INCIDENT_ROLLBACK: 'desktop:ransomware:rollback',
  RANSOMWARE_CANARY_RESET: 'desktop:ransomware:canaryReset',
  RANSOMWARE_EVENT: 'desktop:ransomware:event',

  // Phase H: Notification System & Inbox IPC Channels
  NOTIFICATIONS_GET: 'desktop:notifications:get',
  NOTIFICATIONS_INBOX_STATE_GET: 'desktop:notifications:inboxStateGet',
  NOTIFICATIONS_MARK_READ: 'desktop:notifications:markRead',
  NOTIFICATIONS_MARK_ALL_READ: 'desktop:notifications:markAllRead',
  NOTIFICATIONS_CLEAR_ALL: 'desktop:notifications:clearAll',
  NOTIFICATION_EVENT: 'desktop:notifications:event'
} as const;

export type IpcChannel = typeof IPC_CHANNELS[keyof typeof IPC_CHANNELS];

export const IPC_EVENT_CHANNELS: readonly IpcChannel[] = [
  IPC_CHANNELS.SCAN_PROGRESS_EVENT,
  IPC_CHANNELS.REALTIME_THREAT_EVENT,
  IPC_CHANNELS.TRIGGER_QUICK_SCAN,
  IPC_CHANNELS.RANSOMWARE_EVENT,
  IPC_CHANNELS.NOTIFICATION_EVENT
] as const;

export const IPC_INVOKE_CHANNELS: readonly IpcChannel[] = [
  IPC_CHANNELS.SCAN_START_QUICK,
  IPC_CHANNELS.SCAN_START_FULL,
  IPC_CHANNELS.SCAN_START_CUSTOM,
  IPC_CHANNELS.SCAN_CANCEL,
  IPC_CHANNELS.SCAN_PAUSE,
  IPC_CHANNELS.SCAN_RESUME,
  IPC_CHANNELS.QUARANTINE_LIST,
  IPC_CHANNELS.QUARANTINE_ISOLATE,
  IPC_CHANNELS.QUARANTINE_RESTORE,
  IPC_CHANNELS.QUARANTINE_DELETE,
  IPC_CHANNELS.STATUS_GET,
  IPC_CHANNELS.SETTINGS_GET,
  IPC_CHANNELS.SETTINGS_SAVE,
  IPC_CHANNELS.ASSISTANT_EXPLAIN,
  IPC_CHANNELS.PROCESSES_AUDIT,
  IPC_CHANNELS.PROCESS_CONTAIN,
  IPC_CHANNELS.PROCESS_MONITOR_HEALTH,
  IPC_CHANNELS.PERSISTENCE_AUDIT,
  IPC_CHANNELS.REMOVABLE_MEDIA_GET,
  IPC_CHANNELS.NETWORK_POSTURE_GET,
  IPC_CHANNELS.PRIVACY_SHRED,
  IPC_CHANNELS.RANSOMWARE_STATUS_GET,
  IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_GET,
  IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_ADD,
  IPC_CHANNELS.RANSOMWARE_PROTECTED_FOLDERS_REMOVE,
  IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_GET,
  IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_ADD,
  IPC_CHANNELS.RANSOMWARE_TRUSTED_APPS_REMOVE,
  IPC_CHANNELS.RANSOMWARE_INCIDENTS_GET,
  IPC_CHANNELS.RANSOMWARE_INCIDENT_ROLLBACK,
  IPC_CHANNELS.RANSOMWARE_CANARY_RESET,
  IPC_CHANNELS.NOTIFICATIONS_GET,
  IPC_CHANNELS.NOTIFICATIONS_INBOX_STATE_GET,
  IPC_CHANNELS.NOTIFICATIONS_MARK_READ,
  IPC_CHANNELS.NOTIFICATIONS_MARK_ALL_READ,
  IPC_CHANNELS.NOTIFICATIONS_CLEAR_ALL
] as const;


