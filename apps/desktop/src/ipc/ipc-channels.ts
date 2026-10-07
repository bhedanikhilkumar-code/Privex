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
  NOTIFICATION_EVENT: 'desktop:notifications:event',

  // Phase I: Automatic Response Ladder & False-Positive Exclusions
  EXCLUSIONS_GET: 'desktop:exclusions:get',
  EXCLUSION_ADD: 'desktop:exclusions:add',
  EXCLUSION_REMOVE: 'desktop:exclusions:remove',
  EXCLUSION_TOGGLE: 'desktop:exclusions:toggle',
  EXCLUSIONS_CLEAR_ALL: 'desktop:exclusions:clearAll',

  // Phase J: Web & Download MOTW Protection
  MOTW_ANALYZE_FILE: 'desktop:motw:analyzeFile',
  WEB_PROTECTION_STATUS_GET: 'desktop:webProtection:statusGet',

  // Phase K: Practical Email (.eml / .msg) & Network Socket Protection
  EMAIL_ANALYZE_FILE: 'desktop:email:analyzeFile',

  // Phase L: Startup & Persistence Protection
  PERSISTENCE_REMEDIATE: 'desktop:persistence:remediate',
  PERSISTENCE_CHANGED: 'desktop:persistence:changed',

  // Phase M: USB & Removable Media Protection
  REMOVABLE_MEDIA_SCAN: 'desktop:removableMedia:scan',
  MEDIA_DRIVE_ATTACHED: 'desktop:removableMedia:attached',

  // Phase N: Scheduled & On-Demand Scanning
  SCHEDULE_GET: 'desktop:schedule:get',
  SCHEDULE_SAVE: 'desktop:schedule:save',
  SCHEDULE_RUN_NOW: 'desktop:schedule:runNow',
  SCHEDULE_HISTORY_GET: 'desktop:schedule:historyGet',
  SCHEDULE_EVENT: 'desktop:schedule:event',

  // Phase O: Threat Intelligence & Signed Updates
  UPDATE_APPLY_BUNDLE: 'desktop:update:applyBundle',
  UPDATE_ROLLBACK_LKG: 'desktop:update:rollbackLkg',
  UPDATE_STATUS_GET: 'desktop:update:statusGet',
  UPDATE_EVENT: 'desktop:update:event',

  // Phase Q: Self-Health, Watchdog, Audit Log & Tamper Protection
  HEALTH_STATUS_GET: 'desktop:health:statusGet',
  HEALTH_CHECK_RUN: 'desktop:health:checkRun',
  WATCHDOG_STATUS_GET: 'desktop:watchdog:statusGet',
  WATCHDOG_SNOOZE_SHIELD: 'desktop:watchdog:snoozeShield',
  WATCHDOG_RESET_ISOLATION: 'desktop:watchdog:resetIsolation',
  AUDIT_LOGS_GET: 'desktop:audit:logsGet',
  AUDIT_CHAIN_VERIFY: 'desktop:audit:chainVerify',
  AUDIT_EXPORT: 'desktop:audit:export',
  TAMPER_STATUS_GET: 'desktop:tamper:statusGet',
  HEALTH_EVENT: 'desktop:health:event',
  WATCHDOG_EVENT: 'desktop:watchdog:event'
} as const;

export type IpcChannel = typeof IPC_CHANNELS[keyof typeof IPC_CHANNELS];

export const IPC_EVENT_CHANNELS: readonly IpcChannel[] = [
  IPC_CHANNELS.SCAN_PROGRESS_EVENT,
  IPC_CHANNELS.REALTIME_THREAT_EVENT,
  IPC_CHANNELS.TRIGGER_QUICK_SCAN,
  IPC_CHANNELS.RANSOMWARE_EVENT,
  IPC_CHANNELS.NOTIFICATION_EVENT,
  IPC_CHANNELS.PERSISTENCE_CHANGED,
  IPC_CHANNELS.MEDIA_DRIVE_ATTACHED,
  IPC_CHANNELS.SCHEDULE_EVENT,
  IPC_CHANNELS.UPDATE_EVENT,
  IPC_CHANNELS.HEALTH_EVENT,
  IPC_CHANNELS.WATCHDOG_EVENT
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
  IPC_CHANNELS.PERSISTENCE_REMEDIATE,
  IPC_CHANNELS.REMOVABLE_MEDIA_GET,
  IPC_CHANNELS.REMOVABLE_MEDIA_SCAN,
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
  IPC_CHANNELS.NOTIFICATIONS_CLEAR_ALL,
  IPC_CHANNELS.EXCLUSIONS_GET,
  IPC_CHANNELS.EXCLUSION_ADD,
  IPC_CHANNELS.EXCLUSION_REMOVE,
  IPC_CHANNELS.EXCLUSION_TOGGLE,
  IPC_CHANNELS.EXCLUSIONS_CLEAR_ALL,
  IPC_CHANNELS.MOTW_ANALYZE_FILE,
  IPC_CHANNELS.WEB_PROTECTION_STATUS_GET,
  IPC_CHANNELS.EMAIL_ANALYZE_FILE,
  IPC_CHANNELS.SCHEDULE_GET,
  IPC_CHANNELS.SCHEDULE_SAVE,
  IPC_CHANNELS.SCHEDULE_RUN_NOW,
  IPC_CHANNELS.SCHEDULE_HISTORY_GET,
  IPC_CHANNELS.UPDATE_APPLY_BUNDLE,
  IPC_CHANNELS.UPDATE_ROLLBACK_LKG,
  IPC_CHANNELS.UPDATE_STATUS_GET,
  IPC_CHANNELS.HEALTH_STATUS_GET,
  IPC_CHANNELS.HEALTH_CHECK_RUN,
  IPC_CHANNELS.WATCHDOG_STATUS_GET,
  IPC_CHANNELS.WATCHDOG_SNOOZE_SHIELD,
  IPC_CHANNELS.WATCHDOG_RESET_ISOLATION,
  IPC_CHANNELS.AUDIT_LOGS_GET,
  IPC_CHANNELS.AUDIT_CHAIN_VERIFY,
  IPC_CHANNELS.AUDIT_EXPORT,
  IPC_CHANNELS.TAMPER_STATUS_GET
] as const;


