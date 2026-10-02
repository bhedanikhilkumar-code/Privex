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
  PERSISTENCE_AUDIT: 'desktop:persistence:audit',
  REMOVABLE_MEDIA_GET: 'desktop:removableMedia:get',
  NETWORK_POSTURE_GET: 'desktop:networkPosture:get',

  PRIVACY_SHRED: 'desktop:privacy:shred'
} as const;

export type IpcChannel = typeof IPC_CHANNELS[keyof typeof IPC_CHANNELS];

export const IPC_EVENT_CHANNELS: readonly IpcChannel[] = [
  IPC_CHANNELS.SCAN_PROGRESS_EVENT,
  IPC_CHANNELS.REALTIME_THREAT_EVENT
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
  IPC_CHANNELS.PERSISTENCE_AUDIT,
  IPC_CHANNELS.REMOVABLE_MEDIA_GET,
  IPC_CHANNELS.NETWORK_POSTURE_GET,
  IPC_CHANNELS.PRIVACY_SHRED
] as const;
