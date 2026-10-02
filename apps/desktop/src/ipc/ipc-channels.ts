export const IPC_CHANNELS = {
  SCAN_START_QUICK: 'desktop:scan:startQuick',
  SCAN_START_FULL: 'desktop:scan:startFull',
  SCAN_START_CUSTOM: 'desktop:scan:startCustom',
  SCAN_CANCEL: 'desktop:scan:cancel',
  SCAN_PAUSE: 'desktop:scan:pause',
  SCAN_RESUME: 'desktop:scan:resume',
  SCAN_PROGRESS_EVENT: 'desktop:scan:progress',

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
