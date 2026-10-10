import * as path from 'path';
import * as fs from 'fs';
import {
  DesktopSettings,
  DetectedThreat,
  ScanScheduleConfig,
  PpdbBundle,
  AuditQueryFilter,
  AuditLogCategory,
  AuditLogSeverity
} from '../types/desktop.types';

export class IpcValidator {
  private static readonly FORBIDDEN_SHELL_CHARS = /[|&;$`><\r\n\0]/;
  private static readonly PARENT_TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
  private static readonly ENCODED_TRAVERSAL_PATTERN = /%2e%2e/i;
  private static readonly UNC_PATH_PATTERN = /^(?:\\\\|\/\/)/;
  private static readonly PROTECTED_SYSTEM_PREFIXES = [
    'c:\\windows',
    'c:\\program files',
    'c:\\program files (x86)',
    'c:\\programdata\\microsoft',
    'c:\\system volume information',
    'c:\\recovery',
    'c:\\$recycle.bin',
    'c:\\boot',
    'c:\\efi',
    '/etc',
    '/usr',
    '/bin',
    '/sbin',
    '/boot',
    '/dev',
    '/system'
  ];

  /**
   * Validates and normalizes a candidate filesystem path.
   * Throws on path traversal (..), encoded traversal, NTFS ADS streams, UNC shares, null bytes, or dangerous shell characters.
   */
  public static validatePath(inputPath: unknown): string {
    if (typeof inputPath !== 'string') {
      throw new Error('INVALID_PATH: Path must be a non-empty string.');
    }

    if (inputPath.includes('\0')) {
      throw new Error('SECURITY_VIOLATION: Null byte detected in path.');
    }

    const trimmed = inputPath.trim();
    if (!trimmed || trimmed.length > 1024) {
      throw new Error('INVALID_PATH: Path length must be between 1 and 1024 characters.');
    }

    if (this.FORBIDDEN_SHELL_CHARS.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Path contains forbidden shell metacharacters or control bytes.');
    }

    if (this.UNC_PATH_PATTERN.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Remote UNC network paths are prohibited.');
    }

    if (this.PARENT_TRAVERSAL_PATTERN.test(trimmed) || this.ENCODED_TRAVERSAL_PATTERN.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Relative parent directory traversal (..) is prohibited.');
    }

    // Reject NTFS Alternate Data Streams (colon after drive letter index 1, e.g., file.exe:$DATA)
    const colonIdx = trimmed.indexOf(':', 2);
    if (colonIdx !== -1 || (trimmed.startsWith(':') || (trimmed.indexOf(':') === 1 && !/^[a-zA-Z]:/.test(trimmed)))) {
      throw new Error('SECURITY_VIOLATION: NTFS Alternate Data Stream (:) syntax is prohibited.');
    }

    const resolved = path.resolve(trimmed);
    return resolved;
  }

  private static resolveNativeRealPathBestEffort(targetPath: string): string {
    try {
      if (fs.existsSync(targetPath)) {
        return fs.realpathSync.native ? fs.realpathSync.native(targetPath) : fs.realpathSync(targetPath);
      }
      const parentDir = path.dirname(targetPath);
      if (parentDir && parentDir !== targetPath && fs.existsSync(parentDir)) {
        const realParent = fs.realpathSync.native
          ? fs.realpathSync.native(parentDir)
          : fs.realpathSync(parentDir);
        return path.join(realParent, path.basename(targetPath));
      }
    } catch {
      // Fallback to syntactic path.resolve
    }
    return path.resolve(targetPath);
  }

  /**
   * Checks whether a canonical path points into a protected OS system directory.
   * Resolves Windows 8.3 short names and directory junctions via realpathSync.native
   * while explicitly permitting the system/user temp directory (e.g. C:\Windows\Temp or os.tmpdir()).
   */
  public static isProtectedSystemPath(filePath: string): boolean {
    if (!filePath || typeof filePath !== 'string') {
      return false;
    }

    const candidates = [
      filePath.trim(),
      path.resolve(filePath.trim()),
      this.resolveNativeRealPathBestEffort(filePath.trim())
    ];

    const dynamicPrefixes = [...this.PROTECTED_SYSTEM_PREFIXES];
    for (const envVar of ['SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)']) {
      const val = process.env[envVar];
      if (val && typeof val === 'string' && val.trim()) {
        dynamicPrefixes.push(val.trim().toLowerCase());
      }
    }

    for (const candidate of candidates) {
      const rawSlash = candidate.replace(/\\/g, '/').toLowerCase();
      if (rawSlash === '/tmp' || rawSlash.startsWith('/tmp/')) {
        return false;
      }
      const normalized = path.resolve(candidate).toLowerCase();
      if (
        normalized === 'c:\\windows\\temp' ||
        normalized.startsWith('c:\\windows\\temp\\') ||
        rawSlash === 'c:/windows/temp' ||
        rawSlash.startsWith('c:/windows/temp/')
      ) {
        return false;
      }

      const isProtected = dynamicPrefixes.some((prefix) => {
        const prefixSlash = prefix.replace(/\\/g, '/');
        return (
          normalized === prefix ||
          normalized.startsWith(prefix + '\\') ||
          normalized.startsWith(prefix + '/') ||
          rawSlash === prefixSlash ||
          rawSlash.startsWith(prefixSlash + '/')
        );
      });

      if (isProtected) {
        return true;
      }
    }

    return false;
  }

  /**
   * Validates an array of scan target paths.
   */
  public static validateScanTargets(targets: unknown): string[] {
    if (!Array.isArray(targets) || targets.length === 0) {
      throw new Error('INVALID_TARGETS: Must provide at least one target path.');
    }
    if (targets.length > 32) {
      throw new Error('INVALID_TARGETS: Exceeds maximum of 32 concurrent scan target paths.');
    }
    return targets.map((t) => this.validatePath(t));
  }

  /**
   * Validates that an IPC message originated from a trusted local renderer window.
   */
  public static validateSenderOrigin(senderUrl: unknown): boolean {
    if (typeof senderUrl !== 'string' || !senderUrl.trim()) {
      throw new Error('SECURITY_VIOLATION: Missing or untrusted IPC sender origin.');
    }
    const lower = senderUrl.trim().toLowerCase();
    if (lower.includes('\0')) {
      throw new Error('SECURITY_VIOLATION: Null byte in IPC sender origin.');
    }
    const isTrusted =
      lower.startsWith('file://') ||
      lower.startsWith('app://') ||
      lower.startsWith('http://localhost:') ||
      lower.startsWith('http://127.0.0.1:');

    if (!isTrusted) {
      throw new Error(`SECURITY_VIOLATION: Untrusted renderer origin rejected: ${senderUrl}`);
    }
    return true;
  }

  /**
   * Validates an identifier (scanId or quarantineId).
   */
  public static validateId(id: unknown, prefix = ''): string {
    if (typeof id !== 'string') {
      throw new Error('INVALID_ID: Identifier must be a string.');
    }

    const trimmed = id.trim();
    if (!trimmed || trimmed.length > 128) {
      throw new Error('INVALID_ID: Identifier length must be between 1 and 128 characters.');
    }

    if (!/^[a-zA-Z0-9_\-]+$/.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Identifier contains invalid non-alphanumeric characters.');
    }

    if (prefix && !trimmed.startsWith(prefix)) {
      throw new Error(`INVALID_ID: Identifier must start with prefix '${prefix}'.`);
    }

    return trimmed;
  }

  /**
   * Validates cognitive reading level for assistant explanations.
   */
  public static validateCognitiveLevel(level: unknown): 'grade6' | 'grade8' {
    if (level === 'grade8') return 'grade8';
    return 'grade6';
  }

  /**
   * Validates and sanitizes incoming DesktopSettings payload from IPC (GAP-15).
   */
  public static validateSettings(input: unknown): Partial<DesktopSettings> {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw new Error('INVALID_SETTINGS: Settings payload must be a non-null object.');
    }

    const raw = input as Record<string, unknown>;
    const clean: Partial<DesktopSettings> = {};

    const booleanKeys: Array<
      | 'realtimeShieldEnabled'
      | 'monitorDownloads'
      | 'monitorTemp'
      | 'entropyDetectionEnabled'
      | 'autoQuarantineCritical'
      | 'frictionGateEnabled'
    > = [
      'realtimeShieldEnabled',
      'monitorDownloads',
      'monitorTemp',
      'entropyDetectionEnabled',
      'autoQuarantineCritical',
      'frictionGateEnabled'
    ];

    for (const key of booleanKeys) {
      if (raw[key] !== undefined) {
        if (typeof raw[key] !== 'boolean') {
          throw new Error(`INVALID_SETTINGS: Field '${key}' must be a boolean.`);
        }
        clean[key] = raw[key] as boolean;
      }
    }

    if (raw.scanLargeFilesLimitMb !== undefined) {
      if (
        typeof raw.scanLargeFilesLimitMb !== 'number' ||
        Number.isNaN(raw.scanLargeFilesLimitMb) ||
        raw.scanLargeFilesLimitMb < 1 ||
        raw.scanLargeFilesLimitMb > 2048
      ) {
        throw new Error('INVALID_SETTINGS: scanLargeFilesLimitMb must be a number between 1 and 2048.');
      }
      clean.scanLargeFilesLimitMb = Math.floor(raw.scanLargeFilesLimitMb);
    }

    if (raw.cognitiveLevel !== undefined) {
      if (raw.cognitiveLevel !== 'grade6' && raw.cognitiveLevel !== 'grade8') {
        throw new Error('INVALID_SETTINGS: cognitiveLevel must be grade6 or grade8.');
      }
      clean.cognitiveLevel = raw.cognitiveLevel;
    }

    if (raw.excludedPaths !== undefined) {
      if (!Array.isArray(raw.excludedPaths) || raw.excludedPaths.length > 100) {
        throw new Error('INVALID_SETTINGS: excludedPaths must be an array of at most 100 paths.');
      }
      clean.excludedPaths = raw.excludedPaths.map((p) => this.validatePath(p));
    }

    return clean;
  }

  /**
   * Validates a DetectedThreat payload passed over IPC to explainThreat.
   */
  public static validateThreatInput(input: unknown): DetectedThreat {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw new Error('INVALID_THREAT: Threat payload must be a non-null object.');
    }
    const t = input as Record<string, unknown>;
    const id = typeof t.id === 'string' && t.id.trim() ? t.id.trim().slice(0, 128) : `threat-${Date.now()}`;
    const filePath = typeof t.filePath === 'string' && t.filePath.trim() ? t.filePath.trim().slice(0, 1024) : 'unknown';
    const fileName = typeof t.fileName === 'string' && t.fileName.trim() ? t.fileName.trim().slice(0, 255) : 'unknown';
    const threatName = typeof t.threatName === 'string' && t.threatName.trim() ? t.threatName.trim().slice(0, 128) : 'SUSPICIOUS_FILE';
    const riskScore =
      typeof t.riskScore === 'number' && !Number.isNaN(t.riskScore)
        ? Math.max(0, Math.min(100, t.riskScore))
        : 50;

    const allowedSeverities = ['safe', 'low', 'suspicious', 'dangerous', 'critical'];
    const severity =
      typeof t.severity === 'string' && allowedSeverities.includes(t.severity)
        ? (t.severity as DetectedThreat['severity'])
        : 'suspicious';

    const allowedVerdicts = ['ALLOW', 'INFORM', 'WARN', 'BLOCK'];
    const verdict =
      typeof t.verdict === 'string' && allowedVerdicts.includes(t.verdict)
        ? (t.verdict as DetectedThreat['verdict'])
        : 'WARN';

    const evidenceFactors = Array.isArray(t.evidenceFactors)
      ? t.evidenceFactors
          .filter((f): f is string => typeof f === 'string')
          .map((f) => f.slice(0, 500))
          .slice(0, 50)
      : [];

    return {
      id,
      filePath,
      fileName,
      fileSize: typeof t.fileSize === 'number' ? t.fileSize : 0,
      sha256: typeof t.sha256 === 'string' ? t.sha256.slice(0, 64) : '',
      riskScore,
      severity,
      verdict,
      threatName,
      detectedAt: typeof t.detectedAt === 'number' ? t.detectedAt : Date.now(),
      evidenceFactors,
      quarantined: Boolean(t.quarantined)
    };
  }

  /**
   * Validates an integer within allowed range (e.g. PID).
   */
  public static validateNumber(value: unknown, min = 0, max = 9999999): number {
    if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) {
      throw new Error('INVALID_NUMBER: Expected a valid finite integer.');
    }
    if (value < min || value > max) {
      throw new Error(`SECURITY_VIOLATION: Value ${value} is outside valid range [${min}, ${max}].`);
    }
    return value;
  }

  /**
   * Validates a notification ID string.
   */
  public static validateNotificationId(value: unknown): string {
    if (typeof value !== 'string') {
      throw new Error('INVALID_NOTIFICATION_ID: Expected non-empty string for notification ID.');
    }
    const trimmed = value.trim();
    if (!trimmed || trimmed.length > 128) {
      throw new Error('INVALID_NOTIFICATION_ID: Notification ID length must be between 1 and 128 characters.');
    }
    if (/[|&;$`><\r\n\0]/.test(trimmed) || trimmed.includes('..') || trimmed.includes('/') || trimmed.includes('\\')) {
      throw new Error('SECURITY_VIOLATION: Notification ID contains forbidden characters or path traversal.');
    }
    return trimmed;
  }

  /**
   * Validates notification query limit.
   */
  public static validateNotificationLimit(value: unknown, defaultLimit = 100): number {
    if (value === undefined || value === null) {
      return defaultLimit;
    }
    if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) {
      throw new Error('INVALID_LIMIT: Expected a valid integer limit.');
    }
    if (value <= 0 || value > 1000) {
      throw new Error('INVALID_LIMIT: Limit must be between 1 and 1000.');
    }
    return value;
  }

  // ============================================================
  // PHASE I: EXCLUSION VALIDATORS
  // ============================================================

  /**
   * Validates an exclusion ID string.
   */
  public static validateExclusionId(value: unknown): string {
    if (typeof value !== 'string') {
      throw new Error('INVALID_EXCLUSION_ID: Expected non-empty string for exclusion ID.');
    }
    const trimmed = value.trim();
    if (!trimmed || trimmed.length > 128) {
      throw new Error('INVALID_EXCLUSION_ID: Exclusion ID length must be between 1 and 128 characters.');
    }
    if (/[|&;$`><\r\n\0]/.test(trimmed) || trimmed.includes('..') || trimmed.includes('/') || trimmed.includes('\\')) {
      throw new Error('SECURITY_VIOLATION: Exclusion ID contains forbidden characters or path traversal.');
    }
    return trimmed;
  }

  /**
   * Validates create exclusion payload.
   */
  public static validateExclusionInput(input: unknown): {
    type: 'HASH' | 'PATH' | 'DOMAIN';
    value: string;
    ttl?: '24h' | '7d' | '30d' | 'permanent' | number;
    reason?: string;
    frictionToken?: string;
  } {
    if (!input || typeof input !== 'object') {
      throw new Error('INVALID_EXCLUSION_PAYLOAD: Expected object payload for exclusion.');
    }
    const obj = input as Record<string, unknown>;

    if (obj.type !== 'HASH' && obj.type !== 'PATH' && obj.type !== 'DOMAIN') {
      throw new Error('INVALID_EXCLUSION_TYPE: Exclusion type must be HASH, PATH, or DOMAIN.');
    }

    if (typeof obj.value !== 'string' || !obj.value.trim()) {
      throw new Error('INVALID_EXCLUSION_VALUE: Exclusion value must be a non-empty string.');
    }

    let ttl: '24h' | '7d' | '30d' | 'permanent' | number | undefined;
    if (obj.ttl !== undefined && obj.ttl !== null) {
      if (obj.ttl === '24h' || obj.ttl === '7d' || obj.ttl === '30d' || obj.ttl === 'permanent') {
        ttl = obj.ttl;
      } else if (typeof obj.ttl === 'number' && Number.isFinite(obj.ttl) && obj.ttl > 0) {
        ttl = obj.ttl;
      } else {
        throw new Error('INVALID_EXCLUSION_TTL: TTL must be 24h, 7d, 30d, permanent, or positive integer ms.');
      }
    }

    let reason: string | undefined;
    if (obj.reason !== undefined && obj.reason !== null) {
      if (typeof obj.reason !== 'string') {
        throw new Error('INVALID_EXCLUSION_REASON: Reason must be a string.');
      }
      reason = obj.reason.slice(0, 255);
    }

    let frictionToken: string | undefined;
    if (obj.frictionToken !== undefined && obj.frictionToken !== null) {
      if (typeof obj.frictionToken !== 'string') {
        throw new Error('INVALID_FRICTION_TOKEN: Expected string friction token.');
      }
      frictionToken = obj.frictionToken.trim();
    }

    return {
      type: obj.type,
      value: obj.value.trim(),
      ttl,
      reason,
      frictionToken
    };
  }

  public static validateFrictionToken(token: unknown): string {
    if (typeof token !== 'string' || !token.trim()) {
      throw new Error('INVALID_FRICTION_TOKEN: Friction token must be a non-empty string.');
    }
    return token.trim();
  }

  /**
   * Validates a ScanScheduleConfig input payload from IPC.
   * Enforces strict schema verification, rejects prototype pollution, unexpected fields,
   * invalid frequencies, malformed 24-hour time strings, and out-of-range thresholds.
   */
  public static validateScheduleConfig(input: unknown): ScanScheduleConfig {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new Error('INVALID_SCHEDULE_PAYLOAD: Expected object payload for scan schedule configuration.');
    }

    // Prototype pollution & unexpected properties check
    const forbiddenKeys = ['__proto__', 'constructor', 'prototype'];
    const allowedKeys = new Set([
      'enabled',
      'frequency',
      'timeOfDay',
      'weekday',
      'scanType',
      'pauseOnBattery',
      'runMissedOnStartup',
      'autoQuarantine',
      'maxCpuThresholdPct',
      'minBatteryThresholdPct',
      'frictionToken'
    ]);

    const obj = input as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (forbiddenKeys.includes(key)) {
        throw new Error(`SECURITY_VIOLATION: Forbidden prototype key detected: ${key}`);
      }
      if (!allowedKeys.has(key)) {
        throw new Error(`INVALID_SCHEDULE_FIELD: Unexpected field in schedule payload: ${key}`);
      }
    }

    if (typeof obj.enabled !== 'boolean') {
      throw new Error('INVALID_SCHEDULE_ENABLED: Expected boolean for enabled.');
    }

    if (obj.frequency !== 'daily' && obj.frequency !== 'weekly') {
      throw new Error("INVALID_SCHEDULE_FREQUENCY: Expected 'daily' or 'weekly' for frequency.");
    }

    if (typeof obj.timeOfDay !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(obj.timeOfDay.trim())) {
      throw new Error("INVALID_SCHEDULE_TIME: Expected valid 24-hour 'HH:mm' time format (00:00 to 23:59).");
    }

    let weekday: number | undefined;
    if (obj.weekday !== undefined && obj.weekday !== null) {
      if (typeof obj.weekday === 'number' && Number.isInteger(obj.weekday) && obj.weekday >= 0 && obj.weekday <= 6) {
        weekday = obj.weekday;
      } else {
        throw new Error('INVALID_SCHEDULE_WEEKDAY: Expected integer weekday 0-6 (0=Sun, ..., 6=Sat).');
      }
    } else if (obj.frequency === 'weekly') {
      weekday = 0; // default Sunday
    }

    if (obj.scanType !== 'quick' && obj.scanType !== 'full') {
      throw new Error("INVALID_SCHEDULE_SCAN_TYPE: Expected 'quick' or 'full' for scanType.");
    }

    if (typeof obj.pauseOnBattery !== 'boolean') {
      throw new Error('INVALID_SCHEDULE_PAUSE_ON_BATTERY: Expected boolean for pauseOnBattery.');
    }

    if (typeof obj.runMissedOnStartup !== 'boolean') {
      throw new Error('INVALID_SCHEDULE_RUN_MISSED: Expected boolean for runMissedOnStartup.');
    }

    if (typeof obj.autoQuarantine !== 'boolean') {
      throw new Error('INVALID_SCHEDULE_AUTO_QUARANTINE: Expected boolean for autoQuarantine.');
    }

    let maxCpuThresholdPct = 80;
    if (obj.maxCpuThresholdPct !== undefined && obj.maxCpuThresholdPct !== null) {
      if (typeof obj.maxCpuThresholdPct !== 'number' || !Number.isFinite(obj.maxCpuThresholdPct) || obj.maxCpuThresholdPct < 10 || obj.maxCpuThresholdPct > 100) {
        throw new Error('INVALID_SCHEDULE_CPU_THRESHOLD: Expected number between 10 and 100 for maxCpuThresholdPct.');
      }
      maxCpuThresholdPct = Math.floor(obj.maxCpuThresholdPct);
    }

    let minBatteryThresholdPct = 20;
    if (obj.minBatteryThresholdPct !== undefined && obj.minBatteryThresholdPct !== null) {
      if (typeof obj.minBatteryThresholdPct !== 'number' || !Number.isFinite(obj.minBatteryThresholdPct) || obj.minBatteryThresholdPct < 5 || obj.minBatteryThresholdPct > 100) {
        throw new Error('INVALID_SCHEDULE_BATTERY_THRESHOLD: Expected number between 5 and 100 for minBatteryThresholdPct.');
      }
      minBatteryThresholdPct = Math.floor(obj.minBatteryThresholdPct);
    }

    return {
      enabled: obj.enabled,
      frequency: obj.frequency,
      timeOfDay: obj.timeOfDay.trim(),
      weekday,
      scanType: obj.scanType,
      pauseOnBattery: obj.pauseOnBattery,
      runMissedOnStartup: obj.runMissedOnStartup,
      autoQuarantine: obj.autoQuarantine,
      maxCpuThresholdPct,
      minBatteryThresholdPct
    };
  }

  /**
   * Validates a path to an offline .ppdb update bundle file.
   */
  public static validateUpdateBundlePath(filePath: unknown): string {
    const validPath = this.validatePath(filePath);
    if (!validPath.toLowerCase().endsWith('.ppdb')) {
      throw new Error('INVALID_UPDATE_BUNDLE: File must have a .ppdb extension.');
    }
    return validPath;
  }

  /**
   * Validates an update bundle payload or file path passed over IPC.
   */
  public static validateApplyBundlePayload(input: unknown): string | PpdbBundle {
    if (typeof input === 'string') {
      return this.validateUpdateBundlePath(input);
    }
    if (!input || typeof input !== 'object') {
      throw new Error('INVALID_UPDATE_BUNDLE: Payload must be a file path or valid PpdbBundle object.');
    }
    const bundle = input as any;
    if (!bundle.manifest || typeof bundle.manifest !== 'object') {
      throw new Error('INVALID_UPDATE_BUNDLE: Manifest is missing or invalid.');
    }
    if (!bundle.payload || typeof bundle.payload !== 'object') {
      throw new Error('INVALID_UPDATE_BUNDLE: Payload is missing or invalid.');
    }
    if (typeof bundle.signature !== 'string' || !/^[0-9a-fA-F]{128}$/.test(bundle.signature.trim())) {
      throw new Error('INVALID_UPDATE_BUNDLE: Signature is missing or invalid hex format.');
    }
    return bundle as PpdbBundle;
  }

  /**
   * Validates AuditQueryFilter object passed over IPC.
   */
  public static validateAuditFilter(input: unknown): AuditQueryFilter {
    if (!input || typeof input !== 'object') {
      return {};
    }
    const raw = input as Record<string, unknown>;
    let category: AuditLogCategory | undefined;
    let severity: AuditLogSeverity | undefined;
    let startDate: number | undefined;
    let endDate: number | undefined;
    let search: string | undefined;
    let offset: number | undefined;
    let limit: number | undefined;

    const validCategories: AuditLogCategory[] = [
      'DETECTION',
      'SCAN',
      'QUARANTINE',
      'PROCESS',
      'CONFIGURATION',
      'HEALTH_CHECK',
      'WATCHDOG',
      'TAMPER_DETECTION',
      'UPDATE',
      'SHRED',
      'EXCLUSION',
      'SYSTEM'
    ];
    if (typeof raw.category === 'string' && validCategories.includes(raw.category as AuditLogCategory)) {
      category = raw.category as AuditLogCategory;
    }

    const validSeverities: AuditLogSeverity[] = ['INFO', 'WARN', 'ERROR', 'CRITICAL'];
    if (typeof raw.severity === 'string' && validSeverities.includes(raw.severity as AuditLogSeverity)) {
      severity = raw.severity as AuditLogSeverity;
    }

    if (typeof raw.startDate === 'number' && Number.isFinite(raw.startDate) && raw.startDate >= 0) {
      startDate = raw.startDate;
    }

    if (typeof raw.endDate === 'number' && Number.isFinite(raw.endDate) && raw.endDate >= 0) {
      endDate = raw.endDate;
    }

    if (typeof raw.search === 'string') {
      search = raw.search.trim().slice(0, 100);
    }

    if (typeof raw.offset === 'number' && Number.isFinite(raw.offset) && raw.offset >= 0) {
      offset = Math.floor(raw.offset);
    }

    if (typeof raw.limit === 'number' && Number.isFinite(raw.limit) && raw.limit >= 1) {
      limit = Math.min(1000, Math.floor(raw.limit));
    }

    return {
      ...(category ? { category } : {}),
      ...(severity ? { severity } : {}),
      ...(startDate !== undefined ? { startDate } : {}),
      ...(endDate !== undefined ? { endDate } : {}),
      ...(search ? { search } : {}),
      ...(offset !== undefined ? { offset } : {}),
      ...(limit !== undefined ? { limit } : {})
    };
  }

  /**
   * Validates export format ('json' | 'csv').
   */
  public static validateExportFormat(format: unknown): 'json' | 'csv' {
    if (format === 'csv') return 'csv';
    return 'json';
  }

  /**
   * Validates shield snooze duration in milliseconds.
   */
  public static validateSnoozeDuration(durationMs: unknown): number {
    if (typeof durationMs !== 'number' || !Number.isFinite(durationMs) || durationMs < 1000 || durationMs > 86400000) {
      throw new Error('INVALID_SNOOZE_DURATION: Duration must be between 1,000ms and 86,400,000ms (24h).');
    }
    return Math.floor(durationMs);
  }

  /**
   * Validates component name for watchdog isolation reset.
   */
  public static validateComponentName(name: unknown): string {
    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 100) {
      throw new Error('INVALID_COMPONENT_NAME: Component name must be a non-empty string under 100 characters.');
    }
    return name.trim();
  }
}


