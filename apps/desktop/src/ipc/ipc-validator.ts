import * as path from 'path';
import { DesktopSettings, DetectedThreat } from '../types/desktop.types';

export class IpcValidator {
  private static readonly FORBIDDEN_SHELL_CHARS = /[|&;$`><\r\n\0]/;
  private static readonly PARENT_TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
  private static readonly UNC_PATH_PATTERN = /^(?:\\\\|\/\/)/;
  private static readonly PROTECTED_SYSTEM_PREFIXES = [
    'c:\\windows',
    'c:\\program files',
    'c:\\program files (x86)',
    'c:\\programdata\\microsoft',
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
   * Throws on path traversal (..), UNC shares, null bytes, or dangerous shell characters.
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

    if (this.PARENT_TRAVERSAL_PATTERN.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Relative parent directory traversal (..) is prohibited.');
    }

    const resolved = path.resolve(trimmed);
    return resolved;
  }

  /**
   * Checks whether a canonical path points into a protected OS system directory.
   * Explicitly permits the system/user temp directory (e.g. C:\Windows\Temp or os.tmpdir())
   * since temporary directories are active malware ingress points.
   */
  public static isProtectedSystemPath(filePath: string): boolean {
    const rawSlash = filePath.trim().replace(/\\/g, '/').toLowerCase();
    if (rawSlash === '/tmp' || rawSlash.startsWith('/tmp/')) {
      return false;
    }
    const normalized = path.resolve(filePath).toLowerCase();
    if (
      normalized === 'c:\\windows\\temp' ||
      normalized.startsWith('c:\\windows\\temp\\')
    ) {
      return false;
    }
    return this.PROTECTED_SYSTEM_PREFIXES.some(
      (prefix) =>
        normalized === prefix ||
        normalized.startsWith(prefix + '\\') ||
        normalized.startsWith(prefix + '/') ||
        rawSlash === prefix ||
        rawSlash.startsWith(prefix + '/')
    );
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
}
