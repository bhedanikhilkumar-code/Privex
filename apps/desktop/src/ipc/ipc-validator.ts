import * as path from 'path';

export class IpcValidator {
  private static readonly FORBIDDEN_SHELL_CHARS = /[|&;$`><\r\n\0]/;
  private static readonly PARENT_TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
  private static readonly UNC_PATH_PATTERN = /^(?:\\\\|\/\/)/;

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
}
