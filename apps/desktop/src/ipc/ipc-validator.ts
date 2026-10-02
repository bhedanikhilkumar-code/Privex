import * as path from 'path';

export class IpcValidator {
  private static readonly FORBIDDEN_SHELL_CHARS = /[|&;$`><\r\n\0]/;

  /**
   * Validates and normalizes a candidate filesystem path.
   * Throws on path traversal, null bytes, or dangerous shell characters.
   */
  public static validatePath(inputPath: unknown): string {
    if (typeof inputPath !== 'string') {
      throw new Error('INVALID_PATH: Path must be a non-empty string.');
    }

    const trimmed = inputPath.trim();
    if (!trimmed || trimmed.length > 1024) {
      throw new Error('INVALID_PATH: Path length must be between 1 and 1024 characters.');
    }

    if (trimmed.includes('\0')) {
      throw new Error('SECURITY_VIOLATION: Null byte detected in path.');
    }

    if (this.FORBIDDEN_SHELL_CHARS.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Path contains forbidden shell metacharacters or control bytes.');
    }

    const resolved = path.resolve(trimmed);
    return resolved;
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
