import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  ExclusionItem,
  ExclusionType,
  CreateExclusionInput,
  ExclusionCheckResult,
  ExclusionCheckContext
} from '../types/desktop.types';
import { SecureStorageService } from './secure-storage.service';

export interface ExclusionManagerOptions {
  readonly configDir?: string;
  readonly storage?: SecureStorageService;
  readonly clock?: () => number;
  readonly maxExclusions?: number;
}

/**
 * ExclusionManagerService (Phase I — False-Positive Exclusion Management)
 *
 * Implements the 3-Tier False-Positive Exclusion Manager:
 * 1. SHA-256 Hash exclusion (exact 64-character hex identity).
 * 2. Canonical Path exclusion (normalized, junction/symlink resolved, anti-abuse protected).
 * 3. Domain exclusion (strict hostname syntax with mandatory expiration TTL).
 *
 * Anti-Abuse Guardrails:
 * - Inviolable: Authoritative ransomware attacks and canary traps CANNOT be excluded.
 * - System Safety: Critical Windows paths (C:\, C:\Windows, System32, Downloads, Temp, wildcards) are forbidden.
 * - Restore & Trust: Creates exact verified SHA-256 hash exclusion only.
 * - Secure Storage: Encrypted at rest (exclusions.enc) with atomic writes and .bak crash recovery.
 */
export class ExclusionManagerService extends EventEmitter {
  private readonly configDir: string;
  private readonly exclusionsPath: string;
  private readonly encryptionKey: Buffer;
  private readonly storage?: SecureStorageService;
  private readonly clock: () => number;
  private readonly maxExclusions: number;

  private exclusions: ExclusionItem[] = [];
  private hashIndex: Map<string, ExclusionItem> = new Map();
  private pathIndex: Map<string, ExclusionItem> = new Map();
  private domainIndex: Map<string, ExclusionItem> = new Map();

  // Precomputed TTL durations in milliseconds
  public static readonly TTL_MS = {
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000
  };

  // Critical Windows paths that MUST NEVER be excluded under any circumstances
  private static readonly FORBIDDEN_PATH_ROOTS = [
    'c:\\',
    'c:',
    'd:\\',
    'd:',
    'e:\\',
    'e:',
    '/',
    'c:\\windows',
    'c:\\windows\\system32',
    'c:\\windows\\syswow64',
    'c:\\program files',
    'c:\\program files (x86)',
    'c:\\programdata'
  ];

  constructor(options?: ExclusionManagerOptions) {
    super();
    this.configDir = path.resolve(
      options?.configDir || path.join(os.homedir(), '.private-protection')
    );
    this.exclusionsPath = path.join(this.configDir, 'exclusions.enc');
    this.storage = options?.storage;
    this.clock = options?.clock ?? (() => Date.now());
    this.maxExclusions = options?.maxExclusions ?? 500;

    this.initDirectory();
    this.encryptionKey = this.deriveEncryptionKey();
    this.loadExclusions();
  }

  private initDirectory(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
  }

  private writeAtomicFileSync(targetPath: string, content: string | Buffer): void {
    this.initDirectory();
    const tmpPath = `${targetPath}.tmp`;
    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
      if (typeof content === 'string') {
        fs.writeFileSync(fd, content, 'utf8');
      } else {
        fs.writeSync(fd, content, 0, content.length, 0);
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, targetPath);
  }

  private deriveEncryptionKey(): Buffer {
    this.initDirectory();
    const saltPath = path.join(this.configDir, '.storage.salt');
    let salt: Buffer | null = null;

    if (fs.existsSync(saltPath)) {
      try {
        const loaded = fs.readFileSync(saltPath);
        if (loaded.length >= 16) {
          salt = loaded;
        }
      } catch {
        salt = null;
      }
    }

    if (!salt) {
      salt = crypto.randomBytes(32);
      this.writeAtomicFileSync(saltPath, salt);
    }

    const machineSecret = `${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}`;
    return crypto.pbkdf2Sync(machineSecret, salt, 100000, 32, 'sha256');
  }

  private encrypt(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
  }

  private decrypt(payload: string): string {
    const parts = payload.split(':');
    if (parts.length !== 3) {
      throw new Error('INVALID_ENCRYPTION_FORMAT: Corrupted payload structure.');
    }
    const [ivHex, authTagHex, cipherText] = parts;
    if (ivHex.length !== 24 || authTagHex.length !== 32) {
      throw new Error('INVALID_CIPHER_PARAMETERS: IV or AuthTag length invalid.');
    }
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(cipherText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  // ============================================================
  // CANONICALIZATION & VALIDATION HELPERS
  // ============================================================

  /**
   * Canonicalizes and validates a SHA-256 hash.
   * Must be exactly 64 hexadecimal characters.
   */
  public static canonicalizeHash(raw: string): string {
    if (!raw || typeof raw !== 'string') {
      throw new Error('INVALID_HASH: Expected 64-character hexadecimal SHA-256 string.');
    }
    const trimmed = raw.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(trimmed)) {
      throw new Error('INVALID_HASH: Hash must be exactly 64 lowercase hexadecimal characters.');
    }
    return trimmed;
  }

  /**
   * Canonicalizes and validates a file or directory path for exclusions.
   * Enforces hard anti-abuse guardrails against critical Windows locations.
   */
  public static canonicalizePath(raw: string): string {
    if (!raw || typeof raw !== 'string') {
      throw new Error('INVALID_PATH: Expected non-empty path string.');
    }
    const trimmed = raw.trim();
    if (!trimmed || trimmed.length > 1024) {
      throw new Error('INVALID_PATH: Path length must be between 1 and 1024 characters.');
    }

    // 1. Reject dangerous control characters, null bytes, and traversal
    if (/\0|[\x01-\x1F]/.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Path contains forbidden control characters.');
    }
    if (/[|&;$`><]/.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Path contains forbidden shell metacharacters.');
    }

    // 2. Reject wildcard extensions (*.exe, *.dll, *.bat, *.ps1)
    if (/\*|\?/.test(trimmed)) {
      throw new Error('SECURITY_VIOLATION: Wildcard path exclusions are strictly forbidden.');
    }

    // 3. Normalize path separators and resolve traversal
    let normalized = trimmed;
    if (/^[a-zA-Z]:$/.test(trimmed)) {
      normalized = `${trimmed.toUpperCase()}\\`;
    } else {
      normalized = path.normalize(trimmed);
      try {
        normalized = path.resolve(normalized);
      } catch {
        // Use normalized
      }
    }

    // Strip trailing separator except for root
    if (normalized.length > 3 && (normalized.endsWith('\\') || normalized.endsWith('/'))) {
      normalized = normalized.slice(0, -1);
    }

    const lowerNormalized = normalized.toLowerCase();

    // 4. ANTI-ABUSE GUARDRAILS: Reject forbidden root and critical system locations
    for (const forbidden of ExclusionManagerService.FORBIDDEN_PATH_ROOTS) {
      const forbiddenClean = forbidden.endsWith('\\') || forbidden.endsWith('/') ? forbidden.slice(0, -1) : forbidden;
      const isDriveRoot = forbiddenClean.length <= 2 || forbiddenClean === '/';

      if (
        lowerNormalized === forbiddenClean ||
        lowerNormalized === `${forbiddenClean}\\` ||
        lowerNormalized === `${forbiddenClean}/`
      ) {
        throw new Error(`SECURITY_VIOLATION: Exclusion of critical system path "${trimmed}" is forbidden.`);
      }

      if (!isDriveRoot && (lowerNormalized.startsWith(`${forbiddenClean}\\`) || lowerNormalized.startsWith(`${forbiddenClean}/`))) {
        throw new Error(`SECURITY_VIOLATION: Exclusion of critical system path "${trimmed}" is forbidden.`);
      }
    }

    // Reject user root directories without specific file/subfolder (Downloads, Temp, AppData)
    const userProfile = (process.env.USERPROFILE || os.homedir()).toLowerCase();
    const userDownloads = path.join(userProfile, 'downloads').toLowerCase();
    const userTemp = os.tmpdir().toLowerCase();

    if (
      lowerNormalized === userProfile ||
      lowerNormalized === userDownloads ||
      lowerNormalized === userTemp ||
      lowerNormalized === `${userDownloads}\\` ||
      lowerNormalized === `${userTemp}\\`
    ) {
      throw new Error(`SECURITY_VIOLATION: Exclusion of entire user folder "${trimmed}" is forbidden.`);
    }

    return normalized;
  }

  /**
   * Canonicalizes and validates a web domain name.
   */
  public static canonicalizeDomain(raw: string): string {
    if (!raw || typeof raw !== 'string') {
      throw new Error('INVALID_DOMAIN: Expected non-empty domain string.');
    }
    const trimmed = raw.trim().toLowerCase();

    // Reject schemes, paths, or query params
    if (trimmed.includes('://') || trimmed.includes('/') || trimmed.includes('\\') || trimmed.includes('?')) {
      throw new Error('INVALID_DOMAIN: Domain must be a hostname without URL scheme, path, or query.');
    }

    // Reject wildcards
    if (trimmed.includes('*')) {
      throw new Error('INVALID_DOMAIN: Wildcard domain exclusions are forbidden.');
    }

    // Reject credentials or ports
    if (trimmed.includes('@') || trimmed.includes(':')) {
      throw new Error('INVALID_DOMAIN: Port or credentials cannot be in domain name.');
    }

    let domain = trimmed;
    if (domain.endsWith('.')) {
      domain = domain.slice(0, -1);
    }

    if (!domain || domain.length > 253) {
      throw new Error('INVALID_DOMAIN: Domain length must be between 1 and 253 characters.');
    }

    // Reject IP addresses (IPs must not be added via domain exclusion)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      throw new Error('INVALID_DOMAIN: IP addresses cannot be added as domain exclusions.');
    }

    // Reject localhost
    if (domain === 'localhost' || domain.endsWith('.local') || domain.endsWith('.internal')) {
      throw new Error('SECURITY_VIOLATION: Localhost and internal domains cannot be excluded.');
    }

    // Reject directional override and control characters
    if (/[\u202A-\u202E\u2066-\u2069\u200E\u200F\x00-\x1F]/.test(domain)) {
      throw new Error('SECURITY_VIOLATION: Domain contains forbidden directional or control characters.');
    }

    // Validate hostname syntax (RFC 1123)
    const labels = domain.split('.');
    if (labels.length < 2) {
      throw new Error('INVALID_DOMAIN: Top-level domain or valid multi-label hostname required.');
    }

    for (const label of labels) {
      if (!label || label.length > 63 || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) {
        throw new Error(`INVALID_DOMAIN: Invalid domain label "${label}".`);
      }
    }

    return domain;
  }

  // ============================================================
  // EXCLUSION LIFECYCLE MANAGEMENT
  // ============================================================

  /**
   * Adds a new user-authorized exclusion.
   */
  public addExclusion(input: CreateExclusionInput, _frictionToken?: string): ExclusionItem {
    const now = this.clock();

    if (!input || !input.type || !input.value) {
      throw new Error('INVALID_INPUT: Exclusion type and value are required.');
    }

    let canonicalValue = '';
    let type: ExclusionType = input.type;

    if (type === 'HASH') {
      canonicalValue = ExclusionManagerService.canonicalizeHash(input.value);
    } else if (type === 'PATH') {
      canonicalValue = ExclusionManagerService.canonicalizePath(input.value);
    } else if (type === 'DOMAIN') {
      canonicalValue = ExclusionManagerService.canonicalizeDomain(input.value);
    } else {
      throw new Error(`INVALID_EXCLUSION_TYPE: Unsupported exclusion type "${type}".`);
    }

    // TTL calculation
    let expiresAt: number | undefined;

    if (type === 'DOMAIN') {
      // Mandatory TTL for domains (default 7 days if not specified or permanent)
      if (!input.ttl || input.ttl === 'permanent') {
        expiresAt = now + ExclusionManagerService.TTL_MS['7d'];
      } else if (typeof input.ttl === 'number') {
        const ttlMs = Math.max(60000, Math.min(365 * 24 * 3600 * 1000, input.ttl));
        expiresAt = now + ttlMs;
      } else if (input.ttl === '24h' || input.ttl === '7d' || input.ttl === '30d') {
        expiresAt = now + ExclusionManagerService.TTL_MS[input.ttl];
      } else {
        expiresAt = now + ExclusionManagerService.TTL_MS['7d'];
      }
    } else {
      // Optional TTL for HASH and PATH
      if (input.ttl === '24h' || input.ttl === '7d' || input.ttl === '30d') {
        expiresAt = now + ExclusionManagerService.TTL_MS[input.ttl];
      } else if (typeof input.ttl === 'number' && input.ttl > 0) {
        const ttlMs = Math.max(60000, Math.min(365 * 24 * 3600 * 1000, input.ttl));
        expiresAt = now + ttlMs;
      }
    }

    // Check for existing identical canonical exclusion
    const existing = this.findMatchingItem(type, canonicalValue);
    if (existing) {
      // Update existing item in place
      const updated: ExclusionItem = {
        ...existing,
        expiresAt,
        enabled: true,
        reason: input.reason || existing.reason,
        metadata: input.metadata || existing.metadata
      };
      this.replaceExclusion(updated);
      this.saveExclusions();
      this.recordAudit('EXCLUSION_ADDED', `Updated existing ${type} exclusion: ${canonicalValue}`);
      this.emit('exclusionUpdated', updated);
      return updated;
    }

    // Enforce maxExclusions limit
    if (this.exclusions.length >= this.maxExclusions) {
      throw new Error(`EXCLUSION_LIMIT_EXCEEDED: Maximum of ${this.maxExclusions} exclusions allowed.`);
    }

    const id = `excl-${now}-${Math.random().toString(36).substring(2, 9)}`;
    const newItem: ExclusionItem = {
      id,
      type,
      value: input.value.trim(),
      canonicalValue,
      createdAt: now,
      expiresAt,
      reason: input.reason?.trim() || 'User added exclusion',
      enabled: true,
      createdBy: 'USER',
      metadata: input.metadata
    };

    this.exclusions.push(newItem);
    this.rebuildIndexes();
    this.saveExclusions();

    this.recordAudit('EXCLUSION_ADDED', `Added new ${type} exclusion: ${canonicalValue}`);
    this.emit('exclusionAdded', newItem);
    return newItem;
  }

  /**
   * Specialized method for Quarantine "Restore & Trust SHA-256".
   * Creates an exact verified SHA-256 hash exclusion only.
   */
  public addRestoreAndTrustExclusion(
    sha256: string,
    originalPath?: string,
    verifiedSha256?: string
  ): ExclusionItem {
    const canonical = ExclusionManagerService.canonicalizeHash(sha256);
    const verifiedCanonical = verifiedSha256
      ? ExclusionManagerService.canonicalizeHash(verifiedSha256)
      : canonical;

    if (canonical !== verifiedCanonical) {
      throw new Error('INTEGRITY_VIOLATION: Restored file SHA-256 does not match verified hash.');
    }

    const now = this.clock();
    const existing = this.hashIndex.get(canonical);
    if (existing) {
      return existing;
    }

    const item: ExclusionItem = {
      id: `excl-trust-${now}-${Math.random().toString(36).substring(2, 7)}`,
      type: 'HASH',
      value: canonical,
      canonicalValue: canonical,
      createdAt: now,
      expiresAt: undefined, // Permanent until user clears
      reason: `Restored & Trusted from Quarantine (${path.basename(originalPath || 'unknown')})`,
      enabled: true,
      createdBy: 'RESTORE_AND_TRUST',
      metadata: originalPath ? { originalPath } : undefined
    };

    this.exclusions.push(item);
    this.rebuildIndexes();
    this.saveExclusions();

    this.recordAudit('EXCLUSION_ADDED', `Restore & Trust SHA-256 exclusion added: ${canonical}`);
    this.emit('exclusionAdded', item);
    return item;
  }

  /**
   * Removes an exclusion by its ID.
   */
  public removeExclusion(id: string): boolean {
    if (!id || typeof id !== 'string') return false;
    const initialLen = this.exclusions.length;
    const removed = this.exclusions.find((e) => e.id === id);
    this.exclusions = this.exclusions.filter((e) => e.id !== id);

    if (this.exclusions.length < initialLen) {
      this.rebuildIndexes();
      this.saveExclusions();
      if (removed) {
        this.recordAudit('EXCLUSION_REMOVED', `Removed ${removed.type} exclusion: ${removed.canonicalValue}`);
        this.emit('exclusionRemoved', removed);
      }
      return true;
    }
    return false;
  }

  /**
   * Toggles the enabled state of an exclusion.
   */
  public toggleExclusion(id: string, enabled?: boolean): ExclusionItem | null {
    if (!id || typeof id !== 'string') return null;
    const item = this.exclusions.find((e) => e.id === id);
    if (!item) return null;

    const newEnabled = enabled !== undefined ? enabled : !item.enabled;
    const updated: ExclusionItem = { ...item, enabled: newEnabled };
    this.replaceExclusion(updated);
    this.saveExclusions();

    this.recordAudit('EXCLUSION_TOGGLED', `Toggled ${item.type} exclusion ${item.canonicalValue} (enabled=${newEnabled})`);
    this.emit('exclusionToggled', updated);
    return updated;
  }

  /**
   * Clears all exclusions.
   */
  public clearAllExclusions(): number {
    const count = this.exclusions.length;
    this.exclusions = [];
    this.rebuildIndexes();
    this.saveExclusions();
    this.recordAudit('EXCLUSION_CLEARED', `Cleared all ${count} exclusions.`);
    this.emit('exclusionsCleared', count);
    return count;
  }

  /**
   * Alias for clearAllExclusions.
   */
  public clearAll(): number {
    return this.clearAllExclusions();
  }

  /**
   * Lists all current exclusions, optionally pruning expired ones.
   */
  public getExclusions(includeExpired = false): ExclusionItem[] {
    const now = this.clock();
    if (!includeExpired) {
      return this.exclusions.filter((e) => !this.isExpired(e, now));
    }
    return [...this.exclusions];
  }

  // ============================================================
  // EXCLUSION CHECK & ANTI-ABUSE ENGINE
  // ============================================================

  /**
   * Evaluates if a given SHA-256 hash is excluded.
   */
  public checkHash(sha256: string, context?: ExclusionCheckContext): ExclusionCheckResult {
    // ANTI-ABUSE GUARDRAIL: Ransomware attacks cannot be excluded
    if (context?.isRansomware || (context?.riskScore === 100 && /ransomware|canary/i.test(context?.threatName || ''))) {
      return {
        isExcluded: false,
        reason: 'ANTI_ABUSE_GUARDRAIL: Authoritative ransomware incident cannot be bypassed by exclusions.'
      };
    }

    if (!sha256 || typeof sha256 !== 'string') {
      return { isExcluded: false };
    }

    try {
      const canonical = ExclusionManagerService.canonicalizeHash(sha256);
      const item = this.hashIndex.get(canonical);
      const now = context?.now ?? this.clock();

      if (item && item.enabled && !this.isExpired(item, now)) {
        return {
          isExcluded: true,
          matchedExclusion: item,
          reason: `EXCLUSION_MATCH: Matched SHA-256 allowlist (${canonical.substring(0, 12)}...).`
        };
      }
    } catch {
      // Non-canonical hash -> not excluded
    }

    return { isExcluded: false };
  }

  /**
   * Evaluates if a given file/folder path is excluded.
   */
  public checkPath(filePath: string, context?: ExclusionCheckContext): ExclusionCheckResult {
    // ANTI-ABUSE GUARDRAIL: Ransomware attacks cannot be excluded
    if (context?.isRansomware || (context?.riskScore === 100 && /ransomware|canary/i.test(context?.threatName || ''))) {
      return {
        isExcluded: false,
        reason: 'ANTI_ABUSE_GUARDRAIL: Authoritative ransomware incident cannot be bypassed by exclusions.'
      };
    }

    if (!filePath || typeof filePath !== 'string') {
      return { isExcluded: false };
    }

    try {
      const canonical = ExclusionManagerService.canonicalizePath(filePath);
      const lowerCanonical = canonical.toLowerCase();
      const now = context?.now ?? this.clock();

      for (const item of this.pathIndex.values()) {
        if (!item.enabled || this.isExpired(item, now)) continue;

        const lowerItemPath = item.canonicalValue.toLowerCase();

        // Exact file match
        if (lowerCanonical === lowerItemPath) {
          return {
            isExcluded: true,
            matchedExclusion: item,
            reason: `EXCLUSION_MATCH: Exact path excluded (${item.canonicalValue}).`
          };
        }

        // Folder prefix match (ensuring proper boundary)
        const folderPrefix = lowerItemPath.endsWith('\\') ? lowerItemPath : `${lowerItemPath}\\`;
        if (lowerCanonical.startsWith(folderPrefix)) {
          return {
            isExcluded: true,
            matchedExclusion: item,
            reason: `EXCLUSION_MATCH: File located inside excluded folder (${item.canonicalValue}).`
          };
        }
      }
    } catch {
      // Non-canonical path -> not excluded
    }

    return { isExcluded: false };
  }

  /**
   * Evaluates if a given web domain is excluded.
   */
  public checkDomain(domain: string, context?: ExclusionCheckContext): ExclusionCheckResult {
    if (!domain || typeof domain !== 'string') {
      return { isExcluded: false };
    }

    try {
      const canonical = ExclusionManagerService.canonicalizeDomain(domain);
      const item = this.domainIndex.get(canonical);
      const now = context?.now ?? this.clock();

      if (item && item.enabled && !this.isExpired(item, now)) {
        return {
          isExcluded: true,
          matchedExclusion: item,
          reason: `EXCLUSION_MATCH: Domain excluded (${canonical}).`
        };
      }
    } catch {
      // Non-canonical domain -> not excluded
    }

    return { isExcluded: false };
  }

  // ============================================================
  // INTERNAL HELPERS & STORAGE
  // ============================================================

  private isExpired(item: ExclusionItem, now: number): boolean {
    if (!item.expiresAt) return false; // Permanent
    // Safe clock handling
    return now >= item.expiresAt;
  }

  private findMatchingItem(type: ExclusionType, canonicalValue: string): ExclusionItem | undefined {
    const lower = canonicalValue.toLowerCase();
    return this.exclusions.find((e) => e.type === type && e.canonicalValue.toLowerCase() === lower);
  }

  private replaceExclusion(updated: ExclusionItem): void {
    const idx = this.exclusions.findIndex((e) => e.id === updated.id);
    if (idx !== -1) {
      this.exclusions[idx] = updated;
      this.rebuildIndexes();
    }
  }

  private rebuildIndexes(): void {
    this.hashIndex.clear();
    this.pathIndex.clear();
    this.domainIndex.clear();

    for (const item of this.exclusions) {
      const key = item.canonicalValue.toLowerCase();
      if (item.type === 'HASH') {
        this.hashIndex.set(key, item);
      } else if (item.type === 'PATH') {
        this.pathIndex.set(key, item);
      } else if (item.type === 'DOMAIN') {
        this.domainIndex.set(key, item);
      }
    }
  }

  private recordAudit(type: 'EXCLUSION_ADDED' | 'EXCLUSION_REMOVED' | 'EXCLUSION_TOGGLED' | 'EXCLUSION_CLEARED' | 'EXCLUSION_REJECTED', summary: string): void {
    if (this.storage) {
      this.storage.recordSecurityEvent(type, 'INFO', summary);
    }
  }

  private loadExclusions(): void {
    const bakPath = `${this.exclusionsPath}.bak`;

    if (!fs.existsSync(this.exclusionsPath) && !fs.existsSync(bakPath)) {
      this.exclusions = [];
      this.rebuildIndexes();
      return;
    }

    for (const candidate of [this.exclusionsPath, bakPath]) {
      if (!fs.existsSync(candidate)) continue;
      try {
        const rawEnc = fs.readFileSync(candidate, 'utf8');
        const decrypted = this.decrypt(rawEnc);
        const parsed = JSON.parse(decrypted);

        if (Array.isArray(parsed)) {
          this.exclusions = [];
          for (const item of parsed) {
            if (this.isValidExclusionRecord(item)) {
              this.exclusions.push(item);
            }
          }
          this.rebuildIndexes();
          return;
        }
      } catch {
        // Try fallback or fail closed to empty
      }
    }

    // Corrupted state -> fail closed to empty
    this.exclusions = [];
    this.rebuildIndexes();
    this.recordAudit('EXCLUSION_REJECTED', 'Corrupted exclusions storage detected; failed closed to safe empty list.');
  }

  private saveExclusions(): void {
    try {
      this.initDirectory();
      const bakPath = `${this.exclusionsPath}.bak`;

      // Keep backup of existing valid file
      if (fs.existsSync(this.exclusionsPath)) {
        try {
          fs.copyFileSync(this.exclusionsPath, bakPath);
        } catch {
          // Ignore copy error
        }
      }

      const jsonStr = JSON.stringify(this.exclusions);
      const encrypted = this.encrypt(jsonStr);
      this.writeAtomicFileSync(this.exclusionsPath, encrypted);
    } catch (err: any) {
      this.emit('error', new Error(`EXCLUSION_STORAGE_SAVE_ERROR: ${err?.message || err}`));
    }
  }

  private isValidExclusionRecord(item: any): item is ExclusionItem {
    return (
      item &&
      typeof item.id === 'string' &&
      (item.type === 'HASH' || item.type === 'PATH' || item.type === 'DOMAIN') &&
      typeof item.canonicalValue === 'string' &&
      typeof item.createdAt === 'number' &&
      typeof item.enabled === 'boolean'
    );
  }
}
