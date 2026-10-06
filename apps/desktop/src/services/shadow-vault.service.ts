import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import {
  ShadowVaultBackupRecord,
  ShadowVaultOptions,
  ShadowVaultStats,
  FileRollbackResult,
  IncidentRollbackResult
} from '../types/desktop.types';
import { IpcValidator } from '../ipc/ipc-validator';

/**
 * ShadowVaultService (Phase G)
 *
 * Implements authenticated Copy-on-Write encrypted local backups of protected documents:
 * - Location: ~/.private-protection/shadow-vault/
 * - Encryption: Authenticated AES-256-GCM container (magic: PPSHADOW1)
 * - Limits: 50 MB per file, 2 GB total vault quota with FIFO eviction
 * - Rollback: 1-click rollbackIncident(incidentId) with mandatory exact pre-attack SHA-256 revalidation
 * - Anti-corruption: Atomic writes, authenticated tags, .bak manifest recovery, fail-closed rollback
 */
export class ShadowVaultService {
  private vaultDir: string;
  private manifestPath: string;
  private vaultKey: Buffer;
  private manifest: Map<string, ShadowVaultBackupRecord> = new Map();
  private readonly maxFileSizeBytes: number;
  private readonly maxVaultQuotaBytes: number;

  public static readonly DEFAULT_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;      // 50 MB
  public static readonly DEFAULT_MAX_VAULT_QUOTA_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB
  public static readonly CONTAINER_MAGIC = Buffer.from('PPSHADOW1', 'utf8');   // 8 bytes
  public static readonly MANIFEST_MAGIC = Buffer.from('PPSMANIF1', 'utf8');    // 8 bytes

  constructor(options?: ShadowVaultOptions) {
    this.vaultDir = path.resolve(
      options?.customVaultDir || path.join(os.homedir(), '.private-protection', 'shadow-vault')
    );
    this.maxFileSizeBytes = options?.maxFileSizeBytes ?? ShadowVaultService.DEFAULT_MAX_FILE_SIZE_BYTES;
    this.maxVaultQuotaBytes = options?.maxVaultQuotaBytes ?? ShadowVaultService.DEFAULT_MAX_VAULT_QUOTA_BYTES;
    this.manifestPath = path.join(this.vaultDir, 'shadow-manifest.json.enc');

    this.ensureSafeVaultDir();
    this.vaultKey = this.initVaultKey();
    this.loadManifest();
  }

  public getVaultDir(): string {
    return this.vaultDir;
  }

  private ensureSafeVaultDir(): void {
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }
    const stat = fs.lstatSync(this.vaultDir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error('SECURITY_VIOLATION: ShadowVault directory cannot be a symbolic link or non-directory.');
    }
  }

  /**
   * Initializes or loads the 256-bit vault master key.
   */
  private initVaultKey(): Buffer {
    this.ensureSafeVaultDir();
    const keyPath = path.join(this.vaultDir, '.vault.key');

    if (fs.existsSync(keyPath)) {
      try {
        const stat = fs.lstatSync(keyPath);
        if (!stat.isSymbolicLink() && stat.isFile()) {
          const loaded = fs.readFileSync(keyPath);
          if (loaded.length === 32) {
            return loaded;
          }
        }
      } catch {
        // Fall through to regeneration
      }
    }

    const saltPath = path.join(this.vaultDir, '.vault.salt');
    let salt: Buffer;
    if (fs.existsSync(saltPath)) {
      try {
        salt = fs.readFileSync(saltPath);
      } catch {
        salt = crypto.randomBytes(32);
        this.writeAtomicFileSync(saltPath, salt, 0o600);
      }
    } else {
      salt = crypto.randomBytes(32);
      this.writeAtomicFileSync(saltPath, salt, 0o600);
    }

    const machineSecret = `${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}:SHADOWVAULT`;
    const derivedKey = crypto.pbkdf2Sync(machineSecret, salt, 100000, 32, 'sha256');
    this.writeAtomicFileSync(keyPath, derivedKey, 0o600);
    return derivedKey;
  }

  private writeAtomicFileSync(targetPath: string, content: Buffer | string, mode = 0o600): void {
    this.ensureSafeVaultDir();
    const tmpPath = `${targetPath}.tmp.${Date.now()}.${Math.random().toString(36).substring(2, 7)}`;
    const fd = fs.openSync(tmpPath, 'w', mode);
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

  private loadManifest(): void {
    this.manifest.clear();
    if (!fs.existsSync(this.manifestPath)) {
      return;
    }

    try {
      const encrypted = fs.readFileSync(this.manifestPath);
      const decrypted = this.decryptManifest(encrypted);
      const items: ShadowVaultBackupRecord[] = JSON.parse(decrypted);
      for (const item of items) {
        if (item.backupId && item.canonicalPath && item.preAttackSha256) {
          this.manifest.set(item.backupId, item);
        }
      }
    } catch {
      // Attempt recovery from .bak
      const bakPath = `${this.manifestPath}.bak`;
      if (fs.existsSync(bakPath)) {
        try {
          const encBak = fs.readFileSync(bakPath);
          const decBak = this.decryptManifest(encBak);
          const items: ShadowVaultBackupRecord[] = JSON.parse(decBak);
          for (const item of items) {
            this.manifest.set(item.backupId, item);
          }
          this.saveManifest(); // Recommit primary manifest
          return;
        } catch {
          // Fall through to empty manifest
        }
      }
    }
  }

  private saveManifest(): void {
    this.ensureSafeVaultDir();
    const items = Array.from(this.manifest.values());
    const jsonStr = JSON.stringify(items);
    const encrypted = this.encryptManifest(jsonStr);

    // Save .bak copy of current working manifest if it exists
    if (fs.existsSync(this.manifestPath)) {
      try {
        fs.copyFileSync(this.manifestPath, `${this.manifestPath}.bak`);
      } catch {
        // Best effort
      }
    }

    this.writeAtomicFileSync(this.manifestPath, encrypted, 0o600);
  }

  private encryptManifest(plainText: string): Buffer {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
    const cipherText = Buffer.concat([cipher.update(Buffer.from(plainText, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Container: [MAGIC 8B] [IV 12B] [TAG 16B] [CIPHERTEXT]
    return Buffer.concat([ShadowVaultService.MANIFEST_MAGIC, iv, tag, cipherText]);
  }

  private decryptManifest(data: Buffer): string {
    const magicLen = ShadowVaultService.MANIFEST_MAGIC.length;
    const minLen = magicLen + 12 + 16;
    if (data.length < minLen) {
      throw new Error('CORRUPTED_MANIFEST: Manifest file length too short.');
    }

    const magic = data.subarray(0, magicLen);
    if (!magic.equals(ShadowVaultService.MANIFEST_MAGIC)) {
      throw new Error('INVALID_MANIFEST_MAGIC: Header magic mismatch.');
    }

    const iv = data.subarray(magicLen, magicLen + 12);
    const tag = data.subarray(magicLen + 12, magicLen + 28);
    const cipherText = data.subarray(magicLen + 28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
    decipher.setAuthTag(tag);
    const plainText = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return plainText.toString('utf8');
  }

  /**
   * Encrypts a file payload into authenticated PPSHADOW1 container format.
   */
  private encryptPayload(plainBytes: Buffer, canonicalPath: string, sha256: string): {
    container: Buffer;
    ivHex: string;
    authTagHex: string;
  } {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);

    // AAD binds canonical path and expected pre-attack SHA256 to prevent cross-file substitution attacks
    const aad = Buffer.from(`${canonicalPath}|${sha256}`, 'utf8');
    cipher.setAAD(aad);

    const cipherText = Buffer.concat([cipher.update(plainBytes), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const container = Buffer.concat([
      ShadowVaultService.CONTAINER_MAGIC,
      iv,
      authTag,
      cipherText
    ]);

    return {
      container,
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex')
    };
  }

  /**
   * Decrypts an authenticated PPSHADOW1 container and verifies AAD and authentication tag.
   */
  private decryptPayload(container: Buffer, canonicalPath: string, expectedSha256: string): Buffer {
    const magicLen = ShadowVaultService.CONTAINER_MAGIC.length;
    const minLen = magicLen + 12 + 16;
    if (container.length < minLen) {
      throw new Error('CORRUPTED_BACKUP: Backup blob length too short.');
    }

    const magic = container.subarray(0, magicLen);
    if (!magic.equals(ShadowVaultService.CONTAINER_MAGIC)) {
      throw new Error('INVALID_BACKUP_MAGIC: ShadowVault container magic mismatch.');
    }

    const iv = container.subarray(magicLen, magicLen + 12);
    const authTag = container.subarray(magicLen + 12, magicLen + 28);
    const cipherText = container.subarray(magicLen + 28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
    const aad = Buffer.from(`${canonicalPath}|${expectedSha256}`, 'utf8');
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);

    try {
      const plainBytes = Buffer.concat([decipher.update(cipherText), decipher.final()]);
      return plainBytes;
    } catch (err: any) {
      throw new Error(`CORRUPTED_BACKUP: Authentication tag verification failed: ${err.message}`);
    }
  }

  /**
   * Enforces FIFO quota management. Evicts oldest backups until total size + requiredBytes <= maxVaultQuotaBytes.
   */
  private enforceQuota(requiredBytes: number): void {
    if (requiredBytes > this.maxVaultQuotaBytes) {
      throw new Error('QUOTA_EXCEEDED: Requested backup size exceeds total vault capacity.');
    }

    let currentTotal = this.getTotalVaultSizeBytes();
    if (currentTotal + requiredBytes <= this.maxVaultQuotaBytes) {
      return;
    }

    // Sort backups by timestamp ascending (oldest first)
    const sorted = Array.from(this.manifest.values()).sort(
      (a, b) => a.backupTimestamp - b.backupTimestamp
    );

    for (const item of sorted) {
      if (currentTotal + requiredBytes <= this.maxVaultQuotaBytes) {
        break;
      }

      // Evict oldest item
      this.manifest.delete(item.backupId);
      try {
        if (fs.existsSync(item.blobPath)) {
          fs.unlinkSync(item.blobPath);
        }
      } catch {
        // Ignore deletion errors
      }
      currentTotal -= item.fileSize;
    }

    this.saveManifest();
  }

  public getTotalVaultSizeBytes(): number {
    let sum = 0;
    for (const record of this.manifest.values()) {
      sum += record.fileSize;
    }
    return sum;
  }

  /**
   * Backs up a target file into ShadowVault with authenticated encryption and pre-attack SHA-256 binding.
   */
  public async backupFile(filePath: string, incidentId?: string): Promise<ShadowVaultBackupRecord> {
    const validatedPath = IpcValidator.validatePath(filePath);
    const canonicalPath = path.resolve(validatedPath);

    if (!fs.existsSync(canonicalPath)) {
      throw new Error(`FILE_NOT_FOUND: Cannot backup non-existent file '${canonicalPath}'.`);
    }

    const stat = fs.statSync(canonicalPath);
    if (stat.isDirectory()) {
      throw new Error(`INVALID_TARGET: Target path '${canonicalPath}' is a directory.`);
    }

    if (stat.size > this.maxFileSizeBytes) {
      throw new Error(
        `EXCEEDS_FILE_SIZE_LIMIT: File size (${stat.size} bytes) exceeds maximum limit of 50 MB (${this.maxFileSizeBytes} bytes).`
      );
    }

    // Read plain file bytes and compute pre-attack SHA-256
    const plainBytes = fs.readFileSync(canonicalPath);
    const preAttackSha256 = crypto.createHash('sha256').update(plainBytes).digest('hex');

    // Enforce quota with FIFO eviction before persisting
    this.enforceQuota(plainBytes.length);

    // Encrypt payload
    const backupId = `bk-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const blobPath = path.join(this.vaultDir, `${backupId}.blob`);
    const { container, ivHex, authTagHex } = this.encryptPayload(plainBytes, canonicalPath, preAttackSha256);

    // Write encrypted blob atomically
    this.writeAtomicFileSync(blobPath, container, 0o600);

    const record: ShadowVaultBackupRecord = {
      backupId,
      incidentId,
      originalPath: filePath,
      canonicalPath,
      preAttackSha256,
      fileSize: plainBytes.length,
      blobPath,
      backupTimestamp: Date.now(),
      iv: ivHex,
      authTag: authTagHex
    };

    this.manifest.set(backupId, record);
    this.saveManifest();

    return record;
  }

  /**
   * Restores an individual backed up file with mandatory exact SHA-256 re-verification.
   */
  public async rollbackFile(backupId: string, customDestination?: string): Promise<FileRollbackResult> {
    const record = this.manifest.get(backupId);
    if (!record) {
      return {
        success: false,
        filePath: 'UNKNOWN',
        originalSha256: 'UNKNOWN',
        error: `BACKUP_NOT_FOUND: No backup record found for ID '${backupId}'.`
      };
    }

    const targetDest = customDestination
      ? path.resolve(IpcValidator.validatePath(customDestination))
      : record.canonicalPath;

    // Verify blob exists
    if (!fs.existsSync(record.blobPath)) {
      return {
        success: false,
        filePath: targetDest,
        originalSha256: record.preAttackSha256,
        error: `BLOB_NOT_FOUND: Encrypted blob '${record.blobPath}' missing from vault.`
      };
    }

    try {
      const container = fs.readFileSync(record.blobPath);
      const plainBytes = this.decryptPayload(container, record.canonicalPath, record.preAttackSha256);

      // Ensure target destination directory exists
      const targetDir = path.dirname(targetDest);
      if (!fs.existsSync(targetDir)) {
        fs.mkdirSync(targetDir, { recursive: true });
      }

      // Write restored file atomically
      this.writeAtomicFileSync(targetDest, plainBytes, 0o644);

      // Recompute and verify restored SHA-256
      const restoredBytes = fs.readFileSync(targetDest);
      const restoredSha256 = crypto.createHash('sha256').update(restoredBytes).digest('hex');

      if (restoredSha256 !== record.preAttackSha256) {
        // Rollback failed closed: delete corrupted restoration immediately
        try {
          fs.unlinkSync(targetDest);
        } catch {
          // Ignore
        }
        return {
          success: false,
          filePath: targetDest,
          originalSha256: record.preAttackSha256,
          restoredSha256,
          error: `RESTORATION_HASH_MISMATCH: Restored file SHA-256 '${restoredSha256}' does not match expected pre-attack hash '${record.preAttackSha256}'. File deleted for safety.`
        };
      }

      return {
        success: true,
        filePath: targetDest,
        originalSha256: record.preAttackSha256,
        restoredSha256,
        bytesRestored: plainBytes.length
      };
    } catch (err: any) {
      return {
        success: false,
        filePath: targetDest,
        originalSha256: record.preAttackSha256,
        error: err?.message || 'Decryption or restoration failed.'
      };
    }
  }

  /**
   * Rolls back all files associated with a ransomware incident.
   * Success is true ONLY IF all files are restored and verified with exact pre-attack SHA-256!
   */
  public async rollbackIncident(incidentId: string): Promise<IncidentRollbackResult> {
    if (!incidentId || typeof incidentId !== 'string') {
      return {
        incidentId: String(incidentId),
        success: false,
        totalFiles: 0,
        restoredCount: 0,
        failedCount: 1,
        restoredFiles: [],
        failedFiles: [{ filePath: 'N/A', reason: 'INVALID_INCIDENT_ID' }],
        completedAt: Date.now()
      };
    }

    const matchingRecords = Array.from(this.manifest.values()).filter(
      (r) => r.incidentId === incidentId
    );

    if (matchingRecords.length === 0) {
      return {
        incidentId,
        success: false,
        totalFiles: 0,
        restoredCount: 0,
        failedCount: 1,
        restoredFiles: [],
        failedFiles: [{ filePath: 'N/A', reason: `INCIDENT_NOT_FOUND: No backups for incident '${incidentId}'.` }],
        completedAt: Date.now()
      };
    }

    const restoredFiles: Array<{
      filePath: string;
      originalSha256: string;
      restoredSha256: string;
      bytesRestored: number;
    }> = [];

    const failedFiles: Array<{
      filePath: string;
      reason: string;
    }> = [];

    for (const record of matchingRecords) {
      const result = await this.rollbackFile(record.backupId);
      if (result.success && result.restoredSha256) {
        restoredFiles.push({
          filePath: result.filePath,
          originalSha256: result.originalSha256,
          restoredSha256: result.restoredSha256,
          bytesRestored: result.bytesRestored ?? record.fileSize
        });
      } else {
        failedFiles.push({
          filePath: result.filePath,
          reason: result.error || 'Restoration failed'
        });
      }
    }

    const allSucceeded = failedFiles.length === 0 && restoredFiles.length === matchingRecords.length;

    return {
      incidentId,
      success: allSucceeded,
      totalFiles: matchingRecords.length,
      restoredCount: restoredFiles.length,
      failedCount: failedFiles.length,
      restoredFiles,
      failedFiles,
      completedAt: Date.now()
    };
  }

  public getStats(): ShadowVaultStats {
    const totalSizeBytes = this.getTotalVaultSizeBytes();
    const utilizationPercent = Math.min(
      100,
      Math.round((totalSizeBytes / this.maxVaultQuotaBytes) * 10000) / 100
    );
    return {
      backupCount: this.manifest.size,
      totalSizeBytes,
      maxQuotaBytes: this.maxVaultQuotaBytes,
      utilizationPercent
    };
  }

  public getBackups(): ShadowVaultBackupRecord[] {
    return Array.from(this.manifest.values());
  }

  public getIncidentBackups(incidentId: string): ShadowVaultBackupRecord[] {
    return Array.from(this.manifest.values()).filter((r) => r.incidentId === incidentId);
  }

  public purgeAll(): void {
    try {
      if (fs.existsSync(this.vaultDir)) {
        const entries = fs.readdirSync(this.vaultDir);
        for (const entry of entries) {
          const p = path.join(this.vaultDir, entry);
          try {
            fs.unlinkSync(p);
          } catch {
            // Ignore
          }
        }
      }
    } catch {
      // Ignore
    }
    this.manifest.clear();
  }
}
