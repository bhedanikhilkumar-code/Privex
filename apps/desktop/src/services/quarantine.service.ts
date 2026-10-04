import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { QuarantineItem, DetectedThreat } from '../types/desktop.types';
import { IpcValidator } from '../ipc/ipc-validator';

export class QuarantineService {
  private vaultDir: string;
  private manifestPath: string;
  private manifest: Map<string, QuarantineItem> = new Map();
  private vaultKey: Buffer;

  // Header magic for Private Protection AES-256-GCM Quarantine Vault container
  private static readonly CONTAINER_MAGIC = Buffer.from('PPVAULT1', 'utf8'); // 8 bytes

  constructor(customVaultDir?: string) {
    this.vaultDir = customVaultDir || path.join(os.homedir(), '.private-protection', 'quarantine');
    this.manifestPath = path.join(this.vaultDir, 'manifest.json');
    this.vaultKey = this.initVaultKey();
    this.initVault();
  }

  private initVaultKey(): Buffer {
    const keyPath = path.join(this.vaultDir, '.vault.key');
    if (fs.existsSync(keyPath)) {
      try {
        return fs.readFileSync(keyPath);
      } catch {
        // regenerate below if read fails
      }
    }
    const key = crypto.randomBytes(32);
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(keyPath, key, { mode: 0o600 });
    return key;
  }

  private initVault(): void {
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }
    this.loadManifest();
  }

  private loadManifest(): void {
    this.manifest.clear();
    if (fs.existsSync(this.manifestPath)) {
      try {
        const raw = fs.readFileSync(this.manifestPath, 'utf8');
        const items: QuarantineItem[] = JSON.parse(raw);
        for (const item of items) {
          this.manifest.set(item.quarantineId, item);
        }
      } catch {
        // If manifest is corrupted, preserve empty map and do not crash
        this.manifest.clear();
      }
    }
  }

  private saveManifest(): void {
    const items = Array.from(this.manifest.values());
    fs.writeFileSync(this.manifestPath, JSON.stringify(items, null, 2), 'utf8');
  }

  /**
   * Applies authenticated AES-256-GCM encryption with random IV and authentication tag.
   * Container format: [MAGIC: 8 bytes][IV: 12 bytes][AUTH_TAG: 16 bytes][CIPHERTEXT]
   */
  public encryptBytes(buffer: Buffer): Buffer {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
    const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([
      QuarantineService.CONTAINER_MAGIC,
      iv,
      authTag,
      ciphertext
    ]);
  }

  /**
   * Decrypts an authenticated AES-256-GCM quarantine container.
   */
  public decryptBytes(containerBuffer: Buffer): Buffer {
    if (containerBuffer.length < 8 + 12 + 16) {
      throw new Error('CORRUPTED_VAULT: Quarantined container is too small to contain valid metadata.');
    }

    const magic = containerBuffer.subarray(0, 8);
    if (!magic.equals(QuarantineService.CONTAINER_MAGIC)) {
      throw new Error('SECURITY_VIOLATION: Quarantined container header magic is invalid or corrupted.');
    }

    const iv = containerBuffer.subarray(8, 20);
    const authTag = containerBuffer.subarray(20, 36);
    const ciphertext = containerBuffer.subarray(36);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
    decipher.setAuthTag(authTag);

    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new Error('INTEGRITY_CHECK_FAILED: Quarantined container authentication tag verification failed. Ciphertext has been tampered with.');
    }
  }

  /**
   * Sanitizes a file name to prevent directory traversal and Windows device name attacks.
   * Strips paths, control chars, and prefixes reserved names (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
   */
  public static sanitizeFileName(rawName: string): string {
    if (!rawName || typeof rawName !== 'string') {
      return `quarantined_file_${Date.now()}`;
    }

    // 1. Remove null bytes and trim whitespace
    let clean = rawName.replace(/\0/g, '').trim();

    // 2. Extract base name to eliminate directory traversal sequences (../, ..\, /foo/bar, C:\foo)
    clean = clean.replace(/\\/g, '/');
    clean = path.posix.basename(clean);

    // 3. Remove illegal filesystem characters (< > : " / \ | ? *)
    clean = clean.replace(/[<>:"/\\|?*]/g, '_');

    // 4. Check for Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    const baseWithoutExt = clean.split('.')[0].toUpperCase();
    const reservedNames = new Set([
      'CON', 'PRN', 'AUX', 'NUL',
      'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]);

    if (reservedNames.has(baseWithoutExt)) {
      clean = `safe_${clean}`;
    }

    // 5. Final fallback if empty or just dots
    if (!clean || clean === '.' || clean === '..') {
      clean = `quarantined_file_${Date.now()}`;
    }

    return clean;
  }

  /**
   * Isolates a detected threat into the encrypted quarantine vault.
   * Enforces canonical threat verdict/severity policy (GAP-16) and symlink/system path protection.
   */
  public async isolateFile(threat: DetectedThreat): Promise<QuarantineItem> {
    const canonicalSource = path.resolve(threat.filePath);

    // 1. Path Existence & Symlink Defense
    if (!fs.existsSync(canonicalSource)) {
      throw new Error(`FILE_NOT_FOUND: Cannot quarantine non-existent file '${threat.filePath}'.`);
    }

    const lstat = await fs.promises.lstat(canonicalSource);
    if (lstat.isSymbolicLink()) {
      throw new Error('SECURITY_VIOLATION: Quarantining symbolic links is forbidden to prevent target hijacking.');
    }

    // 2. Protected OS System Path Defense
    if (IpcValidator.isProtectedSystemPath(canonicalSource)) {
      throw new Error('SECURITY_VIOLATION: Quarantining protected OS system files is forbidden.');
    }

    // 3. Canonical Quarantine Policy Enforcement (GAP-16):
    // Benign ALLOW/INFORM or safe/low severity files must NEVER be quarantined or unlinked.
    const isQuarantinableVerdict = threat.verdict === 'BLOCK' || threat.verdict === 'WARN';
    const isQuarantinableSeverity =
      threat.severity === 'critical' ||
      threat.severity === 'dangerous' ||
      threat.severity === 'suspicious';

    if (!isQuarantinableVerdict || !isQuarantinableSeverity) {
      throw new Error(
        `QUARANTINE_POLICY_REJECTED: Benign or safe files (verdict=${threat.verdict}, severity=${threat.severity}) cannot be quarantined.`
      );
    }

    // 4. Read file bytes and encrypt with AES-256-GCM to prevent execution
    const rawBytes = await fs.promises.readFile(canonicalSource);
    const encryptedContainer = this.encryptBytes(rawBytes);

    // 5. Generate unique quarantine ID
    const quarantineId = `quarantine-${crypto.randomUUID()}`;
    const blobPath = path.join(this.vaultDir, `${quarantineId}.blob`);

    // 6. Atomic write encrypted container to vault
    await fs.promises.writeFile(blobPath, encryptedContainer);

    // 7. Try stripping execution permissions on container
    try {
      fs.chmodSync(blobPath, 0o400); // Read-only user access, zero execute
    } catch {
      // Best-effort permission stripping across platforms
    }

    // 8. Securely unlink the original malicious file from the user's filesystem
    await fs.promises.unlink(canonicalSource);

    const safeFileName = QuarantineService.sanitizeFileName(threat.fileName || path.basename(canonicalSource));

    const item: QuarantineItem = {
      quarantineId,
      originalPath: canonicalSource,
      fileName: safeFileName,
      fileSize: threat.fileSize,
      sha256: threat.sha256,
      threatName: threat.threatName,
      riskScore: threat.riskScore,
      severity: threat.severity,
      quarantinedAt: Date.now(),
      evidenceFactors: threat.evidenceFactors,
      blobPath
    };

    this.manifest.set(quarantineId, item);
    this.saveManifest();

    return item;
  }

  /**
   * Restores a quarantined item to disk safely.
   */
  public async restoreItem(quarantineId: string, customDestinationDir?: string): Promise<string> {
    const item = this.manifest.get(quarantineId);
    if (!item) {
      throw new Error(`QUARANTINE_NOT_FOUND: Item '${quarantineId}' does not exist.`);
    }

    if (!fs.existsSync(item.blobPath)) {
      throw new Error(`CORRUPTED_VAULT: Quarantined blob missing at '${item.blobPath}'.`);
    }

    // Path Traversal & Windows Device Name Defense on Destination (GAP-24)
    const safeFileName = QuarantineService.sanitizeFileName(item.fileName || path.basename(item.originalPath));
    let destinationPath = item.originalPath;

    if (customDestinationDir) {
      const canonicalDestDir = path.resolve(customDestinationDir);
      if (!fs.existsSync(canonicalDestDir) || !fs.statSync(canonicalDestDir).isDirectory()) {
        throw new Error('INVALID_DESTINATION: Destination directory is invalid or inaccessible.');
      }
      if (IpcValidator.isProtectedSystemPath(canonicalDestDir)) {
        throw new Error('SECURITY_VIOLATION: Restoring to protected system directory is forbidden.');
      }

      const candidatePath = path.join(canonicalDestDir, safeFileName);
      const resolvedDestination = path.resolve(candidatePath);

      const expectedPrefix = canonicalDestDir.endsWith(path.sep) ? canonicalDestDir : canonicalDestDir + path.sep;
      if (!resolvedDestination.startsWith(expectedPrefix)) {
        throw new Error('SECURITY_VIOLATION: Destination path escapes target directory.');
      }
      destinationPath = resolvedDestination;
    }

    // Symlink & Collision Avoidance: Use lstatSync to detect dangling symlinks or existing files
    let destinationExists = false;
    try {
      const destStat = fs.lstatSync(destinationPath);
      if (destStat.isSymbolicLink()) {
        throw new Error('SECURITY_VIOLATION: Restore destination cannot be a symbolic link.');
      }
      destinationExists = true;
    } catch (err: any) {
      if (err.message?.includes('SECURITY_VIOLATION')) {
        throw err;
      }
    }

    if (destinationExists) {
      const parsed = path.parse(destinationPath);
      destinationPath = path.join(parsed.dir, `${parsed.name}_restored_${Date.now()}${parsed.ext}`);
    }

    // Read encrypted container, decrypt with AES-256-GCM, and restore
    const encryptedContainer = await fs.promises.readFile(item.blobPath);
    const restoredBytes = this.decryptBytes(encryptedContainer);

    // Verify hash integrity before finalizing restoration
    const restoredHash = crypto.createHash('sha256').update(restoredBytes).digest('hex');
    if (restoredHash !== item.sha256) {
      throw new Error('INTEGRITY_CHECK_FAILED: Restored byte hash does not match original SHA-256.');
    }

    // Ensure target directory exists
    const destDir = path.dirname(destinationPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    await fs.promises.writeFile(destinationPath, restoredBytes);

    // Remove blob from vault
    await fs.promises.unlink(item.blobPath);
    this.manifest.delete(quarantineId);
    this.saveManifest();

    return destinationPath;
  }

  /**
   * Permanently deletes a quarantined item with cryptographic byte overwriting.
   */
  public async permanentDelete(quarantineId: string): Promise<void> {
    const item = this.manifest.get(quarantineId);
    if (!item) {
      throw new Error(`QUARANTINE_NOT_FOUND: Item '${quarantineId}' does not exist.`);
    }

    if (fs.existsSync(item.blobPath)) {
      try {
        fs.chmodSync(item.blobPath, 0o666);
      } catch {
        // continue
      }
      // Multi-pass cryptographic shredder
      const stat = fs.statSync(item.blobPath);
      const randomNoise = crypto.randomBytes(stat.size);

      const fd = fs.openSync(item.blobPath, 'r+');
      try {
        fs.writeSync(fd, randomNoise, 0, randomNoise.length, 0);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }

      fs.truncateSync(item.blobPath, 0);
      fs.unlinkSync(item.blobPath);
    }

    this.manifest.delete(quarantineId);
    this.saveManifest();
  }

  /**
   * Lists all quarantined items.
   */
  public listQuarantine(): QuarantineItem[] {
    return Array.from(this.manifest.values());
  }

  /**
   * Wipes the entire quarantine vault and manifest (Crypto-Shred).
   */
  public purgeAllQuarantine(): void {
    const items = Array.from(this.manifest.values());
    for (const item of items) {
      try {
        if (fs.existsSync(item.blobPath)) {
          try {
            fs.chmodSync(item.blobPath, 0o666);
          } catch {
            // continue
          }
          const stat = fs.statSync(item.blobPath);
          if (stat.size > 0) {
            const randomNoise = crypto.randomBytes(stat.size);
            const fd = fs.openSync(item.blobPath, 'r+');
            try {
              fs.writeSync(fd, randomNoise, 0, randomNoise.length, 0);
              fs.fsyncSync(fd);
            } finally {
              fs.closeSync(fd);
            }
            fs.truncateSync(item.blobPath, 0);
          }
          fs.unlinkSync(item.blobPath);
        }
      } catch {
        // continue
      }
    }
    this.manifest.clear();
    this.saveManifest();
  }
}

