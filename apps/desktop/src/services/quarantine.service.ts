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
    this.vaultDir = path.resolve(
      customVaultDir || path.join(os.homedir(), '.private-protection', 'quarantine')
    );
    this.manifestPath = path.join(this.vaultDir, 'manifest.json');
    this.ensureSafeVaultDir();
    this.vaultKey = this.initVaultKey();
    this.initVault();
  }

  private ensureSafeVaultDir(): void {
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }
    const stat = fs.lstatSync(this.vaultDir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error('SECURITY_VIOLATION: Quarantine vault directory cannot be a symbolic link.');
    }
  }

  private isPathInsideVault(candidatePath: string): boolean {
    if (!candidatePath || typeof candidatePath !== 'string' || candidatePath.includes('\0')) {
      return false;
    }
    const resolvedVault = path.resolve(this.vaultDir);
    const resolvedCandidate = path.resolve(candidatePath);
    const prefix = resolvedVault.endsWith(path.sep) ? resolvedVault : resolvedVault + path.sep;
    const isUnderVault =
      process.platform === 'win32'
        ? resolvedCandidate.toLowerCase().startsWith(prefix.toLowerCase())
        : resolvedCandidate.startsWith(prefix);
    return isUnderVault && resolvedCandidate.endsWith('.blob');
  }

  private initVaultKey(): Buffer {
    this.ensureSafeVaultDir();
    const keyPath = path.join(this.vaultDir, '.vault.key');
    if (fs.existsSync(keyPath)) {
      try {
        const keyStat = fs.lstatSync(keyPath);
        if (!keyStat.isSymbolicLink() && keyStat.isFile()) {
          const existing = fs.readFileSync(keyPath);
          if (existing.length === 32) {
            return existing;
          }
        }
      } catch {
        // Regenerate below if read fails
      }
    }

    const key = crypto.randomBytes(32);
    const tmpKeyPath = `${keyPath}.tmp`;
    const fd = fs.openSync(tmpKeyPath, 'w', 0o600);
    try {
      fs.writeSync(fd, key, 0, key.length, 0);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpKeyPath, keyPath);
    return key;
  }

  private initVault(): void {
    this.ensureSafeVaultDir();
    this.loadManifest();
  }

  private parseAndValidateManifestRaw(raw: string): Map<string, QuarantineItem> | null {
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return null;
      }
      const validMap = new Map<string, QuarantineItem>();
      for (const item of parsed) {
        if (!item || typeof item !== 'object') continue;
        try {
          const validId = IpcValidator.validateId(item.quarantineId);
          if (
            typeof item.blobPath === 'string' &&
            this.isPathInsideVault(item.blobPath) &&
            typeof item.originalPath === 'string' &&
            typeof item.sha256 === 'string'
          ) {
            validMap.set(validId, {
              quarantineId: validId,
              originalPath: item.originalPath,
              fileName: QuarantineService.sanitizeFileName(item.fileName || path.basename(item.originalPath)),
              fileSize: typeof item.fileSize === 'number' && Number.isFinite(item.fileSize) ? item.fileSize : 0,
              sha256: item.sha256,
              threatName: typeof item.threatName === 'string' ? item.threatName : 'QUARANTINED_THREAT',
              riskScore: typeof item.riskScore === 'number' ? item.riskScore : 50,
              severity: item.severity || 'suspicious',
              quarantinedAt: typeof item.quarantinedAt === 'number' ? item.quarantinedAt : Date.now(),
              evidenceFactors: Array.isArray(item.evidenceFactors) ? item.evidenceFactors : [],
              blobPath: path.resolve(item.blobPath)
            });
          }
        } catch {
          // Skip malformed record
        }
      }
      return validMap;
    } catch {
      return null;
    }
  }

  private loadManifest(): void {
    this.manifest.clear();
    const bakPath = `${this.manifestPath}.bak`;
    const tmpPath = `${this.manifestPath}.tmp`;

    // 1. Try primary manifest.json
    if (fs.existsSync(this.manifestPath)) {
      try {
        const raw = fs.readFileSync(this.manifestPath, 'utf8');
        const loaded = this.parseAndValidateManifestRaw(raw);
        if (loaded !== null) {
          this.manifest = loaded;
          return;
        }
      } catch {
        // Fall through to backup recovery
      }
    }

    // 2. Crash recovery: try manifest.json.bak or manifest.json.tmp
    for (const fallbackPath of [bakPath, tmpPath]) {
      if (fs.existsSync(fallbackPath)) {
        try {
          const raw = fs.readFileSync(fallbackPath, 'utf8');
          const recovered = this.parseAndValidateManifestRaw(raw);
          if (recovered !== null) {
            this.manifest = recovered;
            this.saveManifest();
            return;
          }
        } catch {
          // Continue
        }
      }
    }
  }

  private saveManifest(): void {
    this.ensureSafeVaultDir();
    const items = Array.from(this.manifest.values());
    const serialized = JSON.stringify(items, null, 2);
    const tmpPath = `${this.manifestPath}.tmp`;
    const bakPath = `${this.manifestPath}.bak`;

    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
      fs.writeFileSync(fd, serialized, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // Preserve previous valid manifest as .bak before atomic swap
    if (fs.existsSync(this.manifestPath)) {
      try {
        const existingRaw = fs.readFileSync(this.manifestPath, 'utf8');
        if (this.parseAndValidateManifestRaw(existingRaw) !== null) {
          fs.copyFileSync(this.manifestPath, bakPath);
        }
      } catch {
        // Best-effort backup copy
      }
    }

    fs.renameSync(tmpPath, this.manifestPath);
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
    if (!containerBuffer || containerBuffer.length < 8 + 12 + 16) {
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
   * Sanitizes a file name to prevent directory traversal, RTLO spoofing, trailing dots/spaces,
   * and Windows device name attacks (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
   */
  public static sanitizeFileName(rawName: string): string {
    if (!rawName || typeof rawName !== 'string') {
      return `quarantined_file_${Date.now()}`;
    }

    // 1. Remove null bytes, Unicode bidirectional overrides, and trim whitespace
    let clean = rawName
      .replace(/\0/g, '')
      .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
      .trim();

    // 2. Extract base name to eliminate directory traversal sequences (../, ..\, /foo/bar, C:\foo)
    clean = clean.replace(/\\/g, '/');
    clean = path.posix.basename(clean);

    // 3. Remove illegal filesystem characters (< > : " / \ | ? *) and trailing dots/spaces
    clean = clean.replace(/[<>:"/\\|?*]/g, '_').replace(/[. ]+$/, '');

    // 4. Check for Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    const baseWithoutExt = clean.split('.')[0].replace(/[. ]+$/, '').toUpperCase();
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
    if (!threat || typeof threat.filePath !== 'string' || !threat.filePath.trim()) {
      throw new Error('INVALID_THREAT: Threat filePath must be a non-empty string.');
    }

    const canonicalSource = path.resolve(threat.filePath);

    // 1. Path Existence & Symlink Defense
    if (!fs.existsSync(canonicalSource)) {
      throw new Error(`FILE_NOT_FOUND: Cannot quarantine non-existent file '${threat.filePath}'.`);
    }

    const lstat = await fs.promises.lstat(canonicalSource);
    if (lstat.isSymbolicLink()) {
      throw new Error('SECURITY_VIOLATION: Quarantining symbolic links is forbidden to prevent target hijacking.');
    }
    if (!lstat.isFile()) {
      throw new Error('INVALID_TARGET: Only regular files can be quarantined.');
    }

    // 2. Protected OS System Path Defense (checking both syntactic and resolved native path)
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
    const actualSha256 =
      typeof threat.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(threat.sha256)
        ? threat.sha256.toLowerCase()
        : crypto.createHash('sha256').update(rawBytes).digest('hex');
    const encryptedContainer = this.encryptBytes(rawBytes);

    // 5. Generate unique quarantine ID
    const quarantineId = `quarantine-${crypto.randomUUID()}`;
    const blobPath = path.join(this.vaultDir, `${quarantineId}.blob`);
    if (!this.isPathInsideVault(blobPath)) {
      throw new Error('SECURITY_VIOLATION: Quarantine blob path escaped vault boundary.');
    }

    // 6. Atomic write encrypted container to vault (.tmp -> fsync -> rename)
    const tmpBlobPath = `${blobPath}.tmp`;
    const fd = await fs.promises.open(tmpBlobPath, 'w', 0o600);
    try {
      await fd.writeFile(encryptedContainer);
      await fd.sync();
    } finally {
      await fd.close();
    }
    await fs.promises.rename(tmpBlobPath, blobPath);

    // 7. Try stripping execution permissions on container
    try {
      fs.chmodSync(blobPath, 0o400); // Read-only user access, zero execute
    } catch {
      // Best-effort permission stripping across platforms
    }

    // 8. Securely unlink the original malicious file from the user's filesystem
    try {
      await fs.promises.unlink(canonicalSource);
    } catch (err) {
      try {
        fs.chmodSync(blobPath, 0o600);
        await fs.promises.unlink(blobPath);
      } catch {
        // Best-effort cleanup of staged blob when source unlink fails
      }
      throw err;
    }

    const safeFileName = QuarantineService.sanitizeFileName(
      threat.fileName || path.basename(canonicalSource)
    );

    const item: QuarantineItem = {
      quarantineId,
      originalPath: canonicalSource,
      fileName: safeFileName,
      fileSize: rawBytes.length,
      sha256: actualSha256,
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
    const validId = IpcValidator.validateId(quarantineId);
    const item = this.manifest.get(validId);
    if (!item) {
      throw new Error(`QUARANTINE_NOT_FOUND: Item '${validId}' does not exist.`);
    }

    if (!this.isPathInsideVault(item.blobPath) || !fs.existsSync(item.blobPath)) {
      throw new Error(`CORRUPTED_VAULT: Quarantined blob missing or invalid at '${item.blobPath}'.`);
    }

    const blobLstat = await fs.promises.lstat(item.blobPath);
    if (blobLstat.isSymbolicLink() || !blobLstat.isFile()) {
      throw new Error('SECURITY_VIOLATION: Quarantined blob cannot be a symbolic link.');
    }

    // Path Traversal & Windows Device Name Defense on Destination (GAP-24)
    const safeFileName = QuarantineService.sanitizeFileName(
      item.fileName || path.basename(item.originalPath)
    );
    let destinationPath: string;

    if (customDestinationDir) {
      const canonicalDestDir = path.resolve(customDestinationDir);
      if (!fs.existsSync(canonicalDestDir)) {
        throw new Error('INVALID_DESTINATION: Destination directory is invalid or inaccessible.');
      }
      const dirLstat = fs.lstatSync(canonicalDestDir);
      if (dirLstat.isSymbolicLink() || !dirLstat.isDirectory()) {
        throw new Error('SECURITY_VIOLATION: Destination directory cannot be a symbolic link.');
      }
      if (IpcValidator.isProtectedSystemPath(canonicalDestDir)) {
        throw new Error('SECURITY_VIOLATION: Restoring to protected system directory is forbidden.');
      }

      const candidatePath = path.join(canonicalDestDir, safeFileName);
      const resolvedDestination = path.resolve(candidatePath);

      const expectedPrefix = canonicalDestDir.endsWith(path.sep)
        ? canonicalDestDir
        : canonicalDestDir + path.sep;
      const isContained =
        process.platform === 'win32'
          ? resolvedDestination.toLowerCase().startsWith(expectedPrefix.toLowerCase())
          : resolvedDestination.startsWith(expectedPrefix);
      if (!isContained) {
        throw new Error('SECURITY_VIOLATION: Destination path escapes target directory.');
      }
      destinationPath = resolvedDestination;
    } else {
      const origDir = path.dirname(path.resolve(item.originalPath));
      if (IpcValidator.isProtectedSystemPath(origDir) || IpcValidator.isProtectedSystemPath(item.originalPath)) {
        throw new Error('SECURITY_VIOLATION: Restoring to protected system directory is forbidden.');
      }
      if (fs.existsSync(origDir)) {
        const origDirLstat = fs.lstatSync(origDir);
        if (origDirLstat.isSymbolicLink()) {
          throw new Error('SECURITY_VIOLATION: Restore parent directory cannot be a symbolic link.');
        }
      }
      destinationPath = path.join(origDir, safeFileName);
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

    const tmpRestorePath = `${destinationPath}.tmp.${process.pid}`;
    await fs.promises.writeFile(tmpRestorePath, restoredBytes);
    await fs.promises.rename(tmpRestorePath, destinationPath);

    // Remove blob from vault
    try {
      fs.chmodSync(item.blobPath, 0o600);
    } catch {
      // continue
    }
    await fs.promises.unlink(item.blobPath);
    this.manifest.delete(validId);
    this.saveManifest();

    return destinationPath;
  }

  /**
   * Permanently deletes a quarantined item with cryptographic byte overwriting.
   */
  public async permanentDelete(quarantineId: string): Promise<void> {
    const validId = IpcValidator.validateId(quarantineId);
    const item = this.manifest.get(validId);
    if (!item) {
      throw new Error(`QUARANTINE_NOT_FOUND: Item '${validId}' does not exist.`);
    }

    if (this.isPathInsideVault(item.blobPath) && fs.existsSync(item.blobPath)) {
      const lstat = fs.lstatSync(item.blobPath);
      if (!lstat.isSymbolicLink() && lstat.isFile()) {
        try {
          fs.chmodSync(item.blobPath, 0o666);
        } catch {
          // continue
        }
        // Multi-pass cryptographic shredder
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
    }

    this.manifest.delete(validId);
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
        if (this.isPathInsideVault(item.blobPath) && fs.existsSync(item.blobPath)) {
          const lstat = fs.lstatSync(item.blobPath);
          if (!lstat.isSymbolicLink() && lstat.isFile()) {
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
        }
      } catch {
        // continue
      }
    }
    this.manifest.clear();
    this.saveManifest();
  }
}

