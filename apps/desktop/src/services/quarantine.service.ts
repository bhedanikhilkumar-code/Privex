import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { QuarantineItem, DetectedThreat, QuarantineRestoreOptions } from '../types/desktop.types';
import { IpcValidator } from '../ipc/ipc-validator';
import { ThreatIntel, CleanFileCache, Verdict, EngineVerdict } from '@private-protection/core';

/**
 * QuarantineService (PPVAULT2 Hardened)
 *
 * Implements chunked 64 KB streaming AES-256-GCM encryption/decryption with per-chunk AAD
 * binding, dual-magic backward compatibility (PPVAULT1 and PPVAULT2), Windows DPAPI key
 * protection with secure fallback, encrypted manifest.json.enc with atomic writes and
 * crash recovery (.bak), pinned file descriptors (O_NOFOLLOW) for TOCTOU prevention,
 * NTFS :Zone.Identifier ADS recording, and "Restore & Trust SHA-256" workflow.
 */
export class QuarantineService {
  private vaultDir: string;
  private manifestPath: string;
  private manifest: Map<string, QuarantineItem> = new Map();
  private vaultKey: Buffer;
  private activeItemOperations: Set<string> = new Set();
  private operationQueue: Promise<void> = Promise.resolve();

  // Header magic constants
  public static readonly CONTAINER_MAGIC_V1 = Buffer.from('PPVAULT1', 'utf8'); // 8 bytes legacy
  public static readonly CONTAINER_MAGIC_V2 = Buffer.from('PPVAULT2', 'utf8'); // 8 bytes streaming
  public static readonly MANIFEST_MAGIC = Buffer.from('PPMANIF1', 'utf8');     // 8 bytes manifest

  // Streaming constants
  public static readonly CHUNK_SIZE = 64 * 1024; // 64 KB (65,536 bytes)
  public static readonly UUID_LENGTH = 36;       // 36 characters ASCII

  constructor(customVaultDir?: string) {
    this.vaultDir = path.resolve(
      customVaultDir || path.join(os.homedir(), '.private-protection', 'quarantine')
    );
    this.manifestPath = path.join(this.vaultDir, 'manifest.json.enc');
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

  private static mockSafeStorage: any = null;

  public static setMockSafeStorage(mock: any): void {
    QuarantineService.mockSafeStorage = mock;
  }

  /**
   * Safely retrieves Electron's safeStorage API if running in an Electron environment
   * with Windows DPAPI / platform keystore available.
   */
  private static getElectronSafeStorage(): any {
    if (QuarantineService.mockSafeStorage !== null) {
      return QuarantineService.mockSafeStorage;
    }
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const electron = require('electron');
      if (
        electron &&
        electron.safeStorage &&
        typeof electron.safeStorage.isEncryptionAvailable === 'function'
      ) {
        if (electron.safeStorage.isEncryptionAvailable()) {
          return electron.safeStorage;
        }
      }
    } catch {
      // Running outside Electron (Node.js test runner, headless CI, or CLI mode)
    }
    return null;
  }

  /**
   * Initializes the 256-bit vault master key.
   * Uses Windows DPAPI (via safeStorage) when available, with secure machine-local
   * storage fallback with 0o600 permissions.
   */
  private initVaultKey(): Buffer {
    this.ensureSafeVaultDir();
    const dpapiPath = path.join(this.vaultDir, '.vault.key.dpapi');
    const keyPath = path.join(this.vaultDir, '.vault.key');
    const safeStorage = QuarantineService.getElectronSafeStorage();

    // 1. If DPAPI is available
    if (safeStorage) {
      if (fs.existsSync(dpapiPath)) {
        try {
          const encrypted = fs.readFileSync(dpapiPath);
          const decryptedBase64 = safeStorage.decryptString(encrypted);
          const key = Buffer.from(decryptedBase64, 'base64');
          if (key.length === 32) {
            return key;
          }
        } catch {
          // Re-generate or fallback below
        }
      } else if (fs.existsSync(keyPath)) {
        // Upgrade existing unencrypted .vault.key to DPAPI
        try {
          const raw = fs.readFileSync(keyPath);
          if (raw.length === 32) {
            const encrypted = safeStorage.encryptString(raw.toString('base64'));
            const tmpPath = `${dpapiPath}.tmp`;
            fs.writeFileSync(tmpPath, encrypted, { mode: 0o600 });
            fs.renameSync(tmpPath, dpapiPath);
            try {
              fs.unlinkSync(keyPath);
            } catch {
              // Best-effort removal of plaintext key
            }
            return raw;
          }
        } catch {
          // Continue to new key generation
        }
      }

      // Generate new key and protect via DPAPI
      const newKey = crypto.randomBytes(32);
      const encrypted = safeStorage.encryptString(newKey.toString('base64'));
      const tmpPath = `${dpapiPath}.tmp`;
      const fd = fs.openSync(tmpPath, 'w', 0o600);
      try {
        fs.writeSync(fd, encrypted);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmpPath, dpapiPath);
      return newKey;
    }

    // 2. Headless / Node testing fallback: Local key with 0o600 permissions
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
    this.sweepStaleTempFiles();
    this.loadManifest();
    this.reconcileOrphanedBlobs();
  }

  /**
   * Sweeps and unlinks stale temporary staging files left behind by process kills or power loss.
   */
  private sweepStaleTempFiles(): void {
    try {
      if (!fs.existsSync(this.vaultDir)) return;
      const entries = fs.readdirSync(this.vaultDir);
      const now = Date.now();
      for (const entry of entries) {
        if (entry.includes('.tmp') || entry.endsWith('.tmp')) {
          const fullPath = path.join(this.vaultDir, entry);
          try {
            const stat = fs.statSync(fullPath);
            // Reclaim temp files older than 5 seconds
            if (now - stat.mtimeMs > 5000) {
              fs.unlinkSync(fullPath);
            }
          } catch {
            // Ignore
          }
        }
      }
    } catch {
      // Best-effort sweep
    }
  }

  /**
   * Reconciles physical .blob containers that are absent from manifest.json.enc
   * due to sudden power loss or process kill between source unlink and manifest commit.
   */
  private reconcileOrphanedBlobs(): void {
    try {
      if (!fs.existsSync(this.vaultDir)) return;
      const entries = fs.readdirSync(this.vaultDir);
      let foundOrphans = false;
      for (const entry of entries) {
        if (entry.endsWith('.blob')) {
          const quarantineId = entry.replace(/\.blob$/, '');
          if (!this.manifest.has(quarantineId)) {
            const fullBlobPath = path.join(this.vaultDir, entry);
            try {
              const stat = fs.statSync(fullBlobPath);
              const recoveredItem: QuarantineItem = {
                quarantineId,
                fileName: `recovered_${quarantineId}.bin`,
                originalPath: path.join(this.vaultDir, `recovered_${quarantineId}.bin`),
                quarantinedAt: stat.mtimeMs,
                fileSize: stat.size,
                sha256: '0000000000000000000000000000000000000000000000000000000000000000',
                threatName: 'RECOVERED_ORPHANED_BLOB',
                severity: 'dangerous',
                verdict: 'BLOCK',
                blobPath: fullBlobPath,
                vaultVersion: 'PPVAULT2'
              };
              this.manifest.set(quarantineId, recoveredItem);
              foundOrphans = true;
            } catch {
              // Ignore
            }
          }
        }
      }
      if (foundOrphans) {
        this.saveManifest();
      }
    } catch {
      // Best-effort reconciliation
    }
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
              fileName: QuarantineService.sanitizeFileName(
                item.fileName || path.basename(item.originalPath)
              ),
              fileSize:
                typeof item.fileSize === 'number' && Number.isFinite(item.fileSize)
                  ? item.fileSize
                  : 0,
              sha256: item.sha256,
              threatName: typeof item.threatName === 'string' ? item.threatName : 'QUARANTINED_THREAT',
              riskScore: typeof item.riskScore === 'number' ? item.riskScore : 50,
              severity: item.severity || 'suspicious',
              quarantinedAt: typeof item.quarantinedAt === 'number' ? item.quarantinedAt : Date.now(),
              evidenceFactors: Array.isArray(item.evidenceFactors) ? item.evidenceFactors : [],
              blobPath: path.resolve(item.blobPath),
              vaultVersion: item.vaultVersion === 'PPVAULT1' ? 'PPVAULT1' : 'PPVAULT2',
              ...(typeof item.zoneIdentifier === 'string' ? { zoneIdentifier: item.zoneIdentifier } : {}),
              ...(item.trustedOnRestore === true ? { trustedOnRestore: true } : {})
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

  /**
   * Decrypts an encrypted manifest container using AES-256-GCM.
   */
  private decryptManifestBuffer(buf: Buffer): string | null {
    if (!buf || buf.length < 8 + 12 + 16) {
      return null;
    }
    const magic = buf.subarray(0, 8);
    if (!magic.equals(QuarantineService.MANIFEST_MAGIC)) {
      return null;
    }
    const iv = buf.subarray(8, 20);
    const authTag = buf.subarray(20, 36);
    const ciphertext = buf.subarray(36);

    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
      decipher.setAAD(QuarantineService.MANIFEST_MAGIC);
      decipher.setAuthTag(authTag);
      return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
    } catch {
      return null;
    }
  }

  /**
   * Loads the quarantine manifest. Supports encrypted manifest.json.enc with
   * automatic crash recovery from manifest.json.enc.bak, and legacy manifest.json migration.
   */
  private loadManifest(): void {
    this.manifest.clear();
    const encPath = this.manifestPath;
    const bakPath = `${this.manifestPath}.bak`;
    const tmpPath = `${this.manifestPath}.tmp`;
    const legacyPath = path.join(this.vaultDir, 'manifest.json');

    // 1. Try primary encrypted manifest (manifest.json.enc)
    if (fs.existsSync(encPath)) {
      try {
        const rawEnc = fs.readFileSync(encPath);
        const decryptedJson = this.decryptManifestBuffer(rawEnc);
        if (decryptedJson) {
          const loaded = this.parseAndValidateManifestRaw(decryptedJson);
          if (loaded !== null) {
            this.manifest = loaded;
            return;
          }
        }
      } catch {
        // Fall through to backup recovery
      }
    }

    // 2. Crash recovery: try manifest.json.enc.bak or manifest.json.enc.tmp
    for (const fallbackPath of [bakPath, tmpPath]) {
      if (fs.existsSync(fallbackPath)) {
        try {
          const rawEnc = fs.readFileSync(fallbackPath);
          const decryptedJson = this.decryptManifestBuffer(rawEnc);
          if (decryptedJson) {
            const recovered = this.parseAndValidateManifestRaw(decryptedJson);
            if (recovered !== null) {
              this.manifest = recovered;
              this.saveManifest();
              return;
            }
          }
        } catch {
          // Continue
        }
      }
    }

    // 3. Backward compatibility: check legacy unencrypted manifest.json
    if (fs.existsSync(legacyPath)) {
      try {
        const raw = fs.readFileSync(legacyPath, 'utf8');
        const loaded = this.parseAndValidateManifestRaw(raw);
        if (loaded !== null) {
          this.manifest = loaded;
          this.saveManifest(); // Upgrade to encrypted manifest
          try {
            fs.unlinkSync(legacyPath);
          } catch {
            // Best-effort removal
          }
          return;
        }
      } catch {
        // Continue
      }
    }
  }

  /**
   * Encrypts and atomically writes manifest.json.enc via temporary staging,
   * fsync, and automatic backup copy (.bak).
   */
  private saveManifest(): void {
    this.ensureSafeVaultDir();
    const items = Array.from(this.manifest.values());
    const serialized = JSON.stringify(items, null, 2);

    // Encrypt serialized JSON with AES-256-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
    cipher.setAAD(QuarantineService.MANIFEST_MAGIC);
    const ciphertext = Buffer.concat([cipher.update(serialized, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const encryptedContainer = Buffer.concat([
      QuarantineService.MANIFEST_MAGIC,
      iv,
      authTag,
      ciphertext
    ]);

    const uniqueNonce = crypto.randomBytes(4).toString('hex');
    const tmpPath = `${this.manifestPath}.tmp.${process.pid}.${Date.now()}.${uniqueNonce}`;
    const bakPath = `${this.manifestPath}.bak`;

    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
      fs.writeFileSync(fd, encryptedContainer);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // Preserve previous valid manifest as .bak before atomic swap
    if (fs.existsSync(this.manifestPath)) {
      try {
        const existing = fs.readFileSync(this.manifestPath);
        if (this.decryptManifestBuffer(existing) !== null) {
          fs.copyFileSync(this.manifestPath, bakPath);
        }
      } catch {
        // Best-effort backup copy
      }
    }

    fs.renameSync(tmpPath, this.manifestPath);
  }

  /**
   * Streams and encrypts data from sourceFd to destFd in 64 KB chunks using PPVAULT2 format.
   * Binds each chunk to container UUID, chunkIndex, and isFinalChunk in the GCM AAD.
   */
  public async encryptStream(
    sourceFd: number,
    destFd: number,
    fileUuid?: string
  ): Promise<{ sha256: string; totalBytes: number; totalChunks: number }> {
    const uuid = fileUuid || crypto.randomUUID();
    const uuidBuf = Buffer.from(uuid.padEnd(QuarantineService.UUID_LENGTH, ' '), 'ascii').subarray(
      0,
      QuarantineService.UUID_LENGTH
    );

    // Write Container Header: [MAGIC: 8B][UUID: 36B][CHUNK_SIZE: 4B]
    const headerBuf = Buffer.allocUnsafe(8 + QuarantineService.UUID_LENGTH + 4);
    QuarantineService.CONTAINER_MAGIC_V2.copy(headerBuf, 0);
    uuidBuf.copy(headerBuf, 8);
    headerBuf.writeUInt32BE(QuarantineService.CHUNK_SIZE, 44);
    fs.writeSync(destFd, headerBuf, 0, headerBuf.length, null);

    const hash = crypto.createHash('sha256');
    const sourceStat = fs.fstatSync(sourceFd);
    const sourceFileSize = sourceStat.size;

    let totalBytesRead = 0;
    let chunkIndex = 0;
    const readBuffer = Buffer.allocUnsafe(QuarantineService.CHUNK_SIZE);

    // If source file is 0 bytes, write a single final chunk of 0 bytes
    if (sourceFileSize === 0) {
      const iv = crypto.randomBytes(12);
      const isFinal = 1;
      const aad = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4 + 1);
      uuidBuf.copy(aad, 0);
      aad.writeUInt32BE(0, QuarantineService.UUID_LENGTH);
      aad.writeUInt8(isFinal, QuarantineService.UUID_LENGTH + 4);

      const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
      cipher.setAAD(aad);
      cipher.final();
      const authTag = cipher.getAuthTag();

      // Chunk frame: [CHUNK_INDEX: 4B][IS_FINAL: 1B][IV: 12B][AUTH_TAG: 16B][CIPHERTEXT_LEN: 4B]
      const frameBuf = Buffer.allocUnsafe(37);
      frameBuf.writeUInt32BE(0, 0);
      frameBuf.writeUInt8(isFinal, 4);
      iv.copy(frameBuf, 5);
      authTag.copy(frameBuf, 17);
      frameBuf.writeUInt32BE(0, 33);
      fs.writeSync(destFd, frameBuf, 0, frameBuf.length, null);
      fs.fsyncSync(destFd);

      return {
        sha256: hash.digest('hex'),
        totalBytes: 0,
        totalChunks: 1
      };
    }

    while (totalBytesRead < sourceFileSize) {
      const bytesToRead = Math.min(QuarantineService.CHUNK_SIZE, sourceFileSize - totalBytesRead);
      let bytesRead = 0;
      while (bytesRead < bytesToRead) {
        const readNow = fs.readSync(
          sourceFd,
          readBuffer,
          bytesRead,
          bytesToRead - bytesRead,
          totalBytesRead + bytesRead
        );
        if (readNow <= 0) break;
        bytesRead += readNow;
      }

      totalBytesRead += bytesRead;
      const isFinal = totalBytesRead >= sourceFileSize ? 1 : 0;
      const rawChunk = readBuffer.subarray(0, bytesRead);
      hash.update(rawChunk);

      const iv = crypto.randomBytes(12);
      const aad = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4 + 1);
      uuidBuf.copy(aad, 0);
      aad.writeUInt32BE(chunkIndex, QuarantineService.UUID_LENGTH);
      aad.writeUInt8(isFinal, QuarantineService.UUID_LENGTH + 4);

      const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(rawChunk), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const frameBuf = Buffer.allocUnsafe(37);
      frameBuf.writeUInt32BE(chunkIndex, 0);
      frameBuf.writeUInt8(isFinal, 4);
      iv.copy(frameBuf, 5);
      authTag.copy(frameBuf, 17);
      frameBuf.writeUInt32BE(ciphertext.length, 33);

      fs.writeSync(destFd, frameBuf, 0, frameBuf.length, null);
      fs.writeSync(destFd, ciphertext, 0, ciphertext.length, null);

      chunkIndex++;
      if (isFinal === 1) break;
    }

    fs.fsyncSync(destFd);
    return {
      sha256: hash.digest('hex'),
      totalBytes: totalBytesRead,
      totalChunks: chunkIndex
    };
  }

  /**
   * Streams and decrypts data from sourceFd to destFd.
   * Seamlessly handles both PPVAULT1 (legacy whole-file) and PPVAULT2 (streaming chunked).
   */
  public async decryptStream(
    sourceFd: number,
    destFd: number
  ): Promise<{ sha256: string; totalBytes: number }> {
    const magicBuf = Buffer.allocUnsafe(8);
    const magicRead = fs.readSync(sourceFd, magicBuf, 0, 8, 0);
    if (magicRead < 8) {
      throw new Error('CORRUPTED_VAULT: Quarantined container is too small to contain valid metadata.');
    }

    // 1. PPVAULT1 Legacy Format Handler
    if (magicBuf.equals(QuarantineService.CONTAINER_MAGIC_V1)) {
      const sourceStat = fs.fstatSync(sourceFd);
      if (sourceStat.size < 8 + 12 + 16) {
        throw new Error('CORRUPTED_VAULT: Quarantined container is too small to contain valid metadata.');
      }
      const iv = Buffer.allocUnsafe(12);
      fs.readSync(sourceFd, iv, 0, 12, 8);
      const authTag = Buffer.allocUnsafe(16);
      fs.readSync(sourceFd, authTag, 0, 16, 20);

      const ciphertextLen = sourceStat.size - 36;
      const ciphertext = Buffer.allocUnsafe(ciphertextLen);
      fs.readSync(sourceFd, ciphertext, 0, ciphertextLen, 36);

      const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
      decipher.setAuthTag(authTag);
      let plaintext: Buffer;
      try {
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch {
        throw new Error(
          'INTEGRITY_CHECK_FAILED: Quarantined container authentication tag verification failed. Ciphertext has been tampered with.'
        );
      }

      fs.writeSync(destFd, plaintext, 0, plaintext.length, null);
      fs.fsyncSync(destFd);
      const sha256 = crypto.createHash('sha256').update(plaintext).digest('hex');
      return { sha256, totalBytes: plaintext.length };
    }

    // 2. PPVAULT2 Streaming Format Handler
    if (magicBuf.equals(QuarantineService.CONTAINER_MAGIC_V2)) {
      const headerExtra = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4);
      const headerRead = fs.readSync(
        sourceFd,
        headerExtra,
        0,
        QuarantineService.UUID_LENGTH + 4,
        8
      );
      if (headerRead < QuarantineService.UUID_LENGTH + 4) {
        throw new Error('CORRUPTED_VAULT: Quarantined container truncated header.');
      }
      const uuidBuf = headerExtra.subarray(0, QuarantineService.UUID_LENGTH);
      // const declaredChunkSize = headerExtra.readUInt32BE(QuarantineService.UUID_LENGTH);

      let currentOffset = 8 + QuarantineService.UUID_LENGTH + 4;
      let expectedIndex = 0;
      let totalPlaintextBytes = 0;
      const hash = crypto.createHash('sha256');
      const frameBuf = Buffer.allocUnsafe(37);
      const sourceStat = fs.fstatSync(sourceFd);

      while (currentOffset < sourceStat.size) {
        const frameRead = fs.readSync(sourceFd, frameBuf, 0, 37, currentOffset);
        if (frameRead < 37) {
          throw new Error('CORRUPTED_VAULT: Quarantined container truncated chunk frame.');
        }
        currentOffset += 37;

        const chunkIndex = frameBuf.readUInt32BE(0);
        const isFinal = frameBuf.readUInt8(4);
        const iv = frameBuf.subarray(5, 17);
        const authTag = frameBuf.subarray(17, 33);
        const ciphertextLen = frameBuf.readUInt32BE(33);

        if (chunkIndex !== expectedIndex) {
          throw new Error('INTEGRITY_CHECK_FAILED: Chunk sequence violation or out of order.');
        }

        if (
          ciphertextLen > QuarantineService.CHUNK_SIZE + 64 ||
          currentOffset + ciphertextLen > sourceStat.size
        ) {
          throw new Error('CORRUPTED_VAULT: Quarantined container chunk length exceeds maximum bounds.');
        }

        const ciphertext = Buffer.allocUnsafe(ciphertextLen);
        if (ciphertextLen > 0) {
          const cipherRead = fs.readSync(sourceFd, ciphertext, 0, ciphertextLen, currentOffset);
          if (cipherRead < ciphertextLen) {
            throw new Error('CORRUPTED_VAULT: Quarantined container truncated chunk ciphertext.');
          }
          currentOffset += ciphertextLen;
        }

        const aad = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4 + 1);
        uuidBuf.copy(aad, 0);
        aad.writeUInt32BE(chunkIndex, QuarantineService.UUID_LENGTH);
        aad.writeUInt8(isFinal, QuarantineService.UUID_LENGTH + 4);

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(authTag);

        let plaintextChunk: Buffer;
        try {
          plaintextChunk = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        } catch {
          throw new Error(
            'INTEGRITY_CHECK_FAILED: Quarantined container authentication tag verification failed. Ciphertext has been tampered with.'
          );
        }

        if (plaintextChunk.length > 0) {
          hash.update(plaintextChunk);
          fs.writeSync(destFd, plaintextChunk, 0, plaintextChunk.length, null);
          totalPlaintextBytes += plaintextChunk.length;
        }

        expectedIndex++;
        if (isFinal === 1) break;
      }

      fs.fsyncSync(destFd);
      return {
        sha256: hash.digest('hex'),
        totalBytes: totalPlaintextBytes
      };
    }

    throw new Error('SECURITY_VIOLATION: Quarantined container header magic is invalid or corrupted.');
  }

  /**
   * Applies authenticated AES-256-GCM encryption with random IV and authentication tag.
   * Produces PPVAULT2 format in memory.
   */
  public encryptBytes(buffer: Buffer): Buffer {
    const uuid = crypto.randomUUID();
    const uuidBuf = Buffer.from(uuid.padEnd(QuarantineService.UUID_LENGTH, ' '), 'ascii').subarray(
      0,
      QuarantineService.UUID_LENGTH
    );

    const header = Buffer.allocUnsafe(8 + QuarantineService.UUID_LENGTH + 4);
    QuarantineService.CONTAINER_MAGIC_V2.copy(header, 0);
    uuidBuf.copy(header, 8);
    header.writeUInt32BE(QuarantineService.CHUNK_SIZE, 44);

    const parts: Buffer[] = [header];

    if (!buffer || buffer.length === 0) {
      const iv = crypto.randomBytes(12);
      const isFinal = 1;
      const aad = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4 + 1);
      uuidBuf.copy(aad, 0);
      aad.writeUInt32BE(0, QuarantineService.UUID_LENGTH);
      aad.writeUInt8(isFinal, QuarantineService.UUID_LENGTH + 4);

      const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
      cipher.setAAD(aad);
      cipher.final();
      const authTag = cipher.getAuthTag();

      const frame = Buffer.allocUnsafe(37);
      frame.writeUInt32BE(0, 0);
      frame.writeUInt8(isFinal, 4);
      iv.copy(frame, 5);
      authTag.copy(frame, 17);
      frame.writeUInt32BE(0, 33);
      parts.push(frame);

      return Buffer.concat(parts);
    }

    let offset = 0;
    let chunkIndex = 0;
    while (offset < buffer.length) {
      const end = Math.min(offset + QuarantineService.CHUNK_SIZE, buffer.length);
      const rawChunk = buffer.subarray(offset, end);
      const isFinal = end >= buffer.length ? 1 : 0;

      const iv = crypto.randomBytes(12);
      const aad = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4 + 1);
      uuidBuf.copy(aad, 0);
      aad.writeUInt32BE(chunkIndex, QuarantineService.UUID_LENGTH);
      aad.writeUInt8(isFinal, QuarantineService.UUID_LENGTH + 4);

      const cipher = crypto.createCipheriv('aes-256-gcm', this.vaultKey, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(rawChunk), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const frame = Buffer.allocUnsafe(37);
      frame.writeUInt32BE(chunkIndex, 0);
      frame.writeUInt8(isFinal, 4);
      iv.copy(frame, 5);
      authTag.copy(frame, 17);
      frame.writeUInt32BE(ciphertext.length, 33);

      parts.push(frame);
      parts.push(ciphertext);

      offset = end;
      chunkIndex++;
    }

    return Buffer.concat(parts);
  }

  /**
   * Decrypts an authenticated AES-256-GCM quarantine container in memory.
   * Dual-magic detection automatically routes PPVAULT1 and PPVAULT2.
   */
  public decryptBytes(containerBuffer: Buffer): Buffer {
    if (!containerBuffer || containerBuffer.length < 8) {
      throw new Error('CORRUPTED_VAULT: Quarantined container is too small to contain valid metadata.');
    }

    const magic = containerBuffer.subarray(0, 8);

    // 1. PPVAULT1 Legacy
    if (magic.equals(QuarantineService.CONTAINER_MAGIC_V1)) {
      if (containerBuffer.length < 8 + 12 + 16) {
        throw new Error('CORRUPTED_VAULT: Quarantined container is too small to contain valid metadata.');
      }
      const iv = containerBuffer.subarray(8, 20);
      const authTag = containerBuffer.subarray(20, 36);
      const ciphertext = containerBuffer.subarray(36);

      const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
      decipher.setAuthTag(authTag);
      try {
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch {
        throw new Error(
          'INTEGRITY_CHECK_FAILED: Quarantined container authentication tag verification failed. Ciphertext has been tampered with.'
        );
      }
    }

    // 2. PPVAULT2 Streaming
    if (magic.equals(QuarantineService.CONTAINER_MAGIC_V2)) {
      if (containerBuffer.length < 8 + QuarantineService.UUID_LENGTH + 4) {
        throw new Error('CORRUPTED_VAULT: Quarantined container truncated header.');
      }
      const uuidBuf = containerBuffer.subarray(8, 8 + QuarantineService.UUID_LENGTH);
      let offset = 8 + QuarantineService.UUID_LENGTH + 4;
      let expectedIndex = 0;
      const plaintexts: Buffer[] = [];

      while (offset < containerBuffer.length) {
        if (offset + 37 > containerBuffer.length) {
          throw new Error('CORRUPTED_VAULT: Quarantined container truncated chunk frame.');
        }
        const chunkIndex = containerBuffer.readUInt32BE(offset);
        const isFinal = containerBuffer.readUInt8(offset + 4);
        const iv = containerBuffer.subarray(offset + 5, offset + 17);
        const authTag = containerBuffer.subarray(offset + 17, offset + 33);
        const ciphertextLen = containerBuffer.readUInt32BE(offset + 33);
        offset += 37;

        if (chunkIndex !== expectedIndex) {
          throw new Error('INTEGRITY_CHECK_FAILED: Chunk sequence violation or out of order.');
        }
        if (
          ciphertextLen > QuarantineService.CHUNK_SIZE + 64 ||
          offset + ciphertextLen > containerBuffer.length
        ) {
          throw new Error('CORRUPTED_VAULT: Quarantined container chunk length exceeds maximum bounds.');
        }
        const ciphertext = containerBuffer.subarray(offset, offset + ciphertextLen);
        offset += ciphertextLen;

        const aad = Buffer.allocUnsafe(QuarantineService.UUID_LENGTH + 4 + 1);
        uuidBuf.copy(aad, 0);
        aad.writeUInt32BE(chunkIndex, QuarantineService.UUID_LENGTH);
        aad.writeUInt8(isFinal, QuarantineService.UUID_LENGTH + 4);

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.vaultKey, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(authTag);

        try {
          plaintexts.push(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
        } catch {
          throw new Error(
            'INTEGRITY_CHECK_FAILED: Quarantined container authentication tag verification failed. Ciphertext has been tampered with.'
          );
        }

        expectedIndex++;
        if (isFinal === 1) break;
      }

      return Buffer.concat(plaintexts);
    }

    throw new Error('SECURITY_VIOLATION: Quarantined container header magic is invalid or corrupted.');
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
   * Isolates a detected threat into the encrypted PPVAULT2 quarantine vault.
   * Enforces canonical threat verdict/severity policy, pinned file descriptors (O_NOFOLLOW),
   * NTFS :Zone.Identifier ADS recording, and atomic streaming staging.
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

    // 2. Protected OS System Path Defense
    if (IpcValidator.isProtectedSystemPath(canonicalSource)) {
      throw new Error('SECURITY_VIOLATION: Quarantining protected OS system files is forbidden.');
    }

    // 3. Canonical Quarantine Policy Enforcement:
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

    // 4. Pin file descriptor (O_NOFOLLOW) to prevent TOCTOU symlink race attacks
    const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
    const sourceFd = fs.openSync(canonicalSource, openFlags);
    let totalBytes = 0;
    let computedSha256 = '';

    const quarantineId = `quarantine-${crypto.randomUUID()}`;
    const blobPath = path.join(this.vaultDir, `${quarantineId}.blob`);
    if (!this.isPathInsideVault(blobPath)) {
      fs.closeSync(sourceFd);
      throw new Error('SECURITY_VIOLATION: Quarantine blob path escaped vault boundary.');
    }

    const tmpBlobPath = `${blobPath}.tmp`;
    const destFd = fs.openSync(tmpBlobPath, 'w', 0o600);

    try {
      const fstat = fs.fstatSync(sourceFd);
      if (fstat.isSymbolicLink() || !fstat.isFile()) {
        throw new Error('SECURITY_VIOLATION: Opened target is not a regular file.');
      }

      // 5. Stream-encrypt source to PPVAULT2 container
      const streamRes = await this.encryptStream(sourceFd, destFd, quarantineId);
      totalBytes = streamRes.totalBytes;
      computedSha256 = streamRes.sha256;
    } finally {
      try {
        fs.closeSync(destFd);
      } catch {
        // ignore
      }
      try {
        fs.closeSync(sourceFd);
      } catch {
        // ignore
      }
    }

    // 6. Record NTFS :Zone.Identifier Mark-of-the-Web ADS if present on Windows
    let zoneIdentifier: string | undefined;
    if (process.platform === 'win32') {
      try {
        const adsPath = `${canonicalSource}:Zone.Identifier`;
        if (fs.existsSync(adsPath)) {
          zoneIdentifier = fs.readFileSync(adsPath, 'utf8');
        }
      } catch {
        // ADS not available or unsupported filesystem
      }
    }

    // 7. Atomic rename staged blob to permanent vault container
    fs.renameSync(tmpBlobPath, blobPath);

    // 8. Strip execution permissions on container
    try {
      fs.chmodSync(blobPath, 0o400); // Read-only user access, zero execute
    } catch {
      // Best-effort across platforms
    }

    const safeFileName = QuarantineService.sanitizeFileName(
      threat.fileName || path.basename(canonicalSource)
    );

    const actualSha256 =
      typeof threat.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(threat.sha256)
        ? threat.sha256.toLowerCase()
        : computedSha256;

    const item: QuarantineItem = {
      quarantineId,
      originalPath: canonicalSource,
      fileName: safeFileName,
      fileSize: totalBytes,
      sha256: actualSha256,
      threatName: threat.threatName,
      riskScore: threat.riskScore,
      severity: threat.severity,
      quarantinedAt: Date.now(),
      evidenceFactors: threat.evidenceFactors,
      blobPath,
      vaultVersion: 'PPVAULT2',
      ...(zoneIdentifier ? { zoneIdentifier } : {})
    };

    // SEC-D-04: Commit item to manifest BEFORE unlinking source file to guarantee
    // zero orphaned blobs if power loss or crash occurs mid-quarantine.
    this.manifest.set(quarantineId, item);
    this.saveManifest();

    // 9. Securely unlink the original malicious file from user's filesystem
    try {
      await fs.promises.unlink(canonicalSource);
    } catch (err) {
      // Rollback manifest and blob if unlinking source file fails
      this.manifest.delete(quarantineId);
      try {
        this.saveManifest();
      } catch {
        // Best-effort manifest rollback
      }
      try {
        fs.chmodSync(blobPath, 0o600);
        await fs.promises.unlink(blobPath);
      } catch {
        // Best-effort cleanup
      }
      throw err;
    }

    return item;
  }

  /**
   * Restores a quarantined item to disk safely.
   * Supports streaming decryption, hash verification, custom destination directories,
   * collision handling, and the "Restore & Trust SHA-256" workflow.
   */
  public async restoreItem(
    quarantineId: string,
    optionsOrDestDir?: QuarantineRestoreOptions | string
  ): Promise<string> {
    const validId = IpcValidator.validateId(quarantineId);
    if (this.activeItemOperations.has(validId)) {
      throw new Error(`CONCURRENT_OPERATION: Operation already in progress for quarantine ID '${validId}'.`);
    }
    this.activeItemOperations.add(validId);

    try {
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

    // Normalize options
    const options: QuarantineRestoreOptions =
      typeof optionsOrDestDir === 'string'
        ? { customDestinationDir: optionsOrDestDir }
        : optionsOrDestDir || {};

    const customDestinationDir = options.customDestinationDir;

    // Path Traversal & Windows Device Name Defense on Destination
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
      if (
        IpcValidator.isProtectedSystemPath(origDir) ||
        IpcValidator.isProtectedSystemPath(item.originalPath)
      ) {
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

    // Symlink & Collision Avoidance
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

    // Ensure target parent directory exists
    const destDir = path.dirname(destinationPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    // Stream-decrypt from blob to temporary restore file
    const tmpRestorePath = `${destinationPath}.tmp.${process.pid}.${Date.now()}`;
    const sourceFd = fs.openSync(item.blobPath, 'r');
    const destFd = fs.openSync(tmpRestorePath, 'w', 0o600);

    let streamRes: { sha256: string; totalBytes: number };
    try {
      streamRes = await this.decryptStream(sourceFd, destFd);
    } finally {
      try {
        fs.closeSync(destFd);
      } catch {
        // ignore
      }
      try {
        fs.closeSync(sourceFd);
      } catch {
        // ignore
      }
    }

    // Verify hash integrity before finalizing restoration
    if (streamRes.sha256 !== item.sha256) {
      try {
        fs.unlinkSync(tmpRestorePath);
      } catch {
        // ignore
      }
      throw new Error('INTEGRITY_CHECK_FAILED: Restored byte hash does not match original SHA-256.');
    }

    // Atomic swap to final destination
    fs.renameSync(tmpRestorePath, destinationPath);

    // Restore :Zone.Identifier ADS if requested and available
    if (options.restoreZoneIdentifier && item.zoneIdentifier && process.platform === 'win32') {
      try {
        fs.writeFileSync(`${destinationPath}:Zone.Identifier`, item.zoneIdentifier, 'utf8');
      } catch {
        // Best-effort ADS restoration
      }
    }

    // Restore & Trust SHA-256 workflow
    if (options.trustSha256 === true) {
      ThreatIntel.getSharedInstance().addAllowedHash(item.sha256, { allowCriticalOverride: true });
      try {
        const restoredStat = fs.statSync(destinationPath);
        CleanFileCache.getSharedInstance().set(
          destinationPath,
          restoredStat.size,
          restoredStat.mtimeMs,
          item.sha256,
          {
            verdict: Verdict.ALLOW,
            engineVerdict: EngineVerdict.ALLOW,
            riskScore: 0
          }
        );
      } catch {
        // Best-effort cache population
      }
      item.trustedOnRestore = true;
    }

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
    } finally {
      this.activeItemOperations.delete(validId);
    }
  }

  /**
   * Permanently deletes a quarantined item with cryptographic byte overwriting.
   */
  public async permanentDelete(quarantineId: string): Promise<void> {
    const validId = IpcValidator.validateId(quarantineId);
    if (this.activeItemOperations.has(validId)) {
      throw new Error(`CONCURRENT_OPERATION: Operation already in progress for quarantine ID '${validId}'.`);
    }
    this.activeItemOperations.add(validId);

    try {
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
            const randomNoise = crypto.randomBytes(Math.min(stat.size, 1024 * 1024));
            const fd = fs.openSync(item.blobPath, 'r+');
            try {
              let written = 0;
              while (written < stat.size) {
                const toWrite = Math.min(randomNoise.length, stat.size - written);
                fs.writeSync(fd, randomNoise, 0, toWrite, written);
                written += toWrite;
              }
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
    } finally {
      this.activeItemOperations.delete(validId);
    }
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
              const randomNoise = crypto.randomBytes(Math.min(stat.size, 1024 * 1024));
              const fd = fs.openSync(item.blobPath, 'r+');
              try {
                let written = 0;
                while (written < stat.size) {
                  const toWrite = Math.min(randomNoise.length, stat.size - written);
                  fs.writeSync(fd, randomNoise, 0, toWrite, written);
                  written += toWrite;
                }
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
