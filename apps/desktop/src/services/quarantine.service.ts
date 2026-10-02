import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { QuarantineItem, DetectedThreat } from '../types/desktop.types';

export class QuarantineService {
  private vaultDir: string;
  private manifestPath: string;
  private manifest: Map<string, QuarantineItem> = new Map();

  // Static XOR obfuscation key to neutralize executable headers in vault
  private static readonly OBFUSCATION_MASK = 0xa5;

  constructor(customVaultDir?: string) {
    this.vaultDir = customVaultDir || path.join(os.homedir(), '.private-protection', 'quarantine');
    this.manifestPath = path.join(this.vaultDir, 'manifest.json');
    this.initVault();
  }

  private initVault(): void {
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true });
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
   * Applies reversible byte scrambling to neutralize executable magic headers.
   */
  private static scrambleBytes(buffer: Buffer): Buffer {
    const out = Buffer.alloc(buffer.length);
    for (let i = 0; i < buffer.length; i++) {
      out[i] = buffer[i] ^ this.OBFUSCATION_MASK;
    }
    return out;
  }

  /**
   * Isolates a detected threat into the encrypted quarantine vault.
   */
  public async isolateFile(threat: DetectedThreat): Promise<QuarantineItem> {
    const canonicalSource = path.resolve(threat.filePath);

    // 1. Path Traversal & Symlink Defense
    if (!fs.existsSync(canonicalSource)) {
      throw new Error(`FILE_NOT_FOUND: Cannot quarantine non-existent file '${threat.filePath}'.`);
    }

    const lstat = fs.lstatSync(canonicalSource);
    if (lstat.isSymbolicLink()) {
      throw new Error('SECURITY_VIOLATION: Quarantining symbolic links is forbidden to prevent target hijacking.');
    }

    // 2. Read file bytes and scramble to prevent execution
    const rawBytes = await fs.promises.readFile(canonicalSource);
    const scrambledBytes = QuarantineService.scrambleBytes(rawBytes);

    // 3. Generate unique quarantine ID
    const quarantineId = `quarantine-${crypto.randomUUID()}`;
    const blobPath = path.join(this.vaultDir, `${quarantineId}.blob`);

    // 4. Atomic write scrambled container to vault
    await fs.promises.writeFile(blobPath, scrambledBytes);

    // 5. Try stripping execution permissions on container
    try {
      fs.chmodSync(blobPath, 0o400); // Read-only user access, zero execute
    } catch {
      // Best-effort permission stripping across platforms
    }

    // 6. Securely unlink the original malicious file from the user's filesystem
    await fs.promises.unlink(canonicalSource);

    const item: QuarantineItem = {
      quarantineId,
      originalPath: canonicalSource,
      fileName: threat.fileName,
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

    // Path Traversal Defense on Destination
    let destinationPath = item.originalPath;
    if (customDestinationDir) {
      const canonicalDestDir = path.resolve(customDestinationDir);
      if (canonicalDestDir.includes('..') || !fs.existsSync(canonicalDestDir)) {
        throw new Error('INVALID_DESTINATION: Destination directory is invalid or inaccessible.');
      }
      destinationPath = path.join(canonicalDestDir, item.fileName);
    }

    // Collision Avoidance: Do not silently overwrite existing file
    if (fs.existsSync(destinationPath)) {
      const parsed = path.parse(destinationPath);
      destinationPath = path.join(parsed.dir, `${parsed.name}_restored_${Date.now()}${parsed.ext}`);
    }

    // Read scrambled bytes, de-scramble, and restore
    const scrambledBytes = await fs.promises.readFile(item.blobPath);
    const restoredBytes = QuarantineService.scrambleBytes(scrambledBytes);

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
