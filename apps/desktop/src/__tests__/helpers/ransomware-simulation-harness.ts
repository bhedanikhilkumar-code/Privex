import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { RansomwareShieldService } from '../../services/ransomware-shield.service';

export interface SyntheticFileRecord {
  readonly relativePath: string;
  readonly fullPath: string;
  readonly originalBytes: Buffer;
  readonly originalSha256: string;
  readonly size: number;
}

/**
 * RansomwareSimulationHarness (Phase G)
 *
 * STRICT SAFETY INVARIANT:
 * All simulation activity MUST be strictly confined within os.tmpdir()/pp-ransom-sandbox-<uuid>.
 * Any attempt to access or modify paths outside the sandbox root throws SANDBOX_ESCAPE_ABORT.
 */
export class RansomwareSimulationHarness {
  private sandboxId: string;
  private sandboxRoot: string;
  private protectedSubfolder: string;
  private isDestroyed = false;
  private syntheticFiles: Map<string, SyntheticFileRecord> = new Map();

  constructor() {
    this.sandboxId = crypto.randomUUID();
    this.sandboxRoot = path.join(os.tmpdir(), `pp-ransom-sandbox-${this.sandboxId}`);
    this.protectedSubfolder = path.join(this.sandboxRoot, 'ProtectedDocuments');
    this.initSandbox();
  }

  public getSandboxRoot(): string {
    return this.sandboxRoot;
  }

  public getProtectedSubfolder(): string {
    return this.protectedSubfolder;
  }

  private initSandbox(): void {
    if (!fs.existsSync(this.sandboxRoot)) {
      fs.mkdirSync(this.sandboxRoot, { recursive: true, mode: 0o700 });
    }
    if (!fs.existsSync(this.protectedSubfolder)) {
      fs.mkdirSync(this.protectedSubfolder, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Confinement check: throws SANDBOX_ESCAPE_ABORT if candidate path is outside sandbox root.
   */
  public assertConfinement(targetPath: string): string {
    if (!targetPath || typeof targetPath !== 'string') {
      throw new Error('SANDBOX_ESCAPE_ABORT: Invalid empty path.');
    }

    const resolved = path.resolve(targetPath);
    const resolvedRoot = path.resolve(this.sandboxRoot);
    const prefix = resolvedRoot.endsWith(path.sep) ? resolvedRoot : resolvedRoot + path.sep;

    const isInside =
      process.platform === 'win32'
        ? resolved.toLowerCase().startsWith(prefix.toLowerCase()) || resolved.toLowerCase() === resolvedRoot.toLowerCase()
        : resolved.startsWith(prefix) || resolved === resolvedRoot;

    if (!isInside) {
      throw new Error(`SANDBOX_ESCAPE_ABORT: Attempted access outside sandbox root '${targetPath}' (sandbox: '${this.sandboxRoot}').`);
    }

    return resolved;
  }

  /**
   * Creates N synthetic documents with known deterministic bytes and recorded SHA-256 hashes.
   */
  public async generateSyntheticDocuments(count = 30): Promise<SyntheticFileRecord[]> {
    if (this.isDestroyed) {
      throw new Error('SANDBOX_DESTROYED: Harness has been destroyed.');
    }

    const extensions = ['.docx', '.xlsx', '.pdf', '.txt', '.csv'];
    const generated: SyntheticFileRecord[] = [];

    for (let i = 0; i < count; i++) {
      const ext = extensions[i % extensions.length];
      const fileName = `Document_${i + 1}_financial_report${ext}`;
      const fullPath = path.join(this.protectedSubfolder, fileName);
      this.assertConfinement(fullPath);

      // Deterministic benign content
      const content = Buffer.from(
        `PRIVATE_PROTECTION_SYNTHETIC_DOCUMENT_PAYLOAD_${i}_${fileName}_DATA_${crypto.randomBytes(64).toString('hex')}\n`,
        'utf8'
      );
      const originalSha256 = crypto.createHash('sha256').update(content).digest('hex');

      fs.writeFileSync(fullPath, content, { mode: 0o644 });

      const record: SyntheticFileRecord = {
        relativePath: fileName,
        fullPath,
        originalBytes: content,
        originalSha256,
        size: content.length
      };

      this.syntheticFiles.set(fullPath, record);
      generated.push(record);
    }

    return generated;
  }

  /**
   * Simulates ransomware encrypting a file (overwriting with high-entropy pseudo-random bytes).
   */
  public simulateEncryptFile(filePath: string, newExtension?: string): { newPath: string; entropy: number } {
    this.assertConfinement(filePath);

    if (!fs.existsSync(filePath)) {
      throw new Error(`FILE_NOT_FOUND: Cannot encrypt missing file '${filePath}'.`);
    }

    // High-entropy random payload (Shannon entropy ~ 7.9)
    const encryptedBytes = crypto.randomBytes(4096);
    const targetPath = newExtension
      ? `${filePath}${newExtension.startsWith('.') ? newExtension : '.' + newExtension}`
      : filePath;

    this.assertConfinement(targetPath);

    RansomwareShieldService.clearWindowsAttributes(filePath);

    if (newExtension) {
      fs.unlinkSync(filePath);
      fs.writeFileSync(targetPath, encryptedBytes, { mode: 0o644 });
    } else {
      fs.writeFileSync(targetPath, encryptedBytes, { mode: 0o644 });
    }

    return { newPath: targetPath, entropy: 7.95 };
  }

  /**
   * Simulates mass-encryption velocity burst.
   */
  public async simulateVelocityAttack(
    shield: RansomwareShieldService,
    options?: {
      fileCount?: number;
      useLockedExtension?: boolean;
      responsiblePid?: number;
      processName?: string;
    }
  ): Promise<{ affectedFiles: string[]; pids: number[] }> {
    const fileCount = options?.fileCount ?? 30;
    const records = Array.from(this.syntheticFiles.values()).slice(0, fileCount);
    const affected: string[] = [];
    const pid = options?.responsiblePid ?? 4321;
    const processName = options?.processName ?? 'sim_ransomware.exe';

    for (let i = 0; i < records.length; i++) {
      const rec = records[i];
      const ext = options?.useLockedExtension ? '.locked' : undefined;
      const { newPath } = this.simulateEncryptFile(rec.fullPath, ext);
      affected.push(newPath);

      // Ingest write event into shield
      await shield.ingestFilesystemEvent({
        filePath: newPath,
        eventType: options?.useLockedExtension ? 'rename' : 'modify',
        responsiblePid: pid,
        processName,
        entropy: 7.95,
        fileBytes: crypto.randomBytes(1024)
      });
    }

    return { affectedFiles: affected, pids: [pid] };
  }

  public getSyntheticFiles(): Map<string, SyntheticFileRecord> {
    return this.syntheticFiles;
  }

  /**
   * Verifies that all synthetic files have their exact original SHA-256 hashes restored.
   */
  public verifyRestoration(): { verified: boolean; totalChecked: number; mismatched: string[] } {
    const mismatched: string[] = [];
    let checked = 0;

    for (const [fullPath, record] of this.syntheticFiles.entries()) {
      this.assertConfinement(fullPath);
      checked++;

      if (!fs.existsSync(fullPath)) {
        mismatched.push(`${fullPath} (MISSING)`);
        continue;
      }

      const currentBytes = fs.readFileSync(fullPath);
      const currentSha256 = crypto.createHash('sha256').update(currentBytes).digest('hex');

      if (currentSha256 !== record.originalSha256) {
        mismatched.push(
          `${fullPath} (HASH_MISMATCH: expected ${record.originalSha256.substring(0, 10)}..., got ${currentSha256.substring(0, 10)}...)`
        );
      }
    }

    return {
      verified: mismatched.length === 0,
      totalChecked: checked,
      mismatched
    };
  }

  /**
   * Teardown sandbox safely.
   */
  public cleanup(): void {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    try {
      if (fs.existsSync(this.sandboxRoot)) {
        fs.rmSync(this.sandboxRoot, { recursive: true, force: true });
      }
    } catch {
      // Best effort cleanup
    }
  }
}
