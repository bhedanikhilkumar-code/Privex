import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as os from 'os';
import { EventEmitter } from 'events';
import {
  RansomwareProtectionMode,
  TrustedApplication,
  CanaryFileRecord,
  RansomwareThreatType,
  RansomwareIncident,
  IncidentRollbackResult,
  RansomwareShieldOptions,
  RansomwareShieldStatus,
  ProcessContainmentResult
} from '../types/desktop.types';
import { IpcValidator } from '../ipc/ipc-validator';
import { ShadowVaultService } from './shadow-vault.service';
import { ProcessAuditorService } from './process-auditor.service';
import { BehaviorEngineService } from './behavior-engine.service';
import { EntropyScanner } from '@private-protection/core';

interface SlidingWindowEvent {
  readonly timestamp: number;
  readonly filePath: string;
  readonly canonicalPath: string;
  readonly eventType: 'modify' | 'rename' | 'write' | 'create';
  readonly isHighEntropy: boolean;
  readonly isSuspiciousRename: boolean;
  readonly entropy: number;
  readonly responsiblePid?: number;
  readonly processName?: string;
  readonly previousPath?: string;
}

/**
 * RansomwareShieldService (Phase G)
 *
 * Implements local, offline Ransomware Shield:
 * - Protected Folders (Documents, Pictures, Desktop, custom roots)
 * - Smart Mode vs Strict Mode with CanonicalPath + SHA256 + Signer trust registry
 * - Automatic trust revocation upon binary modification
 * - Decoy Canary Trap files (~$_PrivateProtection_Canary_*.docx/.xlsx) with tamper alert (score 100)
 * - 64-slot Sliding-Window Velocity & Entropy Detector (>=25 writes/3s, >=8 H>7.5 or >=10 renames)
 * - Copy-on-Write encrypted ShadowVault backups & 1-click rollback with exact SHA-256 verification
 * - Safe process containment preserving RULE-09 OS immunity via Phase F authorization
 */
export class RansomwareShieldService extends EventEmitter {
  private mode: RansomwareProtectionMode;
  private protectedFolders: Set<string> = new Set();
  private trustedApplications: Map<string, TrustedApplication> = new Map();
  private canaryRegistry: Map<string, CanaryFileRecord> = new Map();
  private incidents: Map<string, RansomwareIncident> = new Map();
  private activeWatchers: Map<string, fs.FSWatcher> = new Map();

  // 64-slot Sliding Window
  public static readonly SLOTS_CAPACITY = 64;
  public static readonly DEFAULT_VELOCITY_THRESHOLD = 25;
  public static readonly DEFAULT_WINDOW_DURATION_MS = 3000;
  public static readonly DEFAULT_ENTROPY_THRESHOLD = 7.5;
  public static readonly DEFAULT_HIGH_ENTROPY_WRITES_THRESHOLD = 8;
  public static readonly DEFAULT_EXTENSION_RENAME_THRESHOLD = 10;

  private slidingWindow: SlidingWindowEvent[] = [];
  private readonly velocityThreshold: number;
  private readonly windowDurationMs: number;
  private readonly entropyThreshold: number;
  private readonly highEntropyWritesThreshold: number;
  private readonly extensionRenameThreshold: number;

  private shadowVault: ShadowVaultService;
  private processAuditor: ProcessAuditorService | null = null;
  private behaviorEngine: BehaviorEngineService | null = null;
  private isRunning = false;
  private dryRunContainment: boolean;
  private enableCanaries: boolean;

  // Known ransomware extension suffixes (case-normalized)
  public static readonly SUSPICIOUS_EXTENSIONS = new Set([
    '.locked',
    '.encrypted',
    '.crypto',
    '.cry',
    '.lock',
    '.enc',
    '.crypted',
    '.ransom',
    '.wnry',
    '.wncry',
    '.wcry',
    '.dark',
    '.vault',
    '.djvu',
    '.stop',
    '.pay',
    '.mallox',
    '.lockbit',
    '.blackcat',
    '.alphv'
  ]);

  // Known compressed/media formats that naturally have high entropy
  public static readonly BENIGN_HIGH_ENTROPY_EXTENSIONS = new Set([
    '.zip',
    '.7z',
    '.rar',
    '.gz',
    '.tar',
    '.bz2',
    '.xz',
    '.jpg',
    '.jpeg',
    '.png',
    '.webp',
    '.gif',
    '.mp4',
    '.mkv',
    '.mov',
    '.avi',
    '.mp3',
    '.aac',
    '.flac',
    '.ogg'
  ]);

  // Event deduplication cache: path -> lastProcessedTimestamp
  private recentEventTimestamps: Map<string, number> = new Map();

  constructor(
    options?: RansomwareShieldOptions,
    shadowVault?: ShadowVaultService,
    processAuditor?: ProcessAuditorService | null,
    behaviorEngine?: BehaviorEngineService | null
  ) {
    super();
    this.mode = options?.mode || 'smart';
    this.dryRunContainment = options?.dryRunContainment || false;
    this.enableCanaries = options?.enableCanaries ?? true;

    this.velocityThreshold = options?.velocityThreshold ?? RansomwareShieldService.DEFAULT_VELOCITY_THRESHOLD;
    this.windowDurationMs = options?.velocityWindowMs ?? RansomwareShieldService.DEFAULT_WINDOW_DURATION_MS;
    this.entropyThreshold = options?.entropyThreshold ?? RansomwareShieldService.DEFAULT_ENTROPY_THRESHOLD;
    this.highEntropyWritesThreshold =
      options?.highEntropyWritesThreshold ?? RansomwareShieldService.DEFAULT_HIGH_ENTROPY_WRITES_THRESHOLD;
    this.extensionRenameThreshold =
      options?.extensionRenameThreshold ?? RansomwareShieldService.DEFAULT_EXTENSION_RENAME_THRESHOLD;

    this.shadowVault =
      shadowVault ||
      new ShadowVaultService(options?.customVaultDir ? { customVaultDir: options.customVaultDir } : undefined);
    this.processAuditor = processAuditor || null;
    this.behaviorEngine = behaviorEngine || null;

    // Initialize protected folders
    const initialFolders = options?.protectedFolders || RansomwareShieldService.getDefaultProtectedRoots();
    for (const folder of initialFolders) {
      this.addProtectedFolder(folder);
    }

    // Initialize trusted applications
    if (options?.trustedApplications) {
      for (const app of options.trustedApplications) {
        this.registerTrustedApplication(app);
      }
    }
  }

  // ============================================================
  // DEFAULT ROOTS RESOLUTION
  // ============================================================

  public static getDefaultProtectedRoots(): string[] {
    const home = os.homedir();
    const candidates = [
      path.join(home, 'Documents'),
      path.join(home, 'Pictures'),
      path.join(home, 'Desktop')
    ];
    return candidates.filter((p) => {
      try {
        return fs.existsSync(p) && fs.statSync(p).isDirectory();
      } catch {
        return false;
      }
    });
  }

  // ============================================================
  // PROTECTED FOLDERS MANAGEMENT
  // ============================================================

  public addProtectedFolder(folderPath: string): string {
    const validated = IpcValidator.validatePath(folderPath);
    const canonical = path.resolve(validated);

    // Verify folder exists or create if safe
    if (!fs.existsSync(canonical)) {
      fs.mkdirSync(canonical, { recursive: true });
    }

    const stat = fs.lstatSync(canonical);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error('SECURITY_VIOLATION: Protected folder cannot be a symbolic link or non-directory.');
    }

    const norm = this.normalizePathKey(canonical);
    this.protectedFolders.add(norm);

    if (this.isRunning) {
      this.watchFolder(canonical);
      if (this.enableCanaries) {
        this.deployCanariesForFolder(canonical);
      }
    }

    return canonical;
  }

  public removeProtectedFolder(folderPath: string): boolean {
    const canonical = path.resolve(folderPath);
    const norm = this.normalizePathKey(canonical);
    const deleted = this.protectedFolders.delete(norm);

    if (deleted) {
      const watcher = this.activeWatchers.get(norm);
      if (watcher) {
        try {
          watcher.close();
        } catch {
          // Ignore
        }
        this.activeWatchers.delete(norm);
      }
      this.cleanupCanariesForFolder(canonical);
    }
    return deleted;
  }

  public getProtectedFolders(): string[] {
    return Array.from(this.protectedFolders);
  }

  public isPathInsideProtectedFolder(candidatePath: string): { isProtected: boolean; folderPath?: string } {
    if (!candidatePath || typeof candidatePath !== 'string' || candidatePath.includes('\0')) {
      return { isProtected: false };
    }

    const resolved = path.resolve(candidatePath);
    const normCandidate = this.normalizePathKey(resolved);

    for (const folder of this.protectedFolders) {
      const folderPrefix = folder.endsWith(path.sep) ? folder : folder + path.sep;
      if (normCandidate === folder || normCandidate.startsWith(folderPrefix)) {
        return { isProtected: true, folderPath: folder };
      }
    }
    return { isProtected: false };
  }

  private normalizePathKey(targetPath: string): string {
    const resolved = path.resolve(targetPath);
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  }

  // ============================================================
  // TRUSTED APPLICATION REGISTRY
  // ============================================================

  public async registerTrustedApplication(app: {
    path?: string;
    canonicalPath?: string;
    sha256?: string;
    signer?: string;
    name?: string;
  }): Promise<TrustedApplication> {
    const rawPath = app.canonicalPath || app.path;
    if (!rawPath) {
      throw new Error('APPLICATION_PATH_REQUIRED: Either path or canonicalPath must be provided.');
    }
    const canonicalPath = path.resolve(IpcValidator.validatePath(rawPath));
    let sha256 = app.sha256;

    if (!sha256 && fs.existsSync(canonicalPath)) {
      const bytes = fs.readFileSync(canonicalPath);
      sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    }

    if (!sha256) {
      throw new Error(`APPLICATION_NOT_FOUND: Cannot register trust for missing binary without SHA-256 '${canonicalPath}'.`);
    }

    const record: TrustedApplication = {
      canonicalPath,
      sha256: sha256.toLowerCase(),
      signer: app.signer,
      name: app.name || path.basename(canonicalPath),
      addedAt: Date.now(),
      isRevoked: false
    };

    const key = this.normalizePathKey(canonicalPath);
    this.trustedApplications.set(key, record);
    return record;
  }

  public removeTrustedApplication(executablePath: string): boolean {
    const key = this.normalizePathKey(path.resolve(executablePath));
    return this.trustedApplications.delete(key);
  }

  public getTrustedApplications(): TrustedApplication[] {
    return Array.from(this.trustedApplications.values());
  }

  /**
   * Verifies an application's trust status.
   * CRITICAL INVARIANT: If executable SHA-256 does not match registered SHA-256,
   * trust is IMMEDIATELY revoked and the application becomes untrusted.
   */
  public async verifyApplicationTrust(executablePath: string): Promise<{
    isTrusted: boolean;
    reason: string;
    app?: TrustedApplication;
  }> {
    const canonicalPath = path.resolve(IpcValidator.validatePath(executablePath));
    const key = this.normalizePathKey(canonicalPath);
    const registered = this.trustedApplications.get(key);

    if (!registered) {
      return { isTrusted: false, reason: 'APPLICATION_NOT_REGISTERED' };
    }

    if (registered.isRevoked) {
      return {
        isTrusted: false,
        reason: registered.revocationReason || 'TRUST_REVOKED',
        app: registered
      };
    }

    if (!fs.existsSync(canonicalPath)) {
      return { isTrusted: false, reason: 'BINARY_MISSING_ON_DISK', app: registered };
    }

    // Recompute live hash on disk
    const liveBytes = fs.readFileSync(canonicalPath);
    const liveSha256 = crypto.createHash('sha256').update(liveBytes).digest('hex').toLowerCase();

    if (liveSha256 !== registered.sha256) {
      // Hash mismatch -> revoke trust immediately!
      const revokedApp: TrustedApplication = {
        ...registered,
        isRevoked: true,
        revocationReason: 'SHA256_MISMATCH: Binary modified or replaced on disk. Previous trust relationship invalidated.'
      };
      this.trustedApplications.set(key, revokedApp);
      this.emit('trustRevoked', {
        app: revokedApp,
        expectedSha256: registered.sha256,
        observedSha256: liveSha256
      });

      return {
        isTrusted: false,
        reason: 'SHA256_MISMATCH: Binary modified or replaced on disk.',
        app: revokedApp
      };
    }

    return { isTrusted: true, reason: 'TRUSTED_APPLICATION', app: registered };
  }

  // ============================================================
  // DECOY CANARY TRAP FILES
  // ============================================================

  public deployCanaries(): CanaryFileRecord[] {
    const deployed: CanaryFileRecord[] = [];
    for (const folder of this.protectedFolders) {
      const records = this.deployCanariesForFolder(folder);
      deployed.push(...records);
    }
    return deployed;
  }

  private deployCanariesForFolder(folderPath: string): CanaryFileRecord[] {
    const deployed: CanaryFileRecord[] = [];
    const names = [
      `~$_PrivateProtection_Canary_Financial_Ledger_${crypto.randomBytes(4).toString('hex')}.docx`,
      `~$_PrivateProtection_Canary_Payroll_Report_${crypto.randomBytes(4).toString('hex')}.xlsx`
    ];

    for (const name of names) {
      const filePath = path.join(folderPath, name);
      const canonicalPath = path.resolve(filePath);

      // Deterministic decoy payload
      const content = Buffer.from(
        `PRIVATE_PROTECTION_CANARY_TRAP_INTEGRITY_PINNED_${name}_${Date.now()}`,
        'utf8'
      );
      const expectedSha256 = crypto.createHash('sha256').update(content).digest('hex');

      try {
        fs.writeFileSync(canonicalPath, content, { mode: 0o644 });

        const canaryId = `canary-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
        const record: CanaryFileRecord = {
          filePath,
          canonicalPath,
          expectedSha256,
          expectedSize: content.length,
          folderPath,
          deployedAt: Date.now(),
          canaryId
        };

        const key = this.normalizePathKey(canonicalPath);
        this.canaryRegistry.set(key, record);
        deployed.push(record);
      } catch {
        // Best effort creation
      }
    }

    return deployed;
  }

  private cleanupCanariesForFolder(folderPath: string): void {
    const normFolder = this.normalizePathKey(folderPath);
    for (const [key, canary] of this.canaryRegistry.entries()) {
      if (this.normalizePathKey(canary.folderPath) === normFolder) {
        try {
          if (fs.existsSync(canary.canonicalPath)) {
            fs.unlinkSync(canary.canonicalPath);
          }
        } catch {
          // Ignore
        }
        this.canaryRegistry.delete(key);
      }
    }
  }

  public getCanaries(): CanaryFileRecord[] {
    return Array.from(this.canaryRegistry.values());
  }

  // ============================================================
  // CANARY TAMPER DETECTION
  // ============================================================

  public async checkCanaryTamper(filePath: string, context?: { responsiblePid?: number; processName?: string }): Promise<boolean> {
    const canonical = path.resolve(filePath);
    const key = this.normalizePathKey(canonical);
    const record = this.canaryRegistry.get(key);

    if (!record) {
      // Check if this matches canary naming pattern in a protected folder
      const base = path.basename(filePath);
      if (base.startsWith('~$_PrivateProtection_Canary_')) {
        // Unexpected canary deletion or rename
        await this.handleCanaryTamperIncident(filePath, record, context);
        return true;
      }
      return false;
    }

    let isTampered = false;
    if (!fs.existsSync(record.canonicalPath)) {
      // Canary deleted
      isTampered = true;
    } else {
      try {
        const stat = fs.statSync(record.canonicalPath);
        if (stat.size !== record.expectedSize) {
          isTampered = true;
        } else {
          const currentBytes = fs.readFileSync(record.canonicalPath);
          const currentSha256 = crypto.createHash('sha256').update(currentBytes).digest('hex');
          if (currentSha256 !== record.expectedSha256) {
            isTampered = true;
          }
        }
      } catch {
        isTampered = true;
      }
    }

    if (isTampered) {
      await this.handleCanaryTamperIncident(filePath, record, context);
      return true;
    }

    return false;
  }

  private async handleCanaryTamperIncident(
    filePath: string,
    _record?: CanaryFileRecord,
    context?: { responsiblePid?: number; processName?: string }
  ): Promise<RansomwareIncident> {
    const incidentId = `inc-canary-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const responsiblePid = context?.responsiblePid;
    const processName = context?.processName;

    let containmentResult: ProcessContainmentResult | undefined;
    if (responsiblePid && responsiblePid > 0) {
      containmentResult = await this.containRansomwareProcess(responsiblePid, processName, 'RANSOMWARE_CANARY_TRIPPED');
    }

    const incident: RansomwareIncident = {
      incidentId,
      detectedAt: Date.now(),
      threatType: 'CANARY_TAMPER',
      reason: `RANSOMWARE_CANARY_TRIPPED: Decoy canary trap '${path.basename(filePath)}' was modified, renamed, or deleted. Score 100.`,
      riskScore: 100,
      severity: 'critical',
      engineVerdict: 'CONTAIN_PROCESS',
      responsiblePid,
      processName,
      containmentResult,
      affectedFiles: [filePath],
      backupIds: [],
      rollbackStatus: 'PENDING',
      metrics: {
        modificationsInWindow: 1,
        highEntropyCount: 1,
        renameCount: 0,
        maxEntropyObserved: 8.0
      }
    };

    this.incidents.set(incidentId, incident);
    this.emit('ransomwareDetected', incident);
    return incident;
  }

  // ============================================================
  // 64-SLOT SLIDING-WINDOW VELOCITY & ENTROPY DETECTOR
  // ============================================================

  /**
   * Ingests a filesystem write/modify/rename event into the 64-slot sliding window.
   * Condition: >= 25 modifications in 3.0s AND (>= 8 high-entropy writes H > 7.5 OR >= 10 renames .locked/.encrypted)
   */
  public async ingestFilesystemEvent(event: {
    filePath: string;
    eventType: 'modify' | 'rename' | 'write' | 'create';
    previousPath?: string;
    responsiblePid?: number;
    processName?: string;
    executablePath?: string;
    entropy?: number;
    fileBytes?: Buffer;
  }): Promise<{ isRansomware: boolean; incident?: RansomwareIncident }> {
    const canonical = path.resolve(event.filePath);
    const now = Date.now();

    // 1. Event deduplication: ignore identical file events within 10ms
    const dedupKey = `${canonical}|${event.eventType}`;
    const lastSeen = this.recentEventTimestamps.get(dedupKey);
    if (lastSeen && now - lastSeen < 10) {
      return { isRansomware: false };
    }
    this.recentEventTimestamps.set(dedupKey, now);

    // 2. Check if this is a decoy canary trap
    const baseName = path.basename(canonical);
    if (baseName.startsWith('~$_PrivateProtection_Canary_')) {
      const isCanaryTamper = await this.checkCanaryTamper(canonical, {
        responsiblePid: event.responsiblePid,
        processName: event.processName
      });
      if (isCanaryTamper) {
        const incident = Array.from(this.incidents.values()).pop();
        return { isRansomware: true, incident };
      }
    }

    // 3. Application access control check for protected folders
    const { isProtected } = this.isPathInsideProtectedFolder(canonical);
    if (isProtected && event.executablePath) {
      const trust = await this.verifyApplicationTrust(event.executablePath);
      if (!trust.isTrusted) {
        if (this.mode === 'strict' || this.isKnownRansomwareExtension(canonical)) {
          const incident = await this.triggerAccessControlIncident(canonical, event);
          return { isRansomware: true, incident };
        }
      }
    }

    // 4. Calculate entropy of write
    let entropy = event.entropy ?? 0;
    if (entropy === 0 && event.fileBytes && event.fileBytes.length > 0) {
      entropy = EntropyScanner.calculateEntropy(event.fileBytes);
    } else if (entropy === 0 && fs.existsSync(canonical)) {
      try {
        const stat = fs.statSync(canonical);
        if (stat.isFile() && stat.size > 0 && stat.size <= 50 * 1024 * 1024) {
          const sliceSize = Math.min(stat.size, 64 * 1024);
          const buf = Buffer.alloc(sliceSize);
          const fd = fs.openSync(canonical, 'r');
          try {
            fs.readSync(fd, buf, 0, sliceSize, 0);
            entropy = EntropyScanner.calculateEntropy(buf);
          } finally {
            fs.closeSync(fd);
          }
        }
      } catch {
        // Fall through
      }
    }

    // Check if high entropy write
    const isBenignFormat = this.isBenignHighEntropyFormat(canonical);
    const isHighEntropy = entropy > this.entropyThreshold && !isBenignFormat;

    // Check if suspicious rename
    const isSuspiciousRename =
      event.eventType === 'rename' && this.isKnownRansomwareExtension(canonical);

    // 5. Ingest into 64-slot sliding window with eviction of expired slots (> 3.0 seconds)
    const windowEvent: SlidingWindowEvent = {
      timestamp: now,
      filePath: event.filePath,
      canonicalPath: canonical,
      eventType: event.eventType,
      isHighEntropy,
      isSuspiciousRename,
      entropy,
      responsiblePid: event.responsiblePid,
      processName: event.processName,
      previousPath: event.previousPath
    };

    this.pruneAndAddSlidingWindowEvent(windowEvent, now);

    // 6. Evaluate Primary Ransomware Condition
    const metrics = this.evaluateSlidingWindowMetrics(now);

    const conditionMet =
      metrics.modificationsInWindow >= this.velocityThreshold &&
      (metrics.highEntropyCount >= this.highEntropyWritesThreshold ||
        metrics.renameCount >= this.extensionRenameThreshold);

    if (conditionMet) {
      const incident = await this.triggerVelocityBurstIncident(metrics, windowEvent);
      return { isRansomware: true, incident };
    }

    return { isRansomware: false };
  }

  private pruneAndAddSlidingWindowEvent(newEvent: SlidingWindowEvent, now: number): void {
    const cutoff = now - this.windowDurationMs;
    // Filter events within window
    const valid = this.slidingWindow.filter((e) => e.timestamp >= cutoff);

    // Ensure capacity <= 64 slots
    if (valid.length >= RansomwareShieldService.SLOTS_CAPACITY) {
      valid.shift(); // FIFO eviction
    }

    valid.push(newEvent);
    this.slidingWindow = valid;
  }

  private evaluateSlidingWindowMetrics(now: number): {
    modificationsInWindow: number;
    highEntropyCount: number;
    renameCount: number;
    maxEntropyObserved: number;
    affectedFiles: string[];
    responsiblePid?: number;
    processName?: string;
  } {
    const cutoff = now - this.windowDurationMs;
    const windowEvents = this.slidingWindow.filter((e) => e.timestamp >= cutoff);

    let highEntropyCount = 0;
    let renameCount = 0;
    let maxEntropyObserved = 0;
    const affectedFilesSet = new Set<string>();
    let responsiblePid: number | undefined;
    let processName: string | undefined;

    for (const ev of windowEvents) {
      affectedFilesSet.add(ev.canonicalPath);
      if (ev.isHighEntropy) highEntropyCount++;
      if (ev.isSuspiciousRename) renameCount++;
      if (ev.entropy > maxEntropyObserved) maxEntropyObserved = ev.entropy;
      if (ev.responsiblePid && !responsiblePid) {
        responsiblePid = ev.responsiblePid;
        processName = ev.processName;
      }
    }

    return {
      modificationsInWindow: windowEvents.length,
      highEntropyCount,
      renameCount,
      maxEntropyObserved,
      affectedFiles: Array.from(affectedFilesSet),
      responsiblePid,
      processName
    };
  }

  private isKnownRansomwareExtension(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return RansomwareShieldService.SUSPICIOUS_EXTENSIONS.has(ext);
  }

  private isBenignHighEntropyFormat(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return RansomwareShieldService.BENIGN_HIGH_ENTROPY_EXTENSIONS.has(ext);
  }

  private async triggerVelocityBurstIncident(
    metrics: {
      modificationsInWindow: number;
      highEntropyCount: number;
      renameCount: number;
      maxEntropyObserved: number;
      affectedFiles: string[];
      responsiblePid?: number;
      processName?: string;
    },
    latestEvent: SlidingWindowEvent
  ): Promise<RansomwareIncident> {
    const incidentId = `inc-vel-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const responsiblePid = metrics.responsiblePid || latestEvent.responsiblePid;
    const processName = metrics.processName || latestEvent.processName;

    let containmentResult: ProcessContainmentResult | undefined;
    if (responsiblePid && responsiblePid > 0) {
      containmentResult = await this.containRansomwareProcess(
        responsiblePid,
        processName,
        'RANSOMWARE_VELOCITY_BURST'
      );
    }

    // Backup affected files in batch with single atomic manifest commit
    const backedUp = await this.shadowVault.backupFiles(metrics.affectedFiles, incidentId);
    const backupIds = backedUp.map((r) => r.backupId);

    const threatType: RansomwareThreatType =
      metrics.renameCount >= this.extensionRenameThreshold
        ? 'SUSPICIOUS_EXTENSION_BURST'
        : 'VELOCITY_BURST';

    const incident: RansomwareIncident = {
      incidentId,
      detectedAt: Date.now(),
      threatType,
      reason: `RANSOMWARE_VELOCITY_BURST: ${metrics.modificationsInWindow} modifications in 3.0s with ${metrics.highEntropyCount} high-entropy writes (max H=${metrics.maxEntropyObserved}) and ${metrics.renameCount} renames. Score 100.`,
      riskScore: 100,
      severity: 'critical',
      engineVerdict: 'CONTAIN_PROCESS',
      responsiblePid,
      processName,
      containmentResult,
      affectedFiles: metrics.affectedFiles,
      backupIds,
      rollbackStatus: backupIds.length > 0 ? 'PENDING' : 'NOT_REQUIRED',
      metrics: {
        modificationsInWindow: metrics.modificationsInWindow,
        highEntropyCount: metrics.highEntropyCount,
        renameCount: metrics.renameCount,
        maxEntropyObserved: metrics.maxEntropyObserved
      }
    };

    this.incidents.set(incidentId, incident);
    this.emit('ransomwareDetected', incident);
    return incident;
  }

  private async triggerAccessControlIncident(
    filePath: string,
    event: {
      responsiblePid?: number;
      processName?: string;
      executablePath?: string;
    }
  ): Promise<RansomwareIncident> {
    const incidentId = `inc-acl-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const responsiblePid = event.responsiblePid;
    const processName = event.processName;

    let containmentResult: ProcessContainmentResult | undefined;
    if (responsiblePid && responsiblePid > 0) {
      containmentResult = await this.containRansomwareProcess(
        responsiblePid,
        processName,
        'UNAUTHORIZED_PROTECTED_FOLDER_WRITE'
      );
    }

    const incident: RansomwareIncident = {
      incidentId,
      detectedAt: Date.now(),
      threatType: 'UNAUTHORIZED_PROTECTED_FOLDER_WRITE',
      reason: `UNAUTHORIZED_PROTECTED_FOLDER_WRITE: Untrusted application '${event.executablePath || processName || 'unknown'}' attempted modification of protected file '${filePath}'.`,
      riskScore: 95,
      severity: 'critical',
      engineVerdict: 'BLOCK',
      responsiblePid,
      processName,
      containmentResult,
      affectedFiles: [filePath],
      backupIds: [],
      rollbackStatus: 'NOT_REQUIRED',
      metrics: {
        modificationsInWindow: 1,
        highEntropyCount: 0,
        renameCount: 0,
        maxEntropyObserved: 0
      }
    };

    this.incidents.set(incidentId, incident);
    this.emit('ransomwareDetected', incident);
    return incident;
  }

  // ============================================================
  // SAFE PROCESS CONTAINMENT (PHASE F INTEGRATION & RULE-09)
  // ============================================================

  public async containRansomwareProcess(
    pid: number,
    processName?: string,
    reason?: string
  ): Promise<ProcessContainmentResult> {
    const now = Date.now();

    // RULE-09 OS Immunity: PID 0, PID 4, and critical system components are strictly protected
    if (pid === 0 || pid === 4) {
      return {
        success: false,
        pid,
        processName: pid === 0 ? '[System Idle Process]' : 'System',
        action: 'REJECTED_PROTECTED',
        reason: 'RULE-09: Process PID 0 and PID 4 are core operating system components and cannot be terminated.',
        containedAt: now
      };
    }

    if (this.behaviorEngine) {
      const isProtected = this.behaviorEngine.isProtectedSystemProcess(
        pid,
        processName || 'unknown',
        undefined
      );
      if (isProtected) {
        return {
          success: false,
          pid,
          processName,
          action: 'REJECTED_PROTECTED',
          reason: `RULE-09: Process '${processName}' (PID ${pid}) is a protected Windows operating system component.`,
          containedAt: now
        };
      }
    }

    // If dry run containment
    if (this.dryRunContainment) {
      return {
        success: true,
        pid,
        processName,
        action: 'TERMINATED',
        reason: 'Dry-run containment: termination simulated successfully.',
        containedAt: now
      };
    }

    // Gated Phase F containment authorization
    if (this.processAuditor && this.behaviorEngine) {
      const fakeNode = {
        pid,
        processName: processName || 'ransomware.exe',
        creationTime: now - 500,
        sanitizedCommandLine: '',
        instanceKey: `${pid}-${now}`
      };
      const auth = this.behaviorEngine.issueContainmentAuthorization(
        fakeNode as any,
        100,
        reason || 'RANSOMWARE_CONTAIN_PROCESS'
      );

      return this.processAuditor.containProcess(pid, {
        authorizationId: auth.authorizationId,
        token: auth.singleUseToken,
        reason: reason || 'Ransomware containment'
      });
    }

    // Fallback: direct OS process kill if running outside BehaviorEngine harness
    try {
      if (process.platform === 'win32') {
        const cp = require('child_process');
        await new Promise<void>((resolve, reject) => {
          cp.execFile('taskkill', ['/PID', String(pid), '/T', '/F'], (err: any) => {
            if (err) {
              const errStr = String(err);
              if (errStr.includes('not found') || err?.code === 128) {
                resolve();
              } else {
                reject(err);
              }
            } else {
              resolve();
            }
          });
        });
      } else {
        process.kill(pid, 'SIGKILL');
      }

      return {
        success: true,
        pid,
        processName,
        action: 'TERMINATED',
        reason: reason || 'Ransomware process terminated',
        containedAt: now
      };
    } catch (err: any) {
      if (err?.code === 'ESRCH') {
        return {
          success: true,
          pid,
          processName,
          action: 'NOT_FOUND',
          reason: 'Process already exited',
          containedAt: now
        };
      }
      return {
        success: false,
        pid,
        processName,
        action: 'FAILED',
        reason: err?.message || 'Containment failed',
        containedAt: now
      };
    }
  }

  // ============================================================
  // INCIDENT ROLLBACK INTEGRATION
  // ============================================================

  public async rollbackIncident(incidentId: string): Promise<IncidentRollbackResult> {
    const incident = this.incidents.get(incidentId);
    const result = await this.shadowVault.rollbackIncident(incidentId);

    if (incident) {
      const updated: RansomwareIncident = {
        ...incident,
        rollbackStatus: result.success
          ? 'ROLLED_BACK'
          : result.restoredCount > 0
          ? 'PARTIAL'
          : 'FAILED'
      };
      this.incidents.set(incidentId, updated);
      this.emit('incidentRolledBack', { incident: updated, result });
    }

    return result;
  }

  public getIncidents(): RansomwareIncident[] {
    return Array.from(this.incidents.values());
  }

  // ============================================================
  // LIFECYCLE & WATCHERS
  // ============================================================

  public async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    for (const folder of this.protectedFolders) {
      this.watchFolder(folder);
      if (this.enableCanaries) {
        this.deployCanariesForFolder(folder);
      }
    }
  }

  private watchFolder(folderPath: string): void {
    const norm = this.normalizePathKey(folderPath);
    if (this.activeWatchers.has(norm)) return;

    try {
      const watcher = fs.watch(
        folderPath,
        { recursive: process.platform === 'win32' },
        (eventType, filename) => {
          if (!filename) return;
          const fullPath = path.join(folderPath, filename);
          const evtType: 'modify' | 'rename' | 'write' | 'create' =
            eventType === 'rename' ? 'rename' : 'modify';
          this.ingestFilesystemEvent({
            filePath: fullPath,
            eventType: evtType
          }).catch(() => {
            // Best effort event processing
          });
        }
      );

      this.activeWatchers.set(norm, watcher);
    } catch {
      // Best effort watcher attachment
    }
  }

  public async stop(): Promise<void> {
    this.isRunning = false;
    for (const watcher of this.activeWatchers.values()) {
      try {
        watcher.close();
      } catch {
        // Ignore
      }
    }
    this.activeWatchers.clear();
  }

  public getStatus(): RansomwareShieldStatus {
    const vaultStats = this.shadowVault.getStats();
    return {
      active: this.isRunning,
      mode: this.mode,
      protectedFolders: Array.from(this.protectedFolders),
      trustedAppsCount: this.trustedApplications.size,
      activeCanariesCount: this.canaryRegistry.size,
      incidentsCount: this.incidents.size,
      vaultTotalSizeBytes: vaultStats.totalSizeBytes,
      vaultBackupCount: vaultStats.backupCount
    };
  }

  public setMode(newMode: RansomwareProtectionMode): void {
    this.mode = newMode;
  }

  public getShadowVault(): ShadowVaultService {
    return this.shadowVault;
  }
}
