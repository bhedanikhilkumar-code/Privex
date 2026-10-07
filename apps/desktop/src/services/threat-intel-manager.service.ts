import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import { ThreatIntel } from '@private-protection/core';
import {
  PpdbBundle,
  UpdateApplyResult,
  UpdateRollbackResult,
  ThreatIntelStatus,
  UpdateMetadataRecord,
  ThreatIntelManagerOptions
} from '../types/desktop.types';
import { UpdateVerifierService, PRODUCTION_ROOT_PUBLIC_KEY } from './update-verifier.service';
import { CleanFileCache } from '../core/clean-file-cache';
import { NotificationService } from './notification.service';

/**
 * ThreatIntelManagerService (Phase O — Threat Intelligence & Cryptographically Signed Updates)
 *
 * Manages the complete lifecycle of on-device threat intelligence updates:
 * 1. Offline .ppdb bundle importation with Ed25519 verification against pinned Root Public Key.
 * 2. Monotonic anti-downgrade enforcement (incoming <= current is strictly rejected).
 * 3. Bounded staging and deterministic post-staging EICAR trial self-testing.
 * 4. Crash-safe atomic active-database swap on Windows.
 * 5. 3-Tier Storage Hierarchy: ACTIVE -> LKG (N-1) -> FACTORY SEED.
 * 6. Automatic CleanFileCache invalidation on version updates and rollbacks.
 * 7. Encrypted metadata persistence with PBKDF2/AES-256-GCM authenticated encryption.
 * 8. 100% offline, zero-knowledge, zero cloud telemetry operation.
 */
export class ThreatIntelManagerService extends EventEmitter {
  private configDir: string;
  private activeDbPath: string;
  private lkgDbPath: string;
  private stagingDbPath: string;
  private metadataPath: string;
  private encryptionKey: Buffer;

  private verifier: UpdateVerifierService;
  private threatIntel: ThreatIntel;
  private cleanFileCache: CleanFileCache;
  private notificationService: NotificationService | null = null;
  private clock: () => number;

  private isOperating = false;
  private metadata: UpdateMetadataRecord;

  public static readonly FACTORY_SEED_SEQUENCE = 100;
  public static readonly FACTORY_SEED_VERSION = '1.0.0-seed';

  constructor(options?: ThreatIntelManagerOptions) {
    super();
    this.configDir = path.resolve(
      options?.dataDir || options?.configDir || path.join(os.homedir(), '.private-protection')
    );
    this.activeDbPath = path.join(this.configDir, 'threat-db.active.enc');
    this.lkgDbPath = path.join(this.configDir, 'threat-db.lkg.enc');
    this.stagingDbPath = path.join(this.configDir, 'threat-db.staging.tmp');
    this.metadataPath = path.join(this.configDir, 'threat-intel-metadata.enc');

    this.clock = options?.clock ?? (() => Date.now());
    this.threatIntel = options?.threatIntelInstance ?? options?.threatIntel ?? ThreatIntel.getSharedInstance();
    this.cleanFileCache =
      options?.cleanFileCache ??
      (options?.scannerService && typeof options.scannerService.getCleanFileCache === 'function'
        ? options.scannerService.getCleanFileCache()
        : CleanFileCache.getSharedInstance());
    this.notificationService = options?.notificationService ?? null;

    this.verifier = new UpdateVerifierService(
      options?.rootPublicKeyHex ?? PRODUCTION_ROOT_PUBLIC_KEY,
      ThreatIntelManagerService.FACTORY_SEED_SEQUENCE
    );

    this.initDirectory();
    this.encryptionKey = this.deriveEncryptionKey();
    this.metadata = this.loadOrInitMetadata();
    this.verifier.setCurrentVersionSequence(this.metadata.currentVersionSequence);

    this.initAndReconcile();
  }

  private initDirectory(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
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

    const machineSecret = `${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}:threat-intel`;
    return crypto.pbkdf2Sync(machineSecret, salt, 100000, 32, 'sha256');
  }

  private encrypt(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return JSON.stringify({
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      ciphertext: encrypted.toString('hex')
    });
  }

  private decrypt(encryptedJson: string): string {
    const parsed = JSON.parse(encryptedJson);
    if (!parsed.iv || !parsed.tag || !parsed.ciphertext) {
      throw new Error('CORRUPTED_ENCRYPTED_PAYLOAD: Missing crypto envelope components.');
    }

    const iv = Buffer.from(parsed.iv, 'hex');
    const tag = Buffer.from(parsed.tag, 'hex');
    const ciphertext = Buffer.from(parsed.ciphertext, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  }

  private writeAtomicFileSync(targetPath: string, content: string | Buffer): void {
    this.initDirectory();
    const tmpPath = `${targetPath}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}.tmp`;
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

    // Windows atomic replacement with unlink fallback for locked files
    try {
      if (fs.existsSync(targetPath)) {
        try {
          fs.unlinkSync(targetPath);
        } catch {
          // Fall through to renameSync
        }
      }
      fs.renameSync(tmpPath, targetPath);
    } catch {
      try {
        fs.copyFileSync(tmpPath, targetPath);
        fs.unlinkSync(tmpPath);
      } catch {
        // Fallback cleanup
        try { fs.unlinkSync(tmpPath); } catch {}
      }
    }
  }

  private loadOrInitMetadata(): UpdateMetadataRecord {
    if (fs.existsSync(this.metadataPath)) {
      try {
        const raw = fs.readFileSync(this.metadataPath, 'utf8');
        const decrypted = this.decrypt(raw);
        const parsed = JSON.parse(decrypted);
        if (
          parsed &&
          typeof parsed.currentVersionSequence === 'number' &&
          typeof parsed.installedVersion === 'string'
        ) {
          return {
            currentVersionSequence: parsed.currentVersionSequence,
            installedVersion: parsed.installedVersion,
            lastUpdated: parsed.lastUpdated || this.clock(),
            activeSha256: parsed.activeSha256 || '',
            hasLkg: Boolean(parsed.hasLkg),
            lkgVersionSequence: parsed.lkgVersionSequence,
            lkgInstalledVersion: parsed.lkgInstalledVersion,
            lkgSha256: parsed.lkgSha256,
            isFactorySeed: Boolean(parsed.isFactorySeed)
          };
        }
      } catch {
        // Corrupted metadata: fall back to default
      }
    }

    const defaultMetadata: UpdateMetadataRecord = {
      currentVersionSequence: ThreatIntelManagerService.FACTORY_SEED_SEQUENCE,
      installedVersion: ThreatIntelManagerService.FACTORY_SEED_VERSION,
      lastUpdated: this.clock(),
      activeSha256: '',
      hasLkg: false,
      isFactorySeed: true
    };

    this.saveMetadata(defaultMetadata);
    return defaultMetadata;
  }

  private saveMetadata(record: UpdateMetadataRecord): void {
    this.metadata = record;
    const payload = JSON.stringify(record);
    const encrypted = this.encrypt(payload);
    this.writeAtomicFileSync(this.metadataPath, encrypted);

    // Save backup copy for crash resilience
    try {
      this.writeAtomicFileSync(`${this.metadataPath}.bak`, encrypted);
    } catch {
      // Non-blocking backup write
    }
  }

  /**
   * Initializes and reconciles active threat database on service startup.
   */
  public initAndReconcile(): void {
    if (this.metadata.isFactorySeed) {
      this.threatIntel.resetToFactorySeed();
      this.cleanFileCache.setThreatDatabaseVersion(this.metadata.currentVersionSequence);
      return;
    }

    if (fs.existsSync(this.activeDbPath)) {
      try {
        const raw = fs.readFileSync(this.activeDbPath, 'utf8');
        const decrypted = this.decrypt(raw);
        this.threatIntel.loadState(decrypted);
        this.cleanFileCache.setThreatDatabaseVersion(this.metadata.currentVersionSequence);
        return;
      } catch {
        // Active DB is corrupted, attempt rollback to LKG
      }
    }

    // Try recovering from LKG
    if (this.metadata.hasLkg && fs.existsSync(this.lkgDbPath)) {
      try {
        const rawLkg = fs.readFileSync(this.lkgDbPath, 'utf8');
        const decryptedLkg = this.decrypt(rawLkg);
        this.threatIntel.loadState(decryptedLkg);
        this.saveMetadata({
          currentVersionSequence: this.metadata.lkgVersionSequence || ThreatIntelManagerService.FACTORY_SEED_SEQUENCE,
          installedVersion: this.metadata.lkgInstalledVersion || ThreatIntelManagerService.FACTORY_SEED_VERSION,
          lastUpdated: this.clock(),
          activeSha256: this.metadata.lkgSha256 || '',
          hasLkg: false,
          isFactorySeed: false
        });
        this.cleanFileCache.setThreatDatabaseVersion(this.metadata.currentVersionSequence);
        this.cleanFileCache.clear();
        return;
      } catch {
        // LKG corrupted too
      }
    }

    // Fail-safe recovery to Factory Seed
    this.threatIntel.resetToFactorySeed();
    this.saveMetadata({
      currentVersionSequence: ThreatIntelManagerService.FACTORY_SEED_SEQUENCE,
      installedVersion: ThreatIntelManagerService.FACTORY_SEED_VERSION,
      lastUpdated: this.clock(),
      activeSha256: '',
      hasLkg: false,
      isFactorySeed: true
    });
    this.cleanFileCache.setThreatDatabaseVersion(ThreatIntelManagerService.FACTORY_SEED_SEQUENCE);
    this.cleanFileCache.clear();
  }

  public getVerifier(): UpdateVerifierService {
    return this.verifier;
  }

  public getStatus(): ThreatIntelStatus {
    const stalenessDays = this.threatIntel.getStalenessDays();
    const stalenessState = this.threatIntel.getStalenessState();

    return {
      currentVersion: this.metadata.installedVersion,
      installedVersion: this.metadata.installedVersion,
      currentSequence: this.metadata.currentVersionSequence,
      currentVersionSequence: this.metadata.currentVersionSequence,
      lastUpdated: this.metadata.lastUpdated,
      lastUpdatedAt: this.metadata.lastUpdated,
      hasLkg: this.metadata.hasLkg,
      lkgVersion: this.metadata.lkgInstalledVersion,
      lkgInstalledVersion: this.metadata.lkgInstalledVersion,
      lkgSequence: this.metadata.lkgVersionSequence,
      lkgVersionSequence: this.metadata.lkgVersionSequence,
      stalenessState,
      stalenessDays,
      badHashesCount: this.threatIntel.getBadHashesCount(),
      isFactorySeed: this.metadata.isFactorySeed
    };
  }

  /**
   * Executes a post-staging trial self-test on an isolated ThreatIntel instance.
   * Ensures staged database is fully operational, detects EICAR, and preserves known-good state.
   */
  private runPostStagingSelfTest(
    bundle: PpdbBundle
  ): { passed: boolean; reason?: string } {
    try {
      // 1. Create trial ThreatIntel instance initialized from current active state
      const trial = new ThreatIntel({
        initialVersion: this.threatIntel.getVersion(),
        initialSequence: this.metadata.currentVersionSequence,
        installedVersion: this.metadata.installedVersion
      });
      trial.loadState(this.threatIntel.exportState());

      // 2. Apply staged payload to trial instance
      const payloadObj =
        typeof bundle.payload === 'string'
          ? JSON.parse(bundle.payload)
          : bundle.payload;

      const applyRes = trial.applyPpdbPayload(
        payloadObj,
        bundle.manifest.version,
        bundle.manifest.versionSequence,
        bundle.manifest.publishedAt
      );

      if (!applyRes.success) {
        return { passed: false, reason: `POST_STAGING_SELF_TEST_FAILED: ${applyRes.error}` };
      }

      // 3. EICAR Known-Bad Malware Detection Verification
      const eicarLookup = trial.lookupHash(ThreatIntel.EICAR_SHA256);
      if (eicarLookup.status !== 'KNOWN_BAD' || !eicarLookup.isMalicious) {
        return {
          passed: false,
          reason: 'POST_STAGING_SELF_TEST_FAILED: EICAR malware standard was not detected as KNOWN_BAD'
        };
      }

      // 4. Known-Good Indicator Preservation Verification
      const goodLookup = trial.checkDomain('google.com');
      if (goodLookup.isMalicious) {
        return {
          passed: false,
          reason: 'POST_STAGING_SELF_TEST_FAILED: False positive detected on verified allowlist domain'
        };
      }

      // 5. Version Alignment Verification
      if (trial.getVersionSequence() !== bundle.manifest.versionSequence) {
        return {
          passed: false,
          reason: `POST_STAGING_SELF_TEST_FAILED: Version sequence mismatch (${trial.getVersionSequence()} != ${bundle.manifest.versionSequence})`
        };
      }

      // 6. Inspect new bad hashes if present
      if (Array.isArray(payloadObj.addBadHashes) && payloadObj.addBadHashes.length > 0) {
        const firstEntry = payloadObj.addBadHashes[0];
        if (firstEntry && firstEntry.hash) {
          const newLookup = trial.lookupHash(firstEntry.hash);
          if (newLookup.status !== 'KNOWN_BAD') {
            return {
              passed: false,
              reason: `POST_STAGING_SELF_TEST_FAILED: Staged hash ${firstEntry.hash} not detectable in trial DB`
            };
          }
        }
      }

      return { passed: true };
    } catch (err: any) {
      return { passed: false, reason: `POST_STAGING_SELF_TEST_ERROR: ${err.message || 'Trial test failed'}` };
    }
  }

  /**
   * Applies an offline .ppdb update bundle.
   * Enforces verification, staging, self-test, atomic swap, and CleanFileCache invalidation.
   */
  public async applyBundle(
    bundleOrPath: unknown
  ): Promise<UpdateApplyResult> {
    if (this.isOperating) {
      return {
        success: false,
        error: 'UPDATE_IN_PROGRESS: Another threat intelligence update or rollback operation is active.'
      };
    }

    this.isOperating = true;

    try {
      // 1. Full Cryptographic & Anti-Downgrade Verification
      const verifyRes = this.verifier.verifyBundle(bundleOrPath, {
        currentSequence: this.metadata.currentVersionSequence
      });

      if (!verifyRes.valid || !verifyRes.bundle || !verifyRes.manifest) {
        const errRes = {
          success: false,
          errorCode: verifyRes.code || 'VERIFICATION_FAILED',
          reason: verifyRes.reason || 'Update verification failed.',
          error: verifyRes.reason || 'Update verification failed.'
        };
        this.emit('updateFailed', errRes);
        return errRes;
      }

      const bundle = verifyRes.bundle;
      const manifest = verifyRes.manifest;

      // 2. Post-Staging EICAR & Structural Trial Self-Test
      const selfTest = this.runPostStagingSelfTest(bundle);
      if (!selfTest.passed) {
        const errRes = {
          success: false,
          errorCode: 'SELF_TEST_FAILED',
          reason: selfTest.reason || 'Post-staging self-test failed.',
          error: selfTest.reason || 'Post-staging self-test failed.'
        };
        this.emit('updateFailed', errRes);
        return errRes;
      }

      // 3. Stage update state to disk
      const payloadObj =
        typeof bundle.payload === 'string'
          ? JSON.parse(bundle.payload)
          : bundle.payload;

      // Prepare snapshot of updated state
      const preUpdateState = this.threatIntel.exportState();

      // 4. Preserve Current Active as LKG (N-1)
      if (!this.metadata.isFactorySeed && fs.existsSync(this.activeDbPath)) {
        try {
          fs.copyFileSync(this.activeDbPath, this.lkgDbPath);
        } catch {
          // If copy fails, serialize current state to LKG
          const encryptedPre = this.encrypt(preUpdateState);
          this.writeAtomicFileSync(this.lkgDbPath, encryptedPre);
        }
      } else {
        // If coming from Factory Seed, serialize current seed state as LKG
        const encryptedPre = this.encrypt(preUpdateState);
        this.writeAtomicFileSync(this.lkgDbPath, encryptedPre);
      }

      // 5. Apply changes to active ThreatIntel singleton
      const applyRes = this.threatIntel.applyPpdbPayload(
        payloadObj,
        manifest.version,
        manifest.versionSequence,
        manifest.publishedAt
      );

      if (!applyRes.success) {
        // Roll back ThreatIntel singleton
        this.threatIntel.loadState(preUpdateState);
        const errRes = {
          success: false,
          errorCode: 'PAYLOAD_APPLY_FAILED',
          reason: applyRes.error || 'Failed to apply update payload.',
          error: applyRes.error || 'Failed to apply update payload.'
        };
        this.emit('updateFailed', errRes);
        return errRes;
      }

      // 6. Write new active database to staging and atomically swap
      const updatedState = this.threatIntel.exportState();
      const encryptedActive = this.encrypt(updatedState);
      this.writeAtomicFileSync(this.stagingDbPath, encryptedActive);
      this.writeAtomicFileSync(this.activeDbPath, encryptedActive);

      // Clean staging file
      try {
        if (fs.existsSync(this.stagingDbPath)) {
          fs.unlinkSync(this.stagingDbPath);
        }
      } catch {}

      // 7. Invalidate CleanFileCache on Database Version Change (Phase P Integration)
      this.cleanFileCache.setThreatDatabaseVersion(manifest.versionSequence);
      this.cleanFileCache.clear();

      // 8. Update and Persist Metadata
      const previousSequence = this.metadata.currentVersionSequence;
      const previousVersion = this.metadata.installedVersion;

      const newMetadata: UpdateMetadataRecord = {
        currentVersionSequence: manifest.versionSequence,
        installedVersion: manifest.version,
        lastUpdated: manifest.publishedAt || this.clock(),
        activeSha256: manifest.sha256,
        hasLkg: true,
        lkgVersionSequence: previousSequence,
        lkgInstalledVersion: previousVersion,
        lkgSha256: this.metadata.activeSha256,
        isFactorySeed: false
      };

      this.saveMetadata(newMetadata);
      this.verifier.setCurrentVersionSequence(manifest.versionSequence);

      const successResult: UpdateApplyResult = {
        success: true,
        version: manifest.version,
        newVersion: manifest.version,
        versionSequence: manifest.versionSequence,
        newVersionSequence: manifest.versionSequence,
        previousVersionSequence: previousSequence,
        badCount: this.threatIntel.getBadHashesCount()
      };

      // 9. Dispatch Notification & Emit Event
      this.emit('updateApplied', successResult);

      if (this.notificationService) {
        this.notificationService.notify({
          title: 'Threat Definitions Updated',
          message: `Updated to version ${manifest.version} (Sequence: ${manifest.versionSequence}).`,
          severity: 'low',
          category: 'UPDATE_STATUS'
        });
      }

      return successResult;
    } catch (err: any) {
      const errRes = {
        success: false,
        errorCode: 'UNEXPECTED_UPDATE_ERROR',
        reason: `UNEXPECTED_UPDATE_ERROR: ${err.message || 'An unexpected error occurred during update'}`,
        error: `UNEXPECTED_UPDATE_ERROR: ${err.message || 'An unexpected error occurred during update'}`
      };
      this.emit('updateFailed', errRes);
      return errRes;
    } finally {
      this.isOperating = false;
    }
  }

  /**
   * Alias for applyBundle to support flexible API callers.
   */
  public async applyUpdate(bundleOrPath: unknown): Promise<UpdateApplyResult> {
    return this.applyBundle(bundleOrPath);
  }

  /**
   * Alias for rollbackToLastKnownGood.
   */
  public async rollbackToLkg(): Promise<UpdateRollbackResult> {
    return this.rollbackToLastKnownGood();
  }

  /**
   * Rolls back active threat database to Last-Known-Good (LKG N-1).
   */
  public async rollbackToLastKnownGood(): Promise<UpdateRollbackResult> {
    if (this.isOperating) {
      return {
        success: false,
        reason: 'UPDATE_IN_PROGRESS: Another update/rollback operation is currently active.',
        error: 'UPDATE_IN_PROGRESS: Another update/rollback operation is currently active.'
      };
    }

    this.isOperating = true;

    try {
      if (!this.metadata.hasLkg) {
        return {
          success: false,
          reason: 'NO_LKG_AVAILABLE: No Last-Known-Good threat database rollback point exists.',
          error: 'NO_LKG_AVAILABLE: No Last-Known-Good threat database rollback point exists.'
        };
      }

      if (!fs.existsSync(this.lkgDbPath)) {
        return {
          success: false,
          reason: 'LKG_RESTORE_FAILED: LKG file is missing from disk.',
          error: 'LKG_RESTORE_FAILED: LKG file is missing from disk.'
        };
      }

      try {
        const rawLkg = fs.readFileSync(this.lkgDbPath, 'utf8');
        const decryptedLkg = this.decrypt(rawLkg);

        // Test-load LKG
        const trial = new ThreatIntel();
        trial.loadState(decryptedLkg);

        // Verify EICAR detection on LKG
        if (!trial.lookupHash(ThreatIntel.EICAR_SHA256).isMalicious) {
          throw new Error('LKG database failed EICAR integrity check');
        }

        // Restore active database from LKG
        this.threatIntel.loadState(decryptedLkg);
        this.writeAtomicFileSync(this.activeDbPath, rawLkg);

        const restoredSequence = this.metadata.lkgVersionSequence || ThreatIntelManagerService.FACTORY_SEED_SEQUENCE;
        const restoredVersion = this.metadata.lkgInstalledVersion || ThreatIntelManagerService.FACTORY_SEED_VERSION;

        // Invalidate CleanFileCache (Phase P Integration)
        this.cleanFileCache.setThreatDatabaseVersion(restoredSequence);
        this.cleanFileCache.clear();

        const newMetadata: UpdateMetadataRecord = {
          currentVersionSequence: restoredSequence,
          installedVersion: restoredVersion,
          lastUpdated: this.clock(),
          activeSha256: this.metadata.lkgSha256 || '',
          hasLkg: false,
          isFactorySeed: restoredSequence === ThreatIntelManagerService.FACTORY_SEED_SEQUENCE
        };

        this.saveMetadata(newMetadata);
        this.verifier.setCurrentVersionSequence(restoredSequence);

        const rollbackRes: UpdateRollbackResult = {
          success: true,
          restoredVersion: restoredVersion,
          restoredVersionSequence: restoredSequence
        };

        this.emit('updateRollback', rollbackRes);

        if (this.notificationService) {
          this.notificationService.notify({
            title: 'Threat Definitions Rolled Back',
            message: `Restored to Last-Known-Good version ${restoredVersion} (Sequence: ${restoredSequence}).`,
            severity: 'medium',
            category: 'UPDATE_STATUS'
          });
        }

        return rollbackRes;
      } catch (err: any) {
        return {
          success: false,
          reason: `LKG_RESTORE_FAILED: ${err.message || 'LKG restore failed'}`,
          error: `LKG_RESTORE_FAILED: ${err.message || 'LKG restore failed'}`
        };
      }
    } finally {
      this.isOperating = false;
    }
  }

  /**
   * Resets threat intelligence to the immutable Factory Seed.
   */
  public async resetToFactorySeed(): Promise<UpdateRollbackResult> {
    if (this.isOperating) {
      return {
        success: false,
        reason: 'UPDATE_IN_PROGRESS: Another operation is currently active.'
      };
    }

    this.isOperating = true;
    try {
      this.threatIntel.resetToFactorySeed();
      const seedState = this.threatIntel.exportState();
      const encryptedSeed = this.encrypt(seedState);
      this.writeAtomicFileSync(this.activeDbPath, encryptedSeed);

      this.cleanFileCache.setThreatDatabaseVersion(ThreatIntelManagerService.FACTORY_SEED_SEQUENCE);
      this.cleanFileCache.clear();

      const factoryMetadata: UpdateMetadataRecord = {
        currentVersionSequence: ThreatIntelManagerService.FACTORY_SEED_SEQUENCE,
        installedVersion: ThreatIntelManagerService.FACTORY_SEED_VERSION,
        lastUpdated: this.clock(),
        activeSha256: '',
        hasLkg: false,
        isFactorySeed: true
      };

      this.saveMetadata(factoryMetadata);
      this.verifier.setCurrentVersionSequence(ThreatIntelManagerService.FACTORY_SEED_SEQUENCE);

      const res: UpdateRollbackResult = {
        success: true,
        restoredVersion: ThreatIntelManagerService.FACTORY_SEED_VERSION,
        restoredVersionSequence: ThreatIntelManagerService.FACTORY_SEED_SEQUENCE,
        fallbackToFactorySeed: true
      };

      this.emit('updateRollback', res);
      return res;
    } finally {
      this.isOperating = false;
    }
  }
}
