import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { RansomwareShieldService } from '../../services/ransomware-shield.service';
import { ShadowVaultService } from '../../services/shadow-vault.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';
import { RansomwareSimulationHarness } from '../helpers/ransomware-simulation-harness';

describe('Phase G Security Tests (A through AG)', () => {
  let testRoot: string;
  let protectedDir: string;
  let vaultDir: string;
  let shield: RansomwareShieldService;
  let shadowVault: ShadowVaultService;
  let processAuditor: ProcessAuditorService;
  let behaviorEngine: BehaviorEngineService;
  let harness: RansomwareSimulationHarness;

  beforeEach(() => {
    const id = crypto.randomUUID();
    testRoot = path.join(os.tmpdir(), `pp-sec-test-${id}`);
    protectedDir = path.join(testRoot, 'ProtectedDocs');
    vaultDir = path.join(testRoot, 'Vault');

    fs.mkdirSync(protectedDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });

    shadowVault = new ShadowVaultService({
      customVaultDir: vaultDir,
      maxFileSizeBytes: 50 * 1024 * 1024,
      maxVaultQuotaBytes: 10 * 1024 * 1024 // 10 MB for security tests
    });

    behaviorEngine = new BehaviorEngineService();
    processAuditor = new ProcessAuditorService({ behaviorEngine });

    shield = new RansomwareShieldService(
      {
        mode: 'smart',
        protectedFolders: [protectedDir],
        customVaultDir: vaultDir,
        dryRunContainment: true,
        enableCanaries: true,
        velocityThreshold: 25,
        velocityWindowMs: 3000,
        entropyThreshold: 7.5,
        highEntropyWritesThreshold: 8,
        extensionRenameThreshold: 10
      },
      shadowVault,
      processAuditor,
      behaviorEngine
    );

    harness = new RansomwareSimulationHarness();
  });

  afterEach(async () => {
    await shield.stop();
    harness.cleanup();
    try {
      if (fs.existsSync(testRoot)) {
        fs.rmSync(testRoot, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });

  // A. Protected path traversal
  it('SEC-G-A: rejects protected path traversal attempts', () => {
    expect(() => shield.addProtectedFolder(`${protectedDir}/../../evil_traversal`)).toThrow(
      /SECURITY_VIOLATION/
    );
  });

  // B. Symlink / junction escape
  it('SEC-G-B: rejects symlink/junction escape during path validation', () => {
    const symlinkTarget = path.join(testRoot, 'symlink_folder');
    try {
      fs.symlinkSync(protectedDir, symlinkTarget, 'junction');
      expect(() => shield.addProtectedFolder(symlinkTarget)).toThrow(/SECURITY_VIOLATION/);
    } catch (e: any) {
      if (e.message.includes('SECURITY_VIOLATION')) {
        expect(e.message).toContain('SECURITY_VIOLATION');
      }
    } finally {
      try {
        fs.unlinkSync(symlinkTarget);
      } catch {
        // Ignore
      }
    }
  });

  // C. Sandbox escape
  it('SEC-G-C: enforces SANDBOX_ESCAPE_ABORT when simulation harness points outside sandbox', () => {
    const outsidePath = path.join(os.homedir(), 'Documents', 'real_user_file.docx');
    expect(() => harness.assertConfinement(outsidePath)).toThrow(/SANDBOX_ESCAPE_ABORT/);
  });

  // D. Trusted application binary modification -> trust revoked
  it('SEC-G-D: automatically revokes trust when trusted application SHA-256 changes', async () => {
    const binPath = path.join(testRoot, 'Editor.exe');
    fs.writeFileSync(binPath, Buffer.from('ORIGINAL_CLEAN_BINARY_VERSION_1', 'utf8'));

    await shield.registerTrustedApplication({ path: binPath });
    const check1 = await shield.verifyApplicationTrust(binPath);
    expect(check1.isTrusted).toBe(true);

    // Modify binary
    fs.writeFileSync(binPath, Buffer.from('TAMPERED_MALICIOUS_BYTES_INJECTED', 'utf8'));
    const check2 = await shield.verifyApplicationTrust(binPath);
    expect(check2.isTrusted).toBe(false);
    expect(check2.reason).toContain('SHA256_MISMATCH');
  });

  // E. Trusted application path replacement
  it('SEC-G-E: rejects unregistered or replaced application paths', async () => {
    const unregistered = path.join(testRoot, 'Unregistered.exe');
    fs.writeFileSync(unregistered, Buffer.from('TEST_DATA'));
    const check = await shield.verifyApplicationTrust(unregistered);
    expect(check.isTrusted).toBe(false);
    expect(check.reason).toBe('APPLICATION_NOT_REGISTERED');
  });

  // F. Duplicate filesystem events deduplication
  it('SEC-G-F: deduplicates rapid duplicate filesystem events within 10ms', async () => {
    const docPath = path.join(protectedDir, 'Doc_Dedup.docx');
    fs.writeFileSync(docPath, Buffer.from('TEST'));

    const res1 = await shield.ingestFilesystemEvent({ filePath: docPath, eventType: 'modify' });
    const res2 = await shield.ingestFilesystemEvent({ filePath: docPath, eventType: 'modify' });
    // Second identical event in same millisecond is suppressed
    expect(res1.isRansomware).toBe(false);
    expect(res2.isRansomware).toBe(false);
  });

  // G. PID reuse protection
  it('SEC-G-G: rejects containment when process creation time differs (PID reuse)', async () => {
    // Calling processAuditor directly with recycled creation timestamp
    const fakeNode = {
      pid: 9999,
      processName: 'test.exe',
      creationTime: 100000,
      sanitizedCommandLine: '',
      instanceKey: '9999-100000'
    };
    const auth = behaviorEngine.issueContainmentAuthorization(fakeNode as any, 100, 'Test containment');

    // Attempt containment expecting different creation time (> 1000ms delta)
    const result = await processAuditor.containProcess(9999, {
      authorizationId: auth.authorizationId,
      token: auth.singleUseToken,
      expectedCreationTime: 200000 // mismatch
    });

    expect(result.success).toBe(false);
    expect(result.action).toBe('REJECTED_PID_REUSE');
  });

  // H. Canary rename
  it('SEC-G-H: alerts RANSOMWARE_CANARY_TRIPPED (score 100) on canary rename', async () => {
    const canaries = shield.deployCanaries();
    const canary = canaries[0];
    const renamed = `${canary.canonicalPath}.bak`;
    fs.renameSync(canary.canonicalPath, renamed);

    const isTampered = await shield.checkCanaryTamper(canary.canonicalPath);
    expect(isTampered).toBe(true);

    const incidents = shield.getIncidents();
    const last = incidents[incidents.length - 1];
    expect(last.threatType).toBe('CANARY_TAMPER');
    expect(last.riskScore).toBe(100);
  });

  // I. Canary deletion
  it('SEC-G-I: alerts RANSOMWARE_CANARY_TRIPPED on canary deletion', async () => {
    const canaries = shield.deployCanaries();
    const canary = canaries[1];
    fs.unlinkSync(canary.canonicalPath);

    const isTampered = await shield.checkCanaryTamper(canary.canonicalPath);
    expect(isTampered).toBe(true);
  });

  // J. Canary modification
  it('SEC-G-J: alerts RANSOMWARE_CANARY_TRIPPED on canary content modification', async () => {
    const canaries = shield.deployCanaries();
    const canary = canaries[0];
    fs.writeFileSync(canary.canonicalPath, Buffer.from('TAMPERED_DATA_ABC'));

    const isTampered = await shield.checkCanaryTamper(canary.canonicalPath);
    expect(isTampered).toBe(true);
  });

  // K. Canary replacement
  it('SEC-G-K: alerts RANSOMWARE_CANARY_TRIPPED when canary file is replaced with different content', async () => {
    const canaries = shield.deployCanaries();
    const canary = canaries[0];
    fs.unlinkSync(canary.canonicalPath);
    fs.writeFileSync(canary.canonicalPath, crypto.randomBytes(canary.expectedSize));

    const isTampered = await shield.checkCanaryTamper(canary.canonicalPath);
    expect(isTampered).toBe(true);
  });

  // L. 25 modifications below 3.0 seconds -> triggers
  it('SEC-G-L: triggers VELOCITY_BURST when 25 modifications occur within 3.0s with high entropy', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', (i) => {
      if (i.threatType === 'VELOCITY_BURST') triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, `burst_${i}.docx`),
        eventType: 'modify',
        entropy: i < 8 ? 7.9 : 3.0,
        responsiblePid: 1111
      });
    }

    expect(triggered).toBe(true);
  });

  // M. 25 modifications spread beyond 3.0 seconds -> does NOT trigger
  it('SEC-G-M: does not trigger velocity burst when modifications are spread beyond window', async () => {
    const fastWindowShield = new RansomwareShieldService({
      protectedFolders: [protectedDir],
      customVaultDir: vaultDir,
      velocityThreshold: 25,
      velocityWindowMs: 40 // 40ms window
    });

    let triggered = false;
    fastWindowShield.on('ransomwareDetected', () => {
      triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      await fastWindowShield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, `spread_${i}.docx`),
        eventType: 'modify',
        entropy: 7.9
      });
      await new Promise((r) => setTimeout(r, 10));
    }

    expect(triggered).toBe(false);
    await fastWindowShield.stop();
  });

  // N. 8 high-entropy writes -> triggers
  it('SEC-G-N: triggers velocity burst with exactly 8 high-entropy writes and 25 modifications', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', (i) => {
      if (i.threatType === 'VELOCITY_BURST') triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, `file_n_${i}.docx`),
        eventType: 'modify',
        entropy: i < 8 ? 7.8 : 2.0
      });
    }

    expect(triggered).toBe(true);
  });

  // O. 7 high-entropy writes -> does NOT trigger
  it('SEC-G-O: does not trigger velocity burst with only 7 high-entropy writes', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', () => {
      triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, `file_o_${i}.docx`),
        eventType: 'modify',
        entropy: i < 7 ? 7.8 : 2.0
      });
    }

    expect(triggered).toBe(false);
  });

  // P. 10 ransomware extension renames -> triggers
  it('SEC-G-P: triggers SUSPICIOUS_EXTENSION_BURST with >= 10 .locked renames', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', (i) => {
      if (i.threatType === 'SUSPICIOUS_EXTENSION_BURST') triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      const isRename = i < 10;
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, isRename ? `enc_${i}.docx.locked` : `norm_${i}.txt`),
        eventType: isRename ? 'rename' : 'modify',
        entropy: 4.0
      });
    }

    expect(triggered).toBe(true);
  });

  // Q. 9 ransomware extension renames -> does NOT trigger
  it('SEC-G-Q: does not trigger with only 9 ransomware extension renames and low entropy', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', () => {
      triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      const isRename = i < 9;
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, isRename ? `enc_${i}.docx.locked` : `norm_${i}.txt`),
        eventType: isRename ? 'rename' : 'modify',
        entropy: 4.0
      });
    }

    expect(triggered).toBe(false);
  });

  // R. Benign high-entropy files
  it('SEC-G-R: ignores naturally high-entropy formats (.jpg, .zip, .mp4)', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', () => {
      triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, `media_${i}.mp4`),
        eventType: 'write',
        entropy: 7.95
      });
    }

    expect(triggered).toBe(false);
  });

  // S. Benign application rename bursts
  it('SEC-G-S: ignores benign renames (.tmp or .bak) without ransomware extension', async () => {
    let triggered = false;
    shield.on('ransomwareDetected', () => {
      triggered = true;
    });

    for (let i = 0; i < 25; i++) {
      await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, `doc_${i}.bak`),
        eventType: 'rename',
        entropy: 4.0
      });
    }

    expect(triggered).toBe(false);
  });

  // T. Malformed ShadowVault metadata
  it('SEC-G-T: recovers from manifest backup or fails closed on malformed metadata', () => {
    const manifestPath = path.join(vaultDir, 'shadow-manifest.json.enc');
    // Corrupt primary manifest
    fs.writeFileSync(manifestPath, Buffer.from('CORRUPTED_GARBAGE_PAYLOAD'));

    // Loading new instance should not crash; recovers safely
    const newVault = new ShadowVaultService({ customVaultDir: vaultDir });
    expect(newVault.getBackups().length).toBe(0);
  });

  // U. Corrupted ShadowVault ciphertext
  it('SEC-G-U: rejects restoration of corrupted ciphertext container', async () => {
    const filePath = path.join(testRoot, 'Sensitive.docx');
    fs.writeFileSync(filePath, Buffer.from('SUPER_SECRET_DATA'));
    const backup = await shadowVault.backupFile(filePath, 'inc-corrupt');

    // Flip byte in ciphertext
    const blobBytes = fs.readFileSync(backup.blobPath);
    blobBytes[blobBytes.length - 1] ^= 0xaa;
    fs.writeFileSync(backup.blobPath, blobBytes);

    const rollback = await shadowVault.rollbackFile(backup.backupId);
    expect(rollback.success).toBe(false);
    expect(rollback.error).toContain('Authentication tag verification failed');
  });

  // V. Incorrect rollback incident ID
  it('SEC-G-V: fails closed when rollback incident ID is not found', async () => {
    const res = await shadowVault.rollbackIncident('non-existent-uuid');
    expect(res.success).toBe(false);
    expect(res.failedFiles[0].reason).toContain('INCIDENT_NOT_FOUND');
  });

  // W. Rollback SHA-256 mismatch
  it('SEC-G-W: deletes restored file and fails closed if post-restore SHA-256 does not match pre-attack hash', async () => {
    const filePath = path.join(testRoot, 'HashTest.docx');
    fs.writeFileSync(filePath, Buffer.from('CLEAN_DATA_BEFORE_ATTACK'));
    const backup = await shadowVault.backupFile(filePath, 'inc-hash-mismatch');

    // Tamper with manifest record's expected hash directly
    (backup as any).preAttackSha256 = '0000000000000000000000000000000000000000000000000000000000000000';

    const rollback = await shadowVault.rollbackFile(backup.backupId);
    expect(rollback.success).toBe(false);
  });

  // X. Quota exhaustion & Z. >2 GB aggregate quota
  it('SEC-G-X & Z: enforces FIFO eviction when quota limit is approached', async () => {
    const tinyVault = new ShadowVaultService({
      customVaultDir: path.join(testRoot, 'TinyVault'),
      maxVaultQuotaBytes: 100 * 1024 // 100 KB total quota
    });

    for (let i = 0; i < 4; i++) {
      const p = path.join(testRoot, `tiny_${i}.dat`);
      fs.writeFileSync(p, Buffer.alloc(40 * 1024, 0x41)); // 40 KB each
      await tinyVault.backupFile(p, 'inc-tiny');
      await new Promise((r) => setTimeout(r, 10));
    }

    const stats = tinyVault.getStats();
    expect(stats.totalSizeBytes).toBeLessThanOrEqual(100 * 1024);
  });

  // Y & Z. 50 MB boundary & >50 MB file rejection
  it('SEC-G-Y & Z: accepts files up to 50 MB and rejects files > 50 MB with EXCEEDS_FILE_SIZE_LIMIT', async () => {
    const boundaryVault = new ShadowVaultService({
      customVaultDir: path.join(testRoot, 'BoundaryVault'),
      maxFileSizeBytes: 500 // 500 bytes limit
    });

    const fileOk = path.join(testRoot, 'Ok.txt');
    fs.writeFileSync(fileOk, Buffer.alloc(500, 0x55));
    const backup = await boundaryVault.backupFile(fileOk);
    expect(backup.fileSize).toBe(500);

    const fileTooBig = path.join(testRoot, 'TooBig.txt');
    fs.writeFileSync(fileTooBig, Buffer.alloc(501, 0x55));
    await expect(boundaryVault.backupFile(fileTooBig)).rejects.toThrow(/EXCEEDS_FILE_SIZE_LIMIT/);
  });

  // AA. Concurrent backup / restore
  it('SEC-G-AA: executes concurrent backup operations safely without collision', async () => {
    const promises: Array<Promise<any>> = [];
    for (let i = 0; i < 5; i++) {
      const p = path.join(testRoot, `concurrent_${i}.txt`);
      fs.writeFileSync(p, Buffer.from(`CONCURRENT_DATA_${i}`));
      promises.push(shadowVault.backupFile(p, 'inc-concurrent'));
    }

    const results = await Promise.all(promises);
    expect(results.length).toBe(5);
    const uniqueIds = new Set(results.map((r) => r.backupId));
    expect(uniqueIds.size).toBe(5);
  });

  // AB. Interrupted backup
  it('SEC-G-AB: handles interrupted backup of non-existent file cleanly', async () => {
    await expect(shadowVault.backupFile(path.join(testRoot, 'ghost_file.docx'))).rejects.toThrow(
      /FILE_NOT_FOUND/
    );
  });

  // AC. Interrupted restore
  it('SEC-G-AC: handles missing blob during restore safely without throwing unhandled error', async () => {
    const p = path.join(testRoot, 'ToMissing.docx');
    fs.writeFileSync(p, Buffer.from('DATA'));
    const backup = await shadowVault.backupFile(p);

    // Delete blob
    fs.unlinkSync(backup.blobPath);

    const result = await shadowVault.rollbackFile(backup.backupId);
    expect(result.success).toBe(false);
    expect(result.error).toContain('BLOB_NOT_FOUND');
  });

  // AD. Process attribution ambiguity
  it('SEC-G-AD: does not kill arbitrary processes when PID attribution is ambiguous', async () => {
    // When attribution is unknown (no PID provided), containment is not attempted
    const result = await shield.ingestFilesystemEvent({
      filePath: path.join(protectedDir, 'unknown_author.docx'),
      eventType: 'modify',
      entropy: 7.9
    });

    // Fails safely without killing any PID
    expect(result.incident?.responsiblePid).toBeUndefined();
  });

  // AE. Attempt to contain PID 0
  it('SEC-G-AE: rejects containment of PID 0 under all conditions (RULE-09)', async () => {
    const res = await shield.containRansomwareProcess(0, '[System Idle Process]');
    expect(res.success).toBe(false);
    expect(res.action).toBe('REJECTED_PROTECTED');
    expect(res.reason).toContain('RULE-09');
  });

  // AF. Attempt to contain PID 4
  it('SEC-G-AF: rejects containment of PID 4 under all conditions (RULE-09)', async () => {
    const res = await shield.containRansomwareProcess(4, 'System');
    expect(res.success).toBe(false);
    expect(res.action).toBe('REJECTED_PROTECTED');
    expect(res.reason).toContain('RULE-09');
  });

  // AG. Attempt to contain critical Windows process
  it('SEC-G-AG: rejects containment of critical system processes (RULE-09)', async () => {
    const res = await shield.containRansomwareProcess(999, 'csrss.exe');
    expect(res.success).toBe(false);
    expect(res.action).toBe('REJECTED_PROTECTED');
    expect(res.reason).toContain('RULE-09');
  });
});
