import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { RansomwareShieldService } from '../../services/ransomware-shield.service';
import { ShadowVaultService } from '../../services/shadow-vault.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';

describe('RansomwareShieldService (Phase G)', () => {
  let testRoot: string;
  let protectedDir: string;
  let vaultDir: string;
  let shield: RansomwareShieldService;
  let shadowVault: ShadowVaultService;
  let processAuditor: ProcessAuditorService;
  let behaviorEngine: BehaviorEngineService;

  beforeEach(() => {
    const id = crypto.randomUUID();
    testRoot = path.join(os.tmpdir(), `pp-shield-test-${id}`);
    protectedDir = path.join(testRoot, 'ProtectedDocs');
    vaultDir = path.join(testRoot, 'Vault');

    fs.mkdirSync(protectedDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });

    shadowVault = new ShadowVaultService({ customVaultDir: vaultDir });
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
  });

  afterEach(async () => {
    await shield.stop();
    try {
      if (fs.existsSync(testRoot)) {
        fs.rmSync(testRoot, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });

  describe('Protected Folders & Path Canonicalization', () => {
    it('manages protected folders and canonicalizes path representations', () => {
      const folders = shield.getProtectedFolders();
      expect(folders.length).toBe(1);
      const isInside = shield.isPathInsideProtectedFolder(path.join(protectedDir, 'test.docx'));
      expect(isInside.isProtected).toBe(true);

      const outside = shield.isPathInsideProtectedFolder(path.join(testRoot, 'outside.txt'));
      expect(outside.isProtected).toBe(false);
    });

    it('rejects path traversal, null bytes, and non-directory protected folders', () => {
      expect(() => shield.addProtectedFolder(`${protectedDir}/../../traversal`)).toThrow(
        /SECURITY_VIOLATION/
      );
      expect(() => shield.addProtectedFolder(`C:\\test\0bad`)).toThrow(/SECURITY_VIOLATION/);
    });
  });

  describe('Trusted Application Registry & SHA-256 Hash Invalidation', () => {
    it('registers and verifies a trusted application by canonical path, sha256, and signer', async () => {
      const binPath = path.join(testRoot, 'TrustedEditor.exe');
      fs.writeFileSync(binPath, Buffer.from('TRUSTED_BINARY_PAYLOAD_V1', 'utf8'));

      const registered = await shield.registerTrustedApplication({
        path: binPath,
        signer: 'Acme Software Corp',
        name: 'TrustedEditor'
      });

      expect(registered.canonicalPath).toBe(path.resolve(binPath));
      expect(registered.sha256).toBeDefined();

      const verification = await shield.verifyApplicationTrust(binPath);
      expect(verification.isTrusted).toBe(true);
      expect(verification.reason).toBe('TRUSTED_APPLICATION');
    });

    it('CRITICAL INVARIANT: automatically revokes trust when trusted binary is modified or replaced', async () => {
      const binPath = path.join(testRoot, 'SafeApp.exe');
      fs.writeFileSync(binPath, Buffer.from('SAFE_INITIAL_BYTES', 'utf8'));

      await shield.registerTrustedApplication({ path: binPath });

      // Initially trusted
      const initial = await shield.verifyApplicationTrust(binPath);
      expect(initial.isTrusted).toBe(true);

      // Binary is modified on disk (e.g., infected by malware)
      fs.writeFileSync(binPath, Buffer.from('MODIFIED_OR_MALICIOUS_BYTES', 'utf8'));

      let trustRevokedFired = false;
      shield.on('trustRevoked', () => {
        trustRevokedFired = true;
      });

      // Verification must immediately detect hash mismatch and revoke trust
      const afterMod = await shield.verifyApplicationTrust(binPath);
      expect(afterMod.isTrusted).toBe(false);
      expect(afterMod.reason).toContain('SHA256_MISMATCH');
      expect(trustRevokedFired).toBe(true);

      // Subsequent check confirms it remains revoked
      const subsequent = await shield.verifyApplicationTrust(binPath);
      expect(subsequent.isTrusted).toBe(false);
      expect(subsequent.app?.isRevoked).toBe(true);
    });
  });

  describe('Decoy Canary Trap Files', () => {
    it('deploys hidden canary files matching ~$_PrivateProtection_Canary_*.docx/.xlsx convention', () => {
      const canaries = shield.deployCanaries();
      expect(canaries.length).toBeGreaterThanOrEqual(2);

      for (const canary of canaries) {
        expect(canary.filePath).toMatch(/~\$_PrivateProtection_Canary_.*\.(docx|xlsx)$/);
        expect(fs.existsSync(canary.canonicalPath)).toBe(true);
        expect(canary.expectedSha256).toBeDefined();
        expect(canary.expectedSize).toBeGreaterThan(0);
      }
    });

    it('detects unauthorized canary modification and immediately alerts RANSOMWARE_CANARY_TRIPPED with score 100', async () => {
      const canaries = shield.deployCanaries();
      const targetCanary = canaries[0];

      let alertFired = false;
      shield.on('ransomwareDetected', (incident) => {
        if (incident.threatType === 'CANARY_TAMPER') {
          alertFired = true;
          expect(incident.riskScore).toBe(100);
          expect(incident.severity).toBe('critical');
          expect(incident.engineVerdict).toBe('CONTAIN_PROCESS');
        }
      });

      // Tamper with canary content
      fs.writeFileSync(targetCanary.canonicalPath, Buffer.from('TAMPERED_CANARY_BYTES', 'utf8'));

      const isTampered = await shield.checkCanaryTamper(targetCanary.canonicalPath, {
        responsiblePid: 9876,
        processName: 'ransomware_sim.exe'
      });

      expect(isTampered).toBe(true);
      expect(alertFired).toBe(true);
    });

    it('detects canary deletion as tamper and raises score 100', async () => {
      const canaries = shield.deployCanaries();
      const targetCanary = canaries[0];

      fs.unlinkSync(targetCanary.canonicalPath);

      const isTampered = await shield.checkCanaryTamper(targetCanary.canonicalPath, {
        responsiblePid: 5555
      });
      expect(isTampered).toBe(true);

      const incidents = shield.getIncidents();
      const last = incidents[incidents.length - 1];
      expect(last.threatType).toBe('CANARY_TAMPER');
      expect(last.riskScore).toBe(100);
    });
  });

  describe('64-Slot Sliding-Window Velocity & Entropy Detector', () => {
    it('triggers RANSOMWARE_VELOCITY_BURST when >= 25 modifications with >= 8 high-entropy writes occur within 3.0s', async () => {
      let triggered = false;
      shield.on('ransomwareDetected', (inc) => {
        if (inc.threatType === 'VELOCITY_BURST') {
          triggered = true;
          expect(inc.riskScore).toBe(100);
          expect(inc.engineVerdict).toBe('CONTAIN_PROCESS');
        }
      });

      // Ingest 25 modifications with 8 high-entropy writes
      for (let i = 0; i < 25; i++) {
        const filePath = path.join(protectedDir, `doc_${i}.docx`);
        fs.writeFileSync(filePath, Buffer.from(`DATA_${i}`));

        const isHighEntropy = i < 8; // exactly 8 high-entropy writes
        await shield.ingestFilesystemEvent({
          filePath,
          eventType: 'modify',
          responsiblePid: 6666,
          processName: 'crypto_locker.exe',
          entropy: isHighEntropy ? 7.85 : 3.2
        });
      }

      expect(triggered).toBe(true);
    });

    it('does NOT trigger if modifications are spread beyond the 3.0-second sliding window', async () => {
      const customShield = new RansomwareShieldService({
        protectedFolders: [protectedDir],
        customVaultDir: vaultDir,
        velocityThreshold: 25,
        velocityWindowMs: 50 // 50ms window for testing expiration
      });

      let triggered = false;
      customShield.on('ransomwareDetected', () => {
        triggered = true;
      });

      // Feed 25 events with 20ms delays between them -> total 500ms > 50ms window
      for (let i = 0; i < 25; i++) {
        await customShield.ingestFilesystemEvent({
          filePath: path.join(protectedDir, `spread_${i}.txt`),
          eventType: 'modify',
          entropy: 7.9
        });
        await new Promise((r) => setTimeout(r, 10));
      }

      expect(triggered).toBe(false);
      await customShield.stop();
    });

    it('does NOT trigger if high-entropy writes are < 8 (e.g. only 7)', async () => {
      let triggered = false;
      shield.on('ransomwareDetected', () => {
        triggered = true;
      });

      // 25 modifications, but only 7 high-entropy writes
      for (let i = 0; i < 25; i++) {
        await shield.ingestFilesystemEvent({
          filePath: path.join(protectedDir, `low_entropy_${i}.txt`),
          eventType: 'modify',
          entropy: i < 7 ? 7.9 : 4.0
        });
      }

      expect(triggered).toBe(false);
    });

    it('triggers SUSPICIOUS_EXTENSION_BURST when >= 10 ransomware extension renames occur in window', async () => {
      let extensionBurstTriggered = false;
      shield.on('ransomwareDetected', (inc) => {
        if (inc.threatType === 'SUSPICIOUS_EXTENSION_BURST') {
          extensionBurstTriggered = true;
          expect(inc.riskScore).toBe(100);
        }
      });

      // Ingest 25 modifications total, including 10 renames to .locked
      for (let i = 0; i < 25; i++) {
        const isRename = i < 10;
        const filePath = path.join(protectedDir, isRename ? `doc_${i}.docx.locked` : `doc_${i}.txt`);
        await shield.ingestFilesystemEvent({
          filePath,
          eventType: isRename ? 'rename' : 'modify',
          responsiblePid: 7777,
          processName: 'ransomware_rename.exe',
          entropy: 5.0
        });
      }

      expect(extensionBurstTriggered).toBe(true);
    });

    it('does not classify benign media formats (.jpg, .mp4, .zip) as ransomware encryption', async () => {
      let triggered = false;
      shield.on('ransomwareDetected', () => {
        triggered = true;
      });

      // 25 photo/video files with natural high entropy
      for (let i = 0; i < 25; i++) {
        await shield.ingestFilesystemEvent({
          filePath: path.join(protectedDir, `photo_${i}.jpg`),
          eventType: 'write',
          entropy: 7.9 // Natural high entropy for JPEG
        });
      }

      // Should NOT trigger because .jpg is recognized as a benign high entropy format
      expect(triggered).toBe(false);
    });
  });

  describe('Safe Process Containment & RULE-09 Invariant', () => {
    it('strictly preserves RULE-09: rejects containment of PID 0 and PID 4 with REJECTED_PROTECTED', async () => {
      const pid0Result = await shield.containRansomwareProcess(0, '[System Idle Process]');
      expect(pid0Result.success).toBe(false);
      expect(pid0Result.action).toBe('REJECTED_PROTECTED');
      expect(pid0Result.reason).toContain('RULE-09');

      const pid4Result = await shield.containRansomwareProcess(4, 'System');
      expect(pid4Result.success).toBe(false);
      expect(pid4Result.action).toBe('REJECTED_PROTECTED');
      expect(pid4Result.reason).toContain('RULE-09');
    });

    it('contains non-system ransomware process safely when dryRun is active', async () => {
      const result = await shield.containRansomwareProcess(8888, 'wannacry.exe');
      expect(result.success).toBe(true);
      expect(result.action).toBe('TERMINATED');
      expect(result.reason).toContain('simulated');
    });
  });

  describe('Access Control: Smart Mode vs Strict Mode', () => {
    it('Strict Mode: blocks untrusted application write to protected folder and raises incident', async () => {
      shield.setMode('strict');
      const untrustedBin = path.join(testRoot, 'UntrustedScripter.exe');
      fs.writeFileSync(untrustedBin, Buffer.from('UNTRUSTED_BYTES'));

      const result = await shield.ingestFilesystemEvent({
        filePath: path.join(protectedDir, 'ImportantDoc.docx'),
        eventType: 'write',
        executablePath: untrustedBin,
        responsiblePid: 1234
      });

      expect(result.isRansomware).toBe(true);
      expect(result.incident?.threatType).toBe('UNAUTHORIZED_PROTECTED_FOLDER_WRITE');
      expect(result.incident?.riskScore).toBe(95);
    });
  });
});
