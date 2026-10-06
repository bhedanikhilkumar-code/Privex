import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import { RansomwareSimulationHarness } from '../helpers/ransomware-simulation-harness';
import { RansomwareShieldService } from '../../services/ransomware-shield.service';
import { ShadowVaultService } from '../../services/shadow-vault.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { BehaviorEngineService } from '../../services/behavior-engine.service';

describe('Phase G Integration: RansomwareSimulationHarness E2E', () => {
  let harness: RansomwareSimulationHarness;
  let shield: RansomwareShieldService;
  let shadowVault: ShadowVaultService;
  let processAuditor: ProcessAuditorService;
  let behaviorEngine: BehaviorEngineService;

  beforeEach(() => {
    harness = new RansomwareSimulationHarness();
    const sandboxVault = path.join(harness.getSandboxRoot(), 'Vault');

    shadowVault = new ShadowVaultService({
      customVaultDir: sandboxVault,
      maxFileSizeBytes: 50 * 1024 * 1024,
      maxVaultQuotaBytes: 100 * 1024 * 1024
    });

    behaviorEngine = new BehaviorEngineService();
    processAuditor = new ProcessAuditorService({ behaviorEngine });

    shield = new RansomwareShieldService(
      {
        mode: 'smart',
        protectedFolders: [harness.getProtectedSubfolder()],
        customVaultDir: sandboxVault,
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
    harness.cleanup();
  });

  it('executes full E2E simulation: attack -> velocity detection -> containment -> 100% SHA-256 rollback', async () => {
    // 1. Generate 30 synthetic documents
    const syntheticDocs = await harness.generateSyntheticDocuments(30);
    expect(syntheticDocs.length).toBe(30);

    const incidentId = 'e2e-ransomware-incident-001';

    // 2. Pre-backup clean documents in ShadowVault (Copy-on-Write baseline)
    for (const doc of syntheticDocs) {
      await shadowVault.backupFile(doc.fullPath, incidentId);
    }

    let detectedIncident: any = null;
    shield.on('ransomwareDetected', (inc) => {
      detectedIncident = inc;
    });

    // 3. Simulate mass-encryption ransomware attack (PID 9119, high-entropy writes)
    const attackResult = await harness.simulateVelocityAttack(shield, {
      fileCount: 30,
      responsiblePid: 9119,
      processName: 'LockBit_Sim.exe'
    });

    expect(attackResult.affectedFiles.length).toBe(30);

    // 4. Assert ransomware behavior was detected
    expect(detectedIncident).not.toBeNull();
    expect(detectedIncident.riskScore).toBe(100);
    expect(detectedIncident.engineVerdict).toBe('CONTAIN_PROCESS');
    expect(detectedIncident.responsiblePid).toBe(9119);
    expect(detectedIncident.containmentResult?.success).toBe(true);

    // Verify files were corrupted by simulated ransomware
    const preRollbackCheck = harness.verifyRestoration();
    expect(preRollbackCheck.verified).toBe(false);
    expect(preRollbackCheck.mismatched.length).toBeGreaterThan(0);

    // 5. Execute 1-click incident rollback
    const rollbackResult = await shield.rollbackIncident(incidentId);
    expect(rollbackResult.success).toBe(true);
    expect(rollbackResult.restoredCount).toBe(30);
    expect(rollbackResult.failedCount).toBe(0);

    // 6. Verify 100% byte-for-byte pre-attack SHA-256 restoration
    const postRollbackCheck = harness.verifyRestoration();
    expect(postRollbackCheck.verified).toBe(true);
    expect(postRollbackCheck.totalChecked).toBe(30);
    expect(postRollbackCheck.mismatched.length).toBe(0);
  }, 30000);

  it('executes canary trap tamper E2E flow: tamper -> immediate alert -> containment', async () => {
    const canaries = shield.deployCanaries();
    expect(canaries.length).toBeGreaterThanOrEqual(2);
    const targetCanary = canaries[0];

    let canaryAlert: any = null;
    shield.on('ransomwareDetected', (inc) => {
      if (inc.threatType === 'CANARY_TAMPER') {
        canaryAlert = inc;
      }
    });

    // Ransomware attempts to encrypt canary
    harness.simulateEncryptFile(targetCanary.canonicalPath);

    const isTampered = await shield.checkCanaryTamper(targetCanary.canonicalPath, {
      responsiblePid: 4242,
      processName: 'WannaCry_Canary_Hit.exe'
    });

    expect(isTampered).toBe(true);
    expect(canaryAlert).not.toBeNull();
    expect(canaryAlert.riskScore).toBe(100);
    expect(canaryAlert.severity).toBe('critical');
    expect(canaryAlert.engineVerdict).toBe('CONTAIN_PROCESS');
    expect(canaryAlert.responsiblePid).toBe(4242);
  });
});
