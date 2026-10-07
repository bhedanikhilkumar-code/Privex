import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScannerService } from '../../services/scanner.service';
import { ThreatIntelManagerService } from '../../services/threat-intel-manager.service';
import { UpdateVerifierService } from '../../services/update-verifier.service';
import { IpcHandler } from '../../ipc/ipc-handler';
import { PpdbPayload } from '../../types/desktop.types';
import { ThreatIntel, generateEd25519KeyPair } from '@private-protection/core';

describe('Phase O Integration: Signed Updates, CleanFileCache Invalidation & LKG Rollback', () => {
  let tempDir: string;
  let testFilesDir: string;
  let scanner: ScannerService;
  let threatIntel: ThreatIntel;
  let manager: ThreatIntelManagerService;
  let keyPair: { publicKeyHex: string; privateKey: any };
  let ipcHandler: IpcHandler;

  const NEW_MALWARE_HASH_V2 = '3333333333333333333333333333333333333333333333333333333333333333';
  const NEW_MALWARE_HASH_V3 = '4444444444444444444444444444444444444444444444444444444444444444';

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-o-integ-'));
    testFilesDir = path.join(tempDir, 'files');
    fs.mkdirSync(testFilesDir, { recursive: true });

    keyPair = generateEd25519KeyPair();
    threatIntel = ThreatIntel.getSharedInstance();
    threatIntel.resetToFactorySeed();

    scanner = new ScannerService();
    manager = new ThreatIntelManagerService({
      dataDir: tempDir,
      threatIntelInstance: threatIntel,
      scannerService: scanner,
      rootPublicKeyHex: keyPair.publicKeyHex
    });

    ipcHandler = new IpcHandler({
      configDir: tempDir,
      vaultDir: path.join(tempDir, 'vault')
    });
    // Inject the test manager with test keys into IpcHandler
    (ipcHandler as any).threatIntelManager = manager;
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  it('INT-O-01: Full lifecycle of signed update application, CleanFileCache invalidation, and LKG rollback', async () => {
    // 1. Initial state verification
    const initialStatus = manager.getStatus();
    expect(initialStatus.currentSequence).toBe(100);
    expect(initialStatus.hasLkg).toBe(false);

    // 2. Create sample benign test file and scan it to populate CleanFileCache
    const benignFile = path.join(testFilesDir, 'document.txt');
    fs.writeFileSync(benignFile, 'This is a clean user file for caching verification.', 'utf8');

    const scanRes1 = await scanner.scanPaths([benignFile], 'quick');
    expect(scanRes1.threats).toHaveLength(0);
    expect(scanner.getCleanFileCache().size).toBe(1);

    // 3. Create signed v2 update introducing NEW_MALWARE_HASH_V2
    const payloadV2: PpdbPayload = {
      maliciousHashes: [
        {
          hash: NEW_MALWARE_HASH_V2,
          threatName: 'Trojan.Win32.PhaseOTest',
          severity: 'critical'
        }
      ]
    };
    const bundleV2 = UpdateVerifierService.createSignedBundle(
      '2026.11.01',
      1001,
      Date.now() - 500,
      payloadV2,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    // 4. Apply update v2
    const applyResV2 = await manager.applyUpdate(bundleV2);
    expect(applyResV2.success).toBe(true);
    expect(applyResV2.version).toBe('2026.11.01');
    expect(applyResV2.versionSequence).toBe(1001);

    // 5. Verify CleanFileCache was invalidated upon update
    expect(scanner.getCleanFileCache().size).toBe(0);

    // 6. Verify threat intelligence now detects the new hash
    const lookupV2 = threatIntel.lookupHash(NEW_MALWARE_HASH_V2);
    expect(lookupV2).not.toBeNull();
    expect(lookupV2?.threatName).toBe('Trojan.Win32.PhaseOTest');

    // 7. Verify LKG is now available (preserving v1 factory state)
    const statusAfterV2 = manager.getStatus();
    expect(statusAfterV2.hasLkg).toBe(true);
    expect(statusAfterV2.lkgVersion).toBe('1.0.0-seed');
    expect(statusAfterV2.lkgSequence).toBe(100);

    // 8. Apply signed v3 update introducing NEW_MALWARE_HASH_V3
    const payloadV3: PpdbPayload = {
      maliciousHashes: [
        {
          hash: NEW_MALWARE_HASH_V3,
          threatName: 'Ransomware.Win32.PhaseOTest2',
          severity: 'critical'
        }
      ]
    };
    const bundleV3 = UpdateVerifierService.createSignedBundle(
      '2026.12.01',
      1002,
      Date.now() - 500,
      payloadV3,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    const applyResV3 = await manager.applyUpdate(bundleV3);
    expect(applyResV3.success).toBe(true);
    expect(applyResV3.versionSequence).toBe(1002);

    // Verify LKG is now v2
    const statusAfterV3 = manager.getStatus();
    expect(statusAfterV3.hasLkg).toBe(true);
    expect(statusAfterV3.lkgVersion).toBe('2026.11.01');
    expect(statusAfterV3.lkgSequence).toBe(1001);

    // 9. Re-populate cache with a file
    await scanner.scanPaths([benignFile], 'quick');
    expect(scanner.getCleanFileCache().size).toBe(1);

    // 10. Trigger LKG rollback
    const rollbackRes = await manager.rollbackToLkg();
    expect(rollbackRes.success).toBe(true);
    expect(rollbackRes.restoredVersion).toBe('2026.11.01');
    expect(rollbackRes.restoredVersionSequence).toBe(1001);

    // 11. Verify CleanFileCache was invalidated upon rollback
    expect(scanner.getCleanFileCache().size).toBe(0);

    // 12. Verify active database was rolled back: V2 hash exists, V3 hash does NOT
    expect(threatIntel.lookupHash(NEW_MALWARE_HASH_V2).isMalicious).toBe(true);
    expect(threatIntel.lookupHash(NEW_MALWARE_HASH_V3).isMalicious).toBe(false);
    expect(threatIntel.getInstalledVersion()).toBe('2026.11.01');
    expect(threatIntel.getVersionSequence()).toBe(1001);
  });

  it('INT-O-02: IPC Handler dispatch executes update application, status query, and rollback', async () => {
    // 1. Check initial IPC status
    const status1 = ipcHandler.handleGetThreatIntelStatus();
    expect(status1.currentSequence).toBe(100);

    // 2. Dispatch UPDATE_APPLY_BUNDLE over IPC
    const payload: PpdbPayload = {
      maliciousHashes: [
        {
          hash: '5'.repeat(64),
          threatName: 'Trojan.IPC.Test',
          severity: 'dangerous'
        }
      ]
    };
    const bundle = UpdateVerifierService.createSignedBundle(
      '2026.11.15',
      1010,
      Date.now() - 500,
      payload,
      keyPair.privateKey,
      keyPair.publicKeyHex
    );

    const applyRes = await ipcHandler.handleApplyUpdateBundle(bundle);
    expect(applyRes.success).toBe(true);
    expect(applyRes.versionSequence).toBe(1010);

    // 3. Verify getProtectionStatus returns updated version
    const protStatus = ipcHandler.handleGetProtectionStatus();
    expect(protStatus.threatDatabaseVersion).toBe('2026.11.15');

    // 4. Dispatch UPDATE_ROLLBACK_LKG over IPC
    const rollbackRes = await ipcHandler.handleRollbackUpdateLkg();
    expect(rollbackRes.success).toBe(true);
    expect(rollbackRes.restoredVersionSequence).toBe(100);

    const protStatusAfter = ipcHandler.handleGetProtectionStatus();
    expect(protStatusAfter.threatDatabaseVersion).toBe('1.0.0-seed');
  });
});
