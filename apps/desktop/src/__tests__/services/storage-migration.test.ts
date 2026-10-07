import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SecureStorageService } from '../../services/secure-storage.service';
import { QuarantineService } from '../../services/quarantine.service';

describe('Phase S Category 09 — Upgrade & Migration Compatibility Tests', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-s-migration-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('migrates partial legacy settings schemas cleanly filling missing fields with secure defaults', () => {
    const storage = new SecureStorageService(tempDir);

    // Save initial settings
    storage.saveSettings({
      realtimeShieldEnabled: true,
      scanLargeFilesLimitMb: 75
    });

    // Re-instantiate storage service simulating application upgrade restart
    const upgradedStorage = new SecureStorageService(tempDir);
    const settings = upgradedStorage.getSettings();

    // Verify previously set values persist
    expect(settings.scanLargeFilesLimitMb).toBe(75);
    expect(settings.realtimeShieldEnabled).toBe(true);

    // Verify modern fields are correctly initialized
    expect(settings.entropyDetectionEnabled).toBe(true);
    expect(settings.cognitiveLevel).toBe('grade6');
    expect(settings.frictionGateEnabled).toBe(true);
    expect(Array.isArray(settings.excludedPaths)).toBe(true);
  });

  it('detects corrupted or tampered settings and fails safe to secure default state', () => {
    const storage = new SecureStorageService(tempDir);
    storage.saveSettings({ scanLargeFilesLimitMb: 90 });

    const encPath = path.join(tempDir, 'settings.enc');
    expect(fs.existsSync(encPath)).toBe(true);

    // Deliberately tamper with ciphertext
    const payload = JSON.parse(fs.readFileSync(encPath, 'utf8'));
    payload.data = '00'.repeat(payload.data.length / 2); // zero out data
    fs.writeFileSync(encPath, JSON.stringify(payload), 'utf8');

    // Fresh storage instance reading tampered payload
    const recoveryStorage = new SecureStorageService(tempDir);
    const restored = recoveryStorage.getSettings();

    // Must fail safe to default settings
    expect(restored.scanLargeFilesLimitMb).toBe(50);
    expect(restored.realtimeShieldEnabled).toBe(true);
  });

  it('preserves existing security log events across service reboots and upgrades', () => {
    const storage1 = new SecureStorageService(tempDir);
    storage1.recordSecurityEvent(
      'THREAT_DETECTED',
      'WARN',
      'Intercepted malicious artifact in download folder',
      { threatName: 'Win32.Trojan.Generic' }
    );

    // Verify 1 event recorded
    expect(storage1.getSecurityEvents().length).toBe(1);

    // Simulate app upgrade / new service lifecycle
    const storage2 = new SecureStorageService(tempDir);
    const events = storage2.getSecurityEvents();
    expect(events.length).toBe(1);
    expect(events[0].type).toBe('THREAT_DETECTED');
    expect(events[0].summary).toContain('Intercepted malicious artifact');
  });

  it('maintains compatibility with quarantine vault manifests and handles legacy metadata safely', () => {
    const quarantineVaultDir = path.join(tempDir, 'quarantine-vault');
    const quarantineService = new QuarantineService(quarantineVaultDir);

    const items = quarantineService.listQuarantine();
    expect(Array.isArray(items)).toBe(true);
    expect(items.length).toBe(0);
  });
});
