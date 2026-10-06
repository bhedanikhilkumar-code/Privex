import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { QuarantineService } from '../../services/quarantine.service';

describe('SEC-E-04 — Automatic Quarantine Vault Exclusion Regression Suite', () => {
  let tempRoot: string;
  let vaultDirA: string;
  let vaultDirB: string;
  let watchDir: string;
  let monitor: RealtimeMonitorService;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-vault-exclusion-test-'));
    vaultDirA = path.join(tempRoot, 'vault-a');
    vaultDirB = path.join(tempRoot, 'vault-b');
    watchDir = path.join(tempRoot, 'user-watch');

    fs.mkdirSync(vaultDirA, { recursive: true });
    fs.mkdirSync(vaultDirB, { recursive: true });
    fs.mkdirSync(watchDir, { recursive: true });

    monitor = new RealtimeMonitorService({
      recursive: true,
      stabilityCheckMs: 0,
      stabilityRetries: 0
    });
  });

  afterEach(() => {
    monitor.stop();
    if (fs.existsSync(tempRoot)) {
      try {
        fs.rmSync(tempRoot, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  });

  it('A & D: setting a quarantine service automatically canonicalizes and excludes vaultDir', () => {
    const quarantineA = new QuarantineService(vaultDirA);
    monitor.setQuarantineService(quarantineA);

    const canonicalVault = path.resolve(vaultDirA);
    const options = monitor.getOptions();

    expect(options.excludedPaths).toContain(canonicalVault);
    expect(monitor.isPathExcluded(vaultDirA)).toBe(true);
    expect(monitor.isPathExcluded(canonicalVault)).toBe(true);
  });

  it('B & C: ignores files created directly or nested inside vaultDir', () => {
    const quarantineA = new QuarantineService(vaultDirA);
    monitor.setQuarantineService(quarantineA);

    const nestedFile = path.join(vaultDirA, 'nested', 'threat.blob');
    const directFile = path.join(vaultDirA, 'threat.blob');
    const manifestFile = path.join(vaultDirA, 'manifest.json.enc');

    expect(monitor.isPathExcluded(directFile)).toBe(true);
    expect(monitor.isPathExcluded(nestedFile)).toBe(true);
    expect(monitor.isPathExcluded(manifestFile)).toBe(true);
  });

  it('E: prevents duplicate exclusion entries upon repeated configuration', () => {
    const quarantineA = new QuarantineService(vaultDirA);
    monitor.setQuarantineService(quarantineA);
    monitor.setQuarantineService(quarantineA); // Second call

    const canonicalVault = path.resolve(vaultDirA);
    const occurrences = monitor.getOptions().excludedPaths.filter(
      (p) => path.resolve(p).toLowerCase() === canonicalVault.toLowerCase()
    ).length;

    expect(occurrences).toBe(1);
  });

  it('F: correctly migrates exclusion when quarantine service is reconfigured', () => {
    const quarantineA = new QuarantineService(vaultDirA);
    const quarantineB = new QuarantineService(vaultDirB);

    monitor.setQuarantineService(quarantineA);
    expect(monitor.isPathExcluded(vaultDirA)).toBe(true);
    expect(monitor.isPathExcluded(vaultDirB)).toBe(false);

    // Reconfigure to vault B
    monitor.setQuarantineService(quarantineB);
    expect(monitor.isPathExcluded(vaultDirA)).toBe(false);
    expect(monitor.isPathExcluded(vaultDirB)).toBe(true);
  });

  it('G: ensures normal user files outside the vault continue to be monitored', () => {
    const quarantineA = new QuarantineService(vaultDirA);
    monitor.setQuarantineService(quarantineA);

    const userFile = path.join(watchDir, 'document.pdf');
    const userNested = path.join(watchDir, 'subfolder', 'script.ps1');

    expect(monitor.isPathExcluded(userFile)).toBe(false);
    expect(monitor.isPathExcluded(userNested)).toBe(false);
  });
});
