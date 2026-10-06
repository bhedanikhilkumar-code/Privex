import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';
import { QuarantineService } from '../../services/quarantine.service';

describe('PersistenceAuditorService (Unit & Audit Tests)', () => {
  let testDir: string;
  let testStartupDir: string;
  let testVaultDir: string;
  let quarantineService: QuarantineService;

  beforeEach(() => {
    testDir = path.join(os.tmpdir(), `pp-persist-test-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`);
    testStartupDir = path.join(testDir, 'startup');
    testVaultDir = path.join(testDir, 'vault');

    fs.mkdirSync(testStartupDir, { recursive: true });
    fs.mkdirSync(testVaultDir, { recursive: true });

    quarantineService = new QuarantineService(testVaultDir);
  });

  afterEach(() => {
    try {
      fs.rmSync(testDir, { recursive: true, force: true });
    } catch {}
  });

  it('generates consistent, deterministic canonical persistence IDs', () => {
    const id1 = PersistenceAuditorService.generateCanonicalId('registry_run_hkcu', 'HKCU\\Software\\Run', 'OneDrive');
    const id2 = PersistenceAuditorService.generateCanonicalId('registry_run_hkcu', 'HKCU\\Software\\Run', 'OneDrive');
    const id3 = PersistenceAuditorService.generateCanonicalId('registry_run_hkcu', 'HKCU\\Software\\Run', 'Discord');

    expect(id1).toBe(id2);
    expect(id1).not.toBe(id3);
    expect(id1.startsWith('persist-')).toBe(true);
  });

  it('audits registry persistence and startup folder items accurately', async () => {
    // 1. Create clean file in startup folder
    const cleanApp = path.join(testStartupDir, 'clean_util.exe');
    fs.writeFileSync(cleanApp, 'MZ' + Buffer.alloc(100).toString('utf8'));

    // 2. Create suspicious script in startup folder
    const scriptApp = path.join(testStartupDir, 'auto_launch.vbs');
    fs.writeFileSync(scriptApp, 'WScript.Echo "Hello"');

    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    LegitApp    REG_SZ    "${cleanApp}" /minimized
    SuspiciousDropper    REG_SZ    powershell.exe -w hidden -enc JABkYXRh...
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(quarantineService, registryReader);

    const result = await auditor.auditStartupLocations({
      customDirs: [testStartupDir]
    });

    expect(result.totalEntriesAudited).toBe(4);
    expect(result.items.length).toBe(4);

    const dropper = result.items.find((i) => i.name === 'SuspiciousDropper');
    expect(dropper).toBeDefined();
    expect(dropper?.isSuspicious).toBe(true);
    expect(dropper?.indicators).toContain('LOLBIN_IN_STARTUP_PERSISTENCE');

    const script = result.items.find((i) => i.name === 'auto_launch.vbs');
    expect(script).toBeDefined();
    expect(script?.isSuspicious).toBe(true);
    expect(script?.indicators).toContain('SCRIPT_IN_STARTUP_FOLDER');
  });

  it('protects clean system binaries and legitimate installed software from false blocks', async () => {
    const mockRegistry: Record<string, string> = {
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    SecurityHealth    REG_SZ    C:\\Windows\\System32\\SecurityHealthSystray.exe
    CleanVendor    REG_SZ    "C:\\Program Files\\TrustedVendor\\App.exe"
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(quarantineService, registryReader);

    const result = await auditor.auditStartupLocations({
      customDirs: [testStartupDir]
    });

    const sysHealth = result.items.find((i) => i.name === 'SecurityHealth');
    expect(sysHealth).toBeDefined();
    expect(sysHealth?.engineVerdict).toBe('ALLOW');
  });

  it('remediates a registry persistence entry by deleting only the exact value', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    GoodEntry    REG_SZ    "C:\\Program Files\\Good.exe"
    BadEntry    REG_SZ    powershell.exe -enc JABz...
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(quarantineService, registryReader);

    const auditRes = await auditor.auditStartupLocations({
      customDirs: []
    });

    const badItem = auditRes.items.find((i) => i.name === 'BadEntry');
    expect(badItem).toBeDefined();

    const remRes = await auditor.remediateItem(badItem!.id);
    expect(remRes.success).toBe(true);
    expect(remRes.deletedRegistryValue).toContain('BadEntry');

    // Verify GoodEntry is still preserved in registry
    const remaining = await registryReader.queryKey('HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run');
    expect(remaining.length).toBe(1);
    expect(remaining[0].valueName).toBe('GoodEntry');
  });

  it('remediates a malicious startup folder file by isolating it into QuarantineService', async () => {
    const malwarePath = path.join(testStartupDir, 'malware.bat');
    fs.writeFileSync(malwarePath, '@echo off\r\nstart powershell -enc test');

    const auditor = new PersistenceAuditorService(quarantineService);
    const auditRes = await auditor.auditStartupLocations({
      customDirs: [testStartupDir]
    });

    const malItem = auditRes.items.find((i) => i.name === 'malware.bat');
    expect(malItem).toBeDefined();

    const remRes = await auditor.remediateItem(malItem!.id);
    expect(remRes.success).toBe(true);
    expect(fs.existsSync(malwarePath)).toBe(false);

    // Verify it exists in QuarantineService
    const qList = await quarantineService.listQuarantine();
    expect(qList.length).toBe(1);
    expect(qList[0].fileName).toBe('malware.bat');
  });

  it('maintains backward-compatible checkPersistenceEntry method', () => {
    const auditor = new PersistenceAuditorService();

    expect(auditor.checkPersistenceEntry('updater.vbs').suspicious).toBe(true);
    expect(auditor.checkPersistenceEntry('document.pdf.bat').suspicious).toBe(true);
    expect(auditor.checkPersistenceEntry('clean_app.exe').suspicious).toBe(false);
  });
});
