import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';
import { QuarantineService } from '../../services/quarantine.service';
import { DesktopSecurityAdapter } from '../../core/desktop-security-adapter';

describe('Phase L Startup & Persistence Protection (Integration Tests)', () => {
  let testDir: string;
  let testStartupDir: string;
  let testVaultDir: string;
  let quarantineService: QuarantineService;

  beforeEach(() => {
    testDir = path.join(os.tmpdir(), `pp-integ-l-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`);
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

  it('INT-L-01: Full End-to-End Persistence Audit & Remediation Lifecycle', async () => {
    // 1. Create a clean utility in startup folder
    const cleanApp = path.join(testStartupDir, 'clean_notes.txt');
    fs.writeFileSync(cleanApp, 'Clean user startup notes');

    // 2. Create a malicious dropper in startup folder
    const dropper = path.join(testStartupDir, 'malicious_startup.bat');
    fs.writeFileSync(dropper, '@echo off\r\npowershell -w hidden -enc JABhID0A...');

    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    SecurityHealth    REG_SZ    C:\\Windows\\System32\\SecurityHealthSystray.exe
    RegistryTrojan    REG_SZ    powershell.exe -w hidden -enc JABz...
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(quarantineService, registryReader);

    // Run audit
    const auditRes = await auditor.auditStartupLocations({
      customDirs: [testStartupDir]
    });

    expect(auditRes.totalEntriesAudited).toBe(4);
    expect(auditRes.threatsFound).toBeGreaterThanOrEqual(1);

    // Identify threats
    const regTrojan = auditRes.items.find((i) => i.name === 'RegistryTrojan');
    const folderTrojan = auditRes.items.find((i) => i.name === 'malicious_startup.bat');

    expect(regTrojan).toBeDefined();
    expect(folderTrojan).toBeDefined();

    // 3. Remediate Registry Trojan
    const remRegRes = await auditor.remediateItem(regTrojan!.id);
    expect(remRegRes.success).toBe(true);

    // 4. Remediate Startup Folder Trojan
    const remFolderRes = await auditor.remediateItem(folderTrojan!.id);
    expect(remFolderRes.success).toBe(true);
    expect(fs.existsSync(dropper)).toBe(false);

    // Verify file exists in Quarantine Vault
    const qList = await quarantineService.listQuarantine();
    expect(qList.length).toBe(1);
    expect(qList[0].fileName).toBe('malicious_startup.bat');

    // 5. Re-audit and verify clean state
    const cleanAudit = await auditor.auditStartupLocations({
      customDirs: [testStartupDir]
    });

    expect(cleanAudit.threatsFound).toBe(0);
    expect(cleanAudit.items.filter((i) => i.isSuspicious).length).toBe(0);
  });

  it('INT-L-02: DesktopSecurityAdapter Persistence Methods Integration', async () => {
    const adapter = new DesktopSecurityAdapter();
    const result = await adapter.auditPersistence({
      customDirs: [testStartupDir],
      customRegistry: {
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': ''
      }
    });

    expect(result).toBeDefined();
    expect(Array.isArray(result.items)).toBe(true);
  });
});
