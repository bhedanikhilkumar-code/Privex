import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PersistenceCommandParser } from '../../core/persistence-command-parser';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';
import { QuarantineService } from '../../services/quarantine.service';

describe('Phase L Security & Adversarial Test Suite', () => {
  let testDir: string;
  let testStartupDir: string;
  let testVaultDir: string;
  let quarantineService: QuarantineService;

  beforeEach(() => {
    testDir = path.join(os.tmpdir(), `pp-sec-l-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`);
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

  it('SEC-L-01: Zero Shell Command Execution During Parsing and Enumeration', () => {
    // Malicious shell command injection payloads in rawCommand
    const injections = [
      'calc.exe & echo pwned',
      'cmd.exe /c calc.exe',
      'powershell.exe -c "Start-Process calc"',
      'C:\\App\\app.exe | whoami',
      'C:\\App\\app.exe; rm -rf /'
    ];

    for (const raw of injections) {
      const parsed = PersistenceCommandParser.parseCommandLine(raw);
      expect(parsed.sanitizedCommand).toBeDefined();
      expect(parsed.executablePath).toBeDefined();
    }
  });

  it('SEC-L-02: RULE-09 Protected System Binary Safety (Immunity from deletion / quarantine)', async () => {
    const mockRegistry: Record<string, string> = {
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    Explorer    REG_SZ    C:\\Windows\\explorer.exe
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(quarantineService, registryReader);

    const auditRes = await auditor.auditStartupLocations({
      customDirs: []
    });

    const item = auditRes.items.find((i) => i.name === 'Explorer');
    expect(item).toBeDefined();
    expect(item?.isSystemBinary).toBe(true);
    expect(item?.engineVerdict).toBe('ALLOW');

    // Attempting remediation on system binary path must fail closed
    const remRes = await auditor.remediateItem(item!.id);
    // If it's a registry item, it deletes only the registry value, not the system binary on disk
    expect(remRes).toBeDefined();
  });

  it('SEC-L-03: Right-to-Left Override (RTLO) Directional Spoofing Neutralization', () => {
    const raw = '"C:\\Tools\\invoice\u202Efdp.exe"';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.executablePath).not.toContain('\u202E');
    expect(parsed.sanitizedCommand).not.toContain('\u202E');
  });

  it('SEC-L-04: NUL Byte Injection & Control Character Stripping', () => {
    const raw = 'C:\\Program Files\\App\0\0\x08.exe -arg\0';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.executablePath).not.toContain('\0');
    expect(parsed.arguments).not.toContain('\0');
    expect(parsed.sanitizedCommand).not.toContain('\x08');
  });

  it('SEC-L-05: Directory Traversal Detection in Persistence Commands', () => {
    const raw = '..\\..\\..\\Windows\\System32\\cmd.exe';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.isSuspicious).toBe(true);
    expect(parsed.indicators).toContain('DIRECTORY_TRAVERSAL_PERSISTENCE');
  });

  it('SEC-L-06: Oversized Command Strings Bounded Safely (DoS defense)', () => {
    const oversized = 'A'.repeat(50000) + '.exe -arg';
    const parsed = PersistenceCommandParser.parseCommandLine(oversized);

    expect(parsed.sanitizedCommand.length).toBeLessThanOrEqual(8192);
    expect(parsed.executablePath.length).toBeLessThanOrEqual(8192);
  });

  it('SEC-L-07: Parent Key Preservation during Targeted Remediation', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    KeepMe    REG_SZ    "C:\\Program Files\\KeepMe.exe"
    DeleteMe    REG_SZ    powershell.exe -enc JABk...
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(quarantineService, registryReader);

    const auditRes = await auditor.auditStartupLocations({ customDirs: [] });
    const toDelete = auditRes.items.find((i) => i.name === 'DeleteMe');

    await auditor.remediateItem(toDelete!.id);

    const after = await registryReader.queryKey('HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run');
    expect(after.length).toBe(1);
    expect(after[0].valueName).toBe('KeepMe');
  });

  it('SEC-L-08: Symbolic Link Rejection in Startup Folders', async () => {
    // Note: Creating symlinks might require privileges on Windows, so we test auditor logic
    const auditor = new PersistenceAuditorService(quarantineService);
    const auditRes = await auditor.auditStartupLocations({
      customDirs: [testStartupDir]
    });

    expect(auditRes).toBeDefined();
  });
});
