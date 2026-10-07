import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { QuickScanService } from '../../services/quick-scan.service';
import { ScannerService } from '../../services/scanner.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';

describe('QuickScanService (Phase N Expansion Suite)', () => {
  let tempDir: string;
  let scanner: ScannerService;
  let processAuditor: ProcessAuditorService;
  let persistenceAuditor: PersistenceAuditorService;
  let quickScanner: QuickScanService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-quick-expansion-'));
    scanner = new ScannerService();
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('includes standard ingress folders (Downloads, Temp, Desktop) in default targets', () => {
    quickScanner = new QuickScanService(scanner);
    const targets = quickScanner.getQuickScanTargets();

    expect(targets.length).toBeGreaterThan(0);
    expect(targets.some((t) => t.toLowerCase().includes('temp') || t === os.tmpdir())).toBe(true);
  });

  it('expands quick scan targets to include active user process binaries from ProcessAuditorService', async () => {
    // Create mock process executable file
    const mockAppPath = path.join(tempDir, 'active_app.exe');
    fs.writeFileSync(mockAppPath, 'MZ_FAKE_PE_HEADER_PAYLOAD');

    processAuditor = new ProcessAuditorService({
      processQueryProvider: async () => [
        { pid: 1234, processName: 'active_app.exe', executablePath: mockAppPath }
      ]
    });

    quickScanner = new QuickScanService({
      scanner,
      processAuditor
    });

    const resolved = await quickScanner.resolveAllQuickScanTargets();
    expect(resolved).toContain(path.resolve(mockAppPath));
  });

  it('expands quick scan targets to include Startup and Persistence registered targets from PersistenceAuditorService', async () => {
    // Create mock persistence target file
    const mockStartupScript = path.join(tempDir, 'startup_updater.bat');
    fs.writeFileSync(mockStartupScript, '@echo off\r\necho updating...');

    const registryReader = new WindowsRegistryReader();
    registryReader.setMockEntries([
      {
        hive: 'HKCU',
        keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        fullKey: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        valueName: 'StartupUpdater',
        valueType: 'REG_SZ',
        rawValue: `"${mockStartupScript}"`,
        isRunOnce: false
      }
    ]);

    persistenceAuditor = new PersistenceAuditorService(null, registryReader);

    quickScanner = new QuickScanService({
      scanner,
      persistenceAuditor
    });

    const resolved = await quickScanner.resolveAllQuickScanTargets();
    expect(resolved).toContain(path.resolve(mockStartupScript));
  });

  it('safely skips non-existent, deleted, or inaccessible process binaries without error', async () => {
    const nonExistentPath = path.join(tempDir, 'deleted_ghost_process.exe');

    processAuditor = new ProcessAuditorService({
      processQueryProvider: async () => [
        { pid: 9999, processName: 'ghost.exe', executablePath: nonExistentPath }
      ]
    });

    quickScanner = new QuickScanService({
      scanner,
      processAuditor
    });

    const resolved = await quickScanner.resolveAllQuickScanTargets();
    expect(resolved).not.toContain(path.resolve(nonExistentPath));
  });

  it('executes Quick Scan across process binaries and persistence targets returning valid ScanResult', async () => {
    const mockBinary = path.join(tempDir, 'clean_tool.bat');
    fs.writeFileSync(mockBinary, '@echo off\r\necho Clean background process');

    processAuditor = new ProcessAuditorService({
      processQueryProvider: async () => [
        { pid: 2222, processName: 'clean_tool.bat', executablePath: mockBinary }
      ]
    });

    quickScanner = new QuickScanService({
      scanner,
      processAuditor
    });

    const result = await quickScanner.executeQuickScan([tempDir]);
    expect(result.status).toBe('completed');
    expect(result.scanType).toBe('quick');
    expect(result.totalFilesScanned).toBeGreaterThanOrEqual(1);
    expect(result.overallVerdict).toBe('ALLOW');
  });
});
