import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { QuickScanService } from '../../services/quick-scan.service';

describe('QuickScanService (High-Risk Ingress Engine)', () => {
  let quickScanner: QuickScanService;
  let tempDir: string;

  beforeEach(() => {
    quickScanner = new QuickScanService();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-quick-scan-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('resolves valid ingress target paths across the operating system', () => {
    const targets = quickScanner.getQuickScanTargets();
    expect(targets.length).toBeGreaterThan(0);
    // Temp directory should always exist
    expect(targets.some((t) => t.includes('Temp') || t.includes('tmp') || t.includes('AppData'))).toBe(true);
  });

  it('filters and scans only executables and deceptive extensions in targeted ingress paths', async () => {
    // Write 1 benign txt, 1 executable, 1 deceptive double extension
    fs.writeFileSync(path.join(tempDir, 'plain.txt'), 'Ignored by executable filter');
    fs.writeFileSync(path.join(tempDir, 'installer.exe'), Buffer.from([0x4d, 0x5a, 0x00, 0x00]));
    fs.writeFileSync(path.join(tempDir, 'doc.pdf.exe'), Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

    const result = await quickScanner.executeQuickScan([tempDir]);
    // plain.txt is skipped by the filter
    expect(result.totalFilesScanned).toBe(2);
    expect(result.threats.some((t) => t.fileName === 'doc.pdf.exe')).toBe(true);
  });
});
