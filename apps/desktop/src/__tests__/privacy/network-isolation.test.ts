import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DesktopSecurityAdapter } from '../../core/desktop-security-adapter';
import { ScannerService } from '../../services/scanner.service';

describe('Privacy & Network Air-Gap Isolation (Zero Exfiltration Guarantee)', () => {
  let fetchSpy: any;
  let xhrOpenSpy: any;
  let beaconSpy: any;
  let tempDir: string;

  beforeEach(() => {
    fetchSpy = vi.fn().mockImplementation(() => {
      throw new Error('NETWORK_VIOLATION: fetch() invoked in zero-cloud desktop client');
    });
    globalThis.fetch = fetchSpy;

    xhrOpenSpy = vi.fn().mockImplementation(() => {
      throw new Error('NETWORK_VIOLATION: XMLHttpRequest invoked in zero-cloud desktop client');
    });
    (globalThis as any).XMLHttpRequest = class {
      open = xhrOpenSpy;
      send = vi.fn();
    };

    beaconSpy = vi.fn();
    if (typeof navigator !== 'undefined') {
      (navigator as any).sendBeacon = beaconSpy;
    }

    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-net-test-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('performs file analysis with exactly ZERO outbound network requests', async () => {
    const testFile = path.join(tempDir, 'malicious.pdf.exe');
    fs.writeFileSync(testFile, Buffer.from([0x4d, 0x5a, 0x90, 0x00]));

    const adapter = new DesktopSecurityAdapter();
    const result = await adapter.analyzeFile(testFile);

    expect(result.verdict).toBe('BLOCK');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('runs recursive filesystem scan with exactly ZERO outbound network requests', async () => {
    fs.writeFileSync(path.join(tempDir, 'file1.txt'), 'Hello safe file');
    fs.writeFileSync(path.join(tempDir, 'file2.exe'), Buffer.from([0x4d, 0x5a]));

    const scanner = new ScannerService();
    const result = await scanner.scanPaths([tempDir], 'full');

    expect(result.totalFilesScanned).toBe(2);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('synthesizes AI assistant threat explanations with ZERO outbound LLM cloud requests', async () => {
    const adapter = new DesktopSecurityAdapter();
    const threat = {
      id: 'threat-privacy-1',
      filePath: 'C:\\Users\\Test\\Downloads\\trojan.exe',
      fileName: 'trojan.exe',
      fileSize: 1024,
      sha256: '0000000000000000000000000000000000000000000000000000000000000000',
      riskScore: 80,
      severity: 'critical' as const,
      verdict: 'BLOCK' as const,
      threatName: 'TROJAN_HEURISTIC',
      detectedAt: Date.now(),
      evidenceFactors: ['Disguised executable'],
      quarantined: false
    };

    const explanation = await adapter.explainThreat(threat, 'grade6');
    expect(explanation.summary).toBeDefined();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });
});
