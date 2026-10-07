import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { FileAnalyzer } from '../../core/file-analyzer';
import { ScannerService } from '../../services/scanner.service';

describe('Phase S Category 11 — False Positive Corpus Validation (500 File Benchmark)', () => {
  let tempDir: string;
  let scanner: ScannerService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-s-fp-corpus-'));
    scanner = new ScannerService();
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  it('evaluates a diverse 500-sample benign corpus with ZERO false-positive blocks or quarantines', async () => {
    const categories = [
      { prefix: 'doc', ext: '.txt', count: 75, gen: (i: number) => `User business report #${i}. Monthly financial summary for Q${(i % 4) + 1}. All operations nominal.` },
      { prefix: 'pdf', ext: '.pdf', count: 50, gen: (i: number) => `%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n% Benign document #${i}` },
      { prefix: 'data', ext: '.json', count: 75, gen: (i: number) => JSON.stringify({ id: i, name: `sample-${i}`, active: true, timestamp: Date.now() }, null, 2) },
      { prefix: 'csv', ext: '.csv', count: 50, gen: (i: number) => `id,name,value\n${i},Record_${i},${i * 100}\n${i + 1},Record_${i + 1},${(i + 1) * 100}` },
      { prefix: 'code', ext: '.ts', count: 75, gen: (i: number) => `export function computeMetric${i}(a: number, b: number): number {\n  return a + b * ${i};\n}\n` },
      { prefix: 'markup', ext: '.html', count: 50, gen: (i: number) => `<!DOCTYPE html><html><head><title>Internal Portal ${i}</title></head><body><h1>Welcome</h1></body></html>` },
      { prefix: 'config', ext: '.yaml', count: 50, gen: (i: number) => `version: '3.8'\nservices:\n  worker-${i}:\n    image: node:20-alpine\n    restart: always\n` },
      { prefix: 'script', ext: '.ps1', count: 25, gen: (i: number) => `Write-Host "Deploying benign build #${i} to internal test environment"` },
      { prefix: 'media', ext: '.svg', count: 50, gen: (i: number) => `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="${(i % 40) + 10}" fill="blue"/></svg>` }
    ];

    let totalCreated = 0;
    const filePaths: string[] = [];

    for (const cat of categories) {
      for (let i = 0; i < cat.count; i++) {
        const filePath = path.join(tempDir, `${cat.prefix}_${i}${cat.ext}`);
        fs.writeFileSync(filePath, cat.gen(i), 'utf8');
        filePaths.push(filePath);
        totalCreated++;
      }
    }

    expect(totalCreated).toBe(500);

    // Scan entire directory using ScannerService
    const scanResult = await scanner.scanPaths([tempDir], 'custom');

    // Verification assertions
    expect(scanResult.totalFilesScanned).toBe(500);
    expect(scanResult.threats.length).toBe(0);
    expect(scanResult.overallVerdict).toBe('ALLOW');

    // Individual deep inspection sample of each file category via FileAnalyzer
    for (let c = 0; c < categories.length; c++) {
      const sampleFile = filePaths[c * 50]; // sample from each bucket
      const analysis = await FileAnalyzer.analyzeFile(sampleFile);
      expect(analysis.verdict).toBe('ALLOW');
      expect(analysis.severity).toBe('safe');
      expect(analysis.riskScore).toBeLessThan(50);
      expect(analysis.disposition).toBe('SAFE');
    }
  });

  it('guarantees benign executables and scripts are not flagged purely by extension or benign MZ header', async () => {
    // Normal benign script
    const scriptPath = path.join(tempDir, 'backup-routine.bat');
    fs.writeFileSync(scriptPath, '@echo off\necho Backing up databases to local backup volume...\n', 'utf8');
    
    const scriptAnalysis = await FileAnalyzer.analyzeFile(scriptPath);
    expect(['ALLOW', 'INFORM']).toContain(scriptAnalysis.verdict);
    expect(scriptAnalysis.verdict).not.toBe('BLOCK');
    expect(scriptAnalysis.severity).not.toBe('critical');

    // Valid synthetic clean PE32+ executable
    const exePath = path.join(tempDir, 'sample-app.exe');
    const validPe = Buffer.alloc(1024, 0);
    const view = new DataView(validPe.buffer, validPe.byteOffset, validPe.byteLength);
    view.setUint16(0x00, 0x5a4d, true); // 'MZ'
    const peOffset = 0x80;
    view.setUint32(0x3c, peOffset, true); // e_lfanew = 128
    view.setUint32(peOffset, 0x00004550, true); // 'PE\0\0'
    const coff = peOffset + 4;
    view.setUint16(coff + 0, 0x8664, true); // Machine: AMD64
    view.setUint16(coff + 2, 1, true);      // NumberOfSections: 1
    view.setUint32(coff + 4, 1710000000, true);
    view.setUint16(coff + 16, 240, true);
    view.setUint16(coff + 18, 0x0022, true);
    const opt = coff + 20;
    view.setUint16(opt + 0, 0x020b, true); // PE32+
    view.setUint32(opt + 16, 0x1000, true);
    view.setUint16(opt + 68, 2, true);
    view.setUint32(opt + 108, 16, true);
    const secTable = opt + 240;
    const secName = '.text\0\0\0';
    for (let i = 0; i < 8; i++) view.setUint8(secTable + i, secName.charCodeAt(i));
    view.setUint32(secTable + 8, 0x1000, true);
    view.setUint32(secTable + 12, 0x1000, true);
    view.setUint32(secTable + 16, 0x200, true);
    view.setUint32(secTable + 20, 0x200, true);
    view.setUint32(secTable + 36, 0x20000000 | 0x40000000 | 0x00000020, true); // RX text section
    fs.writeFileSync(exePath, validPe);

    const exeAnalysis = await FileAnalyzer.analyzeFile(exePath);
    expect(exeAnalysis.isDeceptiveExtension).toBe(false);
    expect(['ALLOW', 'INFORM']).toContain(exeAnalysis.verdict);
    expect(exeAnalysis.verdict).not.toBe('BLOCK');
  });
});
