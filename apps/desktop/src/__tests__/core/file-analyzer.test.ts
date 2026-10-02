import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { FileAnalyzer } from '../../core/file-analyzer';

describe('FileAnalyzer (Desktop Core)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-test-file-analyzer-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('calculates Shannon entropy correctly for low and high entropy buffers', () => {
    // Uniform repetitive bytes -> 0 entropy
    const zeroEntropyBuf = Buffer.alloc(1000, 0x41); // 'AAAA...'
    expect(FileAnalyzer.calculateEntropy(zeroEntropyBuf)).toBe(0);

    // Pseudo-random bytes -> high entropy close to 8.0
    const highEntropyBuf = crypto.randomBytes(4096);
    const entropy = FileAnalyzer.calculateEntropy(highEntropyBuf);
    expect(entropy).toBeGreaterThan(7.5);
  });

  it('detects magic headers for Windows PE, Linux ELF, and Mach-O', () => {
    const peBuf = Buffer.from([0x4d, 0x5a, 0x90, 0x00]); // MZ
    expect(FileAnalyzer.detectMagicHeader(peBuf)).toBe('PE/MZ_EXECUTABLE');

    const elfBuf = Buffer.from([0x7f, 0x45, 0x4c, 0x46]); // ELF
    expect(FileAnalyzer.detectMagicHeader(elfBuf)).toBe('ELF_EXECUTABLE');

    const machBuf = Buffer.from([0xfe, 0xed, 0xfa, 0xce]); // Mach-O
    expect(FileAnalyzer.detectMagicHeader(machBuf)).toBe('MACHO_EXECUTABLE');

    const textBuf = Buffer.from('Just normal plain text document');
    expect(FileAnalyzer.detectMagicHeader(textBuf)).toBeNull();
  });

  it('detects double-extension deception (e.g. invoice.pdf.exe)', () => {
    const deceptive = FileAnalyzer.checkDeceptiveExtension('urgent_invoice.pdf.exe');
    expect(deceptive.isDeceptive).toBe(true);
    expect(deceptive.fakeExt).toBe('.pdf');
    expect(deceptive.realExt).toBe('.exe');

    const normal = FileAnalyzer.checkDeceptiveExtension('document.pdf');
    expect(normal.isDeceptive).toBe(false);

    const normalExe = FileAnalyzer.checkDeceptiveExtension('setup.exe');
    expect(normalExe.isDeceptive).toBe(false);
  });

  it('analyzes a benign text file as safe with zero risk', async () => {
    const safeFilePath = path.join(tempDir, 'notes.txt');
    fs.writeFileSync(safeFilePath, 'These are standard meeting notes.', 'utf8');

    const result = await FileAnalyzer.analyzeFile(safeFilePath);
    expect(result.fileName).toBe('notes.txt');
    expect(result.verdict).toBe('ALLOW');
    expect(result.severity).toBe('safe');
    expect(result.riskScore).toBe(0);
    expect(result.isDeceptiveExtension).toBe(false);
    expect(result.isExecutable).toBe(false);
    expect(result.sha256).toHaveLength(64);
  });

  it('flags disguised executable with PDF extension but PE header as BLOCK', async () => {
    const disguisedPath = path.join(tempDir, 'statement.pdf');
    // Write MZ magic bytes followed by content
    const maliciousBytes = Buffer.concat([
      Buffer.from([0x4d, 0x5a]), // MZ header
      Buffer.alloc(1024, 0x90)
    ]);
    fs.writeFileSync(disguisedPath, maliciousBytes);

    const result = await FileAnalyzer.analyzeFile(disguisedPath);
    expect(result.fileName).toBe('statement.pdf');
    expect(result.verdict).toBe('BLOCK');
    expect(result.severity).toBe('dangerous');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.magicHeader).toBe('PE/MZ_EXECUTABLE');
    expect(result.threatName).toBe('DISGUISED_EXECUTABLE');
    expect(result.evidenceFactors.some((f) => f.includes('Executable disguise'))).toBe(true);
  });

  it('flags double-extension deceptive file with high entropy as critical BLOCK', async () => {
    const doubleExtPath = path.join(tempDir, 'salary_report.xlsx.exe');
    // High entropy payload disguised as xlsx.exe
    const highEntropyBytes = crypto.randomBytes(8192);
    fs.writeFileSync(doubleExtPath, highEntropyBytes);

    const result = await FileAnalyzer.analyzeFile(doubleExtPath);
    expect(result.fileName).toBe('salary_report.xlsx.exe');
    expect(result.verdict).toBe('BLOCK');
    expect(result.severity).toBe('critical');
    expect(result.riskScore).toBeGreaterThanOrEqual(75);
    expect(result.isDeceptiveExtension).toBe(true);
    expect(result.evidenceFactors.some((f) => f.includes('Double extension deception'))).toBe(true);
  });
});
