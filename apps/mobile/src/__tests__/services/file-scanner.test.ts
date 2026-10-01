import { describe, it, expect } from 'vitest';
import { FileScannerService } from '../../services/file-scanner.service';
import { Verdict, SeverityLevel } from '@private-protection/core';

describe('FileScannerService (Header & Entropy Inspection)', () => {
  const service = new FileScannerService();

  it('detects deceptive double extension masking an executable as a document', () => {
    const result = service.inspectFile({
      name: 'urgent_invoice.pdf.exe',
      sizeBytes: 10240,
      mimeType: 'application/octet-stream',
      headerBytes: [0x4d, 0x5a, 0x90, 0x00] // MZ
    });

    expect(result.verdict).toBe(Verdict.DANGEROUS);
    expect(result.severity).toBe(SeverityLevel.CRITICAL);
    expect(result.threatCategory).toBe('DECEPTIVE_DOUBLE_EXTENSION');
    expect(result.isExecutable).toBe(true);
    expect(result.evidence.some((e) => e.name === 'Deceptive Double Extension')).toBe(true);
  });

  it('detects standalone Android DEX bytecode headers', () => {
    const result = service.inspectFile({
      name: 'payload.dex',
      sizeBytes: 4096,
      mimeType: 'application/octet-stream',
      headerBytes: [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00] // dex\n
    });

    expect(result.isExecutable).toBe(true);
    expect(result.detectedMimeType).toBe('application/vnd.android.dex');
    expect(result.score).toBeGreaterThanOrEqual(60);
  });

  it('detects Linux/Android native ELF binary headers', () => {
    const result = service.inspectFile({
      name: 'miner_daemon',
      sizeBytes: 20480,
      mimeType: 'application/octet-stream',
      headerBytes: [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00] // \x7fELF
    });

    expect(result.isExecutable).toBe(true);
    expect(result.detectedMimeType).toBe('application/x-elf');
    expect(result.score).toBeGreaterThanOrEqual(70);
  });

  it('allows normal PDF document headers without flagging as executable', () => {
    const result = service.inspectFile({
      name: 'quarterly_report.pdf',
      sizeBytes: 524288,
      mimeType: 'application/pdf',
      headerBytes: [0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34] // %PDF
    });

    expect(result.verdict).toBe(Verdict.ALLOW);
    expect(result.isExecutable).toBe(false);
    expect(result.score).toBe(0);
  });

  it('calculates Shannon entropy correctly for high-entropy packed bytes', () => {
    // Generate pseudo-random bytes
    const randomBytes: number[] = [];
    for (let i = 0; i < 256; i++) {
      randomBytes.push(i);
    }
    const result = service.inspectFile({
      name: 'packed.exe',
      sizeBytes: 1024,
      mimeType: 'application/octet-stream',
      headerBytes: [0x4d, 0x5a, ...randomBytes]
    });

    expect(result.shannonEntropy).toBeGreaterThan(7.0);
    expect(result.isExecutable).toBe(true);
  });
});
