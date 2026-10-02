import { describe, it, expect } from 'vitest';
import {
  CoreFileAnalyzer,
  DetectionPipeline,
  InputType,
  Verdict,
  SeverityLevel
} from '../../index';

describe('CoreFileAnalyzer & DetectionPipeline FILE Integration (GAP-08)', () => {
  const pipeline = new DetectionPipeline();

  it('computes Shannon entropy accurately for uniform vs high-entropy byte buffers', () => {
    const uniform = new Uint8Array(512).fill(0x41);
    expect(CoreFileAnalyzer.calculateEntropy(uniform)).toBe(0);

    const highEntropy = new Uint8Array(256);
    for (let i = 0; i < 256; i++) highEntropy[i] = i;
    expect(CoreFileAnalyzer.calculateEntropy(highEntropy)).toBe(8);
  });

  it('detects magic headers for PE/MZ, ELF, Mach-O, DEX, and Script payloads', () => {
    expect(CoreFileAnalyzer.detectMagicHeader(new Uint8Array([0x4d, 0x5a, 0x90, 0x00]))).toBe('PE/MZ_EXECUTABLE');
    expect(CoreFileAnalyzer.detectMagicHeader(new Uint8Array([0x7f, 0x45, 0x4c, 0x46]))).toBe('ELF_EXECUTABLE');
    expect(CoreFileAnalyzer.detectMagicHeader(new Uint8Array([0xfe, 0xed, 0xfa, 0xce]))).toBe('MACHO_EXECUTABLE');
    expect(CoreFileAnalyzer.detectMagicHeader(new Uint8Array([0x64, 0x65, 0x78, 0x0a]))).toBe('DEX_BYTECODE');
    expect(
      CoreFileAnalyzer.detectMagicHeader(new TextEncoder().encode('#!/bin/bash\nrm -rf /'))
    ).toBe('SCRIPT_EXECUTABLE');
    expect(CoreFileAnalyzer.detectMagicHeader(new TextEncoder().encode('Hello world'))).toBeNull();
  });

  it('evaluates deceptive double-extension files consistently across desktop and mobile profiles', () => {
    const mzHeader = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
    const desktopOut = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: 'invoice_2026.pdf.exe',
        fileSize: 4096,
        headerBytes: mzHeader
      },
      { platformProfile: 'desktop', sha256: 'abc123' }
    );

    expect(desktopOut.isDeceptiveExtension).toBe(true);
    expect(desktopOut.isExecutable).toBe(true);
    expect(desktopOut.riskScore).toBe(95);
    expect(desktopOut.desktopVerdict).toBe('BLOCK');
    expect(desktopOut.desktopSeverity).toBe('critical');
    expect(desktopOut.verdict).toBe(Verdict.DANGEROUS);
    expect(desktopOut.severity).toBe(SeverityLevel.CRITICAL);

    const mobileOut = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: 'invoice_2026.pdf.exe',
        fileSize: 4096,
        headerBytes: mzHeader
      },
      { platformProfile: 'mobile' }
    );
    expect(mobileOut.verdict).toBe(Verdict.DANGEROUS);
    expect(mobileOut.severity).toBe(SeverityLevel.CRITICAL);
    expect(mobileOut.riskScore).toBe(100);
  });

  it('respects entropyDetectionEnabled=false option when evaluating high-entropy executables', () => {
    const highEntropyExe = new Uint8Array(256);
    for (let i = 0; i < 256; i++) highEntropyExe[i] = i;

    const withEntropy = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: 'app.exe',
        fileSize: 256,
        headerBytes: highEntropyExe
      },
      { entropyDetectionEnabled: true, platformProfile: 'desktop' }
    );
    const withoutEntropy = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: 'app.exe',
        fileSize: 256,
        headerBytes: highEntropyExe
      },
      { entropyDetectionEnabled: false, platformProfile: 'desktop' }
    );

    expect(withEntropy.riskScore).toBe(45); // 15 (.exe) + 30 (entropy)
    expect(withoutEntropy.riskScore).toBe(15); // 15 (.exe) only
  });

  it('routes InputType.FILE through DetectionPipeline.scan()', async () => {
    const mzHeader = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
    const res = await pipeline.scan({
      inputType: InputType.FILE,
      payload: mzHeader,
      metadata: {
        fileName: 'statement.pdf.exe',
        fileSize: '2048'
      }
    });

    expect(res.inputType).toBe(InputType.FILE);
    expect(res.verdict).toBe(Verdict.DANGEROUS);
    expect(res.riskScore).toBe(95);
  });
});
