import { describe, it, expect } from 'vitest';
import { PeAnalyzer, SeverityLevel } from '../../index';

describe('PeAnalyzer (Zero-Allocation, Bounds-Checked PE32/PE32+ Binary Security Parser)', () => {
  /**
   * Helper to construct a minimal synthetic valid PE32 buffer for testing
   */
  function buildSyntheticPe(options?: {
    isWxSection?: boolean;
    isPackerSection?: boolean;
    hasOverlay?: boolean;
    isTruncated?: boolean;
  }): Uint8Array {
    const buffer = new Uint8Array(1024);
    const view = new DataView(buffer.buffer);

    // DOS Header: 'MZ' at 0x00, e_lfanew at 0x3C
    view.setUint16(0x00, 0x5a4d, true); // 'MZ'
    const peOffset = 0x80;
    view.setUint32(0x3c, peOffset, true); // e_lfanew = 128

    if (options?.isTruncated) {
      return buffer.subarray(0, 0x40); // truncated before PE header
    }

    // PE Signature: 'PE\0\0' at e_lfanew
    view.setUint32(peOffset, 0x00004550, true);

    // COFF Header (20 bytes at peOffset + 4)
    const coff = peOffset + 4;
    view.setUint16(coff + 0, 0x8664, true); // Machine: AMD64 (PE32+)
    view.setUint16(coff + 2, 2, true);      // NumberOfSections: 2
    view.setUint32(coff + 4, 1710000000, true); // TimeDateStamp
    view.setUint16(coff + 16, 240, true);   // SizeOfOptionalHeader: 240
    view.setUint16(coff + 18, 0x0022, true); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header (PE32+ magic: 0x020B)
    const opt = coff + 20;
    view.setUint16(opt + 0, 0x020b, true); // PE32+
    view.setUint32(opt + 16, 0x1000, true); // AddressOfEntryPoint
    view.setUint16(opt + 68, 2, true); // Subsystem: Windows GUI
    view.setUint32(opt + 108, 16, true); // NumberOfRvaAndSizes: 16

    // Section Table (2 sections at opt + 240)
    const secTable = opt + 240;

    // Section 1: .text (Code)
    const sec1Name = options?.isPackerSection ? 'UPX0\0\0\0\0' : '.text\0\0\0';
    for (let i = 0; i < 8; i++) view.setUint8(secTable + i, sec1Name.charCodeAt(i));
    view.setUint32(secTable + 8, 0x1000, true);  // VirtualSize
    view.setUint32(secTable + 12, 0x1000, true); // VirtualAddress
    view.setUint32(secTable + 16, 0x200, true);  // SizeOfRawData (512 bytes)
    view.setUint32(secTable + 20, 0x200, true);  // PointerToRawData
    // Characteristics: MEM_EXECUTE | MEM_READ | (MEM_WRITE if W+X)
    let sec1Chars = 0x20000000 | 0x40000000 | 0x00000020;
    if (options?.isWxSection) {
      sec1Chars |= 0x80000000; // IMAGE_SCN_MEM_WRITE (W+X violation!)
    }
    view.setUint32(secTable + 36, sec1Chars, true);

    // Section 2: .data
    const sec2 = secTable + 40;
    const sec2Name = '.data\0\0\0';
    for (let i = 0; i < 8; i++) view.setUint8(sec2 + i, sec2Name.charCodeAt(i));
    view.setUint32(sec2 + 8, 0x800, true);
    view.setUint32(sec2 + 12, 0x2000, true);
    view.setUint32(sec2 + 16, 0x100, true);
    view.setUint32(sec2 + 20, 0x400, true);
    view.setUint32(sec2 + 36, 0x40000000 | 0x80000000, true); // MEM_READ | MEM_WRITE

    if (options?.hasOverlay) {
      // Return buffer larger than maxRawDataEnd (0x400 + 0x100 = 0x500 = 1280)
      const bufferWithOverlay = new Uint8Array(2048);
      bufferWithOverlay.set(buffer);
      // Fill overlay with non-zero bytes
      bufferWithOverlay.fill(0xcc, 0x500);
      return bufferWithOverlay;
    }

    return buffer;
  }

  it('parses valid PE32+ headers correctly without throwing RangeError', () => {
    const peBytes = buildSyntheticPe();
    const result = PeAnalyzer.analyze(peBytes);

    expect(result.isValidPe).toBe(true);
    expect(result.is64Bit).toBe(true);
    expect(result.numberOfSections).toBe(2);
    expect(result.sections).toHaveLength(2);
    expect(result.sections[0].name).toBe('.text');
    expect(result.sections[0].isWritableAndExecutable).toBe(false);
  });

  it('detects dangerous W+X (Writable and Executable) memory sections', () => {
    const wxPe = buildSyntheticPe({ isWxSection: true });
    const result = PeAnalyzer.analyze(wxPe);

    expect(result.isValidPe).toBe(true);
    expect(result.sections[0].isWritableAndExecutable).toBe(true);
    expect(result.evidence.some((e) => e.ruleId === 'pe-wx-section')).toBe(true);

    const wxEvidence = result.evidence.find((e) => e.ruleId === 'pe-wx-section');
    expect(wxEvidence?.severityLevel).toBe(SeverityLevel.CRITICAL);
    expect(wxEvidence?.isCriticalOverride).toBe(true);
  });

  it('detects known runtime packers by section name (e.g. UPX)', () => {
    const upxPe = buildSyntheticPe({ isPackerSection: true });
    const result = PeAnalyzer.analyze(upxPe);

    expect(result.isValidPe).toBe(true);
    expect(result.detectedPackers).toContain('UPX');
    expect(result.evidence.some((e) => e.ruleId === 'pe-known-packer')).toBe(true);
  });

  it('detects unauthenticated overlay payloads appended beyond the last section', () => {
    const overlayPe = buildSyntheticPe({ hasOverlay: true });
    const result = PeAnalyzer.analyze(overlayPe, 2048);

    expect(result.isValidPe).toBe(true);
    expect(result.hasOverlay).toBe(true);
    expect(result.overlaySizeBytes).toBeGreaterThan(0);
    expect(result.evidence.some((e) => e.ruleId === 'pe-suspicious-overlay')).toBe(true);
  });

  it('fails safely on truncated or malformed PE buffers without crashing', () => {
    const truncated = buildSyntheticPe({ isTruncated: true });
    const result = PeAnalyzer.analyze(truncated);

    expect(result.isValidPe).toBe(false);
    expect(result.isMalformed).toBe(true);
    expect(result.malformedReason).toBeDefined();
    // Zero throw guarantee
  });
});
