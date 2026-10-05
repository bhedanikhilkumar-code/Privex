import { describe, it, expect } from 'vitest';
import { ArchiveAnalyzer } from '../../analyzers/archive-analyzer';
import { DetectorLayer } from '../../types';

function createMockZipBuffer(entries: Array<{
  name: string;
  uncompressedSize: number;
  compressedSize: number;
  compressionMethod?: number;
}>): Uint8Array {
  // We construct a valid in-memory ZIP buffer with Central Directory and EOCD
  const chunks: Uint8Array[] = [];
  const localOffsets: number[] = [];
  let currentOffset = 0;

  for (const entry of entries) {
    localOffsets.push(currentOffset);
    const nameBytes = new TextEncoder().encode(entry.name);
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const view = new DataView(localHeader.buffer);
    view.setUint32(0, 0x04034b50, true); // Local File Header signature
    view.setUint16(4, 20, true); // Version needed to extract
    view.setUint16(6, 0, true); // General purpose bit flag
    view.setUint16(8, entry.compressionMethod ?? 8, true); // Compression method (8 = Deflate)
    view.setUint16(10, 0, true); // Mod time
    view.setUint16(12, 0, true); // Mod date
    view.setUint32(14, 0x12345678, true); // CRC-32
    view.setUint32(18, entry.compressedSize, true); // Compressed size
    view.setUint32(22, entry.uncompressedSize, true); // Uncompressed size
    view.setUint16(26, nameBytes.length, true); // File name length
    view.setUint16(28, 0, true); // Extra field length
    localHeader.set(nameBytes, 30);

    chunks.push(localHeader);
    currentOffset += localHeader.length;

    // Payload data dummy bytes (if any)
    const payload = new Uint8Array(Math.min(entry.compressedSize, 16));
    chunks.push(payload);
    currentOffset += payload.length;
  }

  const cdStartOffset = currentOffset;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const nameBytes = new TextEncoder().encode(entry.name);
    const cdHeader = new Uint8Array(46 + nameBytes.length);
    const view = new DataView(cdHeader.buffer);
    view.setUint32(0, 0x02014b50, true); // Central Directory signature
    view.setUint16(4, 20, true); // Version made by
    view.setUint16(6, 20, true); // Version needed
    view.setUint16(8, 0, true); // Bit flag
    view.setUint16(10, entry.compressionMethod ?? 8, true); // Compression method
    view.setUint16(12, 0, true); // Mod time
    view.setUint16(14, 0, true); // Mod date
    view.setUint32(16, 0x12345678, true); // CRC-32
    view.setUint32(20, entry.compressedSize, true); // Compressed size
    view.setUint32(24, entry.uncompressedSize, true); // Uncompressed size
    view.setUint16(28, nameBytes.length, true); // File name length
    view.setUint16(30, 0, true); // Extra field length
    view.setUint16(32, 0, true); // Comment length
    view.setUint16(34, 0, true); // Disk number
    view.setUint16(36, 0, true); // Internal attributes
    view.setUint32(38, 0, true); // External attributes
    view.setUint32(42, localOffsets[i], true); // Local header offset
    cdHeader.set(nameBytes, 46);

    chunks.push(cdHeader);
    currentOffset += cdHeader.length;
  }

  const cdSize = currentOffset - cdStartOffset;
  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true); // EOCD signature
  eocdView.setUint16(4, 0, true); // Disk number
  eocdView.setUint16(6, 0, true); // Start disk
  eocdView.setUint16(8, entries.length, true); // Entries on this disk
  eocdView.setUint16(10, entries.length, true); // Total entries
  eocdView.setUint32(12, cdSize, true); // CD size
  eocdView.setUint32(16, cdStartOffset, true); // CD offset
  eocdView.setUint16(20, 0, true); // Comment length
  chunks.push(eocd);

  const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(totalLength);
  let pos = 0;
  for (const chunk of chunks) {
    out.set(chunk, pos);
    pos += chunk.length;
  }
  return out;
}

describe('ArchiveAnalyzer (Layer 5)', () => {
  it('handles empty or small buffers safely without throwing', () => {
    const res = ArchiveAnalyzer.analyze(new Uint8Array(10));
    expect(res.isArchive).toBe(false);
    expect(res.evidence.length).toBe(0);
  });

  it('identifies non-zip buffers', () => {
    const buf = new Uint8Array(100);
    buf.fill(0xaa);
    const res = ArchiveAnalyzer.analyze(buf);
    expect(res.isArchive).toBe(false);
    expect(res.entries.length).toBe(0);
  });

  it('parses clean zip with text files correctly', () => {
    const zip = createMockZipBuffer([
      { name: 'notes.txt', uncompressedSize: 50, compressedSize: 40 },
      { name: 'docs/readme.md', uncompressedSize: 100, compressedSize: 80 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    expect(res.archiveFormat).toBe('ZIP');
    expect(res.entryCount).toBe(2);
    expect(res.hasZipBombCharacteristics).toBe(false);
    expect(res.hasPathTraversal).toBe(false);
    expect(res.hasDisguisedExecutables).toBe(false);
    expect(res.evidence.length).toBe(0);
  });

  it('detects disguised executables inside archive', () => {
    const zip = createMockZipBuffer([
      { name: 'invoice.pdf.exe', uncompressedSize: 50000, compressedSize: 20000 },
      { name: 'payload.ps1', uncompressedSize: 1000, compressedSize: 500 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    expect(res.hasDisguisedExecutables).toBe(true);
    const rules = res.evidence.map(e => e.ruleId);
    expect(rules).toContain('archive-dangerous-executable');
    expect(rules).toContain('archive-double-extension');
    expect(res.evidence.every(e => e.detectorLayer === DetectorLayer.STRUCTURAL_PARSER)).toBe(true);
  });

  it('detects directory path traversal attempts', () => {
    const zip = createMockZipBuffer([
      { name: '../../windows/system32/cmd.exe', uncompressedSize: 1000, compressedSize: 500 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    expect(res.hasPathTraversal).toBe(true);
    const rules = res.evidence.map(e => e.ruleId);
    expect(rules).toContain('archive-path-traversal');
  });

  it('detects zip bomb characteristics via extreme compression ratio (> 100:1)', () => {
    const zip = createMockZipBuffer([
      { name: 'sparse_bomb.dat', uncompressedSize: 5000000, compressedSize: 1000 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    expect(res.hasZipBombCharacteristics).toBe(true);
    expect(res.compressionRatio).toBeGreaterThan(100);
    const rules = res.evidence.map(e => e.ruleId);
    expect(rules).toContain('archive-zip-bomb');
  });

  it('detects zip bomb characteristics via excessive total uncompressed size (> 100MB)', () => {
    const zip = createMockZipBuffer([
      { name: 'huge_file.dat', uncompressedSize: 150 * 1024 * 1024, compressedSize: 10 * 1024 * 1024 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    expect(res.hasZipBombCharacteristics).toBe(true);
    const rules = res.evidence.map(e => e.ruleId);
    expect(rules).toContain('archive-excessive-size');
  });

  it('detects RTLO bidi spoofing in archive entry names', () => {
    // \u202E is Right-to-Left Override
    const spoofedName = 'urgent_document\u202Ecod.exe';
    const zip = createMockZipBuffer([
      { name: spoofedName, uncompressedSize: 500, compressedSize: 200 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    const rules = res.evidence.map(e => e.ruleId);
    expect(rules).toContain('archive-rtlo-spoof');
  });

  it('detects nested archive containers', () => {
    const zip = createMockZipBuffer([
      { name: 'nested/inner_archive.zip', uncompressedSize: 5000, compressedSize: 4500 }
    ]);
    const res = ArchiveAnalyzer.analyze(zip);
    expect(res.isArchive).toBe(true);
    const rules = res.evidence.map(e => e.ruleId);
    expect(rules).toContain('archive-nested-container');
  });

  it('handles malformed EOCD or truncated central directory safely with fail-closed evidence', () => {
    const zip = createMockZipBuffer([
      { name: 'test.txt', uncompressedSize: 100, compressedSize: 50 }
    ]);
    // Corrupt the EOCD offset
    const corrupted = new Uint8Array(zip);
    const view = new DataView(corrupted.buffer);
    view.setUint32(corrupted.length - 6, 0x7fffffff, true); // invalid CD offset

    const res = ArchiveAnalyzer.analyze(corrupted);
    expect(res.isArchive).toBe(true);
    expect(res.isMalformed).toBe(true);
    expect(res.evidence.some(e => e.ruleId === 'archive-malformed-structure')).toBe(true);
  });
});
