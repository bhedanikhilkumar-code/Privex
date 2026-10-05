import { describe, it, expect } from 'vitest';
import { PeAnalyzer } from '../../analyzers/pe-analyzer';
import { CoreFileAnalyzer } from '../../analyzers/file-analyzer';
import { CleanFileCache } from '../../cache/clean-file-cache';
import { Verdict, EngineVerdict } from '../../types';

function truncatedOptionalHeaderPe(): Uint8Array {
  const buf = new Uint8Array(260);
  const view = new DataView(buf.buffer);
  buf[0] = 0x4d;
  buf[1] = 0x5a;
  view.setUint32(0x3c, 150, true);
  buf.set([0x50, 0x45, 0, 0], 150);
  view.setUint16(154, 0x14c, true); // machine
  view.setUint16(156, 1, true); // sections
  view.setUint16(170, 68, true); // SizeOfOptionalHeader (truncated vs buffer)
  view.setUint16(174, 0x10b, true);
  return buf;
}

describe('Phase C audit remediation', () => {
  it('PeAnalyzer never throws on truncated optional header and fails closed', () => {
    const res = PeAnalyzer.analyze(truncatedOptionalHeaderPe(), 260);
    expect(res.isMalformed).toBe(true);
    expect(res.evidence.some((e) => e.ruleId === 'pe-malformed-structure')).toBe(true);
  });

  it('malformed PE routed through CoreFileAnalyzer is not silently ALLOWed', () => {
    const out = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: 'broken.exe',
        fileSize: 260,
        headerBytes: truncatedOptionalHeaderPe()
      },
      {}
    );
    expect(out.evidence.some((e) => e.ruleId === 'pe-malformed-structure')).toBe(true);
    expect(out.engineVerdict).not.toBe(EngineVerdict.ALLOW);
  });

  it('CleanFileCache refuses non-clean entries', () => {
    const cache = new CleanFileCache();
    cache.set('c:/x/evil.exe', 10, 1, 'a'.repeat(64), {
      verdict: Verdict.DANGEROUS,
      engineVerdict: EngineVerdict.QUARANTINE,
      riskScore: 95
    });
    expect(cache.get('c:/x/evil.exe', 10, 1)).toBeNull();
  });
});
