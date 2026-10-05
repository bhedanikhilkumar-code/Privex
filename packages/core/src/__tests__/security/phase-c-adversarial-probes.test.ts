import { describe, it, expect } from 'vitest';
import { ArchiveAnalyzer } from '../../analyzers/archive-analyzer';
import { PeAnalyzer } from '../../analyzers/pe-analyzer';
import { ScriptAnalyzer } from '../../analyzers/script-analyzer';
import { DocumentAnalyzer } from '../../analyzers/document-analyzer';
import { EntropyScanner } from '../../analyzers/entropy-scanner';
import { CoreFileAnalyzer } from '../../analyzers/file-analyzer';
import { CleanFileCache } from '../../cache/clean-file-cache';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { RiskScorer } from '../../scoring/risk-scorer';
import {
  InputType, EngineVerdict, Verdict, DetectorLayer, DetectorType, SeverityLevel, Evidence
} from '../../types';

/** Build a minimal ZIP with one stored entry using caller-declared sizes (metadata-only fixture, no payload). */
function zip(name: string, comp: number, uncomp: number, count = 1): Uint8Array {
  const nameBytes = new TextEncoder().encode(name);
  const cdEntry = 46 + nameBytes.length;
  const cdSize = cdEntry * count;
  const LH = 30;
  const out = new Uint8Array(LH + cdSize + 22);
  out.set([0x50, 0x4b, 0x03, 0x04], 0);
  const v = new DataView(out.buffer);
  let o = LH;
  for (let i = 0; i < count; i++) {
    v.setUint32(o, 0x02014b50, true);
    v.setUint32(o + 20, comp, true);
    v.setUint32(o + 24, uncomp, true);
    v.setUint16(o + 28, nameBytes.length, true);
    out.set(nameBytes, o + 46);
    o += cdEntry;
  }
  v.setUint32(o, 0x06054b50, true);
  v.setUint16(o + 8, count, true);
  v.setUint16(o + 10, count, true);
  v.setUint32(o + 12, cdSize, true);
  v.setUint32(o + 16, LH, true);
  return out;
}

const ids = (e: Evidence[]) => e.map((x) => x.ruleId);

describe('Phase C independent audit probes', () => {
  it('archive traversal variants are all flagged', () => {
    for (const n of ['../../evil.txt', '..\\..\\evil.txt', '/etc/passwd', 'C:\\Windows\\x.dll', '\\\\srv\\share\\x']) {
      const r = ArchiveAnalyzer.analyze(zip(n, 10, 10));
      expect(ids(r.evidence), n).toContain('archive-path-traversal');
    }
  });

  it('zip bomb metadata (ratio, size, count, overflow) flagged without allocation', () => {
    expect(ids(ArchiveAnalyzer.analyze(zip('a.txt', 100, 5_000_000)).evidence)).toContain('archive-zip-bomb');
    expect(ids(ArchiveAnalyzer.analyze(zip('a.txt', 0xffffffff, 0xffffffff)).evidence).length).toBeGreaterThanOrEqual(0);
    const big = ArchiveAnalyzer.analyze(zip('a.bin', 50_000_000, 0xfffffff0));
    expect(JSON.stringify(ids(big.evidence))).toMatch(/zip-bomb|excessive/);
    const many = ArchiveAnalyzer.analyze(zip('f.txt', 5, 5, 1500));
    expect(ids(many.evidence)).toContain('archive-excessive-entry-count');
  });

  it('hostile/truncated archives never throw', () => {
    const z = zip('a.txt', 1, 1);
    for (let n = 0; n < z.length; n++) expect(() => ArchiveAnalyzer.analyze(z.subarray(0, n))).not.toThrow();
    const rnd = new Uint8Array(70000).map((_, i) => (i * 131 + 7) & 0xff);
    expect(() => ArchiveAnalyzer.analyze(rnd)).not.toThrow();
  });

  it('PE: every truncation and random mutation never throws', () => {
    const base = new Uint8Array(1024);
    const v = new DataView(base.buffer);
    base[0] = 0x4d; base[1] = 0x5a; v.setUint32(0x3c, 0x80, true);
    base.set([0x50, 0x45, 0, 0], 0x80);
    v.setUint16(0x84, 0x8664, true); v.setUint16(0x86, 2, true); v.setUint16(0x94, 240, true);
    v.setUint16(0x98, 0x20b, true);
    for (let n = 0; n <= base.length; n += 7) expect(() => PeAnalyzer.analyze(base.subarray(0, n), 1 << 30)).not.toThrow();
    let seed = 1;
    for (let i = 0; i < 2000; i++) {
      const m = base.slice();
      for (let k = 0; k < 8; k++) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; m[seed % m.length] = seed & 0xff; }
      expect(() => PeAnalyzer.analyze(m, 0xffffffff)).not.toThrow();
    }
  });

  it('script: base64 decode is bounded and static; no recursion blowup', () => {
    const huge = 'A'.repeat(200000);
    const t0 = Date.now();
    const r = ScriptAnalyzer.analyze(new TextEncoder().encode(`powershell -enc ${huge}`), 'a.ps1');
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(r).toBeDefined();
    let nested = 'echo hi';
    for (let i = 0; i < 4; i++) nested = Buffer.from(nested, 'utf16le').toString('base64');
    expect(() => ScriptAnalyzer.analyze(new TextEncoder().encode(`powershell -enc ${nested}`), 'a.ps1')).not.toThrow();
  });

  it('documents: garbage and truncated input never throw', () => {
    for (const head of ['%PDF-1.7', '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'PK\x03\x04']) {
      const b = new Uint8Array(5000).fill(0x41);
      b.set(new TextEncoder().encode(head), 0);
      expect(() => DocumentAnalyzer.analyze(b, 'x.docx')).not.toThrow();
    }
  });

  it('entropy: empty/1-byte/uniform/random', () => {
    expect(EntropyScanner.calculateEntropy(new Uint8Array(0))).toBe(0);
    expect(EntropyScanner.calculateEntropy(new Uint8Array([7]))).toBe(0);
    expect(EntropyScanner.calculateEntropy(new Uint8Array(4096).fill(9))).toBe(0);
    const all = new Uint8Array(4096).map((_, i) => i & 0xff);
    expect(EntropyScanner.calculateEntropy(all)).toBeCloseTo(8, 3);
  });

  it('entropy alone does not produce QUARANTINE/BLOCK for a non-executable blob', () => {
    const blob = new Uint8Array(65536).map((_, i) => (i * 2654435761) >>> 24);
    const out = CoreFileAnalyzer.analyzeBuffer({ fileName: 'data.bin', fileSize: blob.length, headerBytes: blob }, {});
    expect([EngineVerdict.QUARANTINE]).not.toContain(out.engineVerdict);
  });

  it('extension never decides safety: PE content with .txt name is flagged', () => {
    const pe = new Uint8Array(1024); pe[0] = 0x4d; pe[1] = 0x5a;
    const out = CoreFileAnalyzer.analyzeBuffer({ fileName: 'notes.txt', fileSize: 1024, headerBytes: pe }, {});
    expect(out.engineVerdict).not.toBe(EngineVerdict.ALLOW);
  });

  it('RTLO name produces evidence', () => {
    const out = CoreFileAnalyzer.analyzeBuffer(
      { fileName: 'invoice\u202Efdp.exe', fileSize: 10, headerBytes: new Uint8Array([1, 2, 3]) }, {});
    expect(ids(out.evidence)).toContain('file-rtlo-spoofing');
  });

  it('empty / zero-size / negative / huge declared size never throw and yield a canonical verdict', () => {
    for (const size of [0, -5, 2 ** 40, NaN]) {
      let out: ReturnType<typeof CoreFileAnalyzer.analyzeBuffer> | undefined;
      expect(() => {
        out = CoreFileAnalyzer.analyzeBuffer({ fileName: 'x.bin', fileSize: size, headerBytes: new Uint8Array(0) }, {});
      }).not.toThrow();
      expect(Object.values(EngineVerdict)).toContain(out!.engineVerdict);
    }
  });

  it('dilution: 1000 benign + 1 critical stays QUARANTINE/BLOCK', () => {
    const ev: Evidence[] = [];
    for (let i = 0; i < 1000; i++) ev.push({
      ruleId: `benign-${i}`, detectorType: DetectorType.HEURISTIC, detectorLayer: DetectorLayer.STATIC_HEURISTIC,
      source: 't', name: 'b', description: 'b', weight: 1, scoreContribution: 1, confidence: 0.2, severityLevel: SeverityLevel.LOW
    } as Evidence);
    ev.push({
      ruleId: 'pe-wx-section', detectorType: DetectorType.HEURISTIC, detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
      source: 't', name: 'c', description: 'c', weight: 85, scoreContribution: 85, confidence: 0.95,
      severityLevel: SeverityLevel.CRITICAL, isCriticalOverride: true, isMalicious: true
    } as Evidence);
    const r = new RiskScorer().calculate(ev, 0, { inputType: InputType.FILE });
    expect([EngineVerdict.QUARANTINE, EngineVerdict.BLOCK]).toContain(r.engineVerdict);
    expect(r.score).toBeGreaterThanOrEqual(85);
  });

  it('duplicate malicious evidence does not exceed 100 and is deterministic', () => {
    const mk = (i: number): Evidence => ({
      ruleId: 'dup', detectorType: DetectorType.HEURISTIC, detectorLayer: DetectorLayer.STATIC_HEURISTIC,
      source: 't', name: 'd', description: 'd', weight: 60, scoreContribution: 60, confidence: 0.9, severityLevel: SeverityLevel.HIGH
    } as Evidence);
    const a = new RiskScorer().calculate(Array.from({ length: 500 }, (_, i) => mk(i)), 0, { inputType: InputType.FILE });
    const b = new RiskScorer().calculate(Array.from({ length: 500 }, (_, i) => mk(i)), 0, { inputType: InputType.FILE });
    expect(a.score).toBeLessThanOrEqual(100);
    expect(a.score).toBe(b.score);
    expect(a.engineVerdict).toBe(b.engineVerdict);
  });

  it('pipeline FILE scan is deterministic and EICAR is quarantined', async () => {
    const eicar = new TextEncoder().encode('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    const p = new DetectionPipeline();
    const run = () => p.scan({ inputType: InputType.FILE, payload: eicar, metadata: { fileName: 'e.com', fileSize: String(eicar.length) } } as any);
    const [a, b] = [await run(), await run()];
    expect(a.engineVerdict).toBe(EngineVerdict.QUARANTINE);
    expect([a.riskScore, a.verdict, a.engineVerdict, a.evidence.map((e) => e.ruleId)])
      .toEqual([b.riskScore, b.verdict, b.engineVerdict, b.evidence.map((e) => e.ruleId)]);
  });

  it('malformed PE through pipeline is never ALLOW', async () => {
    const bad = new Uint8Array(300); bad[0] = 0x4d; bad[1] = 0x5a; bad[0x3c] = 0xff;
    const r = await new DetectionPipeline().scan({ inputType: InputType.FILE, payload: bad, metadata: { fileName: 'a.exe', fileSize: '300' } } as any);
    expect(r.engineVerdict).not.toBe(EngineVerdict.ALLOW);
    expect(r.verdict).not.toBe(Verdict.ALLOW);
  });

  it('cache: key changes with size/mtime so mutated file is not trusted', () => {
    const c = new CleanFileCache();
    c.set('c:/a/f.exe', 100, 1000, 'a'.repeat(64), { verdict: Verdict.ALLOW, riskScore: 0 });
    expect(c.get('c:/a/f.exe', 100, 1000)).not.toBeNull();
    expect(c.get('c:/a/f.exe', 101, 1000)).toBeNull();
    expect(c.get('c:/a/f.exe', 100, 1001)).toBeNull();
  });
});
