import { describe, it, expect } from 'vitest';
import {
  CoreFileAnalyzer,
  DetectionPipeline,
  InputType,
  RiskScorer,
  Verdict,
  ActionRecommendation,
  SeverityLevel
} from '../../index';

describe('Phase A — Core Security Hardening, Determinism & Fail-Closed Suite', () => {
  it('fails closed to WARN / ANALYSIS_FAILED when FileScanRequest is null, undefined, or has invalid fileSize', () => {
    const outNull = CoreFileAnalyzer.analyzeBuffer(null as any);
    expect(outNull.analysisStatus).toBe('ANALYSIS_FAILED');
    expect(outNull.disposition).toBe('ANALYSIS_FAILED');
    expect(outNull.desktopVerdict).toBe('WARN');
    expect(outNull.verdict).toBe(Verdict.CAUTION);
    expect(outNull.riskScore).toBeGreaterThanOrEqual(50);

    const outNegSize = CoreFileAnalyzer.analyzeBuffer({
      fileName: 'bad.bin',
      fileSize: -100,
      headerBytes: new Uint8Array([0x00, 0x01])
    });
    expect(outNegSize.analysisStatus).toBe('ANALYSIS_FAILED');
    expect(outNegSize.disposition).toBe('ANALYSIS_FAILED');
    expect(outNegSize.desktopVerdict).toBe('WARN');
  });

  it('fails closed when a non-empty file (fileSize > 0) has 0 readable header bytes (UNREADABLE_FILE_HEADER)', () => {
    const out = CoreFileAnalyzer.analyzeBuffer({
      fileName: 'locked_or_unreadable.dat',
      fileSize: 4096,
      headerBytes: new Uint8Array(0)
    });
    expect(out.analysisStatus).toBe('ANALYSIS_FAILED');
    expect(out.disposition).toBe('ANALYSIS_FAILED');
    expect(out.threatName).toBe('UNREADABLE_FILE_HEADER');
    expect(out.desktopVerdict).toBe('WARN');
    expect(out.riskScore).toBeGreaterThanOrEqual(30);
  });

  it('allows a genuinely empty 0-byte benign file (fileSize === 0, headerBytes.length === 0)', () => {
    const out = CoreFileAnalyzer.analyzeBuffer({
      fileName: 'empty_notes.txt',
      fileSize: 0,
      headerBytes: new Uint8Array(0)
    });
    expect(out.analysisStatus).toBe('COMPLETED');
    expect(out.disposition).toBe('SAFE');
    expect(out.desktopVerdict).toBe('ALLOW');
    expect(out.entropy).toBe(0);
    expect(out.sha256).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('detects trailing dots/spaces and Unicode RTLO (\\u202E) extension spoofing on Windows filenames', () => {
    const trailingDots = CoreFileAnalyzer.checkDeceptiveExtension('invoice.pdf.exe... ');
    expect(trailingDots.isDeceptive).toBe(true);
    expect(trailingDots.realExt).toBe('.exe');
    expect(trailingDots.fakeExt).toBe('.pdf');

    const rtloName = `report_\u202Efdp.scr`;
    const rtloCheck = CoreFileAnalyzer.checkDeceptiveExtension(rtloName);
    expect(rtloCheck.isDeceptive).toBe(true);
    expect(rtloCheck.hasRtloSpoofing).toBe(true);

    const rtloOut = CoreFileAnalyzer.analyzeBuffer({
      fileName: rtloName,
      fileSize: 16,
      headerBytes: new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 1, 2, 3, 4])
    });
    expect(rtloOut.desktopVerdict).toBe('BLOCK');
    expect(rtloOut.disposition).toBe('MALICIOUS');
    expect(rtloOut.riskScore).toBeGreaterThanOrEqual(75);
  });

  it('detects standard EICAR antivirus test signature deterministically without fake detections', () => {
    const eicarBytes = new TextEncoder().encode(CoreFileAnalyzer.EICAR_SIGNATURE);
    const out = CoreFileAnalyzer.analyzeBuffer({
      fileName: 'eicar.com.txt',
      fileSize: eicarBytes.length,
      headerBytes: eicarBytes
    });
    expect(out.magicHeader).toBe('EICAR_TEST_SIGNATURE');
    expect(out.threatName).toBe('EICAR_TEST_FILE');
    expect(out.riskScore).toBe(100);
    expect(out.desktopVerdict).toBe('BLOCK');
    expect(out.disposition).toBe('MALICIOUS');
    expect(out.severity).toBe(SeverityLevel.CRITICAL);
  });

  it('preserves 100% bitwise determinism across 50 consecutive runs on identical inputs', async () => {
    const pipeline = new DetectionPipeline();
    const fixedTimestamp = 1760000000000;
    const pePayload = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);

    const baselineFile = CoreFileAnalyzer.analyzeBuffer({
      fileName: 'statement.pdf.exe',
      fileSize: pePayload.length,
      headerBytes: pePayload
    });

    const baselineUrl = await pipeline.scan({
      id: 'det-url-1',
      timestamp: fixedTimestamp,
      inputType: InputType.URL,
      input: 'http://192.168.1.1/paypal-login/verify-account'
    });

    for (let i = 0; i < 50; i++) {
      const runFile = CoreFileAnalyzer.analyzeBuffer({
        fileName: 'statement.pdf.exe',
        fileSize: pePayload.length,
        headerBytes: pePayload
      });
      expect(runFile).toEqual(baselineFile);

      const runUrl = await pipeline.scan({
        id: 'det-url-1',
        timestamp: fixedTimestamp,
        inputType: InputType.URL,
        input: 'http://192.168.1.1/paypal-login/verify-account'
      });
      expect(runUrl.riskScore).toBe(baselineUrl.riskScore);
      expect(runUrl.verdict).toBe(baselineUrl.verdict);
      expect(runUrl.disposition).toBe(baselineUrl.disposition);
      expect(runUrl.timestamp).toBe(baselineUrl.timestamp);
      expect(runUrl.evidence).toEqual(baselineUrl.evidence);
    }
  });

  it('fails closed in DetectionPipeline.scan if an internal analyzer throws an unexpected error', async () => {
    const brokenRuleEngine = {
      evaluateAll: () => {
        throw new Error('Simulated internal rule engine fault');
      }
    } as any;
    const pipeline = new DetectionPipeline({ ruleEngine: brokenRuleEngine });
    const res = await pipeline.scan({
      inputType: InputType.URL,
      input: 'https://example.com'
    });
    expect(res.verdict).toBe(Verdict.CAUTION);
    expect(res.recommendation).toBe(ActionRecommendation.WARN);
    expect(res.analysisStatus).toBe('ANALYSIS_FAILED');
    expect(res.disposition).toBe('ANALYSIS_FAILED');
    expect(res.riskScore).toBe(50);
  });
});
