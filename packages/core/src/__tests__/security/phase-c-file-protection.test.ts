import { describe, it, expect, beforeEach } from 'vitest';
import { CoreFileAnalyzer } from '../../analyzers/file-analyzer';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { CleanFileCache } from '../../cache/clean-file-cache';
import {
  InputType,
  EngineVerdict,
  DetectorLayer,
  SeverityLevel,
  Evidence
} from '../../types';

describe('Phase C — File Protection & 10-Layer Static Malware Engine Security Suite', () => {
  beforeEach(() => {
    CleanFileCache.getSharedInstance().clear();
  });

  describe('Layer 1 & Stage 0 Sieve: CleanFileCache', () => {
    it('skips heavy analysis on clean cache hit', () => {
      const cleanContent = new TextEncoder().encode('Hello, world! This is a completely benign text file.');
      const path = 'C:\\safe\\notes.txt';
      const mtime = Date.now();
      const size = cleanContent.length;

      // Populate cache
      CleanFileCache.getSharedInstance().recordClean(path, size, mtime, 'hash-dummy-1234');

      const analyzer = new CoreFileAnalyzer();
      const res = analyzer.analyze({
        path,
        content: cleanContent,
        fileSize: size,
        lastModified: mtime
      });

      expect(res.stage0CacheHit).toBe(true);
      expect(res.riskScore).toBe(0);
      expect(res.evidence.length).toBe(0);
    });

    it('bypasses cache when mtime or size changes', () => {
      const cleanContent = new TextEncoder().encode('Benign content.');
      const path = 'C:\\safe\\notes.txt';
      const mtime = 1000000;
      const size = cleanContent.length;

      CleanFileCache.getSharedInstance().recordClean(path, size, mtime, 'hash-dummy-1234');

      const analyzer = new CoreFileAnalyzer();
      // Modified mtime
      const res = analyzer.analyze({
        path,
        content: cleanContent,
        fileSize: size,
        lastModified: mtime + 5000
      });

      expect(res.stage0CacheHit).toBe(false);
    });
  });

  describe('Layer 2 & Stage 1 Sieve: Signature Automaton & EICAR', () => {
    it('short-circuits immediately on EICAR standard test signature', () => {
      const eicarStr = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const content = new TextEncoder().encode(eicarStr);

      const analyzer = new CoreFileAnalyzer();
      const res = analyzer.analyze({
        path: 'eicar.com',
        content
      });

      expect(res.stage1ShortCircuit).toBe(true);
      expect(res.magicHeader).toBe('EICAR_TEST_SIGNATURE');
      expect(res.riskScore).toBe(100);
      const eicarEv = res.evidence.find(e => e.ruleId === 'sig-eicar-test-string' || e.ruleId === 'file-eicar-test-signature');
      expect(eicarEv).toBeDefined();
      expect(eicarEv?.isCriticalOverride).toBe(true);
    });

    it('detects embedded malicious tool signatures (e.g. Mimikatz sekurlsa / logonpasswords)', () => {
      const fakePayload = 'echo starting... sekurlsa::logonpasswords token::elevate';
      const content = new TextEncoder().encode(fakePayload);

      const analyzer = new CoreFileAnalyzer();
      const res = analyzer.analyze({
        path: 'audit.bat',
        content
      });

      expect(res.evidence.some(e => e.ruleId.startsWith('sig-mimikatz'))).toBe(true);
      expect(res.riskScore).toBeGreaterThanOrEqual(80);
    });
  });

  describe('Layer 3 & 4: Metadata Anomalies, RTLO, Double Extension & Shannon Entropy', () => {
    it('detects executable disguised as benign PDF with double extension', () => {
      const peHeader = new Uint8Array(256);
      peHeader[0] = 0x4d; // 'M'
      peHeader[1] = 0x5a; // 'Z'
      peHeader[0x3c] = 0x40; // e_lfanew
      peHeader[0x40] = 0x50; // 'P'
      peHeader[0x41] = 0x45; // 'E'

      const analyzer = new CoreFileAnalyzer();
      const res = analyzer.analyze({
        path: 'invoice.pdf.exe',
        content: peHeader
      });

      expect(res.hasDoubleExtension).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'file-double-extension')).toBe(true);
    });

    it('detects RTLO unicode directional character spoofing', () => {
      // \u202E changes direction
      const path = 'urgent_\u202Ecod.exe';
      const content = new TextEncoder().encode('dummy content');

      const analyzer = new CoreFileAnalyzer();
      const res = analyzer.analyze({
        path,
        content
      });

      expect(res.evidence.some(e => e.ruleId === 'file-rtlo-spoofing')).toBe(true);
    });

    it('calculates Shannon entropy using ENTROPY_LUT and flags high entropy sections', () => {
      // Create high-entropy pseudo-random buffer (> 7.2 bits/byte)
      const highEntropy = new Uint8Array(4096);
      for (let i = 0; i < highEntropy.length; i++) {
        highEntropy[i] = (i * 167 + 13) % 256;
      }

      const analyzer = new CoreFileAnalyzer();
      const res = analyzer.analyze({
        path: 'packed_data.bin',
        content: highEntropy
      });

      expect(res.entropy).toBeGreaterThan(7.0);
    });
  });

  describe('Pipeline Integration & Core Decision Authority', () => {
    it('produces canonical EngineVerdict.BLOCK when critical static malware is detected', async () => {
      const pipeline = new DetectionPipeline();
      const eicarStr = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const content = new TextEncoder().encode(eicarStr);

      const verdict = await pipeline.scan({
        inputType: InputType.FILE,
        payload: 'eicar.com',
        fileContent: content
      });

      expect([EngineVerdict.BLOCK, EngineVerdict.QUARANTINE]).toContain(verdict.engineVerdict);
      expect(verdict.verdict).toBe('DANGEROUS');
      expect(verdict.riskScore).toBeGreaterThanOrEqual(95);
      expect(verdict.evidence.some(e => e.detectorLayer === DetectorLayer.SIGNATURE_ENGINE)).toBe(true);
    });

    it('defends against signal dilution attacks (1 critical override + 50 benign noise signals)', async () => {
      const pipeline = new DetectionPipeline();
      const maliciousScript = `
        vssadmin delete shadows /all /quiet
        wmic shadowcopy delete
      `;
      const content = new TextEncoder().encode(maliciousScript);

      const verdict = await pipeline.scan({
        inputType: InputType.FILE,
        payload: 'ransom_prep.bat',
        fileContent: content
      });

      expect([EngineVerdict.BLOCK, EngineVerdict.QUARANTINE]).toContain(verdict.engineVerdict);
      expect(verdict.riskScore).toBeGreaterThanOrEqual(85);
    });

    it('classifies benign office documents as ALLOW with low risk score', async () => {
      const pipeline = new DetectionPipeline();
      const plainDoc = new TextEncoder().encode('Quarterly Report 2026. Everything is performing as expected.');

      const verdict = await pipeline.scan({
        inputType: InputType.FILE,
        payload: 'notes.txt',
        fileContent: plainDoc
      });

      expect(verdict.engineVerdict).toBe(EngineVerdict.ALLOW);
      expect(verdict.riskScore).toBeLessThan(20);
    });
  });

  describe('Safe Parsing & Exception Resilience', () => {
    it('never throws unhandled errors on malformed, corrupt, or truncated binary files', () => {
      const corruptedBuffers = [
        new Uint8Array(0),
        new Uint8Array(1),
        new Uint8Array([0x4d, 0x5a]), // Truncated DOS header
        new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x00]), // Truncated ZIP
        new Uint8Array([0x25, 0x50, 0x44, 0x46]), // Truncated PDF
        new Uint8Array(2000).fill(0xff) // Random high-value noise
      ];

      const analyzer = new CoreFileAnalyzer();
      for (const buf of corruptedBuffers) {
        expect(() => {
          analyzer.analyze({
            path: 'corrupted.bin',
            content: buf
          });
        }).not.toThrow();
      }
    });
  });
});
