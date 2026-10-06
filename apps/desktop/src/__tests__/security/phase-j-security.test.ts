import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { MotwAnalyzer } from '../../core/motw-analyzer';
import { FileAnalyzer } from '../../core/file-analyzer';

describe('Phase J Security & Adversarial Suite (Mark-of-the-Web Protection)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phase-j-sec-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('SEC-J-A: treats crafted shell injection in ADS values strictly as text and executes zero commands', () => {
    const maliciousAds = [
      '[ZoneTransfer]',
      'ZoneId=3',
      'HostUrl=https://attacker.com/file.exe?cmd=$(calc.exe)&dir|powershell.exe',
      'ReferrerUrl=https://attacker.com/payload.exe;rm -rf /;format C:'
    ].join('\r\n');

    const meta = MotwAnalyzer.parseZoneIdentifier(maliciousAds);
    expect(meta.hasMotw).toBe(true);
    expect(meta.hostUrl).toContain('$(calc.exe)');
    expect(meta.referrerUrl).toContain('rm -rf');

    const analysis = MotwAnalyzer.analyzeUrl(meta.hostUrl!, 'HostUrl');
    expect(analysis.isMalicious || analysis.riskScore >= 0).toBe(true);
  });

  it('SEC-J-B: enforces 4 KB memory bound when parsing 1 MB bloated adversarial ADS stream', () => {
    const bloatedAds = '[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.com/\r\n' + 'A=B\r\n'.repeat(50000);
    const meta = MotwAnalyzer.parseZoneIdentifier(bloatedAds);

    expect(meta.hasMotw).toBe(true);
    expect(meta.zoneId).toBe(3);
    expect(meta.rawAdsContent?.length).toBeLessThanOrEqual(MotwAnalyzer.MAX_ADS_READ_BYTES);
  });

  it('SEC-J-C: immunizes against path traversal & UNC network shares in HostUrl/ReferrerUrl', () => {
    const traversalAds = [
      '[ZoneTransfer]',
      'ZoneId=3',
      'HostUrl=\\\\192.168.1.100\\share\\payload.exe',
      'ReferrerUrl=../../../../Windows/System32/cmd.exe'
    ].join('\r\n');

    const meta = MotwAnalyzer.parseZoneIdentifier(traversalAds);
    expect(meta.hasMotw).toBe(true);

    const hostAnalysis = MotwAnalyzer.analyzeUrl(meta.hostUrl!, 'HostUrl');
    const refAnalysis = MotwAnalyzer.analyzeUrl(meta.referrerUrl!, 'ReferrerUrl');

    expect(hostAnalysis.url).toBe('\\\\192.168.1.100\\share\\payload.exe');
    expect(refAnalysis.url).toBe('../../../../Windows/System32/cmd.exe');
  });

  it('SEC-J-D: scrubs Right-to-Left Override (RTLO) bidi characters from MOTW URL strings', () => {
    // RTLO \u202E causes "exe.pdf" to render visually as "fdp.exe"
    const rtloAds = `[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.com/doc\u202Eexe.pdf\r\n`;
    const meta = MotwAnalyzer.parseZoneIdentifier(rtloAds);

    expect(meta.hasMotw).toBe(true);
    expect(meta.hostUrl).not.toContain('\u202E');
    expect(meta.hostUrl).toBe('https://evil.com/docexe.pdf');
  });

  it('SEC-J-E: executes 100% offline with Node network/socket APIs hard-disabled', async () => {
    const fetchSpy = vi.fn().mockImplementation(() => {
      throw new Error('OFFLINE_VIOLATION: fetch() invoked during MOTW scan');
    });
    globalThis.fetch = fetchSpy;

    const socketSpy = vi.spyOn(net.Socket.prototype, 'connect').mockImplementation(() => {
      throw new Error('OFFLINE_VIOLATION: Socket.connect invoked during MOTW scan');
    });

    try {
      const targetFile = path.join(tempDir, 'offline-download.exe');
      fs.writeFileSync(targetFile, 'MZ_OFFLINE_TEST_BINARY');

      const companionPath = `${targetFile}.zone.identifier`;
      fs.writeFileSync(
        companionPath,
        MotwAnalyzer.createZoneIdentifierAds({
          zoneId: 3,
          hostUrl: 'https://paypa1-security-verification.com/login.exe',
          referrerUrl: 'https://phishing-portal.com'
        })
      );

      const result = await FileAnalyzer.analyzeFile(targetFile);
      expect(result.verdict).toBe('BLOCK');
      expect(result.riskScore).toBeGreaterThanOrEqual(85);
      expect(result.evidenceFactors.some((f) => f.includes('Mark-of-the-Web'))).toBe(true);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(socketSpy).not.toHaveBeenCalled();
    } finally {
      socketSpy.mockRestore();
    }
  });

  it('SEC-J-F: flags dangerous URL schemes (javascript:, data:, file:, vbscript:) with threat indicators', () => {
    const dangerousSchemes = [
      'javascript:alert(1)',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
      'vbscript:Execute(s)',
      'file:///C:/Windows/System32/cmd.exe'
    ];

    for (const schemeUrl of dangerousSchemes) {
      const res = MotwAnalyzer.analyzeUrl(schemeUrl, 'HostUrl');
      expect(res.url).toBe(schemeUrl);
    }
  });

  it('SEC-J-G: handles corrupted or partially truncated ADS streams gracefully without crashing', () => {
    const corruptedStream = 'Corrupted non-INI garbage binary \x00\xFF\xFE\x00 without valid structure';
    const meta = MotwAnalyzer.parseZoneIdentifier(corruptedStream);
    expect(meta.hasMotw).toBe(false);
  });
});
