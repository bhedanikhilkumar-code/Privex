import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { MotwAnalyzer } from '../../core/motw-analyzer';
import { ThreatIntel } from '@private-protection/core';

describe('MotwAnalyzer (Phase J — Mark-of-the-Web & Download Origin Security)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'motw-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best-effort
    }
  });

  describe('INI Parsing & Sanitization', () => {
    it('correctly parses standard Windows [ZoneTransfer] metadata', () => {
      const adsContent = [
        '[ZoneTransfer]',
        'ZoneId=3',
        'HostUrl=https://example.com/downloads/setup.exe',
        'ReferrerUrl=https://example.com/products',
        'HostIpAddress=192.0.2.1'
      ].join('\r\n');

      const meta = MotwAnalyzer.parseZoneIdentifier(adsContent);
      expect(meta.hasMotw).toBe(true);
      expect(meta.zoneId).toBe(3);
      expect(meta.zoneName).toBe('INTERNET');
      expect(meta.hostUrl).toBe('https://example.com/downloads/setup.exe');
      expect(meta.referrerUrl).toBe('https://example.com/products');
      expect(meta.hostIpAddress).toBe('192.0.2.1');
    });

    it('maps all Windows Zone IDs (0..4) accurately to canonical zone names', () => {
      const zoneExpectations = [
        { id: 0, name: 'LOCAL_MACHINE' },
        { id: 1, name: 'INTRANET' },
        { id: 2, name: 'TRUSTED' },
        { id: 3, name: 'INTERNET' },
        { id: 4, name: 'RESTRICTED' },
        { id: 99, name: 'UNKNOWN' }
      ];

      for (const { id, name } of zoneExpectations) {
        const meta = MotwAnalyzer.parseZoneIdentifier(`[ZoneTransfer]\r\nZoneId=${id}`);
        expect(meta.zoneId).toBe(id);
        expect(meta.zoneName).toBe(name);
      }
    });

    it('handles empty, whitespace, and comment-only ADS content safely', () => {
      expect(MotwAnalyzer.parseZoneIdentifier(null).hasMotw).toBe(false);
      expect(MotwAnalyzer.parseZoneIdentifier('').hasMotw).toBe(false);
      expect(MotwAnalyzer.parseZoneIdentifier('   \r\n\t  ').hasMotw).toBe(false);
      expect(MotwAnalyzer.parseZoneIdentifier('; Comment only\r\n# Another comment').hasMotw).toBe(false);
    });

    it('scrubs Unicode RTLO bidi override characters and control characters from URLs', () => {
      const raw = `[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/test\u202Efdp.exe\x00\x07`;
      const meta = MotwAnalyzer.parseZoneIdentifier(raw);
      expect(meta.hasMotw).toBe(true);
      expect(meta.hostUrl).toBe('https://example.com/testfdp.exe');
      expect(meta.hostUrl).not.toContain('\u202E');
      expect(meta.hostUrl).not.toContain('\x00');
    });

    it('handles duplicate keys deterministically (first key wins)', () => {
      const raw = [
        '[ZoneTransfer]',
        'ZoneId=3',
        'HostUrl=https://primary.com/file.exe',
        'ZoneId=4',
        'HostUrl=https://secondary.com/file.exe'
      ].join('\r\n');

      const meta = MotwAnalyzer.parseZoneIdentifier(raw);
      expect(meta.zoneId).toBe(3);
      expect(meta.hostUrl).toBe('https://primary.com/file.exe');
    });

    it('strictly bounds input size and parses safely when given oversized ADS streams', () => {
      const padding = 'X'.repeat(10000);
      const raw = `[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/payload.exe\r\n${padding}`;
      const meta = MotwAnalyzer.parseZoneIdentifier(raw);
      expect(meta.hasMotw).toBe(true);
      expect(meta.zoneId).toBe(3);
      expect(meta.hostUrl).toBe('https://example.com/payload.exe');
      expect(meta.rawAdsContent?.length).toBeLessThanOrEqual(MotwAnalyzer.MAX_ADS_READ_BYTES);
    });
  });

  describe('Download Origin URL Threat Analysis', () => {
    it('returns zero origin risk for clean legitimate downloads', () => {
      const result = MotwAnalyzer.analyzeUrl('https://github.com/release/v1.0/tool.zip', 'HostUrl');
      expect(result.riskScore).toBe(0);
      expect(result.isMalicious).toBe(false);
      expect(result.indicators.length).toBe(0);
    });

    it('detects brand typosquatting in download HostUrl and elevates score', () => {
      const result = MotwAnalyzer.analyzeUrl('https://paypa1-security-update.com/patch.exe', 'HostUrl');
      expect(result.riskScore).toBeGreaterThanOrEqual(70);
      expect(result.isMalicious).toBe(true);
      expect(result.threatName).toBe('TYPOSQUATTED_BRAND_DOWNLOAD_ORIGIN');
    });

    it('detects punycode homograph domain in download HostUrl', () => {
      const result = MotwAnalyzer.analyzeUrl('http://xn--gogle-pra.com/updater.exe', 'HostUrl');
      expect(result.riskScore).toBeGreaterThanOrEqual(70);
      expect(result.isMalicious).toBe(true);
      expect(result.threatName).toBe('HOMOGRAPH_PUNYCODE_DOWNLOAD_ORIGIN');
    });

    it('detects raw IP host in download HostUrl and assigns suspicious rating', () => {
      const result = MotwAnalyzer.analyzeUrl('http://198.51.100.23:8080/payload.exe', 'HostUrl');
      expect(result.riskScore).toBeGreaterThanOrEqual(40);
      expect(result.threatName).toBe('RAW_IP_DOWNLOAD_ORIGIN');
    });

    it('detects ThreatIntel known-bad download origins with 100 risk score', () => {
      const badUrl = 'https://malicious-c2-distribution.evil/trojan.exe';
      ThreatIntel.getSharedInstance().addMaliciousUrl(badUrl, {
        category: 'MALWARE'
      });

      const result = MotwAnalyzer.analyzeUrl(badUrl, 'HostUrl');
      expect(result.riskScore).toBe(100);
      expect(result.isMalicious).toBe(true);
    });
  });

  describe('File-Level MOTW Analysis (`analyzeFile`)', () => {
    it('returns hasMotw: false when file has no ADS or companion file', () => {
      const filePath = path.join(tempDir, 'plain-file.txt');
      fs.writeFileSync(filePath, 'Hello world');

      const result = MotwAnalyzer.analyzeFile(filePath);
      expect(result.hasMotw).toBe(false);
      expect(result.originRiskScore).toBe(0);
      expect(result.originSeverity).toBe('safe');
    });

    it('reads companion .zone.identifier fixture and detects malicious phishing origin', () => {
      const filePath = path.join(tempDir, 'invoice.pdf.exe');
      fs.writeFileSync(filePath, 'MZ_DUMMY_BINARY_DATA');

      const companionPath = `${filePath}.zone.identifier`;
      const adsContent = MotwAnalyzer.createZoneIdentifierAds({
        zoneId: 3,
        hostUrl: 'https://chase-bank-verify-account.top/invoice.pdf.exe',
        referrerUrl: 'https://phishing-portal.com/login'
      });
      fs.writeFileSync(companionPath, adsContent);

      const result = MotwAnalyzer.analyzeFile(filePath);
      expect(result.hasMotw).toBe(true);
      expect(result.metadata.zoneId).toBe(3);
      expect(result.metadata.zoneName).toBe('INTERNET');
      expect(result.originRiskScore).toBeGreaterThanOrEqual(70);
      expect(result.isOriginMalicious).toBe(true);
      expect(result.evidenceFactors.length).toBeGreaterThan(0);
    });

    it('preserves clean rating when file originates from clean HTTPS domain (ZoneId=3)', () => {
      const filePath = path.join(tempDir, 'developer-tool.exe');
      fs.writeFileSync(filePath, 'MZ_DUMMY_BINARY_DATA');

      const companionPath = `${filePath}.zone.identifier`;
      const adsContent = MotwAnalyzer.createZoneIdentifierAds({
        zoneId: 3,
        hostUrl: 'https://nodejs.org/dist/v20.0.0/node-v20.0.0-x64.msi',
        referrerUrl: 'https://nodejs.org/en/download'
      });
      fs.writeFileSync(companionPath, adsContent);

      const result = MotwAnalyzer.analyzeFile(filePath);
      expect(result.hasMotw).toBe(true);
      expect(result.originRiskScore).toBe(0);
      expect(result.originSeverity).toBe('safe');
      expect(result.isOriginMalicious).toBe(false);
    });

    it('elevates risk for files marked with ZoneId=4 (Restricted Sites)', () => {
      const filePath = path.join(tempDir, 'restricted.bin');
      fs.writeFileSync(filePath, 'BINARY_CONTENT');

      const companionPath = `${filePath}.zone.identifier`;
      const adsContent = MotwAnalyzer.createZoneIdentifierAds({
        zoneId: 4
      });
      fs.writeFileSync(companionPath, adsContent);

      const result = MotwAnalyzer.analyzeFile(filePath);
      expect(result.hasMotw).toBe(true);
      expect(result.metadata.zoneId).toBe(4);
      expect(result.originRiskScore).toBeGreaterThanOrEqual(60);
      expect(result.originSeverity).toBe('suspicious');
    });
  });
});
