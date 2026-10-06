import * as fs from 'fs';
import * as path from 'path';
import { URLAnalyzer, ThreatIntel } from '@private-protection/core';
import {
  MotwMetadata,
  MotwAnalysisResult,
  MotwUrlAnalysis,
  MotwZoneName
} from '../types/desktop.types';

/**
 * Mark-of-the-Web (MOTW) NTFS Alternate Data Stream (:Zone.Identifier) Analyzer (Phase J).
 *
 * Provides safe, bounded, local-first inspection of download origin metadata extracted from
 * NTFS :Zone.Identifier streams (and cross-platform .zone.identifier companion test fixtures).
 * Correlates download HostUrl and ReferrerUrl with canonical URLAnalyzer and ThreatIntel.
 */
export class MotwAnalyzer {
  public static readonly MAX_ADS_READ_BYTES = 4096; // 4 KB bounded input limit
  public static readonly MAX_URL_STRING_LENGTH = 2048; // RFC-compliant URL bound
  private static readonly RTLO_BIDI_PATTERN = /[\u202A-\u202E\u2066-\u2069]/g;
  private static readonly CONTROL_CHARS_PATTERN = /[\x00-\x1F\x7F]/g;

  private static urlAnalyzerInstance: URLAnalyzer | null = null;

  private static getUrlAnalyzer(): URLAnalyzer {
    if (!this.urlAnalyzerInstance) {
      this.urlAnalyzerInstance = new URLAnalyzer();
    }
    return this.urlAnalyzerInstance;
  }

  /**
   * Reads raw :Zone.Identifier ADS content safely with a strict 4 KB bound.
   * Supports native Windows NTFS stream paths and cross-platform test companion files.
   */
  public static readRawAds(filePath: string): string | null {
    if (!filePath || typeof filePath !== 'string' || filePath.includes('\0')) {
      return null;
    }

    const canonical = path.resolve(filePath);

    // 1. On Windows, attempt native NTFS stream reading
    if (process.platform === 'win32') {
      const streamPath = `${canonical}:Zone.Identifier`;
      try {
        if (fs.existsSync(streamPath)) {
          const fd = fs.openSync(streamPath, 'r');
          try {
            const buf = Buffer.allocUnsafe(this.MAX_ADS_READ_BYTES);
            const bytesRead = fs.readSync(fd, buf, 0, this.MAX_ADS_READ_BYTES, 0);
            if (bytesRead > 0) {
              return buf.subarray(0, bytesRead).toString('utf8');
            }
          } finally {
            fs.closeSync(fd);
          }
        }
      } catch {
        // Fallback to cross-platform companion check below
      }
    }

    // 2. Check companion fixture files (cross-platform test support)
    const companionCandidates = [
      `${canonical}.zone.identifier`,
      `${canonical}.Zone.Identifier`,
      path.join(path.dirname(canonical), `.${path.basename(canonical)}.zone.identifier`)
    ];

    for (const companionPath of companionCandidates) {
      try {
        if (fs.existsSync(companionPath)) {
          const fd = fs.openSync(companionPath, 'r');
          try {
            const buf = Buffer.allocUnsafe(this.MAX_ADS_READ_BYTES);
            const bytesRead = fs.readSync(fd, buf, 0, this.MAX_ADS_READ_BYTES, 0);
            if (bytesRead > 0) {
              return buf.subarray(0, bytesRead).toString('utf8');
            }
          } finally {
            fs.closeSync(fd);
          }
        }
      } catch {
        // Ignore read errors safely
      }
    }

    return null;
  }

  /**
   * Sanitizes untrusted ADS string values, stripping control chars, RTLO bidi overrides,
   * and clamping string length.
   */
  public static sanitizeAdsValue(val: string): string {
    if (!val || typeof val !== 'string') return '';
    return val
      .replace(this.RTLO_BIDI_PATTERN, '')
      .replace(this.CONTROL_CHARS_PATTERN, '')
      .trim()
      .slice(0, this.MAX_URL_STRING_LENGTH);
  }

  /**
   * Parses INI-style Zone.Identifier stream content into structured MotwMetadata.
   */
  public static parseZoneIdentifier(rawContent: string | null): MotwMetadata {
    if (!rawContent || typeof rawContent !== 'string' || !rawContent.trim()) {
      return { hasMotw: false };
    }

    // Bound input length
    const bounded = rawContent.slice(0, this.MAX_ADS_READ_BYTES);
    const lines = bounded.split(/\r?\n/);

    let zoneIdRaw: string | undefined;
    let hostUrlRaw: string | undefined;
    let referrerUrlRaw: string | undefined;
    let hostIpRaw: string | undefined;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith(';') || line.startsWith('#')) continue;

      if (line.startsWith('[') && line.endsWith(']')) {
        continue;
      }

      // Handle properties (either inside [ZoneTransfer] or global if no section header present)
      const eqIdx = line.indexOf('=');
      if (eqIdx <= 0) continue;

      const key = line.slice(0, eqIdx).trim().toLowerCase();
      const val = line.slice(eqIdx + 1).trim();

      if (key === 'zoneid' && zoneIdRaw === undefined) {
        zoneIdRaw = val;
      } else if (key === 'hosturl' && hostUrlRaw === undefined) {
        hostUrlRaw = val;
      } else if (key === 'referrerurl' && referrerUrlRaw === undefined) {
        referrerUrlRaw = val;
      } else if (key === 'hostipaddress' && hostIpRaw === undefined) {
        hostIpRaw = val;
      }
    }

    if (zoneIdRaw === undefined && hostUrlRaw === undefined && referrerUrlRaw === undefined) {
      return { hasMotw: false, rawAdsContent: bounded };
    }

    let parsedZoneId: number | undefined;
    let zoneName: MotwZoneName = 'UNKNOWN';

    if (zoneIdRaw !== undefined) {
      const num = parseInt(zoneIdRaw, 10);
      if (!isNaN(num)) {
        parsedZoneId = num;
        switch (num) {
          case 0:
            zoneName = 'LOCAL_MACHINE';
            break;
          case 1:
            zoneName = 'INTRANET';
            break;
          case 2:
            zoneName = 'TRUSTED';
            break;
          case 3:
            zoneName = 'INTERNET';
            break;
          case 4:
            zoneName = 'RESTRICTED';
            break;
          default:
            zoneName = 'UNKNOWN';
            break;
        }
      }
    }

    const hostUrl = hostUrlRaw ? this.sanitizeAdsValue(hostUrlRaw) : undefined;
    const referrerUrl = referrerUrlRaw ? this.sanitizeAdsValue(referrerUrlRaw) : undefined;
    const hostIpAddress = hostIpRaw ? this.sanitizeAdsValue(hostIpRaw) : undefined;

    return {
      hasMotw: true,
      zoneId: parsedZoneId,
      zoneName,
      ...(hostUrl ? { hostUrl } : {}),
      ...(referrerUrl ? { referrerUrl } : {}),
      ...(hostIpAddress ? { hostIpAddress } : {}),
      rawAdsContent: bounded
    };
  }

  /**
   * Evaluates an individual URL extracted from MOTW metadata using canonical Core analyzers.
   */
  public static analyzeUrl(rawUrl: string, source: 'HostUrl' | 'ReferrerUrl'): MotwUrlAnalysis {
    const sanitized = this.sanitizeAdsValue(rawUrl);
    if (!sanitized) {
      return {
        url: '',
        riskScore: 0,
        indicators: [],
        isMalicious: false
      };
    }

    const indicators: string[] = [];
    let riskScore = 0;
    let threatName: string | undefined;
    let host = '';

    try {
      const parsed = new URL(
        sanitized.startsWith('http://') || sanitized.startsWith('https://')
          ? sanitized
          : `http://${sanitized}`
      );
      host = parsed.hostname;
    } catch {
      host = sanitized.split(/[/?#]/)[0];
    }

    // 1. Check ThreatIntel local hash and domain/URL databases
    const intel = ThreatIntel.getSharedInstance();
    const intelResult = intel.checkUrl(sanitized);
    if (intelResult.isMalicious) {
      riskScore = 100;
      threatName =
        intelResult.threatName && intelResult.threatName !== 'KNOWN_MALICIOUS_INDICATOR'
          ? intelResult.threatName
          : intelResult.threatType === 'IP'
          ? 'RAW_IP_DOWNLOAD_ORIGIN'
          : 'KNOWN_MALICIOUS_DOWNLOAD_ORIGIN';
      indicators.push(
        `${source} matches local threat intelligence blocklist (${intelResult.threatType || 'URL'})`
      );
      return {
        url: sanitized,
        riskScore,
        indicators,
        isMalicious: true,
        threatName,
        host
      };
    }

    // 2. Check Core URLAnalyzer for heuristics, typosquatting, IDN/punycode, raw IPs
    const urlAnalyzer = this.getUrlAnalyzer();
    const analysis = urlAnalyzer.analyze(sanitized);

    if (analysis && analysis.indicators && analysis.indicators.length > 0) {
      for (const ind of analysis.indicators) {
        indicators.push(`${source}: ${ind}`);
      }
    }

    // Map URLAnalyzer features to risk score
    if (analysis.riskScore > 0) {
      riskScore = Math.max(riskScore, analysis.riskScore);
    }

    // Tokenize hostname for sub-token brand typosquatting & spoofing
    const topBrands = [
      'paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon',
      'netflix', 'chase', 'bankofamerica', 'wellsfargo', 'coinbase',
      'binance', 'instagram', 'twitter', 'telegram', 'whatsapp'
    ];

    const hostTokens = host.toLowerCase().split(/[.\-_]/).filter(Boolean);
    let detectedBrandSpoof: string | undefined;

    for (const token of hostTokens) {
      for (const brand of topBrands) {
        if (token === brand && !host.endsWith(`${brand}.com`) && !host.endsWith(`${brand}.org`)) {
          detectedBrandSpoof = brand;
          break;
        }
        // Check typosquatting substitutions (e.g. paypa1 -> paypal)
        const normalizedToken = token
          .replace(/1/g, 'l')
          .replace(/0/g, 'o')
          .replace(/5/g, 's')
          .replace(/@/g, 'a')
          .replace(/vv/g, 'w');
        if (normalizedToken === brand || (token.length >= 4 && Math.abs(token.length - brand.length) <= 2 && this.levenshtein(token, brand) <= 2 && token !== brand)) {
          detectedBrandSpoof = brand;
          break;
        }
      }
      if (detectedBrandSpoof) break;
    }

    // Punycode homograph or Brand typosquatting check
    if (analysis.punycodeDecodedHost && (analysis.punycodeDecodedHost.startsWith('xn--') || host.includes('xn--'))) {
      riskScore = Math.max(riskScore, 80);
      threatName = 'HOMOGRAPH_PUNYCODE_DOWNLOAD_ORIGIN';
      indicators.push(`${source}: Punycode IDN homograph domain detected (${host})`);
    } else if (detectedBrandSpoof || (analysis.brandSpoofDistance && analysis.brandSpoofDistance.distance <= 2)) {
      riskScore = Math.max(riskScore, 85);
      threatName = 'TYPOSQUATTED_BRAND_DOWNLOAD_ORIGIN';
      indicators.push(`${source}: Brand spoofing/typosquatting detected (${detectedBrandSpoof || analysis.brandSpoofDistance?.brand})`);
    } else if (analysis.ipBasedHost || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host)) {
      riskScore = Math.max(riskScore, 65);
      threatName = 'RAW_IP_DOWNLOAD_ORIGIN';
    } else if (analysis.suspiciousTld) {
      riskScore = Math.max(riskScore, 45);
      threatName = 'SUSPICIOUS_TLD_DOWNLOAD_ORIGIN';
    }

    const isMalicious = riskScore >= 70;

    return {
      url: sanitized,
      riskScore,
      indicators,
      isMalicious,
      ...(threatName ? { threatName } : {}),
      host
    };
  }

  private static levenshtein(a: string, b: string): number {
    const m = a.length;
    const n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + cost
        );
      }
    }
    return dp[m][n];
  }

  /**
   * Comprehensive MOTW inspection of a file path.
   * Extracts NTFS ADS stream, parses ZoneId/HostUrl/ReferrerUrl, runs local URL threat
   * analysis, and computes the origin risk contribution (+35 to +85).
   */
  public static analyzeFile(filePath: string): MotwAnalysisResult {
    const rawAds = this.readRawAds(filePath);
    const metadata = this.parseZoneIdentifier(rawAds);

    if (!metadata.hasMotw) {
      return {
        hasMotw: false,
        metadata: { hasMotw: false },
        originRiskScore: 0,
        originSeverity: 'safe',
        isOriginMalicious: false,
        threatIndicators: [],
        evidenceFactors: []
      };
    }

    const threatIndicators: string[] = [];
    const evidenceFactors: string[] = [];
    let originRiskScore = 0;

    // Record Zone ID evidence
    const zoneName = metadata.zoneName || 'UNKNOWN';
    const zoneId = metadata.zoneId ?? -1;
    evidenceFactors.push(`Mark-of-the-Web (Zone.Identifier) detected: Zone ${zoneId} (${zoneName})`);

    let hostAnalysis: MotwUrlAnalysis | undefined;
    let referrerAnalysis: MotwUrlAnalysis | undefined;

    // Analyze HostUrl
    if (metadata.hostUrl) {
      hostAnalysis = this.analyzeUrl(metadata.hostUrl, 'HostUrl');
      if (hostAnalysis.indicators.length > 0) {
        threatIndicators.push(...hostAnalysis.indicators);
      }
      if (hostAnalysis.riskScore > 0) {
        originRiskScore = Math.max(originRiskScore, hostAnalysis.riskScore);
      }
      evidenceFactors.push(`Download HostUrl: ${metadata.hostUrl}`);
    }

    // Analyze ReferrerUrl
    if (metadata.referrerUrl) {
      referrerAnalysis = this.analyzeUrl(metadata.referrerUrl, 'ReferrerUrl');
      if (referrerAnalysis.indicators.length > 0) {
        threatIndicators.push(...referrerAnalysis.indicators);
      }
      if (referrerAnalysis.riskScore > 0) {
        originRiskScore = Math.max(originRiskScore, Math.floor(referrerAnalysis.riskScore * 0.9));
      }
      evidenceFactors.push(`Download ReferrerUrl: ${metadata.referrerUrl}`);
    }

    // Elevated risk for Zone 4 (Restricted Sites)
    if (zoneId === 4) {
      originRiskScore = Math.max(originRiskScore, 60);
      threatIndicators.push('File originates from Windows Restricted Sites Security Zone (ZoneId=4)');
    }

    // Map origin risk to severity
    let originSeverity: 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical' = 'safe';
    if (originRiskScore >= 85) {
      originSeverity = 'critical';
    } else if (originRiskScore >= 70) {
      originSeverity = 'dangerous';
    } else if (originRiskScore >= 40) {
      originSeverity = 'suspicious';
    } else if (originRiskScore >= 15) {
      originSeverity = 'low';
    }

    const isOriginMalicious = originRiskScore >= 70;

    if (threatIndicators.length > 0) {
      evidenceFactors.push(...threatIndicators);
    }

    return {
      hasMotw: true,
      metadata,
      originRiskScore,
      originSeverity,
      isOriginMalicious,
      threatIndicators,
      evidenceFactors,
      ...(hostAnalysis ? { hostUrlAnalysis: hostAnalysis } : {}),
      ...(referrerAnalysis ? { referrerUrlAnalysis: referrerAnalysis } : {})
    };
  }

  /**
   * Helper to format a standard INI Zone.Identifier stream string for tests and restoration.
   */
  public static createZoneIdentifierAds(input: {
    zoneId: number;
    hostUrl?: string;
    referrerUrl?: string;
    hostIpAddress?: string;
  }): string {
    const lines = ['[ZoneTransfer]', `ZoneId=${input.zoneId}`];
    if (input.hostUrl) {
      lines.push(`HostUrl=${input.hostUrl}`);
    }
    if (input.referrerUrl) {
      lines.push(`ReferrerUrl=${input.referrerUrl}`);
    }
    if (input.hostIpAddress) {
      lines.push(`HostIpAddress=${input.hostIpAddress}`);
    }
    return lines.join('\r\n') + '\r\n';
  }
}
