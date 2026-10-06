import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { CoreFileAnalyzer, CleanFileCache, ThreatIntel, Verdict, EngineVerdict } from '@private-protection/core';
import { FileAnalysisResult, MotwAnalysisResult, EmailAnalysisResult } from '../types/desktop.types';
import { MotwAnalyzer } from './motw-analyzer';
import { EmailMimeParser } from './email-mime-parser';

export interface DesktopFileAnalyzeOptions {
  readonly entropyDetectionEnabled?: boolean;
  readonly inspectMotw?: boolean;
  readonly inspectEmail?: boolean;
}

/**
 * Desktop filesystem adapter around the canonical @private-protection/core CoreFileAnalyzer (GAP-08).
 * Handles Node.js disk I/O (safe header slice read + SHA-256 streaming) and delegates all
 * security analysis, entropy math, double-extension detection, and verdict scoring to Core.
 */
export class FileAnalyzer {
  private static readonly MAX_HEADER_READ_BYTES = 64 * 1024; // 64 KB

  /**
   * Computes the Shannon entropy of a byte buffer via @private-protection/core.
   */
  public static calculateEntropy(buffer: Buffer): number {
    return CoreFileAnalyzer.calculateEntropy(buffer);
  }

  /**
   * Computes the SHA-256 hash of a file safely via streaming I/O.
   */
  public static async computeSha256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', (err) => reject(err));
    });
  }

  /**
   * Inspects magic header bytes from file buffer via @private-protection/core.
   */
  public static detectMagicHeader(buffer: Buffer): string | null {
    return CoreFileAnalyzer.detectMagicHeader(buffer);
  }

  /**
   * Detects double-extension deception via @private-protection/core.
   */
  public static checkDeceptiveExtension(fileName: string): {
    isDeceptive: boolean;
    fakeExt?: string;
    realExt?: string;
    hasRtloSpoofing?: boolean;
  } {
    return CoreFileAnalyzer.checkDeceptiveExtension(fileName);
  }

  /**
   * Performs complete file analysis without executing the file, delegating security
   * scoring and verdict calculation to @private-protection/core.
   */
  public static async analyzeFile(
    filePath: string,
    options?: DesktopFileAnalyzeOptions
  ): Promise<FileAnalysisResult> {
    if (!filePath || typeof filePath !== 'string' || filePath.includes('\0')) {
      throw new Error('INVALID_FILE_PATH: File path must be a valid non-empty string.');
    }

    const fileName = path.basename(filePath);
    const fd = await fs.promises.open(filePath, 'r');
    let stat: fs.Stats;
    let actualHeaderBuffer: Buffer = Buffer.alloc(0);

    try {
      stat = await fd.stat();
      if (!stat.isFile()) {
        throw new Error('NOT_A_REGULAR_FILE: Target path is not a regular file.');
      }

      // Stage 0: CleanFileCache lookup (< 0.08 ms fast-path)
      const cached = CleanFileCache.getSharedInstance().get(filePath, stat.size, stat.mtimeMs);
      if (cached) {
        return {
          filePath,
          fileName,
          fileSize: stat.size,
          sha256: cached.sha256,
          entropy: 0,
          magicHeader: null,
          isExecutable: false,
          isDeceptiveExtension: false,
          riskScore: cached.riskScore,
          severity: 'safe',
          verdict: 'ALLOW',
          threatName: 'CLEAN_CACHED_FILE',
          evidenceFactors: ['Clean file verified via Stage 0 CleanFileCache fast-path (<0.08ms)'],
          analysisStatus: 'COMPLETED',
          disposition: 'SAFE'
        };
      }

      const bytesToRead = Math.min(stat.size, this.MAX_HEADER_READ_BYTES);
      if (bytesToRead > 0) {
        const rawHeaderBuffer = Buffer.allocUnsafe(bytesToRead);
        let totalBytesRead = 0;
        while (totalBytesRead < bytesToRead) {
          const { bytesRead } = await fd.read(
            rawHeaderBuffer,
            totalBytesRead,
            bytesToRead - totalBytesRead,
            totalBytesRead
          );
          if (bytesRead <= 0) {
            break;
          }
          totalBytesRead += bytesRead;
        }
        actualHeaderBuffer = rawHeaderBuffer.subarray(0, totalBytesRead);
      }
    } finally {
      await fd.close();
    }

    let sha256 = '';
    if (actualHeaderBuffer.length === stat.size) {
      sha256 = crypto.createHash('sha256').update(actualHeaderBuffer).digest('hex');
    } else {
      try {
        sha256 = await this.computeSha256(filePath);
      } catch {
        sha256 = crypto.createHash('sha256').update(actualHeaderBuffer).digest('hex');
      }
    }

    // Check ThreatIntel allowlist before running heuristic / structural parsers (Restore & Trust grant)
    const intel = ThreatIntel.getSharedInstance();
    if (sha256 && intel.isHashAllowed(sha256)) {
      CleanFileCache.getSharedInstance().set(
        filePath,
        stat.size,
        stat.mtimeMs,
        sha256,
        {
          verdict: Verdict.ALLOW,
          engineVerdict: EngineVerdict.ALLOW,
          riskScore: 0
        }
      );
      return {
        filePath,
        fileName,
        fileSize: stat.size,
        sha256,
        entropy: 0,
        magicHeader: null,
        isExecutable: false,
        isDeceptiveExtension: false,
        riskScore: 0,
        severity: 'safe',
        verdict: 'ALLOW',
        threatName: 'TRUSTED_ALLOWLISTED_FILE',
        evidenceFactors: ['File SHA-256 matches trusted local allowlist (Restore & Trust grant)'],
        analysisStatus: 'COMPLETED',
        disposition: 'SAFE'
      };
    }

    const coreOut = CoreFileAnalyzer.analyzeBuffer(
      {
        filePath,
        fileName,
        fileSize: stat.size,
        headerBytes: actualHeaderBuffer
      },
      {
        sha256,
        entropyDetectionEnabled: options?.entropyDetectionEnabled ?? true,
        platformProfile: 'desktop'
      }
    );

    // Phase J: Mark-of-the-Web (Zone.Identifier) & Download Origin Security Inspection
    let motwResult: MotwAnalysisResult | undefined;
    let finalRiskScore = coreOut.riskScore;
    let finalSeverity = coreOut.desktopSeverity;
    let finalVerdict = coreOut.desktopVerdict;
    let finalThreatName = coreOut.threatName;
    const finalEvidenceFactors = [...coreOut.evidenceFactors];

    if (options?.inspectMotw !== false) {
      motwResult = MotwAnalyzer.analyzeFile(filePath);
      if (motwResult.hasMotw) {
        finalEvidenceFactors.push(...motwResult.evidenceFactors);

        if (motwResult.originRiskScore > 0) {
          // Check whether the file has binary/executable characteristics
          const isExec =
            coreOut.isExecutable ||
            coreOut.isDeceptiveExtension ||
            CoreFileAnalyzer.EXECUTABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase()) ||
            coreOut.magicHeader === 'PE/MZ_EXECUTABLE' ||
            coreOut.magicHeader === 'ELF_EXECUTABLE' ||
            coreOut.magicHeader === 'MACHO_EXECUTABLE' ||
            coreOut.magicHeader === 'SCRIPT_EXECUTABLE';

          if (isExec) {
            // High correlation: Downloaded executable from suspicious/malicious origin (+35 to +85)
            finalRiskScore = Math.min(
              100,
              Math.max(coreOut.riskScore + motwResult.originRiskScore, motwResult.originRiskScore)
            );
          } else {
            // Downloaded document/other file from suspicious origin
            finalRiskScore = Math.min(
              100,
              coreOut.riskScore + Math.floor(motwResult.originRiskScore * 0.7)
            );
          }

          if (finalRiskScore >= 90 || motwResult.originRiskScore >= 85) {
            finalVerdict = 'BLOCK';
            finalSeverity = 'critical';
            if (finalThreatName === 'BENIGN_FILE' || finalThreatName === 'UNKNOWN') {
              finalThreatName = 'MALICIOUS_DOWNLOAD_ORIGIN';
            }
          } else if (finalRiskScore >= 70 || motwResult.originRiskScore >= 70) {
            if (finalVerdict !== 'BLOCK') {
              finalVerdict = 'WARN';
              finalSeverity = 'dangerous';
            }
            if (finalThreatName === 'BENIGN_FILE' || finalThreatName === 'UNKNOWN') {
              finalThreatName = 'SUSPICIOUS_DOWNLOAD_ORIGIN';
            }
          } else if (finalRiskScore >= 40) {
            if (finalVerdict === 'ALLOW') {
              finalVerdict = 'WARN';
              finalSeverity = 'suspicious';
            }
          }
        }
      }
    }

    // Stage 4: Practical Email (.eml / .msg) Threat Inspection (Phase K)
    let emailResult: EmailAnalysisResult | undefined;
    const shouldInspectEmail = options?.inspectEmail !== false;
    const fileExt = path.extname(filePath).toLowerCase();

    if (shouldInspectEmail && (fileExt === '.eml' || fileExt === '.msg')) {
      emailResult = await EmailMimeParser.analyzeEmailFile(filePath);
      if (emailResult.hasEmailMetadata) {
        if (emailResult.evidenceFactors.length > 0) {
          finalEvidenceFactors.push(...emailResult.evidenceFactors);
        }

        if (emailResult.emailRiskScore > 0) {
          finalRiskScore = Math.min(100, Math.max(finalRiskScore, emailResult.emailRiskScore));

          if (finalRiskScore >= 85 || emailResult.emailRiskScore >= 85) {
            finalVerdict = 'BLOCK';
            finalSeverity = 'critical';
            if (finalThreatName === 'BENIGN_FILE' || finalThreatName === 'UNKNOWN') {
              finalThreatName = emailResult.threatIndicators[0] || 'PHISHING_EMAIL_THREAT';
            }
          } else if (finalRiskScore >= 70 || emailResult.emailRiskScore >= 70) {
            if (finalVerdict !== 'BLOCK') {
              finalVerdict = 'WARN';
              finalSeverity = 'dangerous';
            }
            if (finalThreatName === 'BENIGN_FILE' || finalThreatName === 'UNKNOWN') {
              finalThreatName = 'SUSPICIOUS_EMAIL_THREAT';
            }
          } else if (finalRiskScore >= 40) {
            if (finalVerdict === 'ALLOW') {
              finalVerdict = 'WARN';
              finalSeverity = 'suspicious';
            }
          }
        }
      }
    }

    if (finalVerdict === 'ALLOW' && finalRiskScore === 0) {
      CleanFileCache.getSharedInstance().set(
        filePath,
        stat.size,
        stat.mtimeMs,
        coreOut.sha256 || sha256,
        {
          verdict: coreOut.verdict,
          engineVerdict: coreOut.engineVerdict,
          riskScore: coreOut.riskScore
        }
      );
    }

    return {
      filePath,
      fileName: coreOut.fileName,
      fileSize: coreOut.fileSize,
      sha256: coreOut.sha256,
      entropy: coreOut.entropy,
      magicHeader: coreOut.magicHeader,
      isExecutable: coreOut.isExecutable,
      isDeceptiveExtension: coreOut.isDeceptiveExtension,
      riskScore: finalRiskScore,
      severity: finalSeverity,
      verdict: finalVerdict,
      threatName: finalThreatName,
      evidenceFactors: finalEvidenceFactors,
      analysisStatus: coreOut.analysisStatus,
      disposition: coreOut.disposition,
      ...(motwResult ? { motw: motwResult } : {}),
      ...(emailResult ? { email: emailResult } : {}),
      ...(coreOut.errorReason ? { errorReason: coreOut.errorReason } : {})
    };
  }

  /**
   * Fail-closed wrapper around analyzeFile that never throws and never converts file
   * access or analysis errors into SAFE/ALLOW (Step 7).
   */
  public static async analyzeFileSafe(
    filePath: string,
    options?: DesktopFileAnalyzeOptions
  ): Promise<FileAnalysisResult> {
    try {
      return await this.analyzeFile(filePath, options);
    } catch (err: any) {
      const safePath = typeof filePath === 'string' ? filePath : 'unknown';
      const fileName = typeof filePath === 'string' && filePath ? path.basename(filePath) : 'unknown';
      const deceptive = this.checkDeceptiveExtension(fileName);
      const errorCode = err?.code || err?.message || 'ANALYSIS_ERROR';
      const factors = [
        `File analysis failed (${errorCode}); fail-closed warning applied.`
      ];
      if (deceptive.isDeceptive) {
        factors.push(
          `Deceptive extension detected on unreadable file: disguised as '${deceptive.fakeExt}', actual '${deceptive.realExt}'`
        );
      }
      return {
        filePath: safePath,
        fileName,
        fileSize: 0,
        sha256: '',
        entropy: 0,
        magicHeader: null,
        isExecutable: deceptive.isDeceptive,
        isDeceptiveExtension: deceptive.isDeceptive,
        riskScore: deceptive.isDeceptive ? 65 : 50,
        severity: deceptive.isDeceptive ? 'dangerous' : 'suspicious',
        verdict: deceptive.isDeceptive ? 'BLOCK' : 'WARN',
        threatName: deceptive.isDeceptive ? 'LOCKED_DECEPTIVE_EXECUTABLE' : 'ANALYSIS_FAILED',
        evidenceFactors: factors,
        analysisStatus: 'ANALYSIS_FAILED',
        disposition: 'ANALYSIS_FAILED',
        errorReason: String(errorCode)
      };
    }
  }
}
