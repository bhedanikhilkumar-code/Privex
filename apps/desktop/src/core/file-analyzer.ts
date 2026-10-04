import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { CoreFileAnalyzer } from '@private-protection/core';
import { FileAnalysisResult } from '../types/desktop.types';

export interface DesktopFileAnalyzeOptions {
  readonly entropyDetectionEnabled?: boolean;
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
    const stat = await fs.promises.stat(filePath);
    const fileName = path.basename(filePath);

    // Read header chunk safely
    const bytesToRead = Math.min(stat.size, this.MAX_HEADER_READ_BYTES);
    const headerBuffer = Buffer.alloc(bytesToRead);

    if (bytesToRead > 0) {
      const fd = await fs.promises.open(filePath, 'r');
      try {
        await fd.read(headerBuffer, 0, bytesToRead, 0);
      } finally {
        await fd.close();
      }
    }

    const sha256 =
      bytesToRead === stat.size
        ? crypto.createHash('sha256').update(headerBuffer).digest('hex')
        : await this.computeSha256(filePath);
    const coreOut = CoreFileAnalyzer.analyzeBuffer(
      {
        filePath,
        fileName,
        fileSize: stat.size,
        headerBytes: headerBuffer
      },
      {
        sha256,
        entropyDetectionEnabled: options?.entropyDetectionEnabled ?? true,
        platformProfile: 'desktop'
      }
    );

    return {
      filePath,
      fileName: coreOut.fileName,
      fileSize: coreOut.fileSize,
      sha256: coreOut.sha256,
      entropy: coreOut.entropy,
      magicHeader: coreOut.magicHeader,
      isExecutable: coreOut.isExecutable,
      isDeceptiveExtension: coreOut.isDeceptiveExtension,
      riskScore: coreOut.riskScore,
      severity: coreOut.desktopSeverity,
      verdict: coreOut.desktopVerdict,
      threatName: coreOut.threatName,
      evidenceFactors: coreOut.evidenceFactors
    };
  }
}
