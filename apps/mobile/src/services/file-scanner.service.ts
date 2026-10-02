import {
  CoreFileAnalyzer,
  Verdict,
  ActionRecommendation,
  FrictionLevel
} from '@private-protection/core';
import { FileMetadataInput, FileInspectionResult } from '../types/mobile.types';

/**
 * Mobile single-file inspector delegating all header, double-extension, and Shannon entropy
 * evaluation to the canonical @private-protection/core CoreFileAnalyzer (GAP-08).
 */
export class FileScannerService {
  /**
   * Inspects user-selected file header bytes and metadata in volatile RAM.
   * Does NOT crawl device directories or execute binaries.
   */
  public inspectFile(input: FileMetadataInput): FileInspectionResult {
    const { name, sizeBytes, headerBytes, mimeType } = input;
    const uint8Bytes =
      headerBytes instanceof Uint8Array ? headerBytes : new Uint8Array(headerBytes);

    const coreOut = CoreFileAnalyzer.analyzeBuffer(
      {
        fileName: name,
        fileSize: sizeBytes,
        headerBytes: uint8Bytes,
        mimeType
      },
      {
        platformProfile: 'mobile'
      }
    );

    const verdict = coreOut.verdict;
    return {
      fileName: coreOut.fileName,
      sizeBytes: coreOut.fileSize,
      detectedMimeType: coreOut.detectedMimeType,
      isExecutable: coreOut.isExecutable,
      shannonEntropy: Math.round(coreOut.entropy * 100) / 100,
      verdict,
      severity: coreOut.severity,
      score: coreOut.riskScore,
      threatCategory: coreOut.threatName,
      evidence: coreOut.evidence,
      recommendation: {
        action:
          verdict === Verdict.DANGEROUS
            ? ActionRecommendation.BLOCK
            : verdict === Verdict.SUSPICIOUS
            ? ActionRecommendation.WARN
            : ActionRecommendation.ALLOW,
        frictionLevel:
          verdict === Verdict.DANGEROUS ? FrictionLevel.HIGH : FrictionLevel.NONE,
        suggestedAction:
          verdict === Verdict.DANGEROUS
            ? 'Do not open or execute this file. Delete from downloads immediately.'
            : verdict === Verdict.SUSPICIOUS
            ? 'Proceed with caution. Verify sender and origin.'
            : 'File header appears normal.',
        bypassPermitted: true
      }
    };
  }
}
