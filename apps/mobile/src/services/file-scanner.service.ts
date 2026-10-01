import {
  Verdict,
  SeverityLevel,
  Evidence,
  ActionRecommendation,
  FrictionLevel
} from '@private-protection/core';
import { FileMetadataInput, FileInspectionResult } from '../types/mobile.types';

export class FileScannerService {
  /**
   * Inspects user-selected file header bytes and metadata in volatile RAM.
   * Does NOT crawl device directories or execute binaries.
   */
  public inspectFile(input: FileMetadataInput): FileInspectionResult {
    const { name, sizeBytes, headerBytes } = input;
    const evidence: Evidence[] = [];
    let score = 0;
    let isExecutable = false;
    let detectedMimeType = input.mimeType || 'application/octet-stream';
    let threatCategory = 'FILE_BENIGN';

    const bytes = Array.from(headerBytes instanceof Uint8Array ? headerBytes : new Uint8Array(headerBytes));

    // 1. Double extension spoofing check (e.g. invoice.pdf.apk or document.docx.exe)
    const lowerName = name.toLowerCase();
    const doubleExtMatch = lowerName.match(/\.(pdf|doc|docx|png|jpg|jpeg|txt|xlsx)\.(apk|exe|dex|bat|cmd|vbs|ps1|sh)$/);
    if (doubleExtMatch) {
      score += 85;
      threatCategory = 'DECEPTIVE_DOUBLE_EXTENSION';
      evidence.push({
        source: 'FileHeaderAnalyzer',
        name: 'Deceptive Double Extension',
        description: `File name masks executable extension (.${doubleExtMatch[2]}) with deceptive document extension (.${doubleExtMatch[1]}).`,
        weight: 85,
        confidence: 0.95,
        isCriticalOverride: true
      });
    }

    // 2. Magic byte inspection
    // Windows PE Executable (MZ)
    if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
      isExecutable = true;
      detectedMimeType = 'application/x-dosexec';
      score += 80;
      if (threatCategory === 'FILE_BENIGN') threatCategory = 'UNVERIFIED_BINARY_EXECUTABLE';
      evidence.push({
        source: 'FileHeaderAnalyzer',
        name: 'Windows Executable Header',
        description: 'File contains MS-DOS/PE executable magic bytes (MZ). High threat risk on mobile if masked as document.',
        weight: 80,
        confidence: 0.99
      });
    }

    // Linux/Android ELF Executable (\x7fELF)
    if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
      isExecutable = true;
      detectedMimeType = 'application/x-elf';
      score += 75;
      if (threatCategory === 'FILE_BENIGN') threatCategory = 'NATIVE_ELF_BINARY';
      evidence.push({
        source: 'FileHeaderAnalyzer',
        name: 'Native ELF Binary',
        description: 'File contains Linux/Android ELF binary executable header.',
        weight: 75,
        confidence: 0.99
      });
    }

    // Android DEX Bytecode (dex\n)
    if (bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a) {
      isExecutable = true;
      detectedMimeType = 'application/vnd.android.dex';
      score += 70;
      if (threatCategory === 'FILE_BENIGN') threatCategory = 'STANDALONE_DEX_BYTECODE';
      evidence.push({
        source: 'FileHeaderAnalyzer',
        name: 'Android DEX Bytecode',
        description: 'Standalone Android Dalvik Executable bytecode detected outside an APK container.',
        weight: 70,
        confidence: 0.95
      });
    }

    // APK / ZIP Archive (PK\x03\x04)
    if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
      if (lowerName.endsWith('.apk')) {
        detectedMimeType = 'application/vnd.android.package-archive';
        score += 35; // Sideloaded APK caution
        if (threatCategory === 'FILE_BENIGN') threatCategory = 'SIDELOADED_APK_PACKAGE';
        evidence.push({
          source: 'FileHeaderAnalyzer',
          name: 'Sideloaded Android Package',
          description: 'Sideloaded Android application package (APK). Verify the developer signature before installing.',
          weight: 35,
          confidence: 0.9
        });
      }
    }

    // 3. Shannon entropy calculation over available header bytes
    const entropy = this.computeShannonEntropy(bytes);
    if (entropy > 7.5 && isExecutable) {
      score += 20;
      evidence.push({
        source: 'FileHeaderAnalyzer',
        name: 'High Binary Entropy',
        description: `Shannon entropy is ${entropy.toFixed(2)}/8.0, indicating heavy packing or encrypted payload structures.`,
        weight: 20,
        confidence: 0.85
      });
    }

    const overallScore = Math.min(100, score);
    let verdict = Verdict.ALLOW;
    let severity = SeverityLevel.NONE;

    if (overallScore >= 80) {
      verdict = Verdict.DANGEROUS;
      severity = SeverityLevel.CRITICAL;
    } else if (overallScore >= 60) {
      verdict = Verdict.SUSPICIOUS;
      severity = SeverityLevel.HIGH;
    } else if (overallScore >= 30) {
      verdict = Verdict.CAUTION;
      severity = SeverityLevel.MEDIUM;
    }

    return {
      fileName: name,
      sizeBytes,
      detectedMimeType,
      isExecutable,
      shannonEntropy: Math.round(entropy * 100) / 100,
      verdict,
      severity,
      score: overallScore,
      threatCategory,
      evidence,
      recommendation: {
        action: verdict === Verdict.DANGEROUS ? ActionRecommendation.BLOCK : (verdict === Verdict.SUSPICIOUS ? ActionRecommendation.WARN : ActionRecommendation.ALLOW),
        frictionLevel: verdict === Verdict.DANGEROUS ? FrictionLevel.HIGH : FrictionLevel.NONE,
        suggestedAction: verdict === Verdict.DANGEROUS
          ? 'Do not open or execute this file. Delete from downloads immediately.'
          : (verdict === Verdict.SUSPICIOUS
            ? 'Proceed with caution. Verify sender and origin.'
            : 'File header appears normal.'),
        bypassPermitted: true
      }
    };
  }

  private computeShannonEntropy(bytes: number[]): number {
    if (bytes.length === 0) return 0;
    const frequencies: Record<number, number> = {};
    for (const byte of bytes) {
      frequencies[byte] = (frequencies[byte] || 0) + 1;
    }
    let entropy = 0;
    const len = bytes.length;
    for (const byte in frequencies) {
      const p = frequencies[byte] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
