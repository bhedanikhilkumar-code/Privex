import {
  ActionRecommendation,
  DetectorType,
  Evidence,
  FileScanRequest,
  FileScanResult,
  SeverityLevel,
  Verdict
} from '../types';

export interface CoreFileAnalysisOptions {
  readonly sha256?: string;
  readonly entropyDetectionEnabled?: boolean;
  readonly platformProfile?: 'desktop' | 'mobile';
}

export interface CoreFileAnalysisOutput extends FileScanResult {
  readonly detectedMimeType: string;
  readonly desktopSeverity: 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical';
  readonly desktopVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK';
  readonly actionRecommendation: ActionRecommendation;
  readonly evidence: Evidence[];
}

/**
 * Canonical cross-platform File Header, Extension & Shannon Entropy Analyzer
 * in @private-protection/core (GAP-08).
 * Operates purely in memory on Uint8Array / byte arrays without OS-specific fs dependencies.
 */
export class CoreFileAnalyzer {
  public static readonly HIGH_ENTROPY_THRESHOLD_DESKTOP = 7.2;
  public static readonly HIGH_ENTROPY_THRESHOLD_MOBILE = 7.5;

  public static readonly EXECUTABLE_EXTENSIONS = new Set([
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.wsf', '.cpl', '.com', '.msi', '.pif', '.hta', '.jar', '.apk', '.dex', '.sh'
  ]);

  public static readonly DOCUMENT_EXTENSIONS = new Set([
    '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
    '.txt', '.rtf', '.jpg', '.jpeg', '.png', '.gif', '.zip'
  ]);

  /**
   * Computes the Shannon entropy of a byte buffer (0.0 to 8.0).
   */
  public static calculateEntropy(buffer: Uint8Array | number[]): number {
    const len = buffer.length;
    if (len === 0) return 0;

    const frequencies = new Uint32Array(256);
    for (let i = 0; i < len; i++) {
      frequencies[buffer[i] & 0xff]++;
    }

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / len;
        entropy -= p * Math.log2(p);
      }
    }

    return Math.round(entropy * 1000) / 1000;
  }

  /**
   * Inspects magic header bytes from a file buffer without executing the payload.
   */
  public static detectMagicHeader(buffer: Uint8Array | number[]): string | null {
    if (buffer.length < 2) return null;

    // MZ (Windows Portable Executable / DOS)
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      return 'PE/MZ_EXECUTABLE';
    }

    // ELF (Linux / Android executable)
    if (
      buffer.length >= 4 &&
      buffer[0] === 0x7f &&
      buffer[1] === 0x45 &&
      buffer[2] === 0x4c &&
      buffer[3] === 0x46
    ) {
      return 'ELF_EXECUTABLE';
    }

    // Mach-O (macOS executable)
    if (buffer.length >= 4) {
      if (
        (buffer[0] === 0xfe && buffer[1] === 0xed && buffer[2] === 0xfa && buffer[3] === 0xce) ||
        (buffer[0] === 0xcf && buffer[1] === 0xfa && buffer[2] === 0xed && buffer[3] === 0xfe) ||
        (buffer[0] === 0xca && buffer[1] === 0xfe && buffer[2] === 0xba && buffer[3] === 0xbe)
      ) {
        return 'MACHO_EXECUTABLE';
      }
    }

    // DEX (Android Dalvik Executable)
    if (
      buffer.length >= 4 &&
      buffer[0] === 0x64 &&
      buffer[1] === 0x65 &&
      buffer[2] === 0x78 &&
      buffer[3] === 0x0a
    ) {
      return 'DEX_BYTECODE';
    }

    // Shell script / PowerShell / Batch
    const sliceLen = Math.min(buffer.length, 128);
    let headerAscii = '';
    for (let i = 0; i < sliceLen; i++) {
      headerAscii += String.fromCharCode(buffer[i] & 0xff);
    }
    const lowerHeader = headerAscii.toLowerCase();
    if (
      lowerHeader.startsWith('#!/') ||
      lowerHeader.includes('powershell') ||
      lowerHeader.includes('wscript.shell')
    ) {
      return 'SCRIPT_EXECUTABLE';
    }

    return null;
  }

  /**
   * Detects double-extension deception (e.g. urgent_invoice.pdf.exe or document.pdf.apk).
   */
  public static checkDeceptiveExtension(fileName: string): {
    isDeceptive: boolean;
    fakeExt?: string;
    realExt?: string;
  } {
    const parts = fileName.toLowerCase().split('.');
    if (parts.length >= 3) {
      const realExt = '.' + parts[parts.length - 1];
      const fakeExt = '.' + parts[parts.length - 2];

      if (this.EXECUTABLE_EXTENSIONS.has(realExt) && this.DOCUMENT_EXTENSIONS.has(fakeExt)) {
        return { isDeceptive: true, fakeExt, realExt };
      }
    }
    return { isDeceptive: false };
  }

  /**
   * Evaluates a file header + metadata request and produces canonical Core + platform-compatible verdicts.
   */
  public static analyzeBuffer(
    request: FileScanRequest,
    options?: CoreFileAnalysisOptions
  ): CoreFileAnalysisOutput {
    const bytes =
      request.headerBytes instanceof Uint8Array
        ? request.headerBytes
        : new Uint8Array(request.headerBytes);

    const fileName = request.fileName || 'unknown';
    const lowerName = fileName.toLowerCase();
    const lastDotIndex = lowerName.lastIndexOf('.');
    const ext = lastDotIndex >= 0 ? lowerName.slice(lastDotIndex) : '';
    const entropyEnabled = options?.entropyDetectionEnabled !== false;
    const profile = options?.platformProfile || 'desktop';

    const entropy = this.calculateEntropy(bytes);
    const magicHeader = this.detectMagicHeader(bytes);
    const deceptive = this.checkDeceptiveExtension(fileName);

    const isZipHeader =
      bytes.length >= 4 &&
      bytes[0] === 0x50 &&
      bytes[1] === 0x4b &&
      bytes[2] === 0x03 &&
      bytes[3] === 0x04;

    const evidence: Evidence[] = [];
    const evidenceFactors: string[] = [];
    let riskScore = 0;
    let threatName = profile === 'mobile' ? 'FILE_BENIGN' : 'BENIGN_FILE';
    let detectedMimeType = request.mimeType || 'application/octet-stream';

    if (magicHeader === 'PE/MZ_EXECUTABLE') {
      detectedMimeType = 'application/x-dosexec';
    } else if (magicHeader === 'ELF_EXECUTABLE') {
      detectedMimeType = 'application/x-elf';
    } else if (magicHeader === 'DEX_BYTECODE') {
      detectedMimeType = 'application/vnd.android.dex';
    } else if (isZipHeader && ext === '.apk') {
      detectedMimeType = 'application/vnd.android.package-archive';
    }

    const hasBinaryExecutableHeader =
      magicHeader === 'PE/MZ_EXECUTABLE' ||
      magicHeader === 'ELF_EXECUTABLE' ||
      magicHeader === 'MACHO_EXECUTABLE' ||
      magicHeader === 'DEX_BYTECODE';

    const hasExecutableHeader =
      hasBinaryExecutableHeader || magicHeader === 'SCRIPT_EXECUTABLE';

    const isDeclaredExecutable = this.EXECUTABLE_EXTENSIONS.has(ext);

    if (profile === 'mobile') {
      if (deceptive.isDeceptive) {
        riskScore += 85;
        threatName = 'DECEPTIVE_DOUBLE_EXTENSION';
        const desc = `File name masks executable extension (${deceptive.realExt}) with deceptive document extension (${deceptive.fakeExt}).`;
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-double-extension',
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'Deceptive Double Extension',
          description: desc,
          weight: 85,
          scoreContribution: 85,
          confidence: 0.95,
          isCriticalOverride: true
        });
      }

      if (magicHeader === 'PE/MZ_EXECUTABLE') {
        riskScore += 80;
        if (threatName === 'FILE_BENIGN') threatName = 'UNVERIFIED_BINARY_EXECUTABLE';
        const desc = 'File contains MS-DOS/PE executable magic bytes (MZ). High threat risk on mobile if masked as document.';
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-pe-header',
          detectorType: DetectorType.RULE,
          source: 'FileHeaderAnalyzer',
          name: 'Windows Executable Header',
          description: desc,
          weight: 80,
          scoreContribution: 80,
          confidence: 0.99
        });
      } else if (magicHeader === 'ELF_EXECUTABLE') {
        riskScore += 75;
        if (threatName === 'FILE_BENIGN') threatName = 'NATIVE_ELF_BINARY';
        const desc = 'File contains Linux/Android ELF binary executable header.';
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-elf-header',
          detectorType: DetectorType.RULE,
          source: 'FileHeaderAnalyzer',
          name: 'Native ELF Binary',
          description: desc,
          weight: 75,
          scoreContribution: 75,
          confidence: 0.99
        });
      } else if (magicHeader === 'DEX_BYTECODE') {
        riskScore += 70;
        if (threatName === 'FILE_BENIGN') threatName = 'STANDALONE_DEX_BYTECODE';
        const desc = 'Standalone Android Dalvik Executable bytecode detected outside an APK container.';
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-dex-header',
          detectorType: DetectorType.RULE,
          source: 'FileHeaderAnalyzer',
          name: 'Android DEX Bytecode',
          description: desc,
          weight: 70,
          scoreContribution: 70,
          confidence: 0.95
        });
      }

      if (isZipHeader && ext === '.apk') {
        riskScore += 35;
        if (threatName === 'FILE_BENIGN') threatName = 'SIDELOADED_APK_PACKAGE';
        const desc = 'Sideloaded Android application package (APK). Verify the developer signature before installing.';
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-sideloaded-apk',
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'Sideloaded Android Package',
          description: desc,
          weight: 35,
          scoreContribution: 35,
          confidence: 0.9
        });
      }

      if (
        entropyEnabled &&
        entropy > this.HIGH_ENTROPY_THRESHOLD_MOBILE &&
        (isDeclaredExecutable || hasExecutableHeader)
      ) {
        riskScore += 20;
        const desc = `Shannon entropy is ${entropy.toFixed(2)}/8.0, indicating heavy packing or encrypted payload structures.`;
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-high-entropy',
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'High Binary Entropy',
          description: desc,
          weight: 20,
          scoreContribution: 20,
          confidence: 0.85
        });
      }
    } else {
      // Desktop profile
      if (deceptive.isDeceptive) {
        riskScore += 50;
        const desc = `Double extension deception: disguised as '${deceptive.fakeExt}', actual '${deceptive.realExt}'`;
        evidenceFactors.push(desc);
        threatName = 'DECEPTIVE_DOUBLE_EXTENSION';
        evidence.push({
          ruleId: 'file-double-extension',
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'Deceptive Double Extension',
          description: desc,
          weight: 50,
          scoreContribution: 50,
          confidence: 0.95
        });

        if (
          magicHeader === 'PE/MZ_EXECUTABLE' ||
          magicHeader === 'ELF_EXECUTABLE' ||
          magicHeader === 'MACHO_EXECUTABLE'
        ) {
          riskScore += 30;
          const synergyDesc = `Deceptive double extension carries active executable payload (${magicHeader})`;
          evidenceFactors.push(synergyDesc);
          evidence.push({
            ruleId: 'file-double-ext-binary-synergy',
            detectorType: DetectorType.RULE,
            source: 'FileHeaderAnalyzer',
            name: 'Deceptive Double Extension Binary Payload',
            description: synergyDesc,
            weight: 30,
            scoreContribution: 30,
            confidence: 0.99,
            isCriticalOverride: true
          });
        }
      }

      const claimedDocument = this.DOCUMENT_EXTENSIONS.has(ext);
      const hasDesktopBinaryHeader =
        magicHeader === 'PE/MZ_EXECUTABLE' ||
        magicHeader === 'ELF_EXECUTABLE' ||
        magicHeader === 'MACHO_EXECUTABLE';

      if (claimedDocument && hasDesktopBinaryHeader) {
        riskScore += 65;
        const desc = `Executable disguise: claimed '${ext}' extension but contains executable header (${magicHeader})`;
        evidenceFactors.push(desc);
        threatName = 'DISGUISED_EXECUTABLE';
        evidence.push({
          ruleId: 'file-disguised-executable',
          detectorType: DetectorType.RULE,
          source: 'FileHeaderAnalyzer',
          name: 'Disguised Executable Header',
          description: desc,
          weight: 65,
          scoreContribution: 65,
          confidence: 0.98
        });
      }

      if (isDeclaredExecutable) {
        const desc = `Executable extension detected: '${ext}'`;
        evidenceFactors.push(desc);
        riskScore += 15;
        evidence.push({
          ruleId: 'file-executable-extension',
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'Executable Extension',
          description: desc,
          weight: 15,
          scoreContribution: 15,
          confidence: 0.85
        });
      }

      if (
        entropyEnabled &&
        entropy > this.HIGH_ENTROPY_THRESHOLD_DESKTOP &&
        (isDeclaredExecutable || hasDesktopBinaryHeader)
      ) {
        riskScore += 30;
        const desc = `High Shannon entropy (${entropy} / 8.0) indicates packed, encrypted, or obfuscated payload`;
        evidenceFactors.push(desc);
        if (threatName === 'BENIGN_FILE') {
          threatName = 'OBFUSCATED_SUSPICIOUS_PAYLOAD';
        }
        evidence.push({
          ruleId: 'file-high-entropy',
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'High Binary Entropy',
          description: desc,
          weight: 30,
          scoreContribution: 30,
          confidence: 0.85
        });
      }
    }

    riskScore = Math.min(100, Math.max(0, riskScore));

    if (evidenceFactors.length === 0) {
      evidenceFactors.push('Clean header structure, normal byte entropy, valid extension');
    }

    // Map to Desktop severity & verdict taxonomy
    let desktopSeverity: 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical' = 'safe';
    let desktopVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK' = 'ALLOW';

    if (riskScore >= 75) {
      desktopSeverity = 'critical';
      desktopVerdict = 'BLOCK';
    } else if (riskScore >= 50) {
      desktopSeverity = 'dangerous';
      desktopVerdict = 'BLOCK';
    } else if (riskScore >= 30) {
      desktopSeverity = 'suspicious';
      desktopVerdict = 'WARN';
    } else if (riskScore > 10) {
      desktopSeverity = 'low';
      desktopVerdict = 'INFORM';
    }

    // Map to Core canonical SeverityLevel & Verdict taxonomy
    let severity = SeverityLevel.NONE;
    let verdict = Verdict.ALLOW;
    let actionRecommendation = ActionRecommendation.ALLOW;

    if (profile === 'mobile') {
      if (riskScore >= 80) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.CRITICAL;
        actionRecommendation = ActionRecommendation.BLOCK;
      } else if (riskScore >= 60) {
        verdict = Verdict.SUSPICIOUS;
        severity = SeverityLevel.HIGH;
        actionRecommendation = ActionRecommendation.WARN;
      } else if (riskScore >= 30) {
        verdict = Verdict.CAUTION;
        severity = SeverityLevel.MEDIUM;
        actionRecommendation = ActionRecommendation.WARN;
      }
    } else {
      if (riskScore >= 75) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.CRITICAL;
        actionRecommendation = ActionRecommendation.BLOCK;
      } else if (riskScore >= 50) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.HIGH;
        actionRecommendation = ActionRecommendation.BLOCK;
      } else if (riskScore >= 30) {
        verdict = Verdict.SUSPICIOUS;
        severity = SeverityLevel.MEDIUM;
        actionRecommendation = ActionRecommendation.WARN;
      } else if (riskScore > 10) {
        verdict = Verdict.INFORM;
        severity = SeverityLevel.LOW;
        actionRecommendation = ActionRecommendation.INFORM;
      }
    }

    const isExecutable =
      profile === 'mobile'
        ? hasBinaryExecutableHeader
        : isDeclaredExecutable ||
          magicHeader === 'PE/MZ_EXECUTABLE' ||
          magicHeader === 'ELF_EXECUTABLE' ||
          magicHeader === 'MACHO_EXECUTABLE';

    return {
      filePath: request.filePath,
      fileName,
      fileSize: request.fileSize,
      sha256: options?.sha256 || '',
      entropy,
      magicHeader,
      isExecutable,
      isDeceptiveExtension: deceptive.isDeceptive,
      riskScore,
      severity,
      verdict,
      threatName,
      evidenceFactors,
      detectedMimeType,
      desktopSeverity,
      desktopVerdict,
      actionRecommendation,
      evidence
    };
  }
}
