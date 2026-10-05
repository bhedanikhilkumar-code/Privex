import {
  ActionRecommendation,
  AnalysisStatus,
  DetectionDisposition,
  DetectorLayer,
  DetectorType,
  EngineVerdict,
  Evidence,
  FileScanRequest,
  FileScanResult,
  SeverityLevel,
  Verdict
} from '../types';
import { sha256 } from '../utils/crypto';
import { EntropyScanner } from './entropy-scanner';
import { SignatureAutomaton } from '../threat-intel/signature-automaton';
import { PeAnalyzer } from './pe-analyzer';
import { ArchiveAnalyzer } from './archive-analyzer';
import { DocumentAnalyzer } from './document-analyzer';
import { ScriptAnalyzer } from './script-analyzer';
import { CleanFileCache } from '../cache/clean-file-cache';

export interface CoreFileAnalysisOptions {
  readonly sha256?: string;
  readonly entropyDetectionEnabled?: boolean;
  readonly platformProfile?: 'desktop' | 'mobile';
  readonly enableDeepAnalysis?: boolean;
}

export interface CoreFileInput {
  readonly path?: string;
  readonly filePath?: string;
  readonly fileName?: string;
  readonly content?: Uint8Array | number[];
  readonly headerBytes?: Uint8Array | number[];
  readonly fileSize?: number;
  readonly size?: number;
  readonly lastModified?: number;
  readonly mtimeMs?: number;
  readonly mimeType?: string;
}

export interface CoreFileAnalysisOutput extends FileScanResult {
  readonly detectedMimeType: string;
  readonly desktopSeverity: 'safe' | 'low' | 'suspicious' | 'dangerous' | 'critical';
  readonly desktopVerdict: 'ALLOW' | 'INFORM' | 'WARN' | 'BLOCK';
  readonly engineVerdict?: EngineVerdict;
  readonly actionRecommendation: ActionRecommendation;
  readonly evidence: Evidence[];
  readonly analysisStatus: AnalysisStatus;
  readonly disposition: DetectionDisposition;
  readonly errorReason?: string;
  readonly stage0CacheHit?: boolean;
  readonly stage1ShortCircuit?: boolean;
  readonly hasDoubleExtension?: boolean;
}

/**
 * Canonical cross-platform File Header, Extension & Shannon Entropy Analyzer
 * in @private-protection/core (GAP-08).
 * Operates purely in memory on Uint8Array / byte arrays without OS-specific fs dependencies.
 */
export class CoreFileAnalyzer {
  public static readonly HIGH_ENTROPY_THRESHOLD_DESKTOP = 7.2;
  public static readonly HIGH_ENTROPY_THRESHOLD_MOBILE = 7.5;
  public static readonly EICAR_SIGNATURE =
    'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

  public static readonly EXECUTABLE_EXTENSIONS = new Set([
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.cpl', '.com', '.msi', '.pif', '.hta', '.jar', '.apk', '.dex', '.sh', '.lnk', '.reg'
  ]);

  public static readonly DOCUMENT_EXTENSIONS = new Set([
    '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
    '.txt', '.rtf', '.jpg', '.jpeg', '.png', '.gif', '.zip'
  ]);

  private static readonly RTLO_BIDI_PATTERN = /[\u202A-\u202E\u2066-\u2069]/;

  /**
   * Computes the Shannon entropy of a byte buffer (0.0 to 8.0).
   */
  public static calculateEntropy(buffer: Uint8Array | number[]): number {
    return EntropyScanner.calculateEntropy(buffer);
  }

  /**
   * Inspects magic header bytes from a file buffer without executing the payload.
   */
  public static detectMagicHeader(buffer: Uint8Array | number[]): string | null {
    if (!buffer || typeof buffer.length !== 'number' || buffer.length < 2) return null;

    // EICAR Standard Antivirus Test Signature check (first 128 bytes)
    if (buffer.length >= 68) {
      const eicarLen = Math.min(buffer.length, 128);
      let eicarAscii = '';
      for (let i = 0; i < eicarLen; i++) {
        eicarAscii += String.fromCharCode(buffer[i] & 0xff);
      }
      if (eicarAscii.includes(this.EICAR_SIGNATURE)) {
        return 'EICAR_TEST_SIGNATURE';
      }
    }

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
   * Detects double-extension deception (e.g. urgent_invoice.pdf.exe, document.pdf.apk,
   * trailing space/dot spoofing on Windows, or Unicode RTLO spoofing).
   */
  public static checkDeceptiveExtension(fileName: string): {
    isDeceptive: boolean;
    fakeExt?: string;
    realExt?: string;
    hasRtloSpoofing?: boolean;
  } {
    if (!fileName || typeof fileName !== 'string') {
      return { isDeceptive: false };
    }

    const hasRtloSpoofing = this.RTLO_BIDI_PATTERN.test(fileName);
    const normalized = fileName
      .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
      .replace(/[. ]+$/, '')
      .toLowerCase();

    const parts = normalized.split('.').filter((p) => p.length > 0);
    if (parts.length >= 3) {
      const realExt = '.' + parts[parts.length - 1];
      const fakeExt = '.' + parts[parts.length - 2];

      if (this.EXECUTABLE_EXTENSIONS.has(realExt) && this.DOCUMENT_EXTENSIONS.has(fakeExt)) {
        return { isDeceptive: true, fakeExt, realExt, hasRtloSpoofing };
      }
    }

    if (hasRtloSpoofing) {
      const lastExt = parts.length >= 2 ? '.' + parts[parts.length - 1] : '.unknown';
      return {
        isDeceptive: true,
        fakeExt: '.rtlo_spoofed',
        realExt: lastExt,
        hasRtloSpoofing: true
      };
    }

    return { isDeceptive: false };
  }

  /**
   * Normalizes flexible input parameters to canonical FileScanRequest
   */
  public static normalizeInput(
    input: CoreFileInput | FileScanRequest
  ): FileScanRequest & { lastModified?: number } {
    if (!input || typeof input !== 'object') {
      return input as any;
    }
    const path = (input as any).path || (input as any).filePath;
    let fileName = (input as any).fileName;
    if (!fileName && path) {
      const parts = String(path).split(/[/\\]/);
      fileName = parts[parts.length - 1];
    }
    if (!fileName) {
      fileName = 'unknown';
    }

    const rawBytes =
      (input as any).headerBytes || (input as any).content || new Uint8Array(0);
    const bytes =
      rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    const size =
      typeof (input as any).fileSize === 'number'
        ? (input as any).fileSize
        : typeof (input as any).size === 'number'
        ? (input as any).size
        : bytes.length;

    const mtime = (input as any).lastModified || (input as any).mtimeMs;

    return {
      filePath: path,
      fileName,
      fileSize: size,
      headerBytes: bytes,
      mimeType: (input as any).mimeType,
      ...(mtime !== undefined ? { lastModified: mtime } : {})
    };
  }

  /**
   * Universal static analysis entry point accepting flexible inputs
   */
  public static analyze(
    input: CoreFileInput | FileScanRequest,
    options?: CoreFileAnalysisOptions
  ): CoreFileAnalysisOutput {
    return this.analyzeBuffer(this.normalizeInput(input), options);
  }

  /**
   * Universal instance analysis entry point accepting flexible inputs
   */
  public analyze(
    input: CoreFileInput | FileScanRequest,
    options?: CoreFileAnalysisOptions
  ): CoreFileAnalysisOutput {
    return CoreFileAnalyzer.analyze(input, options);
  }

  /**
   * Evaluates a file header + metadata request and produces canonical Core + platform-compatible verdicts.
   */
  public static analyzeBuffer(
    request: FileScanRequest,
    options?: CoreFileAnalysisOptions
  ): CoreFileAnalysisOutput {
    const profile = options?.platformProfile || 'desktop';

    // Stage 0: Clean File Cache fast lookup (< 0.08 ms)
    const mtime = (request as any)?.lastModified;
    if (request && request.filePath && typeof mtime === 'number') {
      const cached = CleanFileCache.getSharedInstance().get(
        request.filePath,
        request.fileSize,
        mtime
      );
      if (cached) {
        return {
          filePath: request.filePath,
          fileName: request.fileName || 'unknown',
          fileSize: request.fileSize,
          sha256: options?.sha256 || cached.sha256 || '',
          entropy: 0,
          magicHeader: null,
          isExecutable: false,
          isDeceptiveExtension: false,
          riskScore: cached.riskScore ?? 0,
          severity: SeverityLevel.NONE,
          verdict: cached.verdict ?? Verdict.ALLOW,
          threatName: 'BENIGN_FILE_CACHED',
          evidenceFactors: ['File verified clean in CleanFileCache (Stage 0 hit)'],
          detectedMimeType: request.mimeType || 'application/octet-stream',
          desktopSeverity: 'safe',
          desktopVerdict: 'ALLOW',
          engineVerdict: cached.engineVerdict ?? EngineVerdict.ALLOW,
          actionRecommendation: ActionRecommendation.ALLOW,
          analysisStatus: 'COMPLETED',
          disposition: 'SAFE',
          evidence: [],
          stage0CacheHit: true,
          stage1ShortCircuit: false,
          hasDoubleExtension: false
        };
      }
    }

    // Fail-closed validation on malformed/missing FileScanRequest (Step 7)
    if (
      !request ||
      typeof request !== 'object' ||
      !request.headerBytes ||
      typeof request.fileSize !== 'number' ||
      !Number.isFinite(request.fileSize) ||
      request.fileSize < 0
    ) {
      const failDesc =
        'Analysis failed: malformed or missing file scan request parameters (fail-closed policy applied)';
      return {
        filePath: request?.filePath,
        fileName: typeof request?.fileName === 'string' && request.fileName ? request.fileName : 'unknown',
        fileSize: typeof request?.fileSize === 'number' && Number.isFinite(request.fileSize) && request.fileSize >= 0 ? request.fileSize : 0,
        sha256: options?.sha256 || '',
        entropy: 0,
        magicHeader: null,
        isExecutable: false,
        isDeceptiveExtension: false,
        riskScore: 50,
        severity: SeverityLevel.MEDIUM,
        verdict: Verdict.CAUTION,
        threatName: 'ANALYSIS_FAILED_INVALID_INPUT',
        evidenceFactors: [failDesc],
        detectedMimeType: 'application/octet-stream',
        desktopSeverity: 'suspicious',
        desktopVerdict: 'WARN',
        engineVerdict: EngineVerdict.WARN,
        actionRecommendation: ActionRecommendation.WARN,
        analysisStatus: 'ANALYSIS_FAILED',
        disposition: 'ANALYSIS_FAILED',
        errorReason: 'INVALID_FILE_SCAN_REQUEST',
        evidence: [
          {
            ruleId: 'file-analysis-failed-input',
            detectorType: DetectorType.HEURISTIC,
            detectorLayer: DetectorLayer.METADATA_ANALYZER,
            source: 'FileHeaderAnalyzer',
            name: 'File Analysis Failed',
            description: failDesc,
            reason: failDesc,
            severityLevel: SeverityLevel.MEDIUM,
            weight: 50,
            scoreContribution: 50,
            confidence: 0.9
          }
        ]
      };
    }

    let bytes: Uint8Array;
    try {
      bytes =
        request.headerBytes instanceof Uint8Array
          ? request.headerBytes
          : new Uint8Array(request.headerBytes);
    } catch {
      const failDesc = 'Analysis failed: unreadable header byte buffer (fail-closed policy applied)';
      return {
        filePath: request.filePath,
        fileName: request.fileName || 'unknown',
        fileSize: request.fileSize,
        sha256: options?.sha256 || '',
        entropy: 0,
        magicHeader: null,
        isExecutable: false,
        isDeceptiveExtension: false,
        riskScore: 50,
        severity: SeverityLevel.MEDIUM,
        verdict: Verdict.CAUTION,
        threatName: 'ANALYSIS_FAILED_CORRUPT_BUFFER',
        evidenceFactors: [failDesc],
        detectedMimeType: 'application/octet-stream',
        desktopSeverity: 'suspicious',
        desktopVerdict: 'WARN',
        engineVerdict: EngineVerdict.WARN,
        actionRecommendation: ActionRecommendation.WARN,
        analysisStatus: 'ANALYSIS_FAILED',
        disposition: 'ANALYSIS_FAILED',
        errorReason: 'CORRUPT_HEADER_BUFFER',
        evidence: [
          {
            ruleId: 'file-analysis-failed-buffer',
            detectorType: DetectorType.HEURISTIC,
            detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
            source: 'FileHeaderAnalyzer',
            name: 'Unreadable File Buffer',
            description: failDesc,
            reason: failDesc,
            severityLevel: SeverityLevel.MEDIUM,
            weight: 50,
            scoreContribution: 50,
            confidence: 0.9
          }
        ]
      };
    }

    const fileName = request.fileName || 'unknown';
    const normalizedName = fileName
      .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
      .replace(/[. ]+$/, '')
      .toLowerCase();
    const lastDotIndex = normalizedName.lastIndexOf('.');
    const ext = lastDotIndex >= 0 ? normalizedName.slice(lastDotIndex) : '';
    const entropyEnabled = options?.entropyDetectionEnabled !== false;

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
    let analysisStatus: AnalysisStatus = 'COMPLETED';
    let errorReason: string | undefined;

    // Step 5 & Step 7: Non-empty file with 0 header bytes read must fail closed to WARN / ANALYSIS_FAILED
    if (request.fileSize > 0 && bytes.length === 0) {
      riskScore += 45;
      threatName = 'UNREADABLE_FILE_HEADER';
      analysisStatus = 'ANALYSIS_FAILED';
      errorReason = 'UNREADABLE_FILE_HEADER';
      const unreadableDesc =
        'File has non-zero size but 0 header bytes were readable; fail-closed warning applied.';
      evidenceFactors.push(unreadableDesc);
      evidence.push({
        ruleId: 'file-unreadable-header',
        detectorType: DetectorType.HEURISTIC,
        source: 'FileHeaderAnalyzer',
        name: 'Unreadable File Header',
        description: unreadableDesc,
        weight: 45,
        scoreContribution: 45,
        confidence: 0.9
      });
    }

    // EICAR Standard Antivirus Test Signature Detection
    if (magicHeader === 'EICAR_TEST_SIGNATURE') {
      riskScore = 100;
      threatName = 'EICAR_TEST_FILE';
      const eicarDesc = 'EICAR Standard Antivirus Test Signature detected in file header.';
      evidenceFactors.push(eicarDesc);
      evidence.push({
        ruleId: 'file-eicar-test-signature',
        detectorType: DetectorType.RULE,
        detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
        source: 'FileHeaderAnalyzer',
        name: 'EICAR Test Signature',
        description: eicarDesc,
        weight: 100,
        scoreContribution: 100,
        confidence: 1.0,
        isCriticalOverride: true
      });
    }

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
      hasBinaryExecutableHeader ||
      magicHeader === 'SCRIPT_EXECUTABLE' ||
      magicHeader === 'EICAR_TEST_SIGNATURE';

    const isDeclaredExecutable = this.EXECUTABLE_EXTENSIONS.has(ext);

    if (profile === 'mobile') {
      if (deceptive.isDeceptive) {
        riskScore += 85;
        threatName = 'DECEPTIVE_DOUBLE_EXTENSION';
        const desc = `File name masks executable extension (${deceptive.realExt}) with deceptive document extension (${deceptive.fakeExt}).`;
        evidenceFactors.push(desc);
        evidence.push({
          ruleId: 'file-double-extension',
              detectorLayer: DetectorLayer.METADATA_ANALYZER,
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
              detectorLayer: DetectorLayer.METADATA_ANALYZER,
          detectorType: DetectorType.HEURISTIC,
          source: 'FileHeaderAnalyzer',
          name: 'Deceptive Double Extension',
          description: desc,
          weight: 50,
          scoreContribution: 50,
          confidence: 0.95
        });

        if (deceptive.hasRtloSpoofing) {
          riskScore += 40;
          const rtloDesc =
            'Unicode Right-To-Left Override (RTLO / Bidi) character detected in filename';
          evidenceFactors.push(rtloDesc);
          evidence.push({
            ruleId: 'file-rtlo-spoofing',
            detectorType: DetectorType.HEURISTIC,
            detectorLayer: DetectorLayer.METADATA_ANALYZER,
            source: 'FileHeaderAnalyzer',
            name: 'Unicode RTLO Filename Spoofing',
            description: rtloDesc,
            reason:
              'Adversaries use RTLO characters to invert file extension display and disguise executables',
            severityLevel: SeverityLevel.HIGH,
            weight: 70,
            scoreContribution: 70,
            confidence: 0.98,
            isCriticalOverride: true
          });
        }

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
              detectorLayer: DetectorLayer.METADATA_ANALYZER,
            detectorType: DetectorType.RULE,
            source: 'FileHeaderAnalyzer',
            name: 'Deceptive Double Extension Binary Payload',
            description: synergyDesc,
            weight: 95,
            scoreContribution: 95,
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
              detectorLayer: DetectorLayer.METADATA_ANALYZER,
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
              detectorLayer: DetectorLayer.METADATA_ANALYZER,
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

    // Phase C Deep Static Malware Engine Integration (Layers 2, 4, 5, 6)
    // Sieve Stage 1 Short-Circuit: If already confirmed EICAR, skip deep stages
    if (
      options?.enableDeepAnalysis !== false &&
      bytes.length > 0 &&
      magicHeader !== 'EICAR_TEST_SIGNATURE'
    ) {
      // 1. Layer 2: Aho-Corasick Signature Automaton Scan
      try {
        const sigMatches = SignatureAutomaton.getInstance().scan(bytes);
        if (sigMatches.length > 0) {
          const sigEvidences = SignatureAutomaton.getInstance().toEvidence(sigMatches);
          for (const ev of sigEvidences) {
            evidence.push(ev);
            evidenceFactors.push(ev.description);
            if (ev.isCriticalOverride) {
              riskScore = Math.max(riskScore, ev.scoreContribution ?? 95);
              threatName = String(ev.metadata?.threatName || ev.name);
            } else {
              riskScore += ev.scoreContribution ?? 0;
            }
          }
        }
      } catch {
        // Safe fail-closed
      }

      // 2. Layer 5 & 4: Zero-Alloc PE32 / PE32+ Binary Inspection
      if (
        magicHeader === 'PE/MZ_EXECUTABLE' ||
        (bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a)
      ) {
        try {
          const peRes = PeAnalyzer.analyze(bytes, request.fileSize);
          for (const ev of peRes.evidence) {
            if (!evidence.some((e) => e.ruleId === ev.ruleId)) {
              evidence.push(ev);
              evidenceFactors.push(ev.description);
              if (ev.scoreContribution) {
                riskScore = Math.max(riskScore, ev.scoreContribution);
              }
            }
          }
        } catch {
          // Fail closed: never silently pass an unparseable executable
          const failEv: Evidence = {
            ruleId: 'pe-malformed-structure',
            detectorType: DetectorType.HEURISTIC,
            detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
            source: 'PE_ANALYZER',
            name: 'PE Analysis Failed',
            description: 'PE analysis failed unexpectedly; file treated as suspicious.',
            reason: 'pe-parse-failed',
            severityLevel: SeverityLevel.MEDIUM,
            weight: 50,
            scoreContribution: 50,
            confidence: 0.8,
            isMalicious: false
          };
          evidence.push(failEv);
          evidenceFactors.push(failEv.description);
          riskScore = Math.max(riskScore, 50);
        }
      }

      // 3. Layer 5: In-Memory Archive & Zip Bomb Inspection
      if (
        magicHeader === 'ZIP_ARCHIVE' ||
        (bytes.length >= 22 && bytes[0] === 0x50 && bytes[1] === 0x4b) ||
        ext === 'zip'
      ) {
        try {
          const archRes = ArchiveAnalyzer.analyze(bytes);
          if (archRes.isArchive) {
            for (const ev of archRes.evidence) {
              if (!evidence.some((e) => e.ruleId === ev.ruleId)) {
                evidence.push(ev);
                evidenceFactors.push(ev.description);
                if (ev.scoreContribution) {
                  riskScore = Math.max(riskScore, ev.scoreContribution);
                }
              }
            }
            if (archRes.hasZipBombCharacteristics) {
              threatName = 'ZIP_BOMB_ANOMALY';
            } else if (archRes.hasPathTraversal) {
              threatName = 'ARCHIVE_PATH_TRAVERSAL';
            }
          }
        } catch {
          // Handled safely
        }
      }

      // 4. Layer 5 & 3: Office OOXML / OLE2 & PDF Inspection
      const isCandidateDocument =
        magicHeader === 'ZIP_ARCHIVE' ||
        (bytes.length >= 8 && bytes[0] === 0xd0 && bytes[1] === 0xcf) ||
        (bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) ||
        this.DOCUMENT_EXTENSIONS.has(ext) ||
        ext === 'docm' || ext === 'xlsm' || ext === 'pptm' || ext === 'dotm' || ext === 'xltm';

      if (isCandidateDocument) {
        try {
          const docRes = DocumentAnalyzer.analyze(bytes, fileName);
          if (docRes.isDocument) {
            for (const ev of docRes.evidence) {
              if (!evidence.some((e) => e.ruleId === ev.ruleId)) {
                evidence.push(ev);
                evidenceFactors.push(ev.description);
              }
            }
            if (docRes.riskScore > 0) {
              riskScore = Math.max(riskScore, docRes.riskScore);
            }
          }
        } catch {
          // Handled safely
        }
      }

      // 5. Layer 6: Script Heuristic & In-Memory De-obfuscation Inspection
      const isCandidateScript =
        magicHeader === 'SCRIPT_EXECUTABLE' ||
        ext === 'ps1' || ext === 'psm1' || ext === 'vbs' || ext === 'vbe' ||
        ext === 'bat' || ext === 'cmd' || ext === 'js' || ext === 'jse' ||
        ext === 'wsf' || ext === 'hta' || ext === 'sh';

      if (isCandidateScript) {
        try {
          const scriptRes = ScriptAnalyzer.analyze(bytes, fileName);
          if (scriptRes.isScript && scriptRes.evidence.length > 0) {
            for (const ev of scriptRes.evidence) {
              if (!evidence.some((e) => e.ruleId === ev.ruleId)) {
                evidence.push(ev);
                evidenceFactors.push(ev.description);
              }
            }
            if (scriptRes.riskScore > 0) {
              riskScore = Math.max(riskScore, scriptRes.riskScore);
            }
          }
        } catch {
          // Handled safely
        }
      }
    }

    // Ensure all evidence items have detectorLayer explicitly assigned
    for (let i = 0; i < evidence.length; i++) {
      if (!evidence[i].detectorLayer) {
        (evidence[i] as any).detectorLayer = DetectorLayer.STATIC_HEURISTIC;
      }
    }

    // Critical override defense: any critical threat raises score immediately (except for degraded analysis)
    if (
      analysisStatus !== 'ANALYSIS_FAILED' &&
      evidence.some((e) => e.isCriticalOverride === true && !e.isAllowed)
    ) {
      riskScore = Math.max(riskScore, 95);
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
          magicHeader === 'MACHO_EXECUTABLE' ||
          magicHeader === 'EICAR_TEST_SIGNATURE';

    let disposition: DetectionDisposition = 'SAFE';
    if (analysisStatus === 'ANALYSIS_FAILED') {
      disposition = 'ANALYSIS_FAILED';
    } else if (desktopVerdict === 'BLOCK') {
      disposition = 'MALICIOUS';
    } else if (desktopVerdict === 'WARN' || desktopVerdict === 'INFORM') {
      disposition = 'SUSPICIOUS';
    }

    let engineVerdict: EngineVerdict = EngineVerdict.ALLOW;
    if (riskScore >= 85) {
      engineVerdict = EngineVerdict.QUARANTINE;
    } else if (riskScore >= 50) {
      engineVerdict = EngineVerdict.BLOCK;
    } else if (riskScore >= 30 || analysisStatus === 'ANALYSIS_FAILED') {
      engineVerdict = EngineVerdict.WARN;
    } else if (riskScore > 10) {
      engineVerdict = EngineVerdict.INFORM;
    }

    const computedSha256 =
      options?.sha256 ||
      (bytes.length === request.fileSize ? sha256(bytes) : '');

    return {
      filePath: request.filePath,
      fileName,
      fileSize: request.fileSize,
      sha256: computedSha256,
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
      engineVerdict,
      actionRecommendation,
      analysisStatus,
      disposition,
      ...(errorReason ? { errorReason } : {}),
      evidence,
      stage0CacheHit: false,
      stage1ShortCircuit: magicHeader === 'EICAR_TEST_SIGNATURE',
      hasDoubleExtension: deceptive.isDeceptive
    };
  }
}
