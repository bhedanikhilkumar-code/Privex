import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { FileAnalysisResult, ThreatSeverity, ThreatVerdict } from '../types/desktop.types';

export class FileAnalyzer {
  private static readonly MAX_HEADER_READ_BYTES = 64 * 1024; // 64 KB
  private static readonly HIGH_ENTROPY_THRESHOLD = 7.2;

  private static readonly EXECUTABLE_EXTENSIONS = new Set([
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.wsf', '.cpl', '.com', '.msi', '.pif', '.hta', '.jar'
  ]);

  private static readonly DOCUMENT_EXTENSIONS = new Set([
    '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
    '.txt', '.rtf', '.jpg', '.jpeg', '.png', '.gif', '.zip'
  ]);

  /**
   * Computes the Shannon entropy of a byte buffer.
   * Theoretical range: 0.0 to 8.0.
   */
  public static calculateEntropy(buffer: Buffer): number {
    if (buffer.length === 0) return 0;

    const frequencies = new Uint32Array(256);
    for (let i = 0; i < buffer.length; i++) {
      frequencies[buffer[i]]++;
    }

    let entropy = 0;
    const len = buffer.length;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / len;
        entropy -= p * Math.log2(p);
      }
    }

    return Math.round(entropy * 1000) / 1000;
  }

  /**
   * Computes the SHA-256 hash of a file safely.
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
   * Inspects magic header bytes from file buffer.
   */
  public static detectMagicHeader(buffer: Buffer): string | null {
    if (buffer.length < 2) return null;

    // MZ (Windows Portable Executable / DOS)
    if (buffer[0] === 0x4d && buffer[1] === 0x5a) {
      return 'PE/MZ_EXECUTABLE';
    }

    // ELF (Linux / Android executable)
    if (buffer.length >= 4 &&
        buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      return 'ELF_EXECUTABLE';
    }

    // Mach-O (macOS executable)
    if (buffer.length >= 4) {
      if ((buffer[0] === 0xfe && buffer[1] === 0xed && buffer[2] === 0xfa && buffer[3] === 0xce) ||
          (buffer[0] === 0xcf && buffer[1] === 0xfa && buffer[2] === 0xed && buffer[3] === 0xfe) ||
          (buffer[0] === 0xca && buffer[1] === 0xfe && buffer[2] === 0xba && buffer[3] === 0xbe)) {
        return 'MACHO_EXECUTABLE';
      }
    }

    // DEX (Android Dalvik Executable)
    if (buffer.length >= 4 &&
        buffer[0] === 0x64 && buffer[1] === 0x65 && buffer[2] === 0x78 && buffer[3] === 0x0a) {
      return 'DEX_BYTECODE';
    }

    // Shell script / PowerShell / Batch
    const headerStr = buffer.subarray(0, Math.min(buffer.length, 128)).toString('ascii').toLowerCase();
    if (headerStr.startsWith('#!/') || headerStr.includes('powershell') || headerStr.includes('wscript.shell')) {
      return 'SCRIPT_EXECUTABLE';
    }

    return null;
  }

  /**
   * Detects double extension deception (e.g. invoice.pdf.exe).
   */
  public static checkDeceptiveExtension(fileName: string): { isDeceptive: boolean; fakeExt?: string; realExt?: string } {
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
   * Performs complete file analysis without executing the file.
   */
  public static async analyzeFile(filePath: string): Promise<FileAnalysisResult> {
    const stat = await fs.promises.stat(filePath);
    const fileName = path.basename(filePath);
    const ext = path.extname(fileName).toLowerCase();

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

    const sha256 = await this.computeSha256(filePath);
    const entropy = this.calculateEntropy(headerBuffer);
    const magicHeader = this.detectMagicHeader(headerBuffer);
    const deceptive = this.checkDeceptiveExtension(fileName);

    const evidenceFactors: string[] = [];
    let riskScore = 0;
    let threatName = 'BENIGN_FILE';

    // Heuristic 1: Double extension deception
    if (deceptive.isDeceptive) {
      riskScore += 50;
      evidenceFactors.push(`Double extension deception: disguised as '${deceptive.fakeExt}', actual '${deceptive.realExt}'`);
      threatName = 'DECEPTIVE_DOUBLE_EXTENSION';

      // Critical synergy: double extension masking an actual binary header
      const hasExecutableHeader = magicHeader === 'PE/MZ_EXECUTABLE' ||
                                  magicHeader === 'ELF_EXECUTABLE' ||
                                  magicHeader === 'MACHO_EXECUTABLE';
      if (hasExecutableHeader) {
        riskScore += 30; // 50 + 30 + 15 = 95
        evidenceFactors.push(`Deceptive double extension carries active executable payload (${magicHeader})`);
      }
    }

    // Heuristic 2: Disguised executable (claimed doc, but has PE/MZ or ELF header)
    const claimedDocument = this.DOCUMENT_EXTENSIONS.has(ext);
    const hasExecutableHeader = magicHeader === 'PE/MZ_EXECUTABLE' ||
                                magicHeader === 'ELF_EXECUTABLE' ||
                                magicHeader === 'MACHO_EXECUTABLE';

    if (claimedDocument && hasExecutableHeader) {
      riskScore += 65;
      evidenceFactors.push(`Executable disguise: claimed '${ext}' extension but contains executable header (${magicHeader})`);
      threatName = 'DISGUISED_EXECUTABLE';
    }

    // Heuristic 3: Suspicious executable extension
    const isDeclaredExecutable = this.EXECUTABLE_EXTENSIONS.has(ext);
    if (isDeclaredExecutable) {
      evidenceFactors.push(`Executable extension detected: '${ext}'`);
      riskScore += 15;
    }

    // Heuristic 4: High byte entropy
    if (entropy > this.HIGH_ENTROPY_THRESHOLD && (isDeclaredExecutable || hasExecutableHeader)) {
      riskScore += 30;
      evidenceFactors.push(`High Shannon entropy (${entropy} / 8.0) indicates packed, encrypted, or obfuscated payload`);
      if (threatName === 'BENIGN_FILE') {
        threatName = 'OBFUSCATED_SUSPICIOUS_PAYLOAD';
      }
    }

    // Bound score
    riskScore = Math.min(100, Math.max(0, riskScore));

    // Determine severity and verdict
    let severity: ThreatSeverity = 'safe';
    let verdict: ThreatVerdict = 'ALLOW';

    if (riskScore >= 75) {
      severity = 'critical';
      verdict = 'BLOCK';
    } else if (riskScore >= 50) {
      severity = 'dangerous';
      verdict = 'BLOCK';
    } else if (riskScore >= 30) {
      severity = 'suspicious';
      verdict = 'WARN';
    } else if (riskScore > 10) {
      severity = 'low';
      verdict = 'INFORM';
    }

    if (evidenceFactors.length === 0) {
      evidenceFactors.push('Clean header structure, normal byte entropy, valid extension');
    }

    return {
      filePath,
      fileName,
      fileSize: stat.size,
      sha256,
      entropy,
      magicHeader,
      isExecutable: isDeclaredExecutable || hasExecutableHeader,
      isDeceptiveExtension: deceptive.isDeceptive,
      riskScore,
      severity,
      verdict,
      threatName,
      evidenceFactors
    };
  }
}
