import * as fs from 'fs';
import * as path from 'path';
import { FileAnalyzer } from './file-analyzer';
import { ShortcutWormAnalysisResult, FileAnalysisResult } from '../types/desktop.types';

/**
 * Safe, Bounds-Checked Binary Windows Shell Link (.LNK) Parser (Phase M).
 *
 * Implements MS-SHLLINK binary specification parsing for detecting USB shortcut worms,
 * LOLBin invocation chains, directory traversal, and deceptive folder icon masking.
 * Never executes any shortcut target and enforces strict bounds checks on all offsets.
 */
export class LnkParser {
  public static readonly MAX_LNK_SIZE = 1024 * 1024; // 1 MB limit
  public static readonly HEADER_SIZE = 0x0000004c; // 76 bytes

  // LinkCLSID: 00021401-0000-0000-C000-000000000046
  private static readonly LNK_CLSID = Buffer.from([
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
  ]);

  private static readonly RTLO_PATTERN = /[\u202E\u202B\u200E\u200F\u2066\u2067\u2068\u2069]/g;
  private static readonly UNC_PATTERN = /^(?:\\\\|\/\/)/;
  private static readonly DEVICE_PATH_PATTERN = /^\\\\\?\\/i;
  private static readonly TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

  private static readonly SCRIPT_INTERPRETERS = new Set([
    'wscript.exe',
    'wscript',
    'cscript.exe',
    'cscript',
    'powershell.exe',
    'powershell',
    'cmd.exe',
    'cmd',
    'mshta.exe',
    'mshta',
    'rundll32.exe',
    'rundll32',
    'certutil.exe',
    'certutil',
    'regsvr32.exe',
    'regsvr32',
    'bitsadmin.exe',
    'bitsadmin'
  ]);

  private static readonly WORM_SPOOFED_NAMES = new Set([
    'documents.lnk',
    'my documents.lnk',
    'pictures.lnk',
    'my pictures.lnk',
    'music.lnk',
    'videos.lnk',
    'desktop.lnk',
    'downloads.lnk',
    'flash drive.lnk',
    'usb.lnk',
    'usb drive.lnk',
    'removable disk.lnk',
    'files.lnk',
    'data.lnk',
    'backup.lnk'
  ]);

  public static sanitizeString(input: string): string {
    if (!input || typeof input !== 'string') return '';
    return input
      .replace(/\0/g, '')
      .replace(this.RTLO_PATTERN, '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .trim();
  }

  /**
   * Safely parses a .lnk file from disk.
   */
  public static async parseFile(
    filePath: string,
    baseDir?: string
  ): Promise<ShortcutWormAnalysisResult> {
    const effectiveBase = baseDir || path.dirname(filePath);

    if (!fs.existsSync(filePath)) {
      return {
        isShortcut: false,
        filePath,
        isSuspicious: false,
        riskScore: 0,
        indicators: [],
        evidenceFactors: []
      };
    }

    try {
      const stat = await fs.promises.stat(filePath);
      if (!stat.isFile() || stat.size > this.MAX_LNK_SIZE) {
        return {
          isShortcut: true,
          filePath,
          isSuspicious: true,
          riskScore: 60,
          indicators: ['LNK_OVERSIZED_OR_INVALID'],
          evidenceFactors: [
            `Shortcut file exceeds maximum allowed size of ${this.MAX_LNK_SIZE} bytes (size=${stat.size})`
          ]
        };
      }

      const buffer = await fs.promises.readFile(filePath);
      return this.parseBuffer(buffer, filePath, effectiveBase);
    } catch (err: any) {
      return {
        isShortcut: true,
        filePath,
        isSuspicious: true,
        riskScore: 40,
        indicators: ['LNK_READ_ERROR'],
        evidenceFactors: [`Failed to read .lnk shortcut file: ${err?.message || 'I/O error'}`]
      };
    }
  }

  /**
   * Parses binary .lnk byte buffer with defensive bounds checking.
   */
  public static async parseBuffer(
    buffer: Buffer,
    filePath = 'memory.lnk',
    baseDir?: string
  ): Promise<ShortcutWormAnalysisResult> {
    const indicators: string[] = [];
    const evidenceFactors: string[] = [];

    // Header size check
    if (buffer.length < this.HEADER_SIZE) {
      return {
        isShortcut: false,
        filePath,
        isSuspicious: true,
        riskScore: 35,
        indicators: ['LNK_TRUNCATED_HEADER'],
        evidenceFactors: [`Shortcut file is smaller than minimum 76-byte header (${buffer.length} bytes)`]
      };
    }

    const headerSize = buffer.readUInt32LE(0);
    if (headerSize !== this.HEADER_SIZE) {
      return {
        isShortcut: false,
        filePath,
        isSuspicious: false,
        riskScore: 0,
        indicators: ['NOT_A_VALID_LNK_HEADER'],
        evidenceFactors: []
      };
    }

    // Verify LinkCLSID
    const clsid = buffer.subarray(4, 20);
    if (!clsid.equals(this.LNK_CLSID)) {
      return {
        isShortcut: false,
        filePath,
        isSuspicious: false,
        riskScore: 0,
        indicators: ['INVALID_LNK_CLSID'],
        evidenceFactors: []
      };
    }

    const linkFlags = buffer.readUInt32LE(0x14);
    const hasLinkTargetIDList = (linkFlags & 0x01) !== 0;
    const hasLinkInfo = (linkFlags & 0x02) !== 0;
    const hasName = (linkFlags & 0x04) !== 0;
    const hasRelativePath = (linkFlags & 0x08) !== 0;
    const hasWorkingDir = (linkFlags & 0x10) !== 0;
    const hasArguments = (linkFlags & 0x20) !== 0;
    const hasIconLocation = (linkFlags & 0x40) !== 0;
    const isUnicode = (linkFlags & 0x80) !== 0;

    let offset = this.HEADER_SIZE;
    let targetPath: string | undefined;

    // 1. LinkTargetIDList structure
    if (hasLinkTargetIDList) {
      if (offset + 2 > buffer.length) {
        return this.createTruncatedResult(filePath, offset, buffer.length);
      }
      const idListSize = buffer.readUInt16LE(offset);
      offset += 2;
      if (offset + idListSize > buffer.length) {
        return this.createTruncatedResult(filePath, offset + idListSize, buffer.length);
      }
      offset += idListSize;
    }

    // 2. LinkInfo structure
    if (hasLinkInfo) {
      if (offset + 4 > buffer.length) {
        return this.createTruncatedResult(filePath, offset, buffer.length);
      }
      const linkInfoSize = buffer.readUInt32LE(offset);
      if (offset + linkInfoSize <= buffer.length && linkInfoSize >= 28) {
        const linkInfoHeaderSize = buffer.readUInt32LE(offset + 4);
        const localBasePathOffset = buffer.readUInt32LE(offset + 16);

        if (localBasePathOffset > 0 && offset + localBasePathOffset < buffer.length) {
          const basePathStart = offset + localBasePathOffset;
          let basePathEnd = basePathStart;
          while (basePathEnd < buffer.length && buffer[basePathEnd] !== 0) {
            basePathEnd++;
          }
          targetPath = this.sanitizeString(buffer.subarray(basePathStart, basePathEnd).toString('ascii'));
        } else if (linkInfoHeaderSize >= 36 && offset + 36 <= buffer.length) {
          const localBasePathUnicodeOffset = buffer.readUInt32LE(offset + 28);
          if (localBasePathUnicodeOffset > 0 && offset + localBasePathUnicodeOffset < buffer.length) {
            const basePathStart = offset + localBasePathUnicodeOffset;
            let basePathEnd = basePathStart;
            while (basePathEnd + 1 < buffer.length && !(buffer[basePathEnd] === 0 && buffer[basePathEnd + 1] === 0)) {
              basePathEnd += 2;
            }
            targetPath = this.sanitizeString(buffer.subarray(basePathStart, basePathEnd).toString('utf16le'));
          }
        }
      }
      offset += linkInfoSize;
    }

    // Helper to read string data
    const readStringData = (currOffset: number): { str: string; nextOffset: number } => {
      if (currOffset + 2 > buffer.length) {
        return { str: '', nextOffset: buffer.length };
      }
      const charCount = buffer.readUInt16LE(currOffset);
      const byteCount = isUnicode ? charCount * 2 : charCount;
      const strStart = currOffset + 2;
      const nextOffset = strStart + byteCount;

      if (nextOffset > buffer.length) {
        return { str: '', nextOffset: buffer.length };
      }

      const raw = isUnicode
        ? buffer.subarray(strStart, nextOffset).toString('utf16le')
        : buffer.subarray(strStart, nextOffset).toString('ascii');

      return { str: this.sanitizeString(raw), nextOffset };
    };

    let nameDescription: string | undefined;
    let relativePath: string | undefined;
    let workingDirectory: string | undefined;
    let commandLineArguments: string | undefined;
    let iconLocation: string | undefined;

    if (hasName && offset < buffer.length) {
      const res = readStringData(offset);
      nameDescription = res.str;
      offset = res.nextOffset;
    }

    if (hasRelativePath && offset < buffer.length) {
      const res = readStringData(offset);
      relativePath = res.str;
      offset = res.nextOffset;
    }

    if (hasWorkingDir && offset < buffer.length) {
      const res = readStringData(offset);
      workingDirectory = res.str;
      offset = res.nextOffset;
    }

    if (hasArguments && offset < buffer.length) {
      const res = readStringData(offset);
      commandLineArguments = res.str;
      offset = res.nextOffset;
    }

    if (hasIconLocation && offset < buffer.length) {
      const res = readStringData(offset);
      iconLocation = res.str;
      offset = res.nextOffset;
    }

    // Evaluate Threat Indicators & Risk Scoring
    let riskScore = 0;
    const baseName = path.basename(filePath).toLowerCase();

    // 1. Check Worm Spoofed Name (e.g. Documents.lnk replacing folder)
    if (this.WORM_SPOOFED_NAMES.has(baseName)) {
      indicators.push('LNK_WORM_SPOOFED_FOLDER_NAME');
      evidenceFactors.push(`Shortcut uses common folder/drive name deception: ${path.basename(filePath)}`);
      riskScore = Math.max(riskScore, 65);
    }

    // 2. Check Target & Script Interpreter Invocation
    const resolvedTarget = targetPath || relativePath || '';
    const baseTargetName = path.basename(resolvedTarget).toLowerCase();

    if (this.SCRIPT_INTERPRETERS.has(baseTargetName)) {
      indicators.push('LNK_INVOKES_SCRIPT_INTERPRETER');
      evidenceFactors.push(`Shortcut targets script interpreter/LOLBin: ${baseTargetName}`);
      riskScore = Math.max(riskScore, 85);
    }

    // 3. Check Command Line Arguments
    if (commandLineArguments) {
      const argsLower = commandLineArguments.toLowerCase();
      if (
        argsLower.includes('-enc') ||
        argsLower.includes('-encodedcommand') ||
        argsLower.includes('hidden') ||
        argsLower.includes('downloadstring') ||
        argsLower.includes('iex') ||
        argsLower.includes('/c start') ||
        argsLower.includes('//e:vbs') ||
        argsLower.includes('powershell') ||
        argsLower.includes('wscript') ||
        argsLower.includes('cscript') ||
        argsLower.includes('bypass') ||
        argsLower.includes('executionpolicy') ||
        argsLower.includes('-file') ||
        argsLower.includes('.vbs') ||
        argsLower.includes('.ps1') ||
        argsLower.includes('.bat') ||
        argsLower.includes('.cmd') ||
        argsLower.includes('.hta') ||
        argsLower.includes('%temp%') ||
        argsLower.includes('%appdata%')
      ) {
        indicators.push('LNK_SUSPICIOUS_CLI_ARGUMENTS');
        evidenceFactors.push(`Shortcut executes suspicious CLI payload: ${commandLineArguments}`);
        riskScore = Math.max(riskScore, 90);
      }
    }

    // 4. Check UNC or Traversal Target
    if (resolvedTarget) {
      if (this.UNC_PATTERN.test(resolvedTarget) || this.DEVICE_PATH_PATTERN.test(resolvedTarget)) {
        indicators.push('LNK_UNC_OR_DEVICE_TARGET');
        evidenceFactors.push(`Shortcut targets remote UNC or raw device path: ${resolvedTarget}`);
        riskScore = Math.max(riskScore, 75);
      }

      if (this.TRAVERSAL_PATTERN.test(resolvedTarget) || resolvedTarget.startsWith('..\\..')) {
        indicators.push('LNK_RELATIVE_TRAVERSAL_TARGET');
        evidenceFactors.push(`Shortcut targets parent directory traversal: ${resolvedTarget}`);
        riskScore = Math.max(riskScore, 80);
      }
    }

    // 5. Check Deceptive Folder Icon Masking
    if (iconLocation) {
      const iconLower = iconLocation.toLowerCase();
      if (
        (iconLower.includes('shell32.dll') || iconLower.includes('imageres.dll')) &&
        (riskScore >= 50 || this.SCRIPT_INTERPRETERS.has(baseTargetName) || Boolean(commandLineArguments))
      ) {
        indicators.push('LNK_DECEPTIVE_FOLDER_ICON_MASK');
        evidenceFactors.push(`Shortcut masks executable/script payload with system folder icon: ${iconLocation}`);
        riskScore = Math.max(riskScore, 85);
      }
    }

    // 6. Deep inspection of referenced target if on disk
    let deepestTargetAnalysis: FileAnalysisResult | undefined;
    if (baseDir && resolvedTarget) {
      const candPaths = [
        path.resolve(baseDir, resolvedTarget),
        path.join(baseDir, path.basename(resolvedTarget))
      ];

      for (const cand of candPaths) {
        try {
          if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
            const fileAnalysis = await FileAnalyzer.analyzeFile(cand, { inspectMotw: false, inspectEmail: false });
            if (!deepestTargetAnalysis || fileAnalysis.riskScore > deepestTargetAnalysis.riskScore) {
              deepestTargetAnalysis = fileAnalysis;
            }
            if (fileAnalysis.verdict === 'BLOCK' || fileAnalysis.riskScore >= 70) {
              indicators.push('LNK_TARGET_PAYLOAD_MALICIOUS');
              evidenceFactors.push(
                `Shortcut payload '${path.basename(cand)}' analyzed as ${fileAnalysis.verdict} (score=${fileAnalysis.riskScore})`
              );
              riskScore = Math.max(riskScore, fileAnalysis.riskScore, 90);
            }
          }
        } catch {
          // Ignore probe errors
        }
      }
    }

    const isSuspicious = riskScore >= 50;

    return {
      isShortcut: true,
      filePath,
      targetPath: resolvedTarget || undefined,
      arguments: commandLineArguments,
      workingDirectory,
      iconLocation,
      description: nameDescription,
      isSuspicious,
      riskScore,
      indicators,
      evidenceFactors,
      targetAnalysis: deepestTargetAnalysis
    };
  }

  private static createTruncatedResult(
    filePath: string,
    offset: number,
    totalBytes: number
  ): ShortcutWormAnalysisResult {
    return {
      isShortcut: true,
      filePath,
      isSuspicious: true,
      riskScore: 50,
      indicators: ['LNK_CORRUPTED_OR_TRUNCATED_STRUCTURE'],
      evidenceFactors: [
        `Shortcut file structure truncated: offset ${offset} exceeds total length ${totalBytes} bytes`
      ]
    };
  }
}
