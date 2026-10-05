import { DetectorLayer, DetectorType, Evidence, SeverityLevel } from '../types';

export interface ArchiveEntryInfo {
  readonly fileName: string;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly compressionMethod: number;
  readonly isDirectory: boolean;
  readonly isExecutableOrScript: boolean;
  readonly hasPathTraversal: boolean;
  readonly hasDoubleExtension: boolean;
  readonly hasRtlo: boolean;
  readonly isNestedArchive: boolean;
}

export interface ArchiveAnalysisResult {
  readonly isArchive: boolean;
  readonly archiveFormat: 'ZIP' | 'UNKNOWN';
  readonly entryCount: number;
  readonly totalCompressedSize: number;
  readonly totalUncompressedSize: number;
  readonly compressionRatio: number;
  readonly entries: ArchiveEntryInfo[];
  readonly hasZipBombCharacteristics: boolean;
  readonly hasPathTraversal: boolean;
  readonly hasDisguisedExecutables: boolean;
  readonly isMalformed: boolean;
  readonly malformedReason?: string;
  readonly evidence: Evidence[];
}

const DANGEROUS_ARCHIVE_EXTENSIONS = new Set([
  '.exe',
  '.dll',
  '.scr',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.vbe',
  '.js',
  '.jse',
  '.wsf',
  '.cpl',
  '.msi',
  '.pif',
  '.hta',
  '.jar',
  '.apk',
  '.dex',
  '.sh',
  '.lnk',
  '.reg'
]);

const NESTED_ARCHIVE_EXTENSIONS = new Set([
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.7z',
  '.rar',
  '.iso',
  '.cab'
]);

const RTLO_BIDI_PATTERN = /[\u202A-\u202E\u2066-\u2069]/;

/**
 * High-Performance, Bounds-Checked Archive & ZIP Structural Parser (Layer 5 / Phase C)
 *
 * Safely parses ZIP Central Directory headers in memory without extracting
 * untrusted archive files to disk.
 * Defends against:
 * 1. Zip bombs (compression ratio > 100:1 or total uncompressed > 100 MB).
 * 2. Path traversal (../, ..\, absolute paths, drive letters, UNC paths).
 * 3. Disguised executables and scripts inside compressed containers.
 * 4. Nested archive nesting and entry flooding (> 1,000 entries).
 */
export class ArchiveAnalyzer {
  public static readonly MAX_ENTRIES_LIMIT = 1000;
  public static readonly MAX_UNCOMPRESSED_TOTAL_BYTES = 100 * 1024 * 1024; // 100 MB
  public static readonly ZIP_BOMB_RATIO_THRESHOLD = 100; // 100:1 ratio

  public static analyze(buffer: Uint8Array | number[]): ArchiveAnalysisResult {
    const defaultFailResult = (reason: string, isZip: boolean = false): ArchiveAnalysisResult => ({
      isArchive: isZip,
      archiveFormat: isZip ? 'ZIP' : 'UNKNOWN',
      entryCount: 0,
      totalCompressedSize: 0,
      totalUncompressedSize: 0,
      compressionRatio: 1.0,
      entries: [],
      hasZipBombCharacteristics: false,
      hasPathTraversal: false,
      hasDisguisedExecutables: false,
      isMalformed: isZip,
      malformedReason: reason,
      evidence: isZip
        ? [
            {
              ruleId: 'archive-malformed-structure',
              detectorType: DetectorType.HEURISTIC,
              detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
              source: 'ARCHIVE_ANALYZER',
              name: 'Malformed Archive Structure',
              description: `Archive structural validation failed safely: ${reason}`,
              reason,
              severityLevel: SeverityLevel.MEDIUM,
              weight: 50,
              scoreContribution: 50,
              confidence: 0.8,
              isMalicious: false
            }
          ]
        : []
    });

    if (!buffer || buffer.length < 22) {
      return defaultFailResult('Buffer too small for archive header');
    }

    const uint8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const view = new DataView(uint8.buffer, uint8.byteOffset, uint8.byteLength);

    // Verify ZIP Local Header Magic: 'PK\x03\x04' (0x04034b50)
    const isZipLocal =
      uint8[0] === 0x50 && uint8[1] === 0x4b && uint8[2] === 0x03 && uint8[3] === 0x04;

    // Verify ZIP Empty or Spanned Header Magic: 'PK\x05\x06' (0x06054b50)
    const isZipEocd =
      uint8[0] === 0x50 && uint8[1] === 0x4b && uint8[2] === 0x05 && uint8[3] === 0x06;

    if (!isZipLocal && !isZipEocd) {
      return defaultFailResult('Not a recognized ZIP archive');
    }

    // 1. Locate End of Central Directory Record (EOCD: 0x06054b50) scanning backwards
    const maxSearch = Math.min(uint8.length, 65557);
    let eocdOffset = -1;

    for (let i = uint8.length - 22; i >= uint8.length - maxSearch; i--) {
      if (
        uint8[i] === 0x50 &&
        uint8[i + 1] === 0x4b &&
        uint8[i + 2] === 0x05 &&
        uint8[i + 3] === 0x06
      ) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset === -1) {
      return defaultFailResult('ZIP End of Central Directory (EOCD) record not found', true);
    }

    // 2. Parse EOCD fields
    const entryCount = view.getUint16(eocdOffset + 10, true);
    const cdSize = view.getUint32(eocdOffset + 12, true);
    const cdOffset = view.getUint32(eocdOffset + 16, true);

    if (cdOffset + cdSize > uint8.length) {
      return defaultFailResult('Central Directory offset extends past archive buffer bounds', true);
    }

    const entries: ArchiveEntryInfo[] = [];
    const evidence: Evidence[] = [];

    let totalCompressed = 0;
    let totalUncompressed = 0;
    let hasZipBomb = false;
    let hasPathTraversal = false;
    let hasDisguisedExecutables = false;
    let cursor = cdOffset;

    // 3. Excessive entry count check
    if (entryCount > ArchiveAnalyzer.MAX_ENTRIES_LIMIT) {
      hasZipBomb = true;
      evidence.push({
        ruleId: 'archive-excessive-entry-count',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'Excessive Archive Entry Count',
        description: `Archive declares ${entryCount} entries, exceeding safe limit (${ArchiveAnalyzer.MAX_ENTRIES_LIMIT})`,
        reason: 'Possible archive decompression bomb attempt',
        severityLevel: SeverityLevel.HIGH,
        weight: 75,
        scoreContribution: 75,
        confidence: 0.9,
        isMalicious: true
      });
    }

    // 4. Iterate Central Directory File Headers (Magic: 0x02014b50)
    const maxEntriesToScan = Math.min(entryCount, ArchiveAnalyzer.MAX_ENTRIES_LIMIT);

    for (let i = 0; i < maxEntriesToScan; i++) {
      if (cursor + 46 > uint8.length) {
        break;
      }

      // Check Central Directory signature 'PK\x01\x02'
      if (
        uint8[cursor] !== 0x50 ||
        uint8[cursor + 1] !== 0x4b ||
        uint8[cursor + 2] !== 0x01 ||
        uint8[cursor + 3] !== 0x02
      ) {
        break;
      }

      const compressionMethod = view.getUint16(cursor + 10, true);
      const compressedSize = view.getUint32(cursor + 20, true);
      const uncompressedSize = view.getUint32(cursor + 24, true);
      const fileNameLength = view.getUint16(cursor + 28, true);
      const extraFieldLength = view.getUint16(cursor + 30, true);
      const fileCommentLength = view.getUint16(cursor + 32, true);

      totalCompressed += compressedSize;
      totalUncompressed += uncompressedSize;

      // Extract filename safely
      let fileName = '';
      if (cursor + 46 + fileNameLength <= uint8.length) {
        const nameBytes = uint8.subarray(cursor + 46, cursor + 46 + fileNameLength);
        fileName = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
      }

      const isDirectory = fileName.endsWith('/') || fileName.endsWith('\\');

      // Traversal Checks
      const hasDotDot = fileName.includes('../') || fileName.includes('..\\');
      const hasRoot = fileName.startsWith('/') || fileName.startsWith('\\') || /^[a-zA-Z]:/.test(fileName);
      const hasUnc = fileName.startsWith('\\\\');
      const entryHasTraversal = hasDotDot || hasRoot || hasUnc;

      if (entryHasTraversal) {
        hasPathTraversal = true;
      }

      // Dangerous extension checks
      const lowerName = fileName.toLowerCase();
      let isExecutableOrScript = false;
      for (const ext of DANGEROUS_ARCHIVE_EXTENSIONS) {
        if (lowerName.endsWith(ext)) {
          isExecutableOrScript = true;
          hasDisguisedExecutables = true;
          break;
        }
      }

      // Double extension check (e.g. invoice.pdf.exe)
      const hasDoubleExtension =
        /\.(pdf|docx?|xlsx?|txt|jpg|png)\.(exe|scr|bat|cmd|ps1|vbs|js)$/i.test(fileName);
      if (hasDoubleExtension) {
        hasDisguisedExecutables = true;
      }

      // RTLO check
      const hasRtlo = RTLO_BIDI_PATTERN.test(fileName);
      if (hasRtlo) {
        hasDisguisedExecutables = true;
      }

      // Nested archive check
      let isNestedArchive = false;
      for (const ext of NESTED_ARCHIVE_EXTENSIONS) {
        if (lowerName.endsWith(ext)) {
          isNestedArchive = true;
          break;
        }
      }

      // Per-entry compression bomb check
      if (uncompressedSize > 10000 && uncompressedSize / Math.max(1, compressedSize) > ArchiveAnalyzer.ZIP_BOMB_RATIO_THRESHOLD) {
        hasZipBomb = true;
      }

      entries.push({
        fileName,
        compressedSize,
        uncompressedSize,
        compressionMethod,
        isDirectory,
        isExecutableOrScript,
        hasPathTraversal: entryHasTraversal,
        hasDoubleExtension,
        hasRtlo,
        isNestedArchive
      });

      cursor += 46 + fileNameLength + extraFieldLength + fileCommentLength;
    }

    // 5. Total Compression Ratio & Size Check
    const overallRatio =
      totalCompressed > 0 ? Math.round((totalUncompressed / totalCompressed) * 100) / 100 : 1.0;

    if (overallRatio > ArchiveAnalyzer.ZIP_BOMB_RATIO_THRESHOLD && totalUncompressed > 1000000) {
      hasZipBomb = true;
      evidence.push({
        ruleId: 'archive-zip-bomb',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'High Compression Ratio Zip Bomb',
        description: `Archive exhibits extreme compression ratio (${overallRatio}:1), characteristic of decompression bombs`,
        reason: 'Decompression ratio exceeds 100:1 safety limit',
        severityLevel: SeverityLevel.CRITICAL,
        weight: 90,
        scoreContribution: 90,
        confidence: 0.95,
        isMalicious: true
      });
      evidence.push({
        ruleId: 'archive-zip-bomb-ratio-detected',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'High Compression Ratio Zip Bomb',
        description: `Archive exhibits extreme compression ratio (${overallRatio}:1)`,
        reason: 'Decompression ratio exceeds 100:1 safety limit',
        severityLevel: SeverityLevel.CRITICAL,
        weight: 90,
        scoreContribution: 90,
        confidence: 0.95,
        isMalicious: true
      });
    }

    if (totalUncompressed > ArchiveAnalyzer.MAX_UNCOMPRESSED_TOTAL_BYTES) {
      hasZipBomb = true;
      evidence.push({
        ruleId: 'archive-excessive-size',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'Excessive Total Uncompressed Size',
        description: `Total declared uncompressed size (${Math.round(totalUncompressed / 1024 / 1024)} MB) exceeds 100 MB sandbox limit`,
        reason: 'Uncompressed payload exceeds memory and disk safety thresholds',
        severityLevel: SeverityLevel.HIGH,
        weight: 75,
        scoreContribution: 75,
        confidence: 0.9,
        isMalicious: true
      });
      evidence.push({
        ruleId: 'archive-zip-bomb-size-detected',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'Excessive Total Uncompressed Size',
        description: `Total declared uncompressed size exceeds limit`,
        reason: 'Uncompressed payload exceeds memory and disk safety thresholds',
        severityLevel: SeverityLevel.HIGH,
        weight: 75,
        scoreContribution: 75,
        confidence: 0.9,
        isMalicious: true
      });
    }

    // 6. Path Traversal Alert
    if (hasPathTraversal) {
      const badEntry = entries.find((e) => e.hasPathTraversal);
      evidence.push({
        ruleId: 'archive-path-traversal',
        detectorType: DetectorType.RULE,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'Archive Path Traversal Payload',
        description: `Archive entry contains directory traversal path: "${badEntry?.fileName || 'unknown'}"`,
        reason: 'Archive contains paths attempting escape from extraction directory',
        severityLevel: SeverityLevel.CRITICAL,
        weight: 95,
        scoreContribution: 95,
        confidence: 1.0,
        isCriticalOverride: true,
        isMalicious: true
      });
      evidence.push({
        ruleId: 'archive-path-traversal-detected',
        detectorType: DetectorType.RULE,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'ARCHIVE_ANALYZER',
        name: 'Archive Path Traversal Payload',
        description: `Archive entry contains directory traversal path: "${badEntry?.fileName || 'unknown'}"`,
        reason: 'Archive contains paths attempting escape from extraction directory',
        severityLevel: SeverityLevel.CRITICAL,
        weight: 95,
        scoreContribution: 95,
        confidence: 1.0,
        isCriticalOverride: true,
        isMalicious: true
      });
    }

    // 7. Disguised Executable, Double Extension, RTLO, or Nested Containers
    for (const entry of entries) {
      if (entry.isExecutableOrScript) {
        evidence.push({
          ruleId: 'archive-dangerous-executable',
          detectorType: DetectorType.RULE,
          detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
          source: 'ARCHIVE_ANALYZER',
          name: 'Dangerous Executable in Archive',
          description: `Archive contains executable or script payload: "${entry.fileName}"`,
          reason: 'Adversaries deliver weaponized executables in compressed archives to evade perimeter filters',
          severityLevel: SeverityLevel.HIGH,
          weight: 75,
          scoreContribution: 75,
          confidence: 0.9,
          isMalicious: true
        });
      }
      if (entry.hasDoubleExtension) {
        evidence.push({
          ruleId: 'archive-double-extension',
          detectorType: DetectorType.RULE,
          detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
          source: 'ARCHIVE_ANALYZER',
          name: 'Deceptive Double Extension in Archive',
          description: `Archive entry has deceptive double extension: "${entry.fileName}"`,
          reason: 'Double extension masks executable payloads as documents',
          severityLevel: SeverityLevel.HIGH,
          weight: 70,
          scoreContribution: 70,
          confidence: 0.95,
          isMalicious: true
        });
      }
      if (entry.hasRtlo) {
        evidence.push({
          ruleId: 'archive-rtlo-spoof',
          detectorType: DetectorType.RULE,
          detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
          source: 'ARCHIVE_ANALYZER',
          name: 'Unicode RTLO Spoofing in Archive',
          description: `Archive entry uses RTLO bidi character: "${entry.fileName}"`,
          reason: 'RTLO characters invert extension display in file managers',
          severityLevel: SeverityLevel.CRITICAL,
          weight: 80,
          scoreContribution: 80,
          confidence: 0.98,
          isCriticalOverride: true,
          isMalicious: true
        });
      }
      if (entry.isNestedArchive) {
        evidence.push({
          ruleId: 'archive-nested-container',
          detectorType: DetectorType.HEURISTIC,
          detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
          source: 'ARCHIVE_ANALYZER',
          name: 'Nested Archive Container',
          description: `Archive contains nested archive container: "${entry.fileName}"`,
          reason: 'Adversaries nest archives multiple levels deep to exhaust scanner timeouts',
          severityLevel: SeverityLevel.MEDIUM,
          weight: 35,
          scoreContribution: 35,
          confidence: 0.8,
          isMalicious: false
        });
      }
    }

    return {
      isArchive: true,
      archiveFormat: 'ZIP',
      entryCount,
      totalCompressedSize: totalCompressed,
      totalUncompressedSize: totalUncompressed,
      compressionRatio: overallRatio,
      entries,
      hasZipBombCharacteristics: hasZipBomb,
      hasPathTraversal,
      hasDisguisedExecutables,
      isMalformed: false,
      evidence
    };
  }
}
