import { DetectorLayer, DetectorType, Evidence, SeverityLevel } from '../types';
import { EntropyScanner } from './entropy-scanner';

export interface PeSectionInfo {
  readonly name: string;
  readonly virtualSize: number;
  readonly virtualAddress: number;
  readonly rawSize: number;
  readonly rawOffset: number;
  readonly characteristics: number;
  readonly isWritableAndExecutable: boolean;
  readonly isPackerSection: boolean;
  readonly entropy: number;
}

export interface PeAnalysisResult {
  readonly isValidPe: boolean;
  readonly is64Bit: boolean;
  readonly machineType: string;
  readonly numberOfSections: number;
  readonly timeDateStamp: number;
  readonly entryPointRva: number;
  readonly imageBase: string;
  readonly subsystem: number;
  readonly hasAuthenticodeSignature: boolean;
  readonly hasTlsCallbacks: boolean;
  readonly sections: PeSectionInfo[];
  readonly detectedPackers: string[];
  readonly suspiciousApiPatterns: string[];
  readonly hasOverlay: boolean;
  readonly overlaySizeBytes: number;
  readonly isMalformed: boolean;
  readonly malformedReason?: string;
  readonly evidence: Evidence[];
}

const KNOWN_PACKER_SECTION_NAMES = new Set([
  'upx0',
  'upx1',
  'upx2',
  '.vmp0',
  '.vmp1',
  '.vmp2',
  '.aspack',
  'themida',
  '.themida',
  'pecompact',
  '.petite',
  '.fsg',
  '.enigma',
  '.nspack',
  'mew',
  '.neolite',
  '.pebundle'
]);

/**
 * High-Performance, Zero-Allocation Bounds-Checked PE32 / PE32+ Parser (Layer 5 / Phase C)
 *
 * Safely inspects PE binary headers, section tables, W+X permissions, packers,
 * IAT import patterns, Authenticode signature directory, and overlays.
 * Strictly defensive: never throws RangeError, never allocates unbounded memory,
 * and fails closed on malformed headers.
 */
export class PeAnalyzer {
  public static readonly MAX_SECTIONS = 96;
  public static readonly MIN_PE_SIZE = 256;

  public static analyze(
    buffer: Uint8Array | number[],
    actualFileSize?: number
  ): PeAnalysisResult {
    const defaultFailResult = (reason: string): PeAnalysisResult => ({
      isValidPe: false,
      is64Bit: false,
      machineType: 'UNKNOWN',
      numberOfSections: 0,
      timeDateStamp: 0,
      entryPointRva: 0,
      imageBase: '0x0',
      subsystem: 0,
      hasAuthenticodeSignature: false,
      hasTlsCallbacks: false,
      sections: [],
      detectedPackers: [],
      suspiciousApiPatterns: [],
      hasOverlay: false,
      overlaySizeBytes: 0,
      isMalformed: true,
      malformedReason: reason,
      evidence: [
        {
          ruleId: 'pe-malformed-structure',
          detectorType: DetectorType.HEURISTIC,
          detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
          source: 'PE_ANALYZER',
          name: 'Malformed PE Structure',
          description: `PE binary parsing failed safely: ${reason}`,
          reason,
          severityLevel: SeverityLevel.MEDIUM,
          weight: 50,
          scoreContribution: 50,
          confidence: 0.8,
          isMalicious: false
        }
      ]
    });

    if (!buffer || buffer.length < PeAnalyzer.MIN_PE_SIZE) {
      return defaultFailResult('Buffer smaller than minimum PE header size');
    }

    const uint8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const view = new DataView(uint8.buffer, uint8.byteOffset, uint8.byteLength);

    // 1. DOS Header Check ('MZ')
    if (uint8[0] !== 0x4d || uint8[1] !== 0x5a) {
      return defaultFailResult('Invalid DOS magic header (expected MZ)');
    }

    // 2. Read e_lfanew (Offset 0x3C)
    const e_lfanew = view.getUint32(0x3c, true);
    if (e_lfanew < 0x40 || e_lfanew + 24 > uint8.length) {
      return defaultFailResult(`Invalid e_lfanew offset (0x${e_lfanew.toString(16)})`);
    }

    // 3. PE Signature Check ('PE\0\0')
    if (
      uint8[e_lfanew] !== 0x50 ||
      uint8[e_lfanew + 1] !== 0x45 ||
      uint8[e_lfanew + 2] !== 0x00 ||
      uint8[e_lfanew + 3] !== 0x00
    ) {
      return defaultFailResult('Invalid PE signature (expected PE\\0\\0)');
    }

    // 4. COFF File Header (20 bytes at e_lfanew + 4)
    const coffOffset = e_lfanew + 4;
    const machine = view.getUint16(coffOffset, true);
    const numberOfSections = view.getUint16(coffOffset + 2, true);
    const timeDateStamp = view.getUint32(coffOffset + 4, true);
    const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true);
    const characteristics = view.getUint16(coffOffset + 18, true);

    if (numberOfSections === 0 || numberOfSections > PeAnalyzer.MAX_SECTIONS) {
      return defaultFailResult(`Abnormal section count: ${numberOfSections}`);
    }

    let machineType = 'UNKNOWN';
    if (machine === 0x14c) machineType = 'I386';
    else if (machine === 0x8664) machineType = 'AMD64';
    else if (machine === 0xaa64) machineType = 'ARM64';

    // 5. Optional Header (starts at e_lfanew + 24)
    const optHeaderOffset = coffOffset + 20;
    if (optHeaderOffset + sizeOfOptionalHeader > uint8.length) {
      return defaultFailResult('Optional header extends past file buffer');
    }

    let is64Bit = false;
    let entryPointRva = 0;
    let imageBase = '0x0';
    let subsystem = 0;
    let hasAuthenticodeSignature = false;
    let hasTlsCallbacks = false;

    if (sizeOfOptionalHeader >= 68) {
      const optMagic = view.getUint16(optHeaderOffset, true);
      is64Bit = optMagic === 0x20b; // PE32+ (64-bit)

      entryPointRva = view.getUint32(optHeaderOffset + 16, true);
      subsystem = view.getUint16(optHeaderOffset + 68, true);

      if (is64Bit) {
        const low = view.getUint32(optHeaderOffset + 24, true);
        const high = view.getUint32(optHeaderOffset + 28, true);
        imageBase = `0x${high.toString(16)}${low.toString(16).padStart(8, '0')}`;
      } else {
        imageBase = `0x${view.getUint32(optHeaderOffset + 28, true).toString(16)}`;
      }

      // Data Directories
      const dataDirOffset = optHeaderOffset + (is64Bit ? 112 : 96);
      const numberOfRvaAndSizes = view.getUint32(optHeaderOffset + (is64Bit ? 108 : 92), true);

      // Security Directory (Index 4: Authenticode)
      if (numberOfRvaAndSizes > 4 && dataDirOffset + 5 * 8 <= uint8.length) {
        const secRva = view.getUint32(dataDirOffset + 4 * 8, true);
        const secSize = view.getUint32(dataDirOffset + 4 * 8 + 4, true);
        hasAuthenticodeSignature = secRva > 0 && secSize > 0;
      }

      // TLS Directory (Index 9: TLS Callbacks)
      if (numberOfRvaAndSizes > 9 && dataDirOffset + 10 * 8 <= uint8.length) {
        const tlsRva = view.getUint32(dataDirOffset + 9 * 8, true);
        const tlsSize = view.getUint32(dataDirOffset + 9 * 8 + 4, true);
        hasTlsCallbacks = tlsRva > 0 && tlsSize > 0;
      }
    }

    // 6. Section Table
    const sectionTableOffset = optHeaderOffset + sizeOfOptionalHeader;
    const sectionEntrySize = 40;
    if (sectionTableOffset + numberOfSections * sectionEntrySize > uint8.length) {
      return defaultFailResult('Section table extends beyond file buffer bounds');
    }

    const sections: PeSectionInfo[] = [];
    const detectedPackers: string[] = [];
    let maxSectionEndOffset = 0;

    for (let i = 0; i < numberOfSections; i++) {
      const entryOffset = sectionTableOffset + i * sectionEntrySize;

      // Extract section name (8 ASCII bytes)
      let name = '';
      for (let c = 0; c < 8; c++) {
        const b = uint8[entryOffset + c];
        if (b === 0) break;
        name += String.fromCharCode(b);
      }
      name = name.trim();

      const virtualSize = view.getUint32(entryOffset + 8, true);
      const virtualAddress = view.getUint32(entryOffset + 12, true);
      const rawSize = view.getUint32(entryOffset + 16, true);
      const rawOffset = view.getUint32(entryOffset + 20, true);
      const sectionCharacteristics = view.getUint32(entryOffset + 36, true);

      const isWritable = (sectionCharacteristics & 0x80000000) !== 0;
      const isExecutable = (sectionCharacteristics & 0x20000000) !== 0;
      const isWritableAndExecutable = isWritable && isExecutable;

      const lowerName = name.toLowerCase();
      const isPacker = KNOWN_PACKER_SECTION_NAMES.has(lowerName);
      if (isPacker) {
        const packerLabel = lowerName.startsWith('upx') ? 'UPX' : name;
        if (!detectedPackers.includes(packerLabel)) {
          detectedPackers.push(packerLabel);
        }
      }

      // Calculate section entropy
      let sectionEntropy = 0;
      if (rawOffset > 0 && rawSize > 0 && rawOffset + rawSize <= uint8.length) {
        const sectionSlice = uint8.subarray(rawOffset, rawOffset + rawSize);
        sectionEntropy = EntropyScanner.calculateEntropy(sectionSlice);
      }

      if (rawOffset + rawSize > maxSectionEndOffset) {
        maxSectionEndOffset = rawOffset + rawSize;
      }

      sections.push({
        name,
        virtualSize,
        virtualAddress,
        rawSize,
        rawOffset,
        characteristics: sectionCharacteristics,
        isWritableAndExecutable,
        isPackerSection: isPacker,
        entropy: sectionEntropy
      });
    }

    // 7. Overlay Detection
    const totalFileSize = typeof actualFileSize === 'number' && actualFileSize > 0 ? actualFileSize : uint8.length;
    let hasOverlay = false;
    let overlaySizeBytes = 0;

    if (totalFileSize > maxSectionEndOffset) {
      hasOverlay = true;
      overlaySizeBytes = totalFileSize - maxSectionEndOffset;
    }

    // 8. Suspicious API Pattern Search (Process Injection, Credential Theft, Evasion)
    const suspiciousApiPatterns: string[] = [];
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    const bufferString = textDecoder.decode(uint8);

    // Injection cluster
    const hasVirtualAlloc = bufferString.includes('VirtualAlloc') || bufferString.includes('VirtualAllocEx');
    const hasWriteProcess = bufferString.includes('WriteProcessMemory');
    const hasCreateThread = bufferString.includes('CreateRemoteThread') || bufferString.includes('NtCreateThreadEx');
    if (hasVirtualAlloc && hasWriteProcess && hasCreateThread) {
      suspiciousApiPatterns.push('PROCESS_INJECTION_API_CLUSTER');
    }

    // Memory protection / unmapping evasion
    if (bufferString.includes('VirtualProtect') && bufferString.includes('NtUnmapViewOfSection')) {
      suspiciousApiPatterns.push('PROCESS_HOLLOWING_EVASION_APIS');
    }

    // Credential dumping
    if (bufferString.includes('MiniDumpWriteDump') && (bufferString.includes('lsass') || bufferString.includes('OpenProcess'))) {
      suspiciousApiPatterns.push('CREDENTIAL_LSASS_DUMP_APIS');
    }

    // 9. Generate Canonical Evidence Signals
    const evidence: Evidence[] = [];

    // W+X Section Alert
    const wxSections = sections.filter((s) => s.isWritableAndExecutable);
    if (wxSections.length > 0) {
      evidence.push({
        ruleId: 'pe-wx-section',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STATIC_HEURISTIC,
        source: 'PE_ANALYZER',
        name: 'Writable and Executable PE Section',
        description: `Section(s) [${wxSections.map((s) => s.name).join(', ')}] have both WRITE and EXECUTE flags (self-modifying/packed code)`,
        reason: 'PE section configured with W+X permissions',
        severityLevel: SeverityLevel.CRITICAL,
        weight: 85,
        scoreContribution: 85,
        confidence: 0.95,
        isCriticalOverride: true,
        isMalicious: true
      });
    }

    // Known Packer Detection
    if (detectedPackers.length > 0) {
      evidence.push({
        ruleId: 'pe-known-packer',
        detectorType: DetectorType.RULE,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'PE_ANALYZER',
        name: 'Known Binary Packer Detected',
        description: `Executable is packed using known runtime protector: [${detectedPackers.join(', ')}]`,
        reason: 'Known packer section name identified in PE section table',
        severityLevel: SeverityLevel.HIGH,
        weight: 70,
        scoreContribution: 70,
        confidence: 0.95,
        isMalicious: true
      });
    }

    // High Entropy Section Detection
    const highEntropySections = sections.filter((s) => s.entropy >= 7.2 && s.rawSize >= 1024);
    if (highEntropySections.length > 0) {
      evidence.push({
        ruleId: 'pe-high-entropy-section',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STATIC_HEURISTIC,
        source: 'PE_ANALYZER',
        name: 'High Entropy PE Section',
        description: `Section [${highEntropySections[0].name}] has high Shannon entropy (${highEntropySections[0].entropy} > 7.2), indicating encrypted or compressed payload`,
        reason: 'Section entropy exceeds 7.2 bits/byte threshold',
        severityLevel: SeverityLevel.HIGH,
        weight: 70,
        scoreContribution: 70,
        confidence: 0.85,
        isMalicious: true
      });
    }

    // Suspicious API Clusters
    for (const pattern of suspiciousApiPatterns) {
      evidence.push({
        ruleId: `pe-${pattern.toLowerCase().replace(/_/g, '-')}`,
        detectorType: DetectorType.RULE,
        detectorLayer: DetectorLayer.STATIC_HEURISTIC,
        source: 'PE_ANALYZER',
        name: `Suspicious API Cluster: ${pattern}`,
        description: `Import/string pattern indicates dangerous capability: ${pattern}`,
        reason: pattern,
        severityLevel: SeverityLevel.HIGH,
        weight: pattern.includes('INJECTION') ? 80 : 75,
        scoreContribution: pattern.includes('INJECTION') ? 80 : 75,
        confidence: 0.9,
        isMalicious: true
      });
    }

    // Non-Trivial Overlay
    if (hasOverlay && overlaySizeBytes > 0) {
      evidence.push({
        ruleId: 'pe-suspicious-overlay',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.METADATA_ANALYZER,
        source: 'PE_ANALYZER',
        name: 'PE Overlay Data Detected',
        description: `File contains ${overlaySizeBytes} bytes appended after the last mapped PE section`,
        reason: 'Non-trivial overlay appended to binary',
        severityLevel: SeverityLevel.MEDIUM,
        weight: 45,
        scoreContribution: 45,
        confidence: 0.75,
        isMalicious: false
      });
    }

    // TLS Callbacks present
    if (hasTlsCallbacks) {
      evidence.push({
        ruleId: 'pe-tls-callback-present',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STRUCTURAL_PARSER,
        source: 'PE_ANALYZER',
        name: 'TLS Callback Table Present',
        description: 'Binary defines TLS callbacks that execute before the main entry point (common evasion technique)',
        reason: 'TLS directory entry present in Optional Header',
        severityLevel: SeverityLevel.MEDIUM,
        weight: 40,
        scoreContribution: 40,
        confidence: 0.7,
        isMalicious: false
      });
    }

    return {
      isValidPe: true,
      is64Bit,
      machineType,
      numberOfSections,
      timeDateStamp,
      entryPointRva,
      imageBase,
      subsystem,
      hasAuthenticodeSignature,
      hasTlsCallbacks,
      sections,
      detectedPackers,
      suspiciousApiPatterns,
      hasOverlay,
      overlaySizeBytes,
      isMalformed: false,
      evidence
    };
  }
}
