import { DetectorLayer, DetectorType, Evidence, SeverityLevel } from '../types';

export interface StaticSignature {
  readonly id: string;
  readonly name: string;
  readonly pattern: string | Uint8Array;
  readonly isWide?: boolean; // Match UTF-16LE
  readonly isNoCase?: boolean; // Case insensitive
  readonly severityLevel: SeverityLevel;
  readonly scoreContribution: number;
  readonly isCriticalOverride?: boolean;
  readonly description: string;
  readonly threatName: string;
}

export interface SignatureMatchResult {
  readonly signature: StaticSignature;
  readonly offset: number;
}

interface TrieNode {
  // Transitions on byte (0-255)
  next: Map<number, number>;
  fail: number;
  output: StaticSignature[];
}

/**
 * High-Performance Flattened Aho-Corasick / YARA-Lite Signature Automaton (Layer 2 / Phase C)
 *
 * Scans a byte buffer in a single O(N) pass, matching multiple signatures
 * simultaneously across ASCII, UTF-16LE (WIDE), and Case-Insensitive (NOCASE) representations.
 * Memory allocated only during compilation; search is zero-allocation.
 */
export class SignatureAutomaton {
  private readonly nodes: TrieNode[] = [];
  private readonly signatures: StaticSignature[] = [];
  private isCompiled = false;

  constructor(signatures?: StaticSignature[]) {
    // Root node at index 0
    this.nodes.push({
      next: new Map<number, number>(),
      fail: 0,
      output: []
    });

    if (signatures && signatures.length > 0) {
      for (const sig of signatures) {
        this.addSignature(sig);
      }
      this.compile();
    }
  }

  public addSignature(sig: StaticSignature): void {
    this.signatures.push(sig);
    this.isCompiled = false;
  }

  /**
   * Compiles added signatures into the Aho-Corasick state machine with failure transitions.
   */
  public compile(): void {
    // Re-initialize root node
    this.nodes.length = 0;
    this.nodes.push({
      next: new Map<number, number>(),
      fail: 0,
      output: []
    });

    for (const sig of this.signatures) {
      // 1. Standard pattern (ASCII or byte sequence)
      const bytePatterns = this.generateBytePatterns(sig);
      for (const bytes of bytePatterns) {
        this.insertPattern(bytes, sig);
      }
    }

    this.buildFailureTransitions();
    this.isCompiled = true;
  }

  private generateBytePatterns(sig: StaticSignature): Uint8Array[] {
    const results: Uint8Array[] = [];

    let baseBytes: Uint8Array;
    if (typeof sig.pattern === 'string') {
      baseBytes = new TextEncoder().encode(sig.pattern);
    } else {
      baseBytes = sig.pattern;
    }

    results.push(baseBytes);

    // If WIDE (UTF-16LE), insert null byte after each ASCII character
    if (sig.isWide && typeof sig.pattern === 'string') {
      const wideBytes = new Uint8Array(sig.pattern.length * 2);
      for (let i = 0; i < sig.pattern.length; i++) {
        const code = sig.pattern.charCodeAt(i);
        wideBytes[i * 2] = code & 0xff;
        wideBytes[i * 2 + 1] = (code >> 8) & 0xff;
      }
      results.push(wideBytes);
    }

    return results;
  }

  private insertPattern(bytes: Uint8Array, sig: StaticSignature): void {
    if (bytes.length === 0) return;

    let currentState = 0;
    for (let i = 0; i < bytes.length; i++) {
      let b = bytes[i];
      if (sig.isNoCase && b >= 0x41 && b <= 0x5a) {
        // Uppercase ASCII A-Z to lowercase a-z
        b = b + 32;
      }

      let nextState = this.nodes[currentState].next.get(b);
      if (nextState === undefined) {
        nextState = this.nodes.length;
        this.nodes.push({
          next: new Map<number, number>(),
          fail: 0,
          output: []
        });
        this.nodes[currentState].next.set(b, nextState);
      }
      currentState = nextState;
    }

    this.nodes[currentState].output.push(sig);
  }

  private buildFailureTransitions(): void {
    const queue: number[] = [];

    // States directly reachable from root have failure link to root
    for (const [, nextState] of this.nodes[0].next.entries()) {
      this.nodes[nextState].fail = 0;
      queue.push(nextState);
    }

    // BFS to build failure links
    while (queue.length > 0) {
      const currentState = queue.shift()!;
      const currentFail = this.nodes[currentState].fail;

      for (const [b, nextState] of this.nodes[currentState].next.entries()) {
        let failureCandidate = currentFail;

        while (failureCandidate > 0 && !this.nodes[failureCandidate].next.has(b)) {
          failureCandidate = this.nodes[failureCandidate].fail;
        }

        const fallback = this.nodes[failureCandidate].next.get(b);
        if (fallback !== undefined && fallback !== nextState) {
          this.nodes[nextState].fail = fallback;
        } else {
          this.nodes[nextState].fail = 0;
        }

        // Union outputs from failure state
        const targetOutputs = this.nodes[this.nodes[nextState].fail].output;
        if (targetOutputs.length > 0) {
          for (const out of targetOutputs) {
            if (!this.nodes[nextState].output.includes(out)) {
              this.nodes[nextState].output.push(out);
            }
          }
        }

        queue.push(nextState);
      }
    }
  }

  /**
   * Scans an input buffer in a single pass.
   * Returns all matched signatures and their byte offsets.
   */
  public scan(buffer: Uint8Array | number[]): SignatureMatchResult[] {
    if (!this.isCompiled) {
      this.compile();
    }

    if (!buffer || buffer.length === 0) {
      return [];
    }

    const matches: SignatureMatchResult[] = [];
    const matchedSigIds = new Set<string>();

    let currentState = 0;
    const len = buffer.length;

    for (let i = 0; i < len; i++) {
      const rawByte = buffer[i] & 0xff;
      // Also test normalized lowercase byte
      const lowerByte = rawByte >= 0x41 && rawByte <= 0x5a ? rawByte + 32 : rawByte;

      // Try transition on rawByte first, then lowerByte
      let nextState: number | undefined = this.nodes[currentState].next.get(rawByte);
      if (nextState === undefined && lowerByte !== rawByte) {
        nextState = this.nodes[currentState].next.get(lowerByte);
      }

      while (currentState > 0 && nextState === undefined) {
        currentState = this.nodes[currentState].fail;
        nextState = this.nodes[currentState].next.get(rawByte);
        if (nextState === undefined && lowerByte !== rawByte) {
          nextState = this.nodes[currentState].next.get(lowerByte);
        }
      }

      if (nextState !== undefined) {
        currentState = nextState;
      } else {
        currentState = 0;
      }

      const nodeOutputs = this.nodes[currentState].output;
      if (nodeOutputs.length > 0) {
        for (const sig of nodeOutputs) {
          if (!matchedSigIds.has(sig.id)) {
            matchedSigIds.add(sig.id);
            matches.push({
              signature: sig,
              offset: i
            });
          }
        }
      }
    }

    return matches;
  }

  /**
   * Converts match results into canonical Evidence[] for Core RiskScorer.
   */
  public toEvidence(matches: SignatureMatchResult[]): Evidence[] {
    return matches.map((m) => ({
      ruleId: m.signature.id,
      detectorType: DetectorType.RULE,
      detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
      source: 'SIGNATURE_AUTOMATON',
      name: m.signature.name,
      description: `${m.signature.description} (offset 0x${m.offset.toString(16)})`,
      reason: m.signature.description,
      severityLevel: m.signature.severityLevel,
      weight: m.signature.isCriticalOverride ? 100 : m.signature.scoreContribution,
      scoreContribution: m.signature.scoreContribution,
      confidence: 1.0,
      isCriticalOverride: m.signature.isCriticalOverride ?? false,
      isMalicious: m.signature.scoreContribution >= 70,
      metadata: {
        threatName: m.signature.threatName,
        matchOffset: String(m.offset)
      }
    }));
  }

  /**
   * Creates an instance pre-seeded with canonical antivirus and anti-ransomware patterns (phase.md Layer 2).
   */
  public static createDefault(): SignatureAutomaton {
    const seeds: StaticSignature[] = [
      // 1. EICAR Standard Antivirus Test File
      {
        id: 'sig-eicar-antivirus-test',
        name: 'EICAR Test Signature',
        pattern: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
        severityLevel: SeverityLevel.CRITICAL,
        scoreContribution: 100,
        isCriticalOverride: true,
        description: 'Matches standard EICAR antivirus test file signature',
        threatName: 'EICAR_STANDARD_TEST_FILE'
      },
      // 2. Mimikatz Credential Dumping Signatures
      {
        id: 'sig-mimikatz-sekurlsa',
        name: 'Mimikatz Sekurlsa Credential Dumper',
        pattern: 'sekurlsa::logonpasswords',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.CRITICAL,
        scoreContribution: 95,
        isCriticalOverride: true,
        description: 'Matches Mimikatz sekurlsa password extraction command',
        threatName: 'TOOL_MIMIKATZ_CRED_DUMPER'
      },
      {
        id: 'sig-minidump-writedump',
        name: 'LSASS Memory Dump API Call',
        pattern: 'MiniDumpWriteDump',
        isWide: true,
        isNoCase: false,
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 80,
        isCriticalOverride: false,
        description: 'References MiniDumpWriteDump API commonly used to dump lsass.exe process memory',
        threatName: 'SUSPICIOUS_LSASS_DUMP_API'
      },
      // 3. Ransomware Volume Shadow Copy Deletion Signatures
      {
        id: 'sig-ransomware-vssadmin-shadows',
        name: 'Vssadmin Shadow Deletion',
        pattern: 'vssadmin delete shadows',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.CRITICAL,
        scoreContribution: 95,
        isCriticalOverride: true,
        description: 'Commands deletion of Windows Volume Shadow Copies via vssadmin',
        threatName: 'RANSOMWARE_SHADOW_DELETION'
      },
      {
        id: 'sig-ransomware-wmic-shadowcopy',
        name: 'WMIC Shadowcopy Delete',
        pattern: 'wmic shadowcopy delete',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.CRITICAL,
        scoreContribution: 95,
        isCriticalOverride: true,
        description: 'Commands deletion of shadow copies via WMIC query',
        threatName: 'RANSOMWARE_SHADOW_DELETION'
      },
      {
        id: 'sig-ransomware-bcdedit-recovery',
        name: 'Bcdedit Disable Recovery',
        pattern: 'recoveryenabled no',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 85,
        description: 'Disables Windows boot recovery mode via bcdedit',
        threatName: 'RANSOMWARE_RECOVERY_TAMPER'
      },
      {
        id: 'sig-ransomware-wbadmin-catalog',
        name: 'Wbadmin Backup Catalog Delete',
        pattern: 'wbadmin delete catalog',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.CRITICAL,
        scoreContribution: 95,
        isCriticalOverride: true,
        description: 'Commands deletion of Windows backup catalog via wbadmin',
        threatName: 'RANSOMWARE_BACKUP_PURGE'
      },
      // 4. In-Memory AMSI / ETW Evasion
      {
        id: 'sig-amsi-bypass-scanbuffer',
        name: 'AMSI ScanBuffer Memory Patching',
        pattern: 'AmsiScanBuffer',
        isWide: true,
        isNoCase: false,
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 85,
        description: 'References AmsiScanBuffer export for runtime anti-malware patching',
        threatName: 'EVASION_AMSI_BYPASS'
      },
      {
        id: 'sig-etw-bypass-eventwrite',
        name: 'ETW EventWrite Patching',
        pattern: 'EtwEventWrite',
        isWide: true,
        isNoCase: false,
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 80,
        description: 'References EtwEventWrite export for runtime telemetry blind-spotting',
        threatName: 'EVASION_ETW_BYPASS'
      },
      // 5. LOLBin Download Cradles
      {
        id: 'sig-lolbin-certutil-urlcache',
        name: 'Certutil Remote Payload Download',
        pattern: 'certutil -urlcache',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 85,
        description: 'Abuses certutil.exe to download remote files from the internet',
        threatName: 'LOLBIN_CERTUTIL_DOWNLOAD'
      },
      {
        id: 'sig-lolbin-bitsadmin-transfer',
        name: 'Bitsadmin Background Transfer',
        pattern: 'bitsadmin /transfer',
        isWide: true,
        isNoCase: true,
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 80,
        description: 'Abuses BITSAdmin to transfer remote payloads in the background',
        threatName: 'LOLBIN_BITSADMIN_DOWNLOAD'
      }
    ];

    return new SignatureAutomaton(seeds);
  }

  private static defaultInstance: SignatureAutomaton | null = null;

  public static getInstance(): SignatureAutomaton {
    if (!this.defaultInstance) {
      this.defaultInstance = this.createDefault();
    }
    return this.defaultInstance;
  }
}
