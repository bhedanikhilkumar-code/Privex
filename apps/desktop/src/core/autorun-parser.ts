import * as fs from 'fs';
import * as path from 'path';
import { FileAnalyzer } from './file-analyzer';
import { AutorunAnalysisResult, FileAnalysisResult } from '../types/desktop.types';

/**
 * Safe, Bounds-Checked Autorun.inf Parser (Phase M).
 *
 * Strictly parses untrusted autorun.inf files without executing any directive,
 * bounding file size, line length, and recursion. Normalizes against NUL injection,
 * RTLO/bidi spoofing, and directory traversal, and correlates referenced executables
 * through the canonical FileAnalyzer pipeline.
 */
export class AutorunParser {
  public static readonly MAX_AUTORUN_SIZE = 64 * 1024; // 64 KB limit
  public static readonly MAX_LINES = 500;
  public static readonly MAX_LINE_LENGTH = 2048;

  private static readonly RTLO_PATTERN = /[\u202E\u202B\u200E\u200F\u2066\u2067\u2068\u2069]/g;
  private static readonly UNC_PATTERN = /^(?:\\\\|\/\/)/;
  private static readonly DEVICE_PATH_PATTERN = /^\\\\\?\\/i;
  private static readonly TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

  private static readonly SCRIPT_INTERPRETERS = new Set([
    'wscript',
    'wscript.exe',
    'cscript',
    'cscript.exe',
    'powershell',
    'powershell.exe',
    'cmd',
    'cmd.exe',
    'mshta',
    'mshta.exe',
    'rundll32',
    'rundll32.exe',
    'certutil',
    'certutil.exe',
    'regsvr32',
    'regsvr32.exe',
    'bash',
    'sh'
  ]);

  private static readonly EXECUTABLE_EXTENSIONS = new Set([
    '.exe',
    '.scr',
    '.pif',
    '.com',
    '.bat',
    '.cmd',
    '.vbs',
    '.vbe',
    '.js',
    '.jse',
    '.wsf',
    '.wsh',
    '.hta',
    '.ps1',
    '.dll',
    '.cpl',
    '.msc',
    '.jar'
  ]);

  /**
   * Sanitizes untrusted text by stripping NULs, control characters, and bidi overrides.
   */
  public static sanitizeString(input: string): string {
    if (!input || typeof input !== 'string') return '';
    return input
      .replace(/\0/g, '')
      .replace(this.RTLO_PATTERN, '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .trim();
  }

  /**
   * Parses an autorun.inf file from disk safely.
   */
  public static async parseFile(
    filePath: string,
    rootDir?: string
  ): Promise<AutorunAnalysisResult> {
    const effectiveRoot = rootDir || path.dirname(filePath);

    if (!fs.existsSync(filePath)) {
      return {
        hasAutorun: false,
        commands: [],
        isSuspicious: false,
        riskScore: 0,
        indicators: [],
        evidenceFactors: []
      };
    }

    try {
      const stat = await fs.promises.stat(filePath);
      if (!stat.isFile() || stat.size > this.MAX_AUTORUN_SIZE) {
        return {
          hasAutorun: true,
          filePath,
          commands: [],
          isSuspicious: true,
          riskScore: 60,
          indicators: ['AUTORUN_OVERSIZED_OR_INVALID'],
          evidenceFactors: [
            `autorun.inf exceeds maximum allowed size of ${this.MAX_AUTORUN_SIZE} bytes (size=${stat.size})`
          ]
        };
      }

      const content = await fs.promises.readFile(filePath, 'utf-8');
      return this.parseContent(content, effectiveRoot, filePath);
    } catch (err: any) {
      return {
        hasAutorun: true,
        filePath,
        commands: [],
        isSuspicious: true,
        riskScore: 40,
        indicators: ['AUTORUN_READ_ERROR'],
        evidenceFactors: [`Failed to read autorun.inf: ${err?.message || 'I/O error'}`]
      };
    }
  }

  /**
   * Parses autorun.inf string content and evaluates threat indicators.
   */
  public static async parseContent(
    rawContent: string,
    rootDir: string,
    filePath?: string
  ): Promise<AutorunAnalysisResult> {
    if (!rawContent || typeof rawContent !== 'string') {
      return {
        hasAutorun: false,
        commands: [],
        isSuspicious: false,
        riskScore: 0,
        indicators: [],
        evidenceFactors: []
      };
    }

    const lines = rawContent.split(/\r?\n/).slice(0, this.MAX_LINES);
    let inAutorunSection = false;
    let hasExplicitSections = false;

    let openTarget: string | undefined;
    let shellExecuteTarget: string | undefined;
    let iconTarget: string | undefined;
    let action: string | undefined;
    const commands: string[] = [];
    const indicators: string[] = [];
    const evidenceFactors: string[] = [];

    // Check if any section headers exist
    for (const rawLine of lines) {
      const trimmed = this.sanitizeString(rawLine.slice(0, this.MAX_LINE_LENGTH));
      if (/^\[.+\]$/.test(trimmed)) {
        hasExplicitSections = true;
        break;
      }
    }

    // Default to inAutorunSection = true if no explicit section headers are present
    inAutorunSection = !hasExplicitSections;

    for (const rawLine of lines) {
      const line = this.sanitizeString(rawLine.slice(0, this.MAX_LINE_LENGTH));
      if (!line || line.startsWith(';') || line.startsWith('#')) {
        continue;
      }

      const sectionMatch = line.match(/^\[([^\]]+)\]$/);
      if (sectionMatch) {
        const secName = sectionMatch[1].trim().toLowerCase();
        inAutorunSection = secName === 'autorun';
        continue;
      }

      if (!inAutorunSection) {
        continue;
      }

      const eqIdx = line.indexOf('=');
      if (eqIdx === -1) continue;

      const key = line.slice(0, eqIdx).trim().toLowerCase();
      const value = this.sanitizeString(line.slice(eqIdx + 1));
      if (!value) continue;

      if (key === 'open') {
        openTarget = value;
        commands.push(`open=${value}`);
      } else if (key === 'shellexecute') {
        shellExecuteTarget = value;
        commands.push(`shellexecute=${value}`);
      } else if (key === 'icon') {
        iconTarget = value;
      } else if (key === 'action') {
        action = value;
      } else if (key.startsWith('shell\\') && key.endsWith('\\command')) {
        commands.push(`${key}=${value}`);
      } else if (key === 'shell') {
        commands.push(`shell=${value}`);
      }
    }

    let riskScore = 0;

    // Evaluate primary targets
    const targetsToEvaluate = [openTarget, shellExecuteTarget].filter(Boolean) as string[];
    for (const cmd of commands) {
      const parts = cmd.split('=');
      if (parts.length > 1 && !targetsToEvaluate.includes(parts[1])) {
        targetsToEvaluate.push(parts[1]);
      }
    }

    let deepestTargetAnalysis: FileAnalysisResult | undefined;

    for (const target of targetsToEvaluate) {
      const targetSanitized = this.sanitizeString(target);

      // Check UNC or device path in autorun directive
      if (this.UNC_PATTERN.test(targetSanitized) || this.DEVICE_PATH_PATTERN.test(targetSanitized)) {
        indicators.push('AUTORUN_UNC_OR_DEVICE_TARGET');
        evidenceFactors.push(`autorun.inf directive references UNC or device path: ${targetSanitized}`);
        riskScore = Math.max(riskScore, 75);
      }

      // Check Directory Traversal
      if (this.TRAVERSAL_PATTERN.test(targetSanitized)) {
        indicators.push('AUTORUN_TRAVERSAL_TARGET');
        evidenceFactors.push(`autorun.inf directive contains parent directory traversal: ${targetSanitized}`);
        riskScore = Math.max(riskScore, 80);
      }

      // Extract binary name / first token
      const tokens = targetSanitized.split(/\s+/);
      const binaryToken = tokens[0] || '';
      const baseBinary = path.basename(binaryToken).toLowerCase();
      const ext = path.extname(baseBinary).toLowerCase();

      // Check script interpreters
      if (this.SCRIPT_INTERPRETERS.has(baseBinary)) {
        indicators.push('AUTORUN_SCRIPT_INTERPRETER');
        evidenceFactors.push(
          `autorun.inf automatically executes script interpreter: ${baseBinary} (full command: ${targetSanitized})`
        );
        riskScore = Math.max(riskScore, 85);
      } else if (this.EXECUTABLE_EXTENSIONS.has(ext)) {
        indicators.push('AUTORUN_EXECUTABLE_DIRECTIVE');
        evidenceFactors.push(
          `autorun.inf automatically executes binary/executable on drive mount: ${baseBinary}`
        );
        riskScore = Math.max(riskScore, 70);
      }

      // Check for obfuscated or hidden command line flags
      const targetLower = targetSanitized.toLowerCase();
      if (
        targetLower.includes('-enc') ||
        targetLower.includes('-encodedcommand') ||
        targetLower.includes('hidden') ||
        targetLower.includes('downloadstring') ||
        targetLower.includes('/c start') ||
        targetLower.includes('//e:vbs')
      ) {
        indicators.push('AUTORUN_SUSPICIOUS_CLI_FLAGS');
        evidenceFactors.push(`autorun.inf command contains suspicious execution flags: ${targetSanitized}`);
        riskScore = Math.max(riskScore, 90);
      }

      // Resolve and inspect on-disk target file if in rootDir
      const candidatePaths = [
        path.join(rootDir, binaryToken),
        path.join(rootDir, path.basename(binaryToken))
      ];

      for (const token of tokens.slice(1)) {
        const cleanToken = token.replace(/["']/g, '');
        if (this.EXECUTABLE_EXTENSIONS.has(path.extname(cleanToken).toLowerCase())) {
          candidatePaths.push(path.join(rootDir, cleanToken));
          candidatePaths.push(path.join(rootDir, path.basename(cleanToken)));
        }
      }

      for (const cand of candidatePaths) {
        try {
          if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
            const fileAnalysis = await FileAnalyzer.analyzeFile(cand, { inspectMotw: false, inspectEmail: false });
            if (!deepestTargetAnalysis || fileAnalysis.riskScore > deepestTargetAnalysis.riskScore) {
              deepestTargetAnalysis = fileAnalysis;
            }
            if (fileAnalysis.verdict === 'BLOCK' || fileAnalysis.riskScore >= 70) {
              indicators.push('AUTORUN_TARGET_MALICIOUS');
              evidenceFactors.push(
                `Referenced autorun payload '${path.basename(cand)}' analyzed as ${fileAnalysis.verdict} (score=${fileAnalysis.riskScore})`
              );
              riskScore = Math.max(riskScore, fileAnalysis.riskScore, 90);
            }
          }
        } catch {
          // Ignore individual file probe errors
        }
      }
    }

    if (commands.length > 0 && riskScore === 0) {
      riskScore = 30; // Non-zero caution for any active autorun directive
      indicators.push('AUTORUN_DIRECTIVES_PRESENT');
      evidenceFactors.push(`autorun.inf contains ${commands.length} directive(s)`);
    }

    const isSuspicious = riskScore >= 50;

    return {
      hasAutorun: true,
      filePath,
      openTarget,
      shellExecuteTarget,
      iconTarget,
      action,
      commands,
      isSuspicious,
      riskScore,
      indicators,
      evidenceFactors,
      targetAnalysis: deepestTargetAnalysis
    };
  }
}
