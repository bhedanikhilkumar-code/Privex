import * as path from 'path';
import * as fs from 'fs';

export interface ParsedPersistenceCommand {
  readonly rawCommand: string;
  readonly sanitizedCommand: string;
  readonly executablePath: string;
  readonly arguments: string;
  readonly isQuoted: boolean;
  readonly hasEnvironmentVariables: boolean;
  readonly isScript: boolean;
  readonly isLolbin: boolean;
  readonly isSuspicious: boolean;
  readonly riskContribution: number;
  readonly indicators: string[];
  readonly evidenceFactors: string[];
}

/**
 * Safe, Bounds-Checked Windows Startup Command-Line & Path Parser (Phase L).
 *
 * Safely parses raw persistence commands from Registry Run/RunOnce keys,
 * Startup folders, and persistence mechanisms without executing the command,
 * spawning child shells, or allowing traversal / NUL / RTLO attacks.
 */
export class PersistenceCommandParser {
  private static readonly MAX_COMMAND_LENGTH = 8192; // 8 KB safety limit
  private static readonly RTLO_PATTERN = /[\u202E\u202B\u200E\u200F\u2066\u2067\u2068\u2069]/g;
  private static readonly TRAVERSAL_PATTERN = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
  private static readonly UNC_PATTERN = /^(?:\\\\|\/\/)/;

  public static readonly SCRIPT_EXTENSIONS = new Set([
    '.vbs',
    '.vbe',
    '.js',
    '.jse',
    '.wsf',
    '.wsh',
    '.bat',
    '.cmd',
    '.ps1',
    '.psm1',
    '.hta',
    '.scr',
    '.pif'
  ]);

  public static readonly EXECUTABLE_EXTENSIONS = new Set([
    '.exe',
    '.com',
    '.dll',
    '.cpl',
    '.msi',
    '.sys',
    '.drv',
    '.ocx',
    ...PersistenceCommandParser.SCRIPT_EXTENSIONS
  ]);

  public static readonly LOLBINS = new Set([
    'powershell.exe',
    'powershell',
    'pwsh.exe',
    'pwsh',
    'cmd.exe',
    'cmd',
    'wscript.exe',
    'wscript',
    'cscript.exe',
    'cscript',
    'mshta.exe',
    'mshta',
    'rundll32.exe',
    'rundll32',
    'regsvr32.exe',
    'regsvr32',
    'certutil.exe',
    'certutil',
    'bitsadmin.exe',
    'bitsadmin',
    'schtasks.exe',
    'schtasks',
    'reg.exe',
    'reg',
    'curl.exe',
    'curl',
    'wget.exe',
    'wget',
    'msiexec.exe',
    'msiexec',
    'hh.exe',
    'hh',
    'installutil.exe',
    'installutil',
    'regasm.exe',
    'regasm',
    'regsvcs.exe',
    'regsvcs'
  ]);

  private static readonly SUSPICIOUS_ARG_PATTERNS = [
    { pattern: /(?:-enc|-encodedcommand)\s+[a-z0-9+/=]{4,}/i, desc: 'Base64-encoded command execution in startup persistence' },
    { pattern: /(?:-w\s+hidden|-windowstyle\s+hidden)/i, desc: 'Hidden window style argument in startup persistence' },
    { pattern: /(?:-nop|-noprofile)/i, desc: 'No-profile switch used to evade profile scripts' },
    { pattern: /(?:-ep\s+bypass|-executionpolicy\s+bypass|-ep\s+unrestricted)/i, desc: 'ExecutionPolicy bypass flag in startup persistence' },
    { pattern: /(?:downloadstring|downloaddata|downloadfile|iwr|invoke-webrequest|curl|wget)/i, desc: 'Remote payload download directive in startup persistence arguments' },
    { pattern: /(?:iex|invoke-expression)/i, desc: 'Dynamic in-memory code execution directive (IEX) in persistence arguments' },
    { pattern: /(?:\/e:vbscript|\/e:jscript|javascript:|vbscript:)/i, desc: 'Direct script engine invocation in arguments' },
    { pattern: /(?:-decode|-urlcache|-split)/i, desc: 'CertUtil payload decoding flags in arguments' },
    { pattern: /(?:[\\/](?:temp|tmp|appdata[\\/]local[\\/]temp|users[\\/]public)[\\/])/i, desc: 'Targeting temporary/untrusted staging directory' }
  ];

  /**
   * Strips control characters, NUL bytes, and directional overrides safely.
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
   * Expands Windows environment variables (%VAR%) via dictionary replacement.
   * NEVER spawns a child process or shell for environment resolution.
   */
  public static expandEnvironmentVariables(input: string): string {
    if (!input || typeof input !== 'string') return '';

    return input.replace(/%([^%]+)%/g, (_match, varName) => {
      const upper = varName.toUpperCase();
      // Safe environment variable mapping with Windows defaults
      if (process.env[varName]) return process.env[varName]!;
      if (process.env[upper]) return process.env[upper]!;

      // Known system fallbacks if running in sandbox/mock test
      if (upper === 'WINDIR' || upper === 'SYSTEMROOT') return process.env.SYSTEMROOT || 'C:\\Windows';
      if (upper === 'SYSTEMDRIVE') return process.env.SYSTEMDRIVE || 'C:';
      if (upper === 'PROGRAMFILES') return process.env.PROGRAMFILES || 'C:\\Program Files';
      if (upper === 'PROGRAMFILES(X86)') return process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)';
      if (upper === 'PROGRAMDATA') return process.env.PROGRAMDATA || 'C:\\ProgramData';
      if (upper === 'APPDATA') return process.env.APPDATA || 'C:\\Users\\Default\\AppData\\Roaming';
      if (upper === 'LOCALAPPDATA') return process.env.LOCALAPPDATA || 'C:\\Users\\Default\\AppData\\Local';
      if (upper === 'USERPROFILE') return process.env.USERPROFILE || 'C:\\Users\\Default';
      if (upper === 'TEMP' || upper === 'TMP') return process.env.TEMP || 'C:\\Windows\\Temp';

      return `%${varName}%`;
    });
  }

  /**
   * Safely parses a raw command-line string into its constituent executable path
   * and argument list, resolving quotes, spaces, and relative paths without execution.
   */
  public static parseCommandLine(
    rawCommand: string,
    baseDir?: string
  ): ParsedPersistenceCommand {
    if (!rawCommand || typeof rawCommand !== 'string') {
      return {
        rawCommand: '',
        sanitizedCommand: '',
        executablePath: '',
        arguments: '',
        isQuoted: false,
        hasEnvironmentVariables: false,
        isScript: false,
        isLolbin: false,
        isSuspicious: false,
        riskContribution: 0,
        indicators: [],
        evidenceFactors: []
      };
    }

    const bounded = rawCommand.substring(0, this.MAX_COMMAND_LENGTH);
    const sanitized = this.sanitizeString(bounded);
    const hasEnvironmentVariables = /%[^%]+%/.test(sanitized);
    const expanded = this.expandEnvironmentVariables(sanitized);

    let executablePath = '';
    let args = '';
    let isQuoted = false;

    const trimmed = expanded.trim();

    // 1. Quoted executable path: "C:\Program Files\App\app.exe" -arg1 -arg2
    if (trimmed.startsWith('"')) {
      const closingQuote = trimmed.indexOf('"', 1);
      if (closingQuote !== -1) {
        executablePath = trimmed.substring(1, closingQuote).trim();
        args = trimmed.substring(closingQuote + 1).trim();
        isQuoted = true;
      } else {
        // Unmatched quote: take whole string without first quote
        executablePath = trimmed.substring(1).trim();
        isQuoted = true;
      }
    } else {
      // 2. Unquoted executable path: e.g. C:\Program Files\App\app.exe /s or app.exe -arg
      // Strategy: Check if there are spaces. If so, try finding known executable extensions.
      const firstSpace = trimmed.indexOf(' ');
      if (firstSpace === -1) {
        executablePath = trimmed;
        args = '';
      } else {
        // Look for common extension endings followed by space or end
        let matchedIndex = -1;
        const lower = trimmed.toLowerCase();

        for (const ext of this.EXECUTABLE_EXTENSIONS) {
          const needle = ext + ' ';
          const idx = lower.indexOf(needle);
          if (idx !== -1 && (matchedIndex === -1 || idx < matchedIndex)) {
            matchedIndex = idx + ext.length;
          }
        }

        if (matchedIndex !== -1) {
          executablePath = trimmed.substring(0, matchedIndex).trim();
          args = trimmed.substring(matchedIndex).trim();
        } else {
          // Fallback: Check if the full unquoted path exists on disk (e.g. C:\Program Files\App.exe)
          if (fs.existsSync(trimmed)) {
            executablePath = trimmed;
            args = '';
          } else {
            // First space split
            executablePath = trimmed.substring(0, firstSpace).trim();
            args = trimmed.substring(firstSpace + 1).trim();
          }
        }
      }
    }

    // Resolve relative paths safely against baseDir if provided
    if (executablePath && !path.isAbsolute(executablePath) && baseDir) {
      executablePath = path.resolve(baseDir, executablePath);
    }

    // Extract file info
    const baseName = (executablePath.split(/[/\\]/).pop() || '').toLowerCase();
    const ext = path.extname(baseName).toLowerCase();

    const isScript = this.SCRIPT_EXTENSIONS.has(ext);
    const isLolbin = this.LOLBINS.has(baseName);

    const indicators: string[] = [];
    const evidenceFactors: string[] = [];
    let riskContribution = 0;

    // Check for suspicious script direct execution
    if (isScript) {
      indicators.push('SCRIPT_IN_STARTUP_PERSISTENCE');
      evidenceFactors.push(`Automated script (${ext}) registered for persistence`);
      riskContribution += 35;
    }

    // Check for LOLBin execution
    if (isLolbin) {
      indicators.push('LOLBIN_IN_STARTUP_PERSISTENCE');
      evidenceFactors.push(`Living-off-the-Land binary (${baseName}) registered in persistence`);
      riskContribution += 30;
    }

    // Inspect command arguments for evasion/download patterns
    for (const { pattern, desc } of this.SUSPICIOUS_ARG_PATTERNS) {
      if (pattern.test(args) || pattern.test(sanitized)) {
        indicators.push('SUSPICIOUS_PERSISTENCE_ARGUMENT');
        evidenceFactors.push(desc);
        riskContribution += 35;
      }
    }

    // Check for execution from temp or public directories
    const lowerPath = executablePath.toLowerCase();
    if (
      lowerPath.includes('\\temp\\') ||
      lowerPath.includes('/temp/') ||
      lowerPath.includes('\\appdata\\local\\temp') ||
      lowerPath.includes('users\\public')
    ) {
      indicators.push('TEMP_DIRECTORY_PERSISTENCE');
      evidenceFactors.push(`Startup target resides in temporary or public directory: ${executablePath}`);
      riskContribution += 40;
    }

    // Check for double extension
    const parts = baseName.split('.');
    if (parts.length >= 3) {
      indicators.push('DOUBLE_EXTENSION_PERSISTENCE');
      evidenceFactors.push(`Startup executable uses deceptive double-extension: ${baseName}`);
      riskContribution += 45;
    }

    // Check for traversal or device path
    if (this.TRAVERSAL_PATTERN.test(rawCommand)) {
      indicators.push('DIRECTORY_TRAVERSAL_PERSISTENCE');
      evidenceFactors.push('Command uses parent directory traversal sequences (..)');
      riskContribution += 30;
    }

    if (this.UNC_PATTERN.test(executablePath)) {
      indicators.push('UNC_NETWORK_PERSISTENCE');
      evidenceFactors.push(`Target points to remote UNC network share: ${executablePath}`);
      riskContribution += 40;
    }

    const isSuspicious = indicators.length > 0 || riskContribution >= 30;

    return {
      rawCommand,
      sanitizedCommand: sanitized,
      executablePath,
      arguments: args,
      isQuoted,
      hasEnvironmentVariables,
      isScript,
      isLolbin,
      isSuspicious,
      riskContribution: Math.min(100, riskContribution),
      indicators,
      evidenceFactors
    };
  }
}
