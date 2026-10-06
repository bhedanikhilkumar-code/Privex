import { execFile } from 'child_process';
import * as util from 'util';

const execFileAsync = util.promisify(execFile);

export type RegistryHive = 'HKCU' | 'HKLM';

export interface RegistryRunEntry {
  readonly hive: RegistryHive;
  readonly keyPath: string;
  readonly fullKey: string;
  readonly valueName: string;
  readonly valueType: 'REG_SZ' | 'REG_EXPAND_SZ' | 'REG_MULTI_SZ' | 'REG_BINARY' | 'UNKNOWN';
  readonly rawValue: string;
  readonly isRunOnce: boolean;
  readonly is64BitView?: boolean;
}

export interface WindowsRegistryReaderOptions {
  readonly customRegistryOutput?: Record<string, string>;
  readonly customEntries?: RegistryRunEntry[];
}

/**
 * Safe, Exception-Resilient Windows Registry Persistence Reader (Phase L).
 *
 * Enumerates HKCU and HKLM Run and RunOnce registry keys across native and WOW6432
 * views using direct execFile('reg.exe') calls without shell expansion or arbitrary mutation.
 */
export class WindowsRegistryReader {
  public static readonly STANDARD_RUN_KEYS: Array<{
    hive: RegistryHive;
    subKey: string;
    isRunOnce: boolean;
    view?: '32' | '64';
  }> = [
    { hive: 'HKCU', subKey: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', isRunOnce: false },
    { hive: 'HKCU', subKey: 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', isRunOnce: true },
    { hive: 'HKLM', subKey: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', isRunOnce: false },
    { hive: 'HKLM', subKey: 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', isRunOnce: true },
    { hive: 'HKLM', subKey: 'Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', isRunOnce: false, view: '32' },
    { hive: 'HKLM', subKey: 'Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce', isRunOnce: true, view: '32' }
  ];

  private customRegistryOutput?: Record<string, string>;
  private customEntries?: RegistryRunEntry[];

  constructor(options?: WindowsRegistryReaderOptions) {
    this.customRegistryOutput = options?.customRegistryOutput;
    this.customEntries = options?.customEntries;
  }

  public setMockRegistry(mockOutput: Record<string, string>): void {
    this.customRegistryOutput = mockOutput;
  }

  public setMockEntries(entries: RegistryRunEntry[]): void {
    this.customEntries = entries;
  }

  /**
   * Reads all standard Run and RunOnce persistence keys.
   */
  public async readAllRunKeys(): Promise<RegistryRunEntry[]> {
    if (this.customEntries) {
      return [...this.customEntries];
    }

    const allEntries: RegistryRunEntry[] = [];

    for (const keyDef of WindowsRegistryReader.STANDARD_RUN_KEYS) {
      try {
        const entries = await this.queryKey(keyDef.hive, keyDef.subKey, {
          isRunOnce: keyDef.isRunOnce,
          view: keyDef.view
        });
        allEntries.push(...entries);
      } catch {
        // Non-blocking key query error (e.g. key does not exist or access denied)
      }
    }

    return allEntries;
  }

  /**
   * Queries a specific registry key safely via reg.exe query.
   */
  public async queryKey(
    hive: RegistryHive,
    subKey: string,
    options?: { isRunOnce?: boolean; view?: '32' | '64' }
  ): Promise<RegistryRunEntry[]> {
    const fullKey = `${hive}\\${subKey}`;
    const isRunOnce = options?.isRunOnce ?? subKey.toLowerCase().includes('runonce');

    // 1. Check mock override
    if (this.customRegistryOutput !== undefined) {
      const output = this.customRegistryOutput[fullKey] || '';
      return this.parseRegOutput(output, hive, subKey, isRunOnce, options?.view === '64');
    }

    // 2. Cross-platform / non-Windows check
    if (process.platform !== 'win32') {
      return [];
    }

    // 3. Direct reg.exe invocation (never shell cmd.exe)
    const args = ['query', fullKey];
    if (options?.view === '32') {
      args.push('/reg:32');
    } else if (options?.view === '64') {
      args.push('/reg:64');
    }

    try {
      const { stdout } = await execFileAsync('reg.exe', args, {
        timeout: 3000,
        maxBuffer: 1024 * 1024,
        windowsHide: true
      });

      return this.parseRegOutput(stdout, hive, subKey, isRunOnce, options?.view === '64');
    } catch {
      // Missing key or access denied returns empty list safely
      return [];
    }
  }

  /**
   * Parses standard reg.exe query tabular output safely.
   *
   * Example output:
   * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
   *     OneDrive    REG_SZ    "C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
   *     Discord     REG_SZ    C:\Users\user\AppData\Local\Discord\app.exe
   */
  public parseRegOutput(
    output: string,
    hive: RegistryHive,
    subKey: string,
    isRunOnce: boolean,
    is64BitView?: boolean
  ): RegistryRunEntry[] {
    if (!output || typeof output !== 'string') return [];

    const entries: RegistryRunEntry[] = [];
    const lines = output.split(/\r?\n/);
    const fullKey = `${hive}\\${subKey}`;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('HKEY_') || trimmed.startsWith('ERROR:')) {
        continue;
      }

      // Match line format: <ValueName>    <Type>    <Data>
      // Using standard reg.exe 4-space or tab delimiter
      const regMatch = line.match(/^\s*(.+?)\s{2,}(REG_[A-Z_]+)\s{2,}(.*)$/);
      if (regMatch) {
        const valueName = regMatch[1].trim();
        const valueTypeRaw = regMatch[2].trim();
        const rawValue = regMatch[3].trim();

        let valueType: RegistryRunEntry['valueType'] = 'UNKNOWN';
        if (valueTypeRaw === 'REG_SZ') valueType = 'REG_SZ';
        else if (valueTypeRaw === 'REG_EXPAND_SZ') valueType = 'REG_EXPAND_SZ';
        else if (valueTypeRaw === 'REG_MULTI_SZ') valueType = 'REG_MULTI_SZ';
        else if (valueTypeRaw === 'REG_BINARY') valueType = 'REG_BINARY';

        entries.push({
          hive,
          keyPath: subKey,
          fullKey,
          valueName,
          valueType,
          rawValue,
          isRunOnce,
          is64BitView
        });
      }
    }

    return entries;
  }

  /**
   * Deletes a specific registry value under a Run key safely.
   * NEVER deletes the parent key. Verifies deletion post-operation.
   */
  public async deleteRunValue(
    hive: RegistryHive,
    subKey: string,
    valueName: string,
    options?: { view?: '32' | '64' }
  ): Promise<{ success: boolean; message?: string }> {
    if (!valueName || typeof valueName !== 'string' || valueName.includes('\0')) {
      return { success: false, message: 'Invalid value name for registry deletion.' };
    }

    const fullKey = `${hive}\\${subKey}`;

    // 1. Mock support
    if (this.customRegistryOutput) {
      if (this.customRegistryOutput[fullKey]) {
        const lines = this.customRegistryOutput[fullKey].split(/\r?\n/);
        const filtered = lines.filter((line) => !line.includes(valueName));
        this.customRegistryOutput[fullKey] = filtered.join('\n');
      }
      return { success: true };
    }

    if (process.platform !== 'win32') {
      return { success: true, message: 'Simulated registry deletion on non-Windows platform.' };
    }

    // 2. Direct reg.exe delete invocation
    const args = ['delete', fullKey, '/v', valueName, '/f'];
    if (options?.view === '32') {
      args.push('/reg:32');
    } else if (options?.view === '64') {
      args.push('/reg:64');
    }

    try {
      await execFileAsync('reg.exe', args, {
        timeout: 4000,
        windowsHide: true
      });

      // Post-operation verification: Query value to ensure it's gone
      const verifyEntries = await this.queryKey(hive, subKey, options);
      const stillExists = verifyEntries.some((e) => e.valueName === valueName);

      if (stillExists) {
        return { success: false, message: 'Registry value deletion could not be verified on disk.' };
      }

      return { success: true };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      return { success: false, message: `Failed to delete registry value: ${errMsg}` };
    }
  }
}
