import { describe, it, expect } from 'vitest';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';

describe('WindowsRegistryReader (Unit Tests)', () => {
  const sampleRegOutput = `
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    OneDrive    REG_SZ    "C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background
    Discord    REG_SZ    C:\\Users\\User\\AppData\\Local\\Discord\\app.exe
    SecurityUpdate    REG_EXPAND_SZ    %TEMP%\\secupdate.exe
`;

  it('parses standard reg.exe query tabular output accurately', () => {
    const reader = new WindowsRegistryReader();
    const entries = reader.parseRegOutput(
      sampleRegOutput,
      'HKCU',
      'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      false
    );

    expect(entries.length).toBe(3);

    expect(entries[0].valueName).toBe('OneDrive');
    expect(entries[0].valueType).toBe('REG_SZ');
    expect(entries[0].rawValue).toBe('"C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background');
    expect(entries[0].hive).toBe('HKCU');
    expect(entries[0].isRunOnce).toBe(false);

    expect(entries[1].valueName).toBe('Discord');
    expect(entries[1].rawValue).toBe('C:\\Users\\User\\AppData\\Local\\Discord\\app.exe');

    expect(entries[2].valueName).toBe('SecurityUpdate');
    expect(entries[2].valueType).toBe('REG_EXPAND_SZ');
  });

  it('handles empty or malformed output without throwing exceptions', () => {
    const reader = new WindowsRegistryReader();
    expect(reader.parseRegOutput('', 'HKCU', 'Key', false)).toEqual([]);
    expect(reader.parseRegOutput('ERROR: The system was unable to find the specified registry key or value.', 'HKCU', 'Key', false)).toEqual([]);
    expect(reader.parseRegOutput('Garbage text without columns', 'HKCU', 'Key', false)).toEqual([]);
  });

  it('queries mock registry data cleanly across multiple hives', async () => {
    const mockOutput: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    Steam    REG_SZ    "C:\\Program Files (x86)\\Steam\\steam.exe" -silent
`,
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    RealtekAudio    REG_SZ    "C:\\Program Files\\Realtek\\Audio\\RtkAud.exe"
`,
      'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run': `
    Helper32    REG_SZ    "C:\\Program Files (x86)\\Vendor\\Helper.exe"
`
    };

    const reader = new WindowsRegistryReader({ customRegistryOutput: mockOutput });
    const allEntries = await reader.readAllRunKeys();

    expect(allEntries.length).toBe(3);
    expect(allEntries.some((e) => e.valueName === 'Steam')).toBe(true);
    expect(allEntries.some((e) => e.valueName === 'RealtekAudio')).toBe(true);
    expect(allEntries.some((e) => e.valueName === 'Helper32')).toBe(true);
  });

  it('deletes a specific value name safely from mock registry', async () => {
    const mockOutput: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    GoodApp    REG_SZ    "C:\\Program Files\\GoodApp.exe"
    BadMalware    REG_SZ    %TEMP%\\malware.exe
`
    };

    const reader = new WindowsRegistryReader({ customRegistryOutput: mockOutput });
    const res = await reader.deleteRunValue('HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'BadMalware');

    expect(res.success).toBe(true);

    const remaining = await reader.queryKey('HKCU', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run');
    expect(remaining.length).toBe(1);
    expect(remaining[0].valueName).toBe('GoodApp');
  });
});
