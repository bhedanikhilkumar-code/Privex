import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { PersistenceCommandParser } from '../../core/persistence-command-parser';

describe('PersistenceCommandParser (Unit Tests)', () => {
  it('safely parses quoted executable paths with arguments', () => {
    const raw = '"C:\\Program Files\\Example Vendor\\App.exe" /background --silent';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.isQuoted).toBe(true);
    expect(parsed.executablePath).toBe('C:\\Program Files\\Example Vendor\\App.exe');
    expect(parsed.arguments).toBe('/background --silent');
    expect(parsed.isSuspicious).toBe(false);
  });

  it('safely parses unquoted executable paths with spaces using extension boundaries', () => {
    const raw = 'C:\\Program Files\\Example Vendor\\Service.exe -start -quiet';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.executablePath).toBe('C:\\Program Files\\Example Vendor\\Service.exe');
    expect(parsed.arguments).toBe('-start -quiet');
    expect(parsed.isSuspicious).toBe(false);
  });

  it('expands environment variables without executing child processes', () => {
    const raw = '%WINDIR%\\System32\\cleanapp.exe /autostart';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.hasEnvironmentVariables).toBe(true);
    expect(parsed.executablePath.toLowerCase()).toContain('system32\\cleanapp.exe');
    expect(parsed.isSuspicious).toBe(false);
  });

  it('sanitizes NUL bytes, RTLO directional overrides, and control characters', () => {
    const raw = '"C:\\Tools\\app\0.exe\u202Ecod.exe" --arg\x07';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.executablePath).not.toContain('\0');
    expect(parsed.executablePath).not.toContain('\u202E');
    expect(parsed.arguments).not.toContain('\x07');
  });

  it('resolves relative paths safely when baseDir is provided', () => {
    const raw = 'tools\\helper.exe --run';
    const baseDir = 'C:\\ProgramData\\App';
    const parsed = PersistenceCommandParser.parseCommandLine(raw, baseDir);

    expect(parsed.executablePath).toBe(path.resolve(baseDir, 'tools\\helper.exe'));
  });

  it('detects automated scripts in persistence', () => {
    const scripts = ['C:\\Users\\User\\startup.vbs', 'C:\\Users\\User\\run.bat', 'C:\\Users\\User\\script.ps1'];

    for (const script of scripts) {
      const parsed = PersistenceCommandParser.parseCommandLine(script);
      expect(parsed.isScript).toBe(true);
      expect(parsed.isSuspicious).toBe(true);
      expect(parsed.indicators).toContain('SCRIPT_IN_STARTUP_PERSISTENCE');
    }
  });

  it('detects LOLBins and suspicious execution arguments', () => {
    const raw = 'powershell.exe -w hidden -enc JABhID0A...';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.isLolbin).toBe(true);
    expect(parsed.isSuspicious).toBe(true);
    expect(parsed.indicators).toContain('LOLBIN_IN_STARTUP_PERSISTENCE');
    expect(parsed.indicators).toContain('SUSPICIOUS_PERSISTENCE_ARGUMENT');
    expect(parsed.riskContribution).toBeGreaterThanOrEqual(60);
  });

  it('detects execution from temporary or public directories', () => {
    const raw = 'C:\\Users\\User\\AppData\\Local\\Temp\\dropper.exe';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.isSuspicious).toBe(true);
    expect(parsed.indicators).toContain('TEMP_DIRECTORY_PERSISTENCE');
    expect(parsed.riskContribution).toBeGreaterThanOrEqual(40);
  });

  it('detects deceptive double-extension executables', () => {
    const raw = 'C:\\Users\\User\\Documents\\invoice.pdf.exe';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.isSuspicious).toBe(true);
    expect(parsed.indicators).toContain('DOUBLE_EXTENSION_PERSISTENCE');
  });

  it('detects UNC network paths in persistence', () => {
    const raw = '\\\\192.168.1.100\\shared\\payload.exe';
    const parsed = PersistenceCommandParser.parseCommandLine(raw);

    expect(parsed.isSuspicious).toBe(true);
    expect(parsed.indicators).toContain('UNC_NETWORK_PERSISTENCE');
  });
});
