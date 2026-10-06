import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LnkParser } from '../../core/lnk-parser';

function createSyntheticLnkBuffer(options: {
  targetPath?: string;
  arguments?: string;
  iconLocation?: string;
  description?: string;
  relativePath?: string;
}): Buffer {
  const header = Buffer.alloc(76);
  header.writeUInt32LE(0x0000004c, 0); // HeaderSize = 76

  // LinkCLSID
  const clsid = Buffer.from([
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
  ]);
  clsid.copy(header, 4);

  let flags = 0;
  if (options.description) flags |= 0x04; // HasName
  if (options.relativePath) flags |= 0x08; // HasRelativePath
  if (options.arguments) flags |= 0x20; // HasArguments
  if (options.iconLocation) flags |= 0x40; // HasIconLocation

  header.writeUInt32LE(flags, 0x14);

  const parts: Buffer[] = [header];

  const writeString = (str: string) => {
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16LE(str.length, 0);
    const strBuf = Buffer.from(str, 'ascii');
    return Buffer.concat([lenBuf, strBuf]);
  };

  if (options.description) {
    parts.push(writeString(options.description));
  }
  if (options.relativePath) {
    parts.push(writeString(options.relativePath));
  }
  if (options.arguments) {
    parts.push(writeString(options.arguments));
  }
  if (options.iconLocation) {
    parts.push(writeString(options.iconLocation));
  }

  return Buffer.concat(parts);
}

describe('LnkParser (Phase M — Binary MS-SHLLINK Shortcut Parser)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-lnk-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('rejects truncated buffer smaller than 76 bytes safely without RangeError', async () => {
    const truncated = Buffer.alloc(30);
    const result = await LnkParser.parseBuffer(truncated, 'truncated.lnk');
    expect(result.isShortcut).toBe(false);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('LNK_TRUNCATED_HEADER');
  });

  it('rejects invalid CLSID or magic header', async () => {
    const invalidHeader = Buffer.alloc(76);
    invalidHeader.writeUInt32LE(0x0000004c, 0);
    // Bad CLSID
    const result = await LnkParser.parseBuffer(invalidHeader, 'badclsid.lnk');
    expect(result.isShortcut).toBe(false);
    expect(result.isSuspicious).toBe(false);
  });

  it('parses benign shortcut to notepad.exe without flagging threat', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: 'C:\\Windows\\notepad.exe',
      description: 'Open Notepad'
    });
    const result = await LnkParser.parseBuffer(buf, 'Notepad.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.targetPath).toBe('C:\\Windows\\notepad.exe');
    expect(result.description).toBe('Open Notepad');
    expect(result.isSuspicious).toBe(false);
    expect(result.riskScore).toBeLessThan(50);
  });

  it('detects shortcut targeting script interpreter (powershell.exe)', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      arguments: '-ExecutionPolicy Bypass -File worm.ps1'
    });
    const result = await LnkParser.parseBuffer(buf, 'Launch.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.indicators).toContain('LNK_INVOKES_SCRIPT_INTERPRETER');
    expect(result.indicators).toContain('LNK_SUSPICIOUS_CLI_ARGUMENTS');
  });

  it('detects shortcut targeting wscript.exe interpreter with hidden argument', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: 'wscript.exe',
      arguments: '//e:vbs //b hidden.vbs'
    });
    const result = await LnkParser.parseBuffer(buf, 'Payload.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('LNK_INVOKES_SCRIPT_INTERPRETER');
  });

  it('detects worm spoofed folder names (Documents.lnk, USB.lnk)', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: 'cmd.exe',
      arguments: '/c start payload.exe'
    });
    const result = await LnkParser.parseBuffer(buf, 'Documents.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('LNK_WORM_SPOOFED_FOLDER_NAME');
  });

  it('detects deceptive folder icon masking (shell32.dll,3)', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: 'cmd.exe',
      arguments: '/c start worm.vbs',
      iconLocation: '%SystemRoot%\\system32\\shell32.dll,3'
    });
    const result = await LnkParser.parseBuffer(buf, 'Flash Drive.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('LNK_DECEPTIVE_FOLDER_ICON_MASK');
  });

  it('detects parent directory traversal in relative target (..\\..\\Windows\\cmd.exe)', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: '..\\..\\Windows\\System32\\cmd.exe',
      arguments: '/c calc.exe'
    });
    const result = await LnkParser.parseBuffer(buf, 'Test.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('LNK_RELATIVE_TRAVERSAL_TARGET');
  });

  it('detects remote UNC target in shortcut (\\\\c2-server\\share\\malware.exe)', async () => {
    const buf = createSyntheticLnkBuffer({
      relativePath: '\\\\evil-server\\share\\payload.exe'
    });
    const result = await LnkParser.parseBuffer(buf, 'Share.lnk');
    expect(result.isShortcut).toBe(true);
    expect(result.isSuspicious).toBe(true);
    expect(result.indicators).toContain('LNK_UNC_OR_DEVICE_TARGET');
  });

  it('parses .lnk file from disk and correlates target analysis', async () => {
    const targetScript = path.join(tempDir, 'evil.bat');
    fs.writeFileSync(targetScript, '@echo off\r\npowershell -enc JAB', 'utf-8');

    const lnkPath = path.join(tempDir, 'Shortcut.lnk');
    const buf = createSyntheticLnkBuffer({
      relativePath: 'evil.bat',
      arguments: '-run'
    });
    fs.writeFileSync(lnkPath, buf);

    const result = await LnkParser.parseFile(lnkPath, tempDir);
    expect(result.isShortcut).toBe(true);
    expect(result.targetAnalysis).toBeDefined();
  });
});
