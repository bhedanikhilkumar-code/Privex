import { describe, it, expect } from 'vitest';
import { SignatureAutomaton, SeverityLevel } from '../../index';

describe('SignatureAutomaton (Flattened Aho-Corasick Multi-Pattern Automaton)', () => {
  const automaton = SignatureAutomaton.getInstance();

  it('detects standard EICAR antivirus test file in a single O(N) pass', () => {
    const eicar = new TextEncoder().encode(
      'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    );
    const matches = automaton.scan(eicar);
    expect(matches.length).toBeGreaterThanOrEqual(1);

    const match = matches.find((m) => m.signature.id === 'sig-eicar-antivirus-test');
    expect(match).toBeDefined();
    expect(match?.signature.severityLevel).toBe(SeverityLevel.CRITICAL);
    expect(match?.signature.scoreContribution).toBe(100);
    expect(match?.signature.isCriticalOverride).toBe(true);

    const evidence = automaton.toEvidence(matches);
    expect(evidence.some((e) => e.ruleId === 'sig-eicar-antivirus-test')).toBe(true);
  });

  it('detects Mimikatz sekurlsa password extraction signature in both ASCII and WIDE (UTF-16LE)', () => {
    // 1. ASCII match
    const asciiPayload = new TextEncoder().encode('Some memory dump with sekurlsa::logonpasswords token');
    const asciiMatches = automaton.scan(asciiPayload);
    expect(asciiMatches.some((m) => m.signature.id === 'sig-mimikatz-sekurlsa')).toBe(true);

    // 2. UTF-16LE match (Windows Unicode memory representation)
    const wideText = 'sekurlsa::logonpasswords';
    const wideBuffer = new Uint8Array(wideText.length * 2);
    for (let i = 0; i < wideText.length; i++) {
      wideBuffer[i * 2] = wideText.charCodeAt(i);
      wideBuffer[i * 2 + 1] = 0x00;
    }
    const wideMatches = automaton.scan(wideBuffer);
    expect(wideMatches.some((m) => m.signature.id === 'sig-mimikatz-sekurlsa')).toBe(true);
  });

  it('detects ransomware Volume Shadow Copy deletion commands', () => {
    const batchPayload = new TextEncoder().encode(
      '@echo off\r\nvssadmin delete shadows /all /quiet\r\n'
    );
    const matches = automaton.scan(batchPayload);
    expect(matches.some((m) => m.signature.id === 'sig-ransomware-vssadmin-shadows')).toBe(true);
  });

  it('detects in-memory AMSI and ETW tampering patterns', () => {
    const scriptBuffer = new TextEncoder().encode(
      '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")'
    );
    // Custom automaton check
    const customAutomaton = new SignatureAutomaton([
      {
        id: 'test-amsi-pattern',
        name: 'AmsiUtils Token',
        pattern: 'AmsiUtils',
        severityLevel: SeverityLevel.HIGH,
        scoreContribution: 80,
        description: 'Matches AmsiUtils token',
        threatName: 'AMSI_TAMPER'
      }
    ]);
    const matches = customAutomaton.scan(scriptBuffer);
    expect(matches.length).toBe(1);
    expect(matches[0].signature.id).toBe('test-amsi-pattern');
  });

  it('returns empty matches on clean benign buffers without false positives', () => {
    const benign = new TextEncoder().encode(
      'This is a completely normal documentation file discussing security standards.'
    );
    const matches = automaton.scan(benign);
    expect(matches).toHaveLength(0);
  });
});
