import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ExclusionManagerService } from '../../services/exclusion-manager.service';
import { ResponsePolicyEngine } from '../../services/response-policy-engine';

describe('Phase I Security Tests — Anti-Abuse Guardrails & Invariants', () => {
  let tempDir: string;
  let service: ExclusionManagerService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-phase-i-'));
    service = new ExclusionManagerService({
      configDir: tempDir
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  describe('SEC-I-01: Critical Windows Paths Prohibition', () => {
    it('strictly forbids adding C:\\, C:\\Windows, and System32 to path exclusions', () => {
      const forbiddenPaths = [
        'C:\\',
        'C:',
        'C:\\Windows',
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64',
        'C:\\Windows\\System32\\drivers',
        'C:\\Program Files',
        'C:\\Program Files (x86)'
      ];

      for (const p of forbiddenPaths) {
        expect(() => {
          service.addExclusion({
            type: 'PATH',
            value: p,
            reason: 'Attacker attempting whole OS allowlisting'
          });
        }).toThrow(/SECURITY_VIOLATION/i);
      }
    });

    it('strictly forbids adding user temporary directories and Downloads root to path exclusions', () => {
      const userSensitiveRoots = [
        path.join(os.homedir(), 'Downloads'),
        os.tmpdir(),
        process.env.TEMP || 'C:\\Users\\default\\AppData\\Local\\Temp'
      ];

      for (const p of userSensitiveRoots) {
        expect(() => {
          service.addExclusion({
            type: 'PATH',
            value: p,
            reason: 'Attacker attempting whole Downloads allowlisting'
          });
        }).toThrow(/SECURITY_VIOLATION/i);
      }
    });

    it('rejects path traversal attempts aimed at bypassing root directory restrictions', () => {
      const traversalCandidate = 'C:\\SomeRandomFolder\\..\\..\\Windows\\System32';
      expect(() => {
        service.addExclusion({
          type: 'PATH',
          value: traversalCandidate,
          reason: 'Path traversal attempt'
        });
      }).toThrow(/SECURITY_VIOLATION/i);
    });
  });

  describe('SEC-I-02: Wildcard & Dangerous Extension Prohibition', () => {
    it('strictly rejects wildcard paths and glob expressions', () => {
      const wildcards = [
        '*.exe',
        '*.*',
        'C:\\tools\\*.dll',
        'C:\\apps\\**',
        'C:\\safe\\*.ps1'
      ];

      for (const w of wildcards) {
        expect(() => {
          service.addExclusion({
            type: 'PATH',
            value: w,
            reason: 'Wildcard exclusion attempt'
          });
        }).toThrow(/SECURITY_VIOLATION.*wildcard/i);
      }
    });
  });

  describe('SEC-I-03: Inviolable Ransomware Invariant', () => {
    it('guarantees that active exclusions CANNOT bypass or silence authoritative ransomware behavior', () => {
      const evilSha256 = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
      // User or attacker previously whitelisted this hash
      service.addExclusion({
        type: 'HASH',
        value: evilSha256,
        reason: 'Legitimate backup utility'
      });

      // Regular check returns true
      expect(service.checkHash(evilSha256).isExcluded).toBe(true);

      // BUT when evaluated in an active Ransomware / Canary tamper incident context:
      const ransomwareContextCheck = service.checkHash(evilSha256, {
        isRansomware: true,
        riskScore: 100,
        verdict: 'CONTAIN_PROCESS'
      });

      expect(ransomwareContextCheck.isExcluded).toBe(false);
      expect(ransomwareContextCheck.reason).toContain('ANTI_ABUSE_GUARDRAIL');
    });

    it('guarantees ResponsePolicyEngine overrides exclusion when ransomware flag is present', () => {
      const evaluation = ResponsePolicyEngine.evaluate({
        riskScore: 100,
        severity: 'critical',
        verdict: 'CONTAIN_PROCESS',
        isRansomwareIncident: true,
        isExcluded: true,
        exclusionReason: 'Whitelisted hash'
      });

      expect(evaluation.tier).toBe('RANSOMWARE_BEHAVIOR');
      expect(evaluation.action).toBe('CONTAIN_AND_ROLLBACK');
      expect(evaluation.isExcluded).toBe(false);
      expect(evaluation.containProcess).toBe(true);
      expect(evaluation.promptRollback).toBe(true);
    });
  });

  describe('SEC-I-04: Domain Syntax & TTL Enforcement', () => {
    it('rejects malformed domains with URL schemes, paths, or injection characters', () => {
      const badDomains = [
        'http://malicious.com',
        'https://evil.com/payload.exe',
        'evil.com;rm -rf /',
        'evil.com\0nullbyte',
        '*.evil.com',
        'evil..com'
      ];

      for (const d of badDomains) {
        expect(() => {
          service.addExclusion({
            type: 'DOMAIN',
            value: d,
            ttl: '7d',
            reason: 'Bad domain'
          });
        }).toThrow(/INVALID_DOMAIN|SECURITY_VIOLATION/);
      }
    });
  });
});
