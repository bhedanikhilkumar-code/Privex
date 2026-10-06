import { describe, it, expect } from 'vitest';
import { ResponsePolicyEngine } from '../../services/response-policy-engine';
import { ResponseEvaluationInput } from '../../types/desktop.types';

describe('ResponsePolicyEngine (Phase I — 5-Tier Response Ladder)', () => {
  describe('Tier 1: LOW (Log Only)', () => {
    it('evaluates benign safe files with zero risk score to LOW tier and LOG_ONLY action', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 0,
        severity: 'safe',
        verdict: 'ALLOW',
        confidence: 1.0
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('LOW');
      expect(result.action).toBe('LOG_ONLY');
      expect(result.autoQuarantine).toBe(false);
      expect(result.requiresConfirmation).toBe(false);
      expect(result.containProcess).toBe(false);
      expect(result.promptRollback).toBe(false);
      expect(result.effectiveScore).toBe(0);
      expect(result.effectiveVerdict).toBe('ALLOW');
    });

    it('evaluates low risk score (1-49) to LOW tier', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 35,
        severity: 'low',
        verdict: 'INFORM',
        confidence: 'medium'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('LOW');
      expect(result.action).toBe('LOG_ONLY');
      expect(result.autoQuarantine).toBe(false);
    });
  });

  describe('Tier 2: MEDIUM (User Warning)', () => {
    it('evaluates suspicious files with risk score 50-74 to MEDIUM tier and WARN_USER action', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 65,
        severity: 'suspicious',
        verdict: 'WARN',
        confidence: 0.8,
        threatName: 'Heuristic.SuspiciousScript'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('MEDIUM');
      expect(result.action).toBe('WARN_USER');
      expect(result.autoQuarantine).toBe(false);
      expect(result.requiresConfirmation).toBe(false);
      expect(result.containProcess).toBe(false);
      expect(result.promptRollback).toBe(false);
    });
  });

  describe('Tier 3: HIGH (Hold / Quarantine Confirmation)', () => {
    it('evaluates dangerous threats with risk score 75-89 to HIGH tier and HOLD_QUARANTINE action', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 82,
        severity: 'dangerous',
        verdict: 'BLOCK',
        confidence: 0.95,
        threatName: 'Trojan.Dropper.Gen'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('HIGH');
      expect(result.action).toBe('HOLD_QUARANTINE');
      expect(result.requiresConfirmation).toBe(true);
      expect(result.autoQuarantine).toBe(false);
      expect(result.containProcess).toBe(false);
    });
  });

  describe('Tier 4: CRITICAL (Automatic Quarantine)', () => {
    it('evaluates critical confirmed malware with risk score 90-100 to CRITICAL tier and AUTO_QUARANTINE action', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 98,
        severity: 'critical',
        verdict: 'BLOCK',
        confidence: 1.0,
        threatName: 'Backdoor.CobaltStrike.Beacon'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('CRITICAL');
      expect(result.action).toBe('AUTO_QUARANTINE');
      expect(result.autoQuarantine).toBe(true);
      expect(result.requiresConfirmation).toBe(false);
      expect(result.containProcess).toBe(false);
    });
  });

  describe('Tier 5: RANSOMWARE_BEHAVIOR (Containment & ShadowVault Rollback)', () => {
    it('evaluates ransomware incident with highest priority to RANSOMWARE_BEHAVIOR tier', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 100,
        severity: 'critical',
        verdict: 'CONTAIN_PROCESS',
        isRansomwareIncident: true,
        threatName: 'Ransomware.LockBit.3',
        evidenceFactors: ['Rapid encryption burst', 'Extension modification .lockbit']
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('RANSOMWARE_BEHAVIOR');
      expect(result.action).toBe('CONTAIN_AND_ROLLBACK');
      expect(result.containProcess).toBe(true);
      expect(result.promptRollback).toBe(true);
      expect(result.autoQuarantine).toBe(false);
    });

    it('evaluates decoy canary trip immediately to RANSOMWARE_BEHAVIOR tier', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 95,
        severity: 'critical',
        verdict: 'BLOCK',
        isCanaryTamper: true,
        threatName: 'DecoyCanaryTamper'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('RANSOMWARE_BEHAVIOR');
      expect(result.action).toBe('CONTAIN_AND_ROLLBACK');
      expect(result.containProcess).toBe(true);
      expect(result.promptRollback).toBe(true);
    });

    it('inviolable invariant: ransomware behavior CANNOT be excluded or bypassed', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 100,
        severity: 'critical',
        verdict: 'CONTAIN_PROCESS',
        isRansomwareIncident: true,
        isExcluded: true,
        exclusionReason: 'User whitelisted hash'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.tier).toBe('RANSOMWARE_BEHAVIOR');
      expect(result.action).toBe('CONTAIN_AND_ROLLBACK');
      expect(result.isExcluded).toBe(false);
    });
  });

  describe('RULE-09 OS Safety & Protected System Binaries', () => {
    it('prevents automatic destructive quarantine on protected system binaries', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 95,
        severity: 'critical',
        verdict: 'BLOCK',
        isProtectedSystemBinary: true,
        threatName: 'SuspiciousBehavior.SystemBinary'
      };

      const result = ResponsePolicyEngine.evaluate(input);

      expect(result.isProtectedSystemBinary).toBe(true);
      expect(result.autoQuarantine).toBe(false);
      expect(result.action).not.toBe('AUTO_QUARANTINE');
      expect(result.requiresConfirmation).toBe(true);
    });
  });

  describe('Deterministic Mathematical Consistency', () => {
    it('produces identical evaluation for identical inputs across 500 iterations', () => {
      const input: ResponseEvaluationInput = {
        riskScore: 78,
        severity: 'dangerous',
        verdict: 'BLOCK',
        threatName: 'Malware.Generic'
      };

      const first = ResponsePolicyEngine.evaluate(input);
      for (let i = 0; i < 500; i++) {
        const next = ResponsePolicyEngine.evaluate(input);
        expect(next.tier).toBe(first.tier);
        expect(next.action).toBe(first.action);
        expect(next.autoQuarantine).toBe(first.autoQuarantine);
        expect(next.requiresConfirmation).toBe(first.requiresConfirmation);
      }
    });

    it('clamps out-of-bounds risk scores safely to [0, 100]', () => {
      const negative = ResponsePolicyEngine.evaluate({
        riskScore: -50,
        severity: 'safe',
        verdict: 'ALLOW'
      });
      expect(negative.effectiveScore).toBe(0);
      expect(negative.tier).toBe('LOW');

      const overflow = ResponsePolicyEngine.evaluate({
        riskScore: 9999,
        severity: 'critical',
        verdict: 'BLOCK'
      });
      expect(overflow.effectiveScore).toBe(100);
      expect(overflow.tier).toBe('CRITICAL');
    });
  });
});
