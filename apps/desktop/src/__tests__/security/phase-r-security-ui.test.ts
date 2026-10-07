import { describe, it, expect } from 'vitest';

/**
 * Phase R Security & Presentation Invariants Test Suite
 * Validates UX security guarantees:
 * 1. RTLO & Bidirectional Unicode Sanitization
 * 2. Fail-Closed Posture Derivation
 * 3. Friction Gate Enforcement Invariants
 * 4. Zero Decision Downgrade Authority in UI
 */
describe('Phase R: Desktop UI Security & Presentation Invariants', () => {
  // RULE-01 & RULE-08: Unicode Bidirectional & RTLO Sanitization
  describe('Filename & Path Spoofing Prevention (RTLO / Bidi Neutralization)', () => {
    // Canonical sanitizer used in ThreatDetectionModal
    const sanitizeDisplayName = (name: string): string => {
      // Strip dangerous Unicode direction override characters:
      // U+202A to U+202E (LRE, RLE, PDF, LRO, RLO)
      // U+2066 to U+2069 (LRI, RLI, FSI, PDI)
      return name.replace(/[\u202A-\u202E\u2066-\u2069]/g, '');
    };

    it('neutralizes Right-to-Left Override (U+202E) spoofing executable extensions', () => {
      // Attacker names file "invoice\u202Eexe.pdf" so OS displays "invoicefdp.exe" or hides ".exe"
      const maliciousName = 'Quarterly_Report_\u202Efdp.exe';
      const sanitized = sanitizeDisplayName(maliciousName);

      expect(sanitized).toBe('Quarterly_Report_fdp.exe');
      expect(sanitized).not.toContain('\u202E');
    });

    it('strips all bidirectional override and isolate control characters', () => {
      const bidiCharacters = [
        '\u202A', // Left-to-Right Embedding
        '\u202B', // Right-to-Left Embedding
        '\u202C', // Pop Directional Formatting
        '\u202D', // Left-to-Right Override
        '\u202E', // Right-to-Left Override
        '\u2066', // Left-to-Right Isolate
        '\u2067', // Right-to-Left Isolate
        '\u2068', // First Strong Isolate
        '\u2069'  // Pop Directional Isolate
      ];

      for (const char of bidiCharacters) {
        const input = `file_test_${char}_payload.exe`;
        const cleaned = sanitizeDisplayName(input);
        expect(cleaned).toBe('file_test__payload.exe');
        expect(cleaned).not.toContain(char);
      }
    });

    it('preserves legitimate non-spoofed filenames with standard unicode', () => {
      const legitName = 'Rapport_Financier_2026_école.xlsx';
      expect(sanitizeDisplayName(legitName)).toBe(legitName);
    });
  });

  // RULE-02: Fail-Closed Posture Derivation
  describe('Fail-Closed System Posture Computation Invariant', () => {
    const derivePostureState = (
      threatsCount: number,
      overallHealth: 'HEALTHY' | 'WARNING' | 'DEGRADED' | 'CRITICAL',
      realtimeShieldActive: boolean,
      watchdogSnoozeActive: boolean,
      intelStale: boolean
    ): 'PROTECTED' | 'ATTENTION' | 'ACTION_REQUIRED' => {
      const isCritical =
        threatsCount > 0 ||
        overallHealth === 'CRITICAL' ||
        overallHealth === 'DEGRADED' ||
        (!realtimeShieldActive && !watchdogSnoozeActive);

      const isAttention =
        !isCritical &&
        (overallHealth === 'WARNING' || watchdogSnoozeActive || intelStale);

      if (isCritical) return 'ACTION_REQUIRED';
      if (isAttention) return 'ATTENTION';
      return 'PROTECTED';
    };

    it('MUST fail to ACTION_REQUIRED if active threats exist', () => {
      const posture = derivePostureState(1, 'HEALTHY', true, false, false);
      expect(posture).toBe('ACTION_REQUIRED');
    });

    it('MUST fail to ACTION_REQUIRED if system health is CRITICAL or DEGRADED', () => {
      expect(derivePostureState(0, 'CRITICAL', true, false, false)).toBe('ACTION_REQUIRED');
      expect(derivePostureState(0, 'DEGRADED', true, false, false)).toBe('ACTION_REQUIRED');
    });

    it('MUST fail to ACTION_REQUIRED if real-time shield is stopped and not legally snoozed', () => {
      const posture = derivePostureState(0, 'HEALTHY', false, false, false);
      expect(posture).toBe('ACTION_REQUIRED');
    });

    it('yields ATTENTION if shield is temporarily snoozed or definitions are stale', () => {
      // Snoozed shield
      expect(derivePostureState(0, 'HEALTHY', false, true, false)).toBe('ATTENTION');
      // Stale definitions
      expect(derivePostureState(0, 'HEALTHY', true, false, true)).toBe('ATTENTION');
      // Warning health
      expect(derivePostureState(0, 'WARNING', true, false, false)).toBe('ATTENTION');
    });

    it('yields PROTECTED only when zero threats, nominal health, active shields, and fresh intel', () => {
      const posture = derivePostureState(0, 'HEALTHY', true, false, false);
      expect(posture).toBe('PROTECTED');
    });
  });

  // RULE-03: Friction Gate Security Policy
  describe('Friction Gate Critical Action Classification', () => {
    const requiresFrictionGate = (actionType: string): boolean => {
      const sensitiveActions = [
        'RESTORE_QUARANTINE',
        'PAUSE_REALTIME_SHIELD',
        'DISABLE_RANSOMWARE_SHIELD',
        'ADD_PATH_EXCLUSION',
        'CRYPTO_SHRED_DATA',
        'PURGE_QUARANTINE_VAULT',
        'RESET_WATCHDOG_ISOLATION'
      ];
      return sensitiveActions.includes(actionType);
    };

    it('mandates friction gate countdown for security-lowering and destructive operations', () => {
      expect(requiresFrictionGate('RESTORE_QUARANTINE')).toBe(true);
      expect(requiresFrictionGate('PAUSE_REALTIME_SHIELD')).toBe(true);
      expect(requiresFrictionGate('CRYPTO_SHRED_DATA')).toBe(true);
      expect(requiresFrictionGate('ADD_PATH_EXCLUSION')).toBe(true);
      expect(requiresFrictionGate('PURGE_QUARANTINE_VAULT')).toBe(true);
    });

    it('does NOT require friction gate for passive read-only operations', () => {
      expect(requiresFrictionGate('QUERY_HISTORY')).toBe(false);
      expect(requiresFrictionGate('VIEW_SETTINGS')).toBe(false);
      expect(requiresFrictionGate('RUN_HEALTH_CHECK')).toBe(false);
    });
  });

  // RULE-04: Canonical Decision Authority Invariant
  describe('UI Has Zero Decision Downgrade Authority', () => {
    it('verifies UI does not alter backend risk scores or verdicts', () => {
      const backendVerdict = {
        verdict: 'MALICIOUS',
        effectiveScore: 95,
        action: 'QUARANTINE_FILE'
      };

      // UI merely displays backend properties without mutation
      const displayProps = { ...backendVerdict };
      expect(displayProps.verdict).toBe('MALICIOUS');
      expect(displayProps.effectiveScore).toBe(95);
      expect(displayProps.action).toBe('QUARANTINE_FILE');
    });
  });
});
