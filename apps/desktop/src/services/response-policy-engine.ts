import {
  ResponseEvaluationInput,
  ResponseEvaluationResult,
  ThreatVerdict,
  ThreatSeverity
} from '../types/desktop.types';

/**
 * ResponsePolicyEngine (Phase I — Automatic Response Ladder)
 *
 * Implements the deterministic 5-Tier Automatic Response Ladder:
 * 1. LOW: Log only, no destructive action, no quarantine, no process termination.
 * 2. MEDIUM: User warning notification, record detection, no automatic destructive action.
 * 3. HIGH: User-visible warning / hold/quarantine decision requiring confirmation.
 * 4. CRITICAL: Automatic quarantine, urgent notification, forensic evidence preservation.
 * 5. RANSOMWARE_BEHAVIOR: Highest-priority response, process containment, ShadowVault rollback prompt.
 *
 * Constitutional Invariants:
 * - Deterministic: same inputs -> exactly same response tier and action.
 * - Anti-Abuse: Authoritative ransomware behavior and canary tamper events CANNOT be excluded or diluted.
 * - RULE-09 OS Safety: Protected Windows system binaries are never quarantined.
 * - Read-Only: Does not modify inputs or invent detection scores; maps authoritative detection to policy.
 */
export class ResponsePolicyEngine {
  /**
   * Alias for evaluateResponse.
   */
  public static evaluate(input: ResponseEvaluationInput): ResponseEvaluationResult {
    return this.evaluateResponse(input);
  }

  /**
   * Deterministically evaluates the response tier and action from authoritative detection inputs.
   */
  public static evaluateResponse(input: ResponseEvaluationInput): ResponseEvaluationResult {
    const riskScore = typeof input.riskScore === 'number' && Number.isFinite(input.riskScore)
      ? Math.max(0, Math.min(100, Math.round(input.riskScore)))
      : 0;

    const severity: ThreatSeverity = input.severity || 'safe';
    const verdict: ThreatVerdict =
      input.verdict === 'BLOCK' || input.verdict === 'MALICIOUS' || input.verdict === 'QUARANTINE'
        ? 'BLOCK'
        : input.verdict === 'WARN' || input.verdict === 'SUSPICIOUS'
        ? 'WARN'
        : input.verdict === 'INFORM'
        ? 'INFORM'
        : 'ALLOW';

    const isProtectedSystemBinary = Boolean(input.isProtectedSystemBinary);
    const isCanaryTamper = Boolean(input.isCanaryTamper);
    const isRansomwareIncident = Boolean(
      input.isRansomwareIncident ||
      isCanaryTamper ||
      input.verdict === 'CONTAIN_PROCESS' ||
      (input.threatName && /ransomware|canary/i.test(input.threatName) && riskScore >= 75)
    );

    // ============================================================
    // 1. TIER 5: RANSOMWARE_BEHAVIOR (Highest Priority)
    // ============================================================
    if (isRansomwareIncident) {
      // ANTI-ABUSE GUARDRAIL: Ransomware incidents cannot be bypassed by exclusions
      return {
        tier: 'RANSOMWARE_BEHAVIOR',
        action: 'CONTAIN_AND_ROLLBACK',
        reason: isCanaryTamper
          ? 'RANSOMWARE_CANARY_TAMPER: Decoy canary tripped; process containment and rollback required.'
          : 'RANSOMWARE_VELOCITY: Mass-write or high-entropy burst detected; containment and rollback required.',
        requiresConfirmation: false,
        autoQuarantine: false,
        containProcess: true,
        promptRollback: true,
        isProtectedSystemBinary,
        isExcluded: false, // Anti-abuse: Exclusions ignored for ransomware
        effectiveScore: Math.max(riskScore, 100),
        effectiveVerdict: 'BLOCK'
      };
    }

    // ============================================================
    // 2. EXCLUSION EVALUATION (For Non-Ransomware Events)
    // ============================================================
    if (input.isExcluded) {
      return {
        tier: 'LOW',
        action: 'LOG_ONLY',
        reason: input.exclusionReason || 'EXCLUSION_ACTIVE: Threat suppressed by active user-authorized exclusion rule.',
        requiresConfirmation: false,
        autoQuarantine: false,
        containProcess: false,
        promptRollback: false,
        isProtectedSystemBinary,
        isExcluded: true,
        effectiveScore: 0,
        effectiveVerdict: 'ALLOW'
      };
    }

    // ============================================================
    // 3. TIER 4: CRITICAL (Auto-Quarantine)
    // ============================================================
    const isCritical =
      riskScore >= 90 ||
      (verdict === 'BLOCK' && severity === 'critical');

    if (isCritical) {
      if (isProtectedSystemBinary) {
        // RULE-09 OS Safety: Cannot quarantine protected system binaries
        return {
          tier: 'HIGH',
          action: 'WARN_USER',
          reason: 'PROTECTED_SYSTEM_BINARY: Critical indicator detected on protected Windows binary; quarantine prevented per RULE-09.',
          requiresConfirmation: true,
          autoQuarantine: false,
          containProcess: false,
          promptRollback: false,
          isProtectedSystemBinary: true,
          isExcluded: false,
          effectiveScore: riskScore,
          effectiveVerdict: 'WARN'
        };
      }

      return {
        tier: 'CRITICAL',
        action: 'AUTO_QUARANTINE',
        reason: `CRITICAL_THREAT: Malicious content verified (verdict=${verdict}, score=${riskScore}, severity=${severity}).`,
        requiresConfirmation: false,
        autoQuarantine: true,
        containProcess: false,
        promptRollback: false,
        isProtectedSystemBinary: false,
        isExcluded: false,
        effectiveScore: riskScore,
        effectiveVerdict: 'BLOCK'
      };
    }

    // ============================================================
    // 4. TIER 3: HIGH (Hold & Confirmation)
    // ============================================================
    const isHigh =
      (riskScore >= 75 && riskScore < 90) ||
      severity === 'dangerous' ||
      (verdict === 'BLOCK' && riskScore >= 75);

    if (isHigh) {
      return {
        tier: 'HIGH',
        action: 'HOLD_QUARANTINE',
        reason: `HIGH_RISK_SUSPICIOUS: Suspicious behavior requires user confirmation (score=${riskScore}, severity=${severity}).`,
        requiresConfirmation: true,
        autoQuarantine: false,
        containProcess: false,
        promptRollback: false,
        isProtectedSystemBinary,
        isExcluded: false,
        effectiveScore: riskScore,
        effectiveVerdict: 'WARN'
      };
    }

    // ============================================================
    // 5. TIER 2: MEDIUM (User Warning)
    // ============================================================
    const isMedium =
      (riskScore >= 50 && riskScore < 75) ||
      verdict === 'WARN' ||
      severity === 'suspicious';

    if (isMedium) {
      return {
        tier: 'MEDIUM',
        action: 'WARN_USER',
        reason: `MEDIUM_RISK_ALERT: Potential anomaly detected; user warning presented (score=${riskScore}).`,
        requiresConfirmation: false,
        autoQuarantine: false,
        containProcess: false,
        promptRollback: false,
        isProtectedSystemBinary,
        isExcluded: false,
        effectiveScore: riskScore,
        effectiveVerdict: 'WARN'
      };
    }

    // ============================================================
    // 6. TIER 1: LOW (Log Only / Benign)
    // ============================================================
    return {
      tier: 'LOW',
      action: 'LOG_ONLY',
      reason: `LOW_RISK_BENIGN: Content classified as safe or benign (verdict=${verdict}, score=${riskScore}).`,
      requiresConfirmation: false,
      autoQuarantine: false,
      containProcess: false,
      promptRollback: false,
      isProtectedSystemBinary,
      isExcluded: false,
      effectiveScore: riskScore,
      effectiveVerdict: verdict === 'INFORM' ? 'INFORM' : 'ALLOW'
    };
  }
}
