import { Verdict, SeverityLevel, RiskAssessment } from '@private-protection/core';
import { AssistantEvidenceToken, AssistantInput, AssistantOutput } from '../types';

export type AutoTaskType =
  | 'AUTO_CONTAINMENT'
  | 'DEFENSE_ADVICE'
  | 'SECURITY_POSTURE_AUDIT'
  | 'COUNTERMEASURE_RECOMMENDATION';

export type AutoTaskPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AutoTaskAction {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly command: string;
  readonly canAutoExecute: boolean; // True if completely safe on-device action
  readonly requiresUserConsent: boolean; // True if friction gate needed
}

export interface AutonomousSecurityTask {
  readonly taskId: string;
  readonly type: AutoTaskType;
  readonly priority: AutoTaskPriority;
  readonly title: string;
  readonly reasoning: string;
  readonly plannedActions: AutoTaskAction[];
  readonly createdAtMs: number;
}

export interface AutoTaskPlanResult {
  readonly tasks: AutonomousSecurityTask[];
  readonly autoExecutedCount: number;
  readonly pendingUserConsentCount: number;
  readonly executionTimeMs: number;
}

/**
 * AutonomousTaskPlanner
 *
 * Evaluates security verdicts and evidence in real-time to generate
 * autonomous defensive containment, advice, and self-healing action plans.
 * Conforms strictly to zero-cloud, privacy-preserving, fail-closed principles.
 */
export class AutonomousTaskPlanner {
  public planAutoTasks(input: {
    verdict: Verdict;
    riskAssessment: RiskAssessment;
    evidenceTokens: AssistantEvidenceToken[];
    targetType?: string;
    untrustedSnippet?: string;
  }): AutoTaskPlanResult {
    const startTime = Date.now();
    const tasks: AutonomousSecurityTask[] = [];

    const isHighThreat =
      input.verdict === Verdict.DANGEROUS ||
      input.riskAssessment.overallScore >= 70 ||
      input.riskAssessment.severity === SeverityLevel.CRITICAL ||
      input.riskAssessment.severity === SeverityLevel.HIGH;

    const isSuspicious =
      input.verdict === Verdict.SUSPICIOUS ||
      (input.riskAssessment.overallScore >= 40 && input.riskAssessment.overallScore < 70);

    // 1. Threat Containment Task
    if (isHighThreat) {
      tasks.push({
        taskId: `auto-contain-${Date.now()}-1`,
        type: 'AUTO_CONTAINMENT',
        priority: 'CRITICAL',
        title: 'Emergency Threat Containment & Isolation',
        reasoning:
          'High-confidence threat or deceptive attack payload identified. Immediate volatile RAM isolation and access shielding initiated.',
        plannedActions: [
          {
            id: 'action-block-render',
            title: 'Block Unsafe Destination',
            description: 'Prevent client navigation and intercept deceptive resource request.',
            command: 'SHIELD_BLOCK_NAVIGATION',
            canAutoExecute: true,
            requiresUserConsent: false
          },
          {
            id: 'action-clear-clipboard',
            title: 'Sanitize Clipboard Payload',
            description: 'Scrub malicious URL or scam text from active system clipboard if present.',
            command: 'PURGE_CLIPBOARD_THREAT',
            canAutoExecute: false,
            requiresUserConsent: true
          },
          {
            id: 'action-quarantine-target',
            title: 'Vault Isolation',
            description: 'Move deceptive target identifier to local on-device blocklist.',
            command: 'LOCAL_VAULT_RECORD',
            canAutoExecute: true,
            requiresUserConsent: false
          }
        ],
        createdAtMs: Date.now()
      });
    }

    // 2. Suspicious Countermeasure Task
    if (isSuspicious) {
      tasks.push({
        taskId: `auto-countermeasure-${Date.now()}-2`,
        type: 'COUNTERMEASURE_RECOMMENDATION',
        priority: 'HIGH',
        title: 'Cautionary Shield & Verification Advisory',
        reasoning:
          'Ambiguous or suspicious communication indicators detected. Protective friction gates recommended before interaction.',
        plannedActions: [
          {
            id: 'action-friction-warning',
            title: 'Display Friction Warning Banner',
            description: 'Alert user with color-coded advisory highlighting detected anomalies.',
            command: 'RENDER_WARNING_MODAL',
            canAutoExecute: true,
            requiresUserConsent: false
          },
          {
            id: 'action-domain-whois-local',
            title: 'Offline Entropy Verification',
            description: 'Perform brand typosquatting & IDN homograph lexical audit.',
            command: 'LOCAL_LEXICAL_AUDIT',
            canAutoExecute: true,
            requiresUserConsent: false
          }
        ],
        createdAtMs: Date.now()
      });
    }

    // 3. Proactive Defensive Guidance Task
    tasks.push({
      taskId: `auto-advice-${Date.now()}-3`,
      type: 'DEFENSE_ADVICE',
      priority: isHighThreat ? 'HIGH' : isSuspicious ? 'MEDIUM' : 'LOW',
      title: 'Actionable Security Guidance & Hardening',
      reasoning:
        'Continuous posture evaluation synthesizing step-by-step guidance tailored to the threat category.',
      plannedActions: [
        {
          id: 'action-plain-explanation',
          title: 'Plain Language Defense Briefing',
          description: 'Synthesize cognitive grade explanation of why this interaction is flagged.',
          command: 'SYNTHESIZE_EXPLANATION',
          canAutoExecute: true,
          requiresUserConsent: false
        },
        {
          id: 'action-password-rotation',
          title: 'Recommend Account Credential Audit',
          description: 'If credentials were entered previously, guide user to rotate passwords immediately.',
          command: 'ADVISE_PASSWORD_RESET',
          canAutoExecute: false,
          requiresUserConsent: true
        }
      ],
      createdAtMs: Date.now()
    });

    let autoExecutedCount = 0;
    let pendingUserConsentCount = 0;

    for (const t of tasks) {
      for (const a of t.plannedActions) {
        if (a.canAutoExecute && !a.requiresUserConsent) {
          autoExecutedCount++;
        } else {
          pendingUserConsentCount++;
        }
      }
    }

    return {
      tasks,
      autoExecutedCount,
      pendingUserConsentCount,
      executionTimeMs: Math.max(0.01, Date.now() - startTime)
    };
  }
}
