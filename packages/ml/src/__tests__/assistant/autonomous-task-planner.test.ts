import { describe, it, expect } from 'vitest';
import { AutonomousTaskPlanner } from '../../assistant/autonomous-task-planner';
import { AISecurityAssistant } from '../../assistant/assistant-runtime';
import { Verdict, SeverityLevel, RiskAssessment } from '@private-protection/core';
import { AssistantInput } from '../../types';

describe('AutonomousTaskPlanner & AI Auto-Task Execution', () => {
  const planner = new AutonomousTaskPlanner();

  it('generates emergency containment tasks for critical phishing threats', () => {
    const riskAssessment: RiskAssessment = {
      overallScore: 92,
      confidence: 0.98,
      severity: SeverityLevel.CRITICAL,
      primaryThreatFactor: 'CREDENTIAL_HARVESTING',
      detectorContributions: { Typosquatting: 92 }
    };

    const plan = planner.planAutoTasks({
      verdict: Verdict.DANGEROUS,
      riskAssessment,
      evidenceTokens: [
        { ruleId: 'rule-phish', category: 'LEXICAL', description: 'Typosquatted domain', scoreContribution: 92 }
      ],
      targetType: 'URL',
      untrustedSnippet: 'http://paypa1-update.buzz'
    });

    expect(plan.tasks.length).toBeGreaterThanOrEqual(2);
    const containmentTask = plan.tasks.find((t) => t.type === 'AUTO_CONTAINMENT');
    expect(containmentTask).toBeDefined();
    expect(containmentTask?.priority).toBe('CRITICAL');
    expect(containmentTask?.plannedActions.length).toBeGreaterThan(0);

    const blockAction = containmentTask?.plannedActions.find((a) => a.command === 'SHIELD_BLOCK_NAVIGATION');
    expect(blockAction).toBeDefined();
    expect(blockAction?.canAutoExecute).toBe(true);

    expect(plan.autoExecutedCount).toBeGreaterThan(0);
  });

  it('generates advisory countermeasure tasks for suspicious communications', () => {
    const riskAssessment: RiskAssessment = {
      overallScore: 55,
      confidence: 0.85,
      severity: SeverityLevel.MEDIUM,
      primaryThreatFactor: 'SUSPICIOUS_URGENCY',
      detectorContributions: { KeywordUrgency: 55 }
    };

    const plan = planner.planAutoTasks({
      verdict: Verdict.SUSPICIOUS,
      riskAssessment,
      evidenceTokens: [
        { ruleId: 'urgency-words', category: 'HEURISTIC', description: 'Urgent deadline detected', scoreContribution: 55 }
      ],
      targetType: 'MESSAGE'
    });

    const countermeasure = plan.tasks.find((t) => t.type === 'COUNTERMEASURE_RECOMMENDATION');
    expect(countermeasure).toBeDefined();
    expect(countermeasure?.priority).toBe('HIGH');
  });

  it('attaches autoTaskPlan automatically to AISecurityAssistant.explain output', async () => {
    const assistant = new AISecurityAssistant();
    const input: AssistantInput = {
      requestId: 'test-req-auto-1',
      verdict: Verdict.DANGEROUS,
      riskAssessment: {
        overallScore: 88,
        confidence: 0.95,
        severity: SeverityLevel.HIGH,
        primaryThreatFactor: 'EXTORTION',
        detectorContributions: {}
      },
      evidenceTokens: [
        { ruleId: 'bitcoin-blackmail', category: 'HEURISTIC', description: 'Demand for cryptocurrency', scoreContribution: 88 }
      ],
      cognitiveReadingGrade: 6,
      targetType: 'MESSAGE',
      untrustedSnippet: 'URGENT: Pay $500 Bitcoin or files deleted'
    };

    const output = await assistant.explain(input);
    expect(output.autoTaskPlan).toBeDefined();
    expect(output.autoTaskPlan?.tasks.length).toBeGreaterThan(0);
    expect(output.autoTaskPlan?.autoExecutedCount).toBeGreaterThan(0);
  });
});
