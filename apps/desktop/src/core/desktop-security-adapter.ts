import {
  DetectionPipeline,
  Verdict,
  SeverityLevel,
  InputType
} from '@private-protection/core';
import {
  UrlSemanticClassifier,
  AISecurityAssistant,
  AssistantInput
} from '@private-protection/ml';
import { FileAnalyzer } from './file-analyzer';
import {
  FileAnalysisResult,
  DetectedThreat,
  DesktopAssistantExplanation,
  MotwAnalysisResult
} from '../types/desktop.types';
import { MotwAnalyzer } from './motw-analyzer';

export class DesktopSecurityAdapter {
  private pipeline: DetectionPipeline;
  private urlClassifier: UrlSemanticClassifier;
  private assistant: AISecurityAssistant;

  constructor() {
    this.pipeline = new DetectionPipeline();
    this.urlClassifier = new UrlSemanticClassifier();
    this.assistant = new AISecurityAssistant();
  }

  /**
   * Analyzes a local filesystem file using the canonical @private-protection/core file analyzer.
   */
  public async analyzeFile(
    filePath: string,
    options?: { entropyDetectionEnabled?: boolean; inspectMotw?: boolean }
  ): Promise<FileAnalysisResult> {
    return FileAnalyzer.analyzeFile(filePath, options);
  }

  /**
   * Performs Mark-of-the-Web (MOTW) NTFS ADS inspection on a file.
   */
  public analyzeMotw(filePath: string): MotwAnalysisResult {
    return MotwAnalyzer.analyzeFile(filePath);
  }

  /**
   * Evaluates an untrusted URL using @private-protection/core and @private-protection/ml.
   */
  public async scanUrl(url: string, readingGrade: 6 | 8 = 6) {
    if (!url || typeof url !== 'string' || url.length > 2048) {
      throw new Error('URL_TOO_LONG_OR_INVALID: URLs must not exceed 2048 bytes.');
    }

    const trimmed = url.trim();
    const coreResult = await this.pipeline.scan({
      input: trimmed,
      inputType: InputType.URL
    });

    const semanticResult = this.urlClassifier.analyzeUrlSemantics(trimmed);
    let combinedScore = coreResult.riskScore || 0;
    let verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    let severity = (coreResult.riskAssessment?.severity as SeverityLevel) || SeverityLevel.NONE;
    let riskAssessment = coreResult.riskAssessment;
    const evidence = [...(coreResult.evidence || [])];
    if (semanticResult.isDeceptive && semanticResult.evidenceToken) {
      evidence.push(semanticResult.evidenceToken);
      const recalculated = this.pipeline.riskScorer.calculate(
        evidence,
        this.pipeline.threatIntel.getStalenessDays()
      );
      combinedScore = Math.min(
        100,
        Math.max(
          recalculated.score,
          coreResult.riskScore || 0,
          semanticResult.evidenceToken.scoreContribution || semanticResult.evidenceToken.weight || 50
        )
      );
      if (combinedScore >= 85) {
        verdict = Verdict.DANGEROUS;
        severity = SeverityLevel.CRITICAL;
      } else if (combinedScore >= 70) {
        verdict = Verdict.SUSPICIOUS;
        severity = SeverityLevel.HIGH;
      } else if (combinedScore >= 50) {
        verdict = Verdict.CAUTION;
        severity = SeverityLevel.MEDIUM;
      }
      if (recalculated.riskAssessment) {
        riskAssessment = {
          ...recalculated.riskAssessment,
          overallScore: combinedScore,
          severity
        };
      }
    }

    const assistantInput: AssistantInput = {
      requestId: `url-${Date.now()}`,
      verdict,
      riskAssessment: riskAssessment || {
        overallScore: combinedScore,
        confidence: 0.85,
        severity,
        primaryThreatFactor: 'URL_INTEGRITY',
        detectorContributions: {}
      },
      evidenceTokens: evidence.map((ev) => ({
        ruleId: ev.indicator || ev.ruleId || 'rule',
        category: (ev as any).type || (ev as any).category || 'URL',
        description: ev.description,
        scoreContribution: ev.scoreContribution || 10
      })),
      cognitiveReadingGrade: readingGrade,
      targetType: 'URL',
      untrustedSnippet: trimmed
    };

    const explanation = await this.assistant.explain(assistantInput);

    return {
      url: trimmed,
      riskScore: combinedScore,
      verdict,
      severity,
      evidence,
      explanation
    };
  }

  /**
   * Evaluates untrusted message or email text.
   */
  public async scanText(text: string, readingGrade: 6 | 8 = 6) {
    if (!text || typeof text !== 'string' || text.length > 10000) {
      throw new Error('TEXT_TOO_LONG_OR_INVALID: Text inputs must not exceed 10000 characters.');
    }

    const trimmed = text.trim();
    const coreResult = await this.pipeline.scan({
      input: trimmed,
      inputType: InputType.TEXT
    });

    const verdict = (coreResult.verdict as Verdict) || Verdict.ALLOW;
    const severity = (coreResult.riskAssessment?.severity as SeverityLevel) || SeverityLevel.NONE;

    const assistantInput: AssistantInput = {
      requestId: `text-${Date.now()}`,
      verdict,
      riskAssessment: coreResult.riskAssessment || {
        overallScore: coreResult.riskScore,
        confidence: 0.85,
        severity,
        primaryThreatFactor: 'TEXT_INTEGRITY',
        detectorContributions: {}
      },
      evidenceTokens: (coreResult.evidence || []).map((ev) => ({
        ruleId: ev.indicator || ev.ruleId || 'rule',
        category: (ev as any).type || (ev as any).category || 'TEXT',
        description: ev.description,
        scoreContribution: ev.scoreContribution || 10
      })),
      cognitiveReadingGrade: readingGrade,
      targetType: 'TEXT',
      untrustedSnippet: trimmed
    };

    const explanation = await this.assistant.explain(assistantInput);

    return {
      text: trimmed,
      riskScore: coreResult.riskScore,
      verdict,
      severity,
      evidence: coreResult.evidence,
      explanation
    };
  }

  /**
   * Synthesizes an on-device plain-language explanation for a detected file threat.
   */
  public async explainThreat(
    threat: DetectedThreat,
    level: 'grade6' | 'grade8' = 'grade6'
  ): Promise<DesktopAssistantExplanation> {
    const readingGrade: 6 | 8 = level === 'grade6' ? 6 : 8;

    let verdict = Verdict.ALLOW;
    if (threat.verdict === 'BLOCK') verdict = Verdict.DANGEROUS;
    else if (threat.verdict === 'WARN') verdict = Verdict.SUSPICIOUS;
    else if (threat.verdict === 'INFORM') verdict = Verdict.INFORM;

    let severity = SeverityLevel.NONE;
    if (threat.severity === 'critical') severity = SeverityLevel.CRITICAL;
    else if (threat.severity === 'dangerous') severity = SeverityLevel.HIGH;
    else if (threat.severity === 'suspicious') severity = SeverityLevel.MEDIUM;
    else if (threat.severity === 'low') severity = SeverityLevel.LOW;

    const evidenceTokens = threat.evidenceFactors.map((factor, idx) => ({
      ruleId: `file-heuristic-${idx + 1}`,
      category: 'FILE_INTEGRITY',
      description: factor,
      scoreContribution: 25
    }));

    const assistantInput: AssistantInput = {
      requestId: threat.id,
      verdict,
      riskAssessment: {
        overallScore: threat.riskScore,
        confidence: 0.9,
        severity,
        primaryThreatFactor: threat.threatName,
        detectorContributions: {}
      },
      evidenceTokens,
      cognitiveReadingGrade: readingGrade,
      targetType: 'FILE',
      untrustedSnippet: threat.fileName
    };

    const output = await this.assistant.explain(assistantInput);

    return {
      threatTitle: threat.threatName,
      summary: output.headline || output.summaryParagraph,
      explanation: output.summaryParagraph,
      riskLevel: threat.severity.toUpperCase(),
      recommendedActions: output.recommendedSteps || [],
      cognitiveLevel: level
    };
  }

  /**
   * Returns current engine versions for transparency.
   */
  public getEngineVersions() {
    return {
      coreVersion: '1.0.0-verified',
      mlVersion: '1.0.0-verified',
      threatDatabaseVersion: '2026.10-offline-seed'
    };
  }
}
