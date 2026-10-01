import {
  ActionRecommendation,
  DetectionRequest,
  DetectionResult,
  Evidence,
  FrictionLevel,
  InputType,
  PrescribedAction,
  Recommendation,
  RiskAssessment,
  RiskCategory,
  ScanRequest,
  SeverityLevel,
  Threat,
  Verdict
} from '../types';
import { RuleEngine } from '../rules/rule-engine';
import { URLAnalyzer } from '../analyzers/url-analyzer';
import { TextAnalyzer } from '../analyzers/text-analyzer';
import { RiskScorer } from '../scoring/risk-scorer';
import { ExplanationEngine } from '../explanation/explanation-engine';
import { ThreatIntel } from '../threat-intel/threat-intel';
import { uuidv4 } from '../utils/crypto';

export interface DetectionPipelineDependencies {
  ruleEngine?: RuleEngine;
  urlAnalyzer?: URLAnalyzer;
  textAnalyzer?: TextAnalyzer;
  riskScorer?: RiskScorer;
  explanationEngine?: ExplanationEngine;
  threatIntel?: ThreatIntel;
}

export class DetectionPipeline {
  public ruleEngine: RuleEngine;
  public urlAnalyzer: URLAnalyzer;
  public textAnalyzer: TextAnalyzer;
  public riskScorer: RiskScorer;
  public explanationEngine: ExplanationEngine;
  public threatIntel: ThreatIntel;

  constructor(deps?: DetectionPipelineDependencies) {
    this.ruleEngine = deps?.ruleEngine || new RuleEngine();
    this.urlAnalyzer = deps?.urlAnalyzer || new URLAnalyzer();
    this.textAnalyzer = deps?.textAnalyzer || new TextAnalyzer();
    this.riskScorer = deps?.riskScorer || new RiskScorer();
    this.explanationEngine = deps?.explanationEngine || new ExplanationEngine();
    this.threatIntel = deps?.threatIntel || new ThreatIntel();
  }

  public async scan(request: ScanRequest | DetectionRequest): Promise<DetectionResult> {
    const startTime = Date.now();
    const scanId = request.id || uuidv4();
    const timestamp = new Date(startTime).toISOString();

    // Map input content and type from flexible request shapes
    const rawInput =
      typeof (request as ScanRequest).input === 'string'
        ? (request as ScanRequest).input
        : typeof (request as ScanRequest).content === 'string'
        ? (request as ScanRequest).content
        : typeof request.payload === 'string'
        ? request.payload
        : '';

    let inputType = (request as ScanRequest).inputType;

    if (!inputType && request.type) {
      const typeStr = String(request.type).toUpperCase();
      if (typeStr === 'URL') inputType = InputType.URL;
      else if (typeStr === 'TEXT' || typeStr === 'MESSAGE') inputType = InputType.TEXT;
      else if (typeStr === 'FILE' || typeStr === 'FILE_HEADER') inputType = InputType.FILE;
      else if (typeStr === 'QR') inputType = InputType.QR;
      else if (typeStr === 'DOM' || typeStr === 'DOM_STRUCTURE') inputType = InputType.DOM;
    }

    if (!rawInput || typeof rawInput !== 'string' || !inputType) {
      const elapsed = Math.max(0.01, Date.now() - startTime);
      const defaultRec: Recommendation = {
        action: PrescribedAction.PROCEED,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'Invalid or empty input provided for analysis.',
        bypassPermitted: true
      };
      const defaultAssessment: RiskAssessment = {
        overallScore: 0,
        confidence: 1.0,
        severity: SeverityLevel.NONE,
        primaryThreatFactor: 'NONE',
        detectorContributions: {}
      };

      return {
        requestId: scanId,
        scanId,
        id: scanId,
        timestamp,
        inputType: inputType || InputType.TEXT,
        verdict: Verdict.ALLOW,
        riskCategory: RiskCategory.SAFE,
        riskScore: 0,
        score: 0,
        confidence: 1.0,
        severity: 'SAFE',
        riskAssessment: defaultAssessment,
        threats: [],
        evidence: [],
        explanation: 'Invalid or empty input provided for analysis.',
        recommendation: ActionRecommendation.ALLOW,
        action: ActionRecommendation.ALLOW,
        executionTimeMs: elapsed,
        error: 'Invalid input or unsupported input type'
      };
    }

    let evidence: Evidence[] = [];

    // 1. Run Rule Engine
    const ruleEvidence = this.ruleEngine.evaluateAll(rawInput, inputType);
    evidence.push(...ruleEvidence);

    // 2. Modality-specific Analyzers
    if (inputType === InputType.URL) {
      const urlEvidence = this.urlAnalyzer.analyze(rawInput);
      evidence.push(...urlEvidence);

      // Check Threat Intel (check exact URL first, then domain)
      try {
        const intelResult = this.threatIntel.checkUrl(rawInput);
        if (intelResult) {
          if (intelResult.isAllowed || intelResult.name === 'Known Good Domain') {
            // Constitutional Allowlist Precedence:
            // Verified allowlist suppresses heuristic and structural risk
            evidence = evidence.filter(
              e => e.source !== 'URL_ANALYZER' && e.source !== 'RULE_ENGINE'
            );
            evidence.push(intelResult);
          } else if (intelResult.isMalicious) {
            evidence.push(intelResult);
          }
        }
      } catch {
        // Fallback gracefully on parsing edge cases
      }
    } else if (inputType === InputType.TEXT) {
      const textEvidence = this.textAnalyzer.analyze(rawInput);
      evidence.push(...textEvidence);
    }

    // 3. Aggregate and Score
    const stalenessDays = this.threatIntel.getStalenessDays();
    const scoreResult = this.riskScorer.calculate(evidence, stalenessDays);

    // 4. Generate Explanation
    const explanation = this.explanationEngine.generate(
      scoreResult.category,
      scoreResult.recommendation,
      evidence
    );

    // 5. Extract Canonical Threats (sorted descending by threat weight)
    const threats: Threat[] = evidence
      .filter(e => (e.scoreContribution ?? e.weight ?? 0) >= 40)
      .sort((a, b) => (b.scoreContribution ?? b.weight ?? 0) - (a.scoreContribution ?? a.weight ?? 0))
      .map(e => {
        const weight = e.scoreContribution ?? e.weight ?? 0;
        const sevLevel =
          weight >= 85
            ? SeverityLevel.CRITICAL
            : weight >= 60
            ? SeverityLevel.HIGH
            : SeverityLevel.MEDIUM;

        return {
          id: e.indicator || e.name.toLowerCase().replace(/[^a-z0-9\-]/g, '-'),
          category: scoreResult.category,
          severity: sevLevel,
          confidence: e.confidence ?? 0.85,
          description: e.description
        };
      });

    const elapsed = Math.max(0.01, Date.now() - startTime);

    return {
      requestId: scanId,
      scanId,
      id: scanId,
      timestamp,
      inputType,
      verdict: scoreResult.verdict || Verdict.ALLOW,
      riskCategory: scoreResult.category,
      riskScore: scoreResult.score,
      score: scoreResult.score,
      confidence: scoreResult.confidence,
      severity: scoreResult.severity,
      riskAssessment: scoreResult.riskAssessment!,
      threats,
      evidence,
      explanation,
      recommendation: scoreResult.recommendation,
      canonicalRecommendation: scoreResult.canonicalRecommendation,
      action: scoreResult.recommendation,
      executionTimeMs: elapsed
    };
  }
}
