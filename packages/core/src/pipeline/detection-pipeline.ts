import { ActionRecommendation, DetectionResult, Evidence, InputType, RiskCategory, ScanRequest } from '../types';
import { RuleEngine } from '../rules/rule-engine';
import { URLAnalyzer } from '../analyzers/url-analyzer';
import { TextAnalyzer } from '../analyzers/text-analyzer';
import { RiskScorer } from '../scoring/risk-scorer';
import { ExplanationEngine } from '../explanation/explanation-engine';
import { ThreatIntel } from '../threat-intel/threat-intel';
import { uuidv4 } from '../utils/crypto';

export class DetectionPipeline {
  private ruleEngine: RuleEngine;
  private urlAnalyzer: URLAnalyzer;
  private textAnalyzer: TextAnalyzer;
  private riskScorer: RiskScorer;
  private explanationEngine: ExplanationEngine;
  private threatIntel: ThreatIntel;

  constructor() {
    this.ruleEngine = new RuleEngine();
    this.urlAnalyzer = new URLAnalyzer();
    this.textAnalyzer = new TextAnalyzer();
    this.riskScorer = new RiskScorer();
    this.explanationEngine = new ExplanationEngine();
    this.threatIntel = new ThreatIntel();
  }

  public async scan(request: ScanRequest): Promise<DetectionResult> {
    const startTime = Date.now();
    const scanId = uuidv4();
    const timestamp = new Date(startTime).toISOString();

    // Map input content and type from flexible request shapes
    const rawInput = request.input || request.content;
    let inputType = request.inputType;

    if (!inputType && request.type) {
      const typeStr = String(request.type).toUpperCase();
      if (typeStr === 'URL') inputType = InputType.URL;
      else if (typeStr === 'TEXT') inputType = InputType.TEXT;
      else if (typeStr === 'FILE') inputType = InputType.FILE;
      else if (typeStr === 'QR') inputType = InputType.QR;
      else if (typeStr === 'DOM') inputType = InputType.DOM;
    }

    if (!rawInput || typeof rawInput !== 'string' || !inputType) {
      return {
        scanId,
        id: scanId,
        timestamp,
        inputType: inputType || InputType.TEXT,
        riskCategory: RiskCategory.SAFE,
        riskScore: 0,
        score: 0,
        confidence: 1.0,
        severity: 'SAFE',
        evidence: [],
        explanation: 'Invalid or empty input provided for analysis.',
        recommendation: ActionRecommendation.ALLOW,
        action: ActionRecommendation.ALLOW,
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

      // Check Threat Intel
      try {
        const urlObj = new URL(rawInput.startsWith('http://') || rawInput.startsWith('https://') ? rawInput : `http://${rawInput}`);
        const intelResult = this.threatIntel.checkDomain(urlObj.hostname);
        if (intelResult) {
          if (intelResult.name === 'Known Good Domain') {
            // Known good domain suppresses heuristic risk
            evidence = evidence.filter(e => e.source !== 'URL_ANALYZER' && e.source !== 'RULE_ENGINE');
            evidence.push(intelResult);
          } else if (intelResult.isMalicious) {
            evidence.push(intelResult);
          }
        }
      } catch { }
    } else if (inputType === InputType.TEXT) {
      const textEvidence = this.textAnalyzer.analyze(rawInput);
      evidence.push(...textEvidence);
    }

    // 3. Aggregate and Score
    const scoreResult = this.riskScorer.calculate(evidence);

    // 4. Generate Explanation
    const explanation = this.explanationEngine.generate(
      scoreResult.category,
      scoreResult.recommendation,
      evidence
    );

    return {
      scanId,
      id: scanId,
      timestamp,
      inputType,
      riskCategory: scoreResult.category,
      riskScore: scoreResult.score,
      score: scoreResult.score,
      confidence: scoreResult.confidence,
      severity: scoreResult.severity,
      evidence,
      explanation,
      recommendation: scoreResult.recommendation,
      action: scoreResult.recommendation
    };
  }
}
