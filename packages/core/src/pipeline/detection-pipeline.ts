import {
  ActionRecommendation,
  DetectionRequest,
  DetectionResult,
  Evidence,
  FileScanRequest,
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
import { CoreFileAnalyzer, CoreFileAnalysisOptions, CoreFileAnalysisOutput } from '../analyzers/file-analyzer';
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

  public scanFile(
    request: FileScanRequest,
    options?: CoreFileAnalysisOptions
  ): CoreFileAnalysisOutput {
    return CoreFileAnalyzer.analyzeBuffer(request, options);
  }

  public async scan(request: ScanRequest | DetectionRequest): Promise<DetectionResult> {
    const startTime = Date.now();
    const scanId = (request && typeof request === 'object' && request.id) ? request.id : uuidv4();
    const requestTime =
      request &&
      typeof request === 'object' &&
      typeof request.timestamp === 'number' &&
      Number.isFinite(request.timestamp)
        ? request.timestamp
        : startTime;
    const timestamp = new Date(requestTime).toISOString();

    const buildFailClosedResult = (
      inputType: InputType = InputType.TEXT,
      errorMsg = 'Invalid input or unsupported input type'
    ): DetectionResult => {
      const elapsed = Math.max(0.01, Date.now() - startTime);
      const defaultRec: Recommendation = {
        action: PrescribedAction.WARN_USER,
        frictionLevel: FrictionLevel.MEDIUM,
        suggestedAction:
          'Invalid, malformed, or empty input provided for analysis. Fail-closed caution policy applied.',
        bypassPermitted: false
      };
      const defaultAssessment: RiskAssessment = {
        overallScore: 50,
        confidence: 0.5,
        severity: SeverityLevel.MEDIUM,
        primaryThreatFactor: 'MALFORMED_INPUT',
        detectorContributions: {}
      };

      return {
        requestId: scanId,
        scanId,
        id: scanId,
        timestamp,
        inputType,
        verdict: Verdict.CAUTION,
        riskCategory: RiskCategory.SUSPICIOUS,
        riskScore: 50,
        score: 50,
        confidence: 0.5,
        severity: 'CAUTION',
        riskAssessment: defaultAssessment,
        threats: [],
        evidence: [],
        explanation:
          'Invalid, malformed, or empty input provided for analysis. Fail-closed caution policy applied.',
        recommendation: ActionRecommendation.WARN,
        canonicalRecommendation: defaultRec,
        action: ActionRecommendation.WARN,
        analysisStatus: 'ANALYSIS_FAILED',
        disposition: 'ANALYSIS_FAILED',
        executionTimeMs: elapsed,
        error: errorMsg
      };
    };

    if (!request || typeof request !== 'object') {
      return buildFailClosedResult(InputType.TEXT, 'Invalid input or unsupported input type');
    }

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

    try {
      if (inputType === InputType.FILE && request.payload instanceof Uint8Array) {
        const meta = (request as ScanRequest).metadata || {};
        const fileOut = CoreFileAnalyzer.analyzeBuffer(
          {
            fileName: meta.fileName || 'unknown',
            filePath: meta.filePath,
            fileSize:
              meta.fileSize !== undefined ? Number(meta.fileSize) : request.payload.length,
            headerBytes: request.payload,
            mimeType: meta.mimeType
          },
          {
            sha256: meta.sha256
          }
        );

        const evidence: Evidence[] = [...fileOut.evidence];
        let riskScore = fileOut.riskScore;
        let verdict = fileOut.verdict;
        let severity = fileOut.severity;
        let recommendation = fileOut.actionRecommendation;
        let disposition = fileOut.disposition;

        if (fileOut.sha256) {
          try {
            const hashIntel = this.threatIntel.checkHash(fileOut.sha256);
            if (hashIntel && hashIntel.isMalicious) {
              evidence.push(hashIntel);
              riskScore = Math.max(riskScore, 95);
              verdict = Verdict.DANGEROUS;
              severity = SeverityLevel.CRITICAL;
              recommendation = ActionRecommendation.BLOCK;
              disposition = 'MALICIOUS';
            }
          } catch {
            // Continue with local file analysis result
          }
        }

        const riskCategory =
          riskScore >= 50
            ? RiskCategory.MALWARE
            : riskScore >= 20
            ? RiskCategory.SUSPICIOUS
            : RiskCategory.SAFE;

        const riskAssessment: RiskAssessment = {
          overallScore: riskScore,
          confidence: fileOut.analysisStatus === 'ANALYSIS_FAILED' ? 0.5 : 0.95,
          severity,
          primaryThreatFactor: fileOut.threatName || 'FILE_INTEGRITY',
          detectorContributions: {
            FileHeaderAnalyzer: riskScore
          }
        };

        const threats: Threat[] = evidence
          .filter((e) => (e.scoreContribution ?? e.weight ?? 0) >= 30)
          .map((e) => ({
            id: (e.ruleId || e.name || 'file-threat').toLowerCase().replace(/[^a-z0-9\-]/g, '-'),
            category: riskCategory,
            severity,
            confidence: e.confidence ?? 0.9,
            description: e.description
          }));

        const elapsed = Math.max(0.01, Date.now() - startTime);
        return {
          requestId: scanId,
          scanId,
          id: scanId,
          timestamp,
          inputType: InputType.FILE,
          verdict,
          riskCategory,
          riskScore,
          score: riskScore,
          confidence: riskAssessment.confidence,
          severity,
          riskAssessment,
          threats,
          evidence,
          explanation: fileOut.evidenceFactors.join('; '),
          recommendation,
          action: recommendation,
          analysisStatus: fileOut.analysisStatus,
          disposition,
          executionTimeMs: elapsed
        };
      }

      if (!rawInput || typeof rawInput !== 'string' || !inputType) {
        return buildFailClosedResult(
          inputType || InputType.TEXT,
          'Invalid input or unsupported input type'
        );
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
              // Verified allowlist suppresses non-critical heuristic risk while preserving critical overrides
              evidence = evidence.filter(
                (e) =>
                  e.isCriticalOverride === true ||
                  (e.source !== 'URL_ANALYZER' && e.source !== 'RULE_ENGINE')
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
      } else if (inputType === InputType.FILE) {
        const meta = (request as ScanRequest).metadata || {};
        const headerBytes = new TextEncoder().encode(rawInput);
        const fileOut = CoreFileAnalyzer.analyzeBuffer({
          fileName: meta.fileName || rawInput,
          filePath: meta.filePath,
          fileSize: Number(meta.fileSize || headerBytes.length),
          headerBytes
        });
        evidence.push(...fileOut.evidence);
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
        .filter((e) => (e.scoreContribution ?? e.weight ?? 0) >= 40)
        .sort((a, b) => (b.scoreContribution ?? b.weight ?? 0) - (a.scoreContribution ?? a.weight ?? 0))
        .map((e) => {
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
      const disposition =
        scoreResult.recommendation === ActionRecommendation.BLOCK
          ? 'MALICIOUS'
          : scoreResult.recommendation === ActionRecommendation.WARN ||
            scoreResult.recommendation === ActionRecommendation.INFORM
          ? 'SUSPICIOUS'
          : 'SAFE';

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
        analysisStatus: 'COMPLETED',
        disposition,
        executionTimeMs: elapsed
      };
    } catch (err: any) {
      return buildFailClosedResult(
        inputType || InputType.TEXT,
        err?.message || 'Unexpected internal detection pipeline error'
      );
    }
  }
}
