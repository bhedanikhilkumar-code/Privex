import {
  ActionRecommendation,
  DetectionRequest,
  DetectionResult,
  DetectorLayer,
  DetectorLayerState,
  EngineVerdict,
  Evidence,
  FileScanRequest,
  FrictionLevel,
  InputType,
  PrescribedAction,
  ProcessInputMetadata,
  ProcessScanRequest,
  ProcessScanResult,
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
import {
  CoreFileAnalyzer,
  CoreFileAnalysisOptions,
  CoreFileAnalysisOutput
} from '../analyzers/file-analyzer';
import { ProcessAnalyzer, ProcessAnalysisOptions } from '../analyzers/process-analyzer';
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

  public scanProcess(
    request: ProcessScanRequest | ProcessInputMetadata,
    options?: ProcessAnalysisOptions
  ): ProcessScanResult {
    return ProcessAnalyzer.analyze(request, {
      threatIntel: options?.threatIntel || this.threatIntel,
      ruleEngine: options?.ruleEngine || this.ruleEngine,
      riskScorer: options?.riskScorer || this.riskScorer
    });
  }

  public async scan(request: ScanRequest | DetectionRequest): Promise<DetectionResult> {
    const startTime = Date.now();
    const scanId =
      request && typeof request === 'object' && request.id ? request.id : uuidv4();
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
      const failLayers: Record<DetectorLayer, DetectorLayerState> = {
        [DetectorLayer.HASH_INTEL]: 'NOT_RUN',
        [DetectorLayer.SIGNATURE_ENGINE]: 'FAILED',
        [DetectorLayer.METADATA_ANALYZER]: 'FAILED',
        [DetectorLayer.STATIC_HEURISTIC]: 'NOT_RUN',
        [DetectorLayer.STRUCTURAL_PARSER]: 'NOT_RUN',
        [DetectorLayer.BEHAVIORAL_ENGINE]: 'NOT_RUN',
        [DetectorLayer.REPUTATION_LOCAL]: 'NOT_RUN',
        [DetectorLayer.CORRELATION_ENGINE]: 'NOT_RUN'
      };

      return {
        requestId: scanId,
        scanId,
        id: scanId,
        timestamp,
        inputType,
        verdict: Verdict.CAUTION,
        engineVerdict: EngineVerdict.WARN,
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
        detectorLayers: failLayers,
        executionTimeMs: elapsed,
        error: errorMsg
      };
    };

    if (!request || typeof request !== 'object') {
      return buildFailClosedResult(InputType.TEXT, 'Invalid input or unsupported input type');
    }

    // Map input content and type from flexible request shapes
    const rawInput: string =
      typeof (request as ScanRequest).input === 'string'
        ? (request as ScanRequest).input!
        : typeof (request as ScanRequest).content === 'string'
        ? (request as ScanRequest).content!
        : typeof request.payload === 'string'
        ? request.payload
        : '';

    let inputType = (request as ScanRequest).inputType;

    if (!inputType && request.type) {
      const typeStr = String(request.type).toUpperCase();
      if (typeStr === 'URL') inputType = InputType.URL;
      else if (typeStr === 'TEXT' || typeStr === 'MESSAGE') inputType = InputType.TEXT;
      else if (typeStr === 'FILE' || typeStr === 'FILE_HEADER') inputType = InputType.FILE;
      else if (typeStr === 'PROCESS' || typeStr === 'PROCESS_EVENT') inputType = InputType.PROCESS;
      else if (typeStr === 'QR') inputType = InputType.QR;
      else if (typeStr === 'DOM' || typeStr === 'DOM_STRUCTURE') inputType = InputType.DOM;
    }

    try {
      // Type-confusion defense: Reject PROCESS requests that pass raw Uint8Array binary buffers
      if (inputType === InputType.PROCESS && request.payload instanceof Uint8Array) {
        return buildFailClosedResult(
          InputType.PROCESS,
          'Type confusion rejected: PROCESS input cannot be a raw binary buffer'
        );
      }

      // 1. Canonical PROCESS Modality Path (Step 12)
      if (inputType === InputType.PROCESS) {
        const meta: Record<string, any> = (request as ScanRequest).metadata || {};
        const explicitProc = (request as ScanRequest).processMetadata;
        const procMeta: ProcessInputMetadata = explicitProc || {
          pid:
            typeof meta.pid === 'number'
              ? meta.pid
              : typeof meta.pid === 'string' && meta.pid.trim() !== ''
              ? Number(meta.pid)
              : 0,
          ppid:
            typeof meta.ppid === 'number'
              ? meta.ppid
              : typeof meta.ppid === 'string' && meta.ppid.trim() !== ''
              ? Number(meta.ppid)
              : undefined,
          processName:
            typeof meta.processName === 'string' && meta.processName.trim().length > 0
              ? meta.processName
              : rawInput.trim(),
          parentName: typeof meta.parentName === 'string' ? meta.parentName : undefined,
          executablePath:
            typeof meta.executablePath === 'string'
              ? meta.executablePath
              : typeof meta.filePath === 'string'
              ? meta.filePath
              : undefined,
          sha256: typeof meta.sha256 === 'string' ? meta.sha256 : undefined,
          isSigned:
            typeof meta.isSigned === 'boolean'
              ? meta.isSigned
              : meta.isSigned === 'true'
              ? true
              : meta.isSigned === 'false'
              ? false
              : undefined,
          signer: typeof meta.signer === 'string' ? meta.signer : undefined,
          commandLine:
            typeof meta.commandLine === 'string'
              ? meta.commandLine
              : rawInput && meta.processName
              ? rawInput
              : undefined,
          creationTimestamp:
            typeof meta.creationTimestamp === 'number' ? meta.creationTimestamp : undefined
        };

        const procOut = this.scanProcess(procMeta);
        if (procOut.analysisStatus === 'ANALYSIS_FAILED') {
          return buildFailClosedResult(
            InputType.PROCESS,
            procOut.errorReason || 'Process metadata validation failed'
          );
        }

        const riskCategory =
          procOut.riskScore >= 50
            ? RiskCategory.MALWARE
            : procOut.riskScore >= 20
            ? RiskCategory.SUSPICIOUS
            : RiskCategory.SAFE;

        const riskAssessment: RiskAssessment = {
          overallScore: procOut.riskScore,
          confidence: procOut.confidence,
          severity: procOut.severity,
          primaryThreatFactor: procOut.threatName || 'PROCESS_INSPECTION',
          detectorContributions: {
            PROCESS_ANALYZER: procOut.riskScore
          }
        };

        const threats: Threat[] = procOut.evidence
          .filter((e) => !e.isAllowed && (e.scoreContribution ?? e.weight ?? 0) >= 30)
          .map((e) => ({
            id: (e.ruleId || e.name || 'proc-threat').toLowerCase().replace(/[^a-z0-9\-]/g, '-'),
            category: riskCategory,
            severity: procOut.severity,
            confidence: e.confidence ?? 0.9,
            description: e.description
          }));

        const canonicalAction =
          procOut.engineVerdict === EngineVerdict.CONTAIN_PROCESS
            ? PrescribedAction.CONTAIN_PROCESS
            : procOut.actionRecommendation === ActionRecommendation.BLOCK
            ? PrescribedAction.BLOCK_NAVIGATION
            : procOut.actionRecommendation === ActionRecommendation.WARN ||
              procOut.actionRecommendation === ActionRecommendation.INFORM
            ? PrescribedAction.WARN_USER
            : PrescribedAction.PROCEED;

        const elapsed = Math.max(0.01, Date.now() - startTime);
        return {
          requestId: scanId,
          scanId,
          id: scanId,
          timestamp,
          inputType: InputType.PROCESS,
          verdict: procOut.verdict,
          engineVerdict: procOut.engineVerdict,
          riskCategory,
          riskScore: procOut.riskScore,
          score: procOut.riskScore,
          confidence: riskAssessment.confidence,
          severity: procOut.severity,
          riskAssessment,
          threats,
          evidence: procOut.evidence,
          explanation: procOut.evidenceFactors.join('; '),
          recommendation: procOut.actionRecommendation,
          canonicalRecommendation: {
            action: canonicalAction,
            frictionLevel:
              procOut.riskScore >= 85
                ? FrictionLevel.HIGH
                : procOut.riskScore >= 50
                ? FrictionLevel.MEDIUM
                : procOut.riskScore >= 20
                ? FrictionLevel.LOW
                : FrictionLevel.NONE,
            suggestedAction: procOut.evidenceFactors.join('; '),
            bypassPermitted: procOut.riskScore < 85
          },
          action: procOut.actionRecommendation,
          analysisStatus: procOut.analysisStatus,
          disposition: procOut.disposition,
          detectorLayers: procOut.detectorLayers,
          executionTimeMs: elapsed
        };
      }

      // 2. Canonical FILE Modality Path with Binary Header Bytes
      const fileBytes =
        request.payload instanceof Uint8Array
          ? request.payload
          : (request as any).fileContent instanceof Uint8Array
          ? (request as any).fileContent
          : (request as any).content instanceof Uint8Array
          ? (request as any).content
          : undefined;

      if (inputType === InputType.FILE && fileBytes) {
        const meta: Record<string, any> = (request as ScanRequest).metadata || {};
        const filePath =
          meta.filePath ||
          (typeof request.payload === 'string' ? request.payload : undefined);
        const fileName =
          meta.fileName ||
          (filePath ? filePath.split(/[/\\]/).pop() : undefined) ||
          'unknown';

        const fileOut = CoreFileAnalyzer.analyzeBuffer(
          {
            fileName,
            filePath,
            fileSize:
              meta.fileSize !== undefined ? Number(meta.fileSize) : fileBytes.length,
            headerBytes: fileBytes,
            mimeType: meta.mimeType
          },
          {
            sha256: meta.sha256
          }
        );

        const detectorLayers: Record<DetectorLayer, DetectorLayerState> = {
          [DetectorLayer.HASH_INTEL]: fileOut.sha256 ? 'EXECUTED' : 'NOT_RUN',
          [DetectorLayer.SIGNATURE_ENGINE]: 'EXECUTED',
          [DetectorLayer.METADATA_ANALYZER]: 'EXECUTED',
          [DetectorLayer.STATIC_HEURISTIC]: 'EXECUTED',
          [DetectorLayer.STRUCTURAL_PARSER]: 'EXECUTED',
          [DetectorLayer.BEHAVIORAL_ENGINE]: 'NOT_RUN',
          [DetectorLayer.REPUTATION_LOCAL]: fileOut.sha256 ? 'EXECUTED' : 'NOT_RUN',
          [DetectorLayer.CORRELATION_ENGINE]: 'EXECUTED'
        };

        let evidence: Evidence[] = [...fileOut.evidence];
        let riskScore = fileOut.riskScore;
        let verdict = fileOut.verdict;
        let engineVerdict = fileOut.engineVerdict || EngineVerdict.ALLOW;
        let severity = fileOut.severity;
        let recommendation = fileOut.actionRecommendation;
        let disposition = fileOut.disposition;

        if (fileOut.sha256) {
          try {
            const hashLookup = this.threatIntel.lookupHash(fileOut.sha256);
            if (hashLookup.disposition === 'KNOWN_BAD' && hashLookup.evidence) {
              evidence.push(hashLookup.evidence);
              riskScore = Math.max(riskScore, 95);
              verdict = Verdict.DANGEROUS;
              engineVerdict = EngineVerdict.QUARANTINE;
              severity = SeverityLevel.CRITICAL;
              recommendation = ActionRecommendation.BLOCK;
              disposition = 'MALICIOUS';
            } else if (hashLookup.disposition === 'KNOWN_GOOD' && hashLookup.evidence) {
              const hasCriticalHeaderThreat = evidence.some((e) => e.isCriticalOverride === true);
              if (!hasCriticalHeaderThreat) {
                evidence = [hashLookup.evidence];
                riskScore = 0;
                verdict = Verdict.ALLOW;
                engineVerdict = EngineVerdict.ALLOW;
                severity = SeverityLevel.NONE;
                recommendation = ActionRecommendation.ALLOW;
                disposition = 'SAFE';
              }
            }
          } catch {
            // Continue with local file analysis result
          }
        }

        // Canonical decision authority: all file evidence is aggregated by RiskScorer.
        const fileScore = this.riskScorer.calculate(evidence, this.threatIntel.getStalenessDays(), {
          inputType: InputType.FILE
        });
        riskScore = fileScore.score;
        verdict = fileScore.verdict || Verdict.ALLOW;
        engineVerdict = fileScore.engineVerdict;
        severity = fileScore.severity;
        recommendation = fileScore.recommendation;
        disposition =
          fileScore.recommendation === ActionRecommendation.BLOCK
            ? 'MALICIOUS'
            : fileScore.recommendation === ActionRecommendation.WARN ||
              fileScore.recommendation === ActionRecommendation.INFORM
            ? 'SUSPICIOUS'
            : 'SAFE';

        // Fail-closed: a failed analysis can never resolve to ALLOW/SAFE
        if (fileOut.analysisStatus === 'ANALYSIS_FAILED' && engineVerdict === EngineVerdict.ALLOW) {
          engineVerdict = EngineVerdict.WARN;
          verdict = Verdict.CAUTION;
          recommendation = ActionRecommendation.WARN;
          disposition = 'ANALYSIS_FAILED';
          riskScore = Math.max(riskScore, 30);
          severity = severity === SeverityLevel.NONE ? SeverityLevel.MEDIUM : severity;
        }

        const riskCategory = fileScore.category;

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
          .filter((e) => !e.isAllowed && (e.scoreContribution ?? e.weight ?? 0) >= 30)
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
          engineVerdict,
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
          detectorLayers,
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
      const detectorLayers: Record<DetectorLayer, DetectorLayerState> = {
        [DetectorLayer.HASH_INTEL]: 'NOT_RUN',
        [DetectorLayer.SIGNATURE_ENGINE]: 'EXECUTED',
        [DetectorLayer.METADATA_ANALYZER]: 'EXECUTED',
        [DetectorLayer.STATIC_HEURISTIC]: 'EXECUTED',
        [DetectorLayer.STRUCTURAL_PARSER]:
          inputType === InputType.FILE || inputType === InputType.DOM ? 'EXECUTED' : 'UNAVAILABLE',
        [DetectorLayer.BEHAVIORAL_ENGINE]: 'NOT_RUN',
        [DetectorLayer.REPUTATION_LOCAL]:
          inputType === InputType.URL || inputType === InputType.FILE ? 'EXECUTED' : 'NOT_RUN',
        [DetectorLayer.CORRELATION_ENGINE]: 'EXECUTED'
      };

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
        const meta: Record<string, any> = (request as ScanRequest).metadata || {};
        const headerBytes = new TextEncoder().encode(rawInput);
        const fileOut = CoreFileAnalyzer.analyzeBuffer(
          {
            fileName: meta.fileName || rawInput,
            filePath: meta.filePath,
            fileSize: Number(meta.fileSize || headerBytes.length),
            headerBytes
          },
          {
            sha256: meta.sha256
          }
        );
        for (const fe of fileOut.evidence) {
          if (!evidence.some((existing) => existing.ruleId && existing.ruleId === fe.ruleId)) {
            evidence.push(fe);
          }
        }
        if (fileOut.sha256) {
          detectorLayers[DetectorLayer.HASH_INTEL] = 'EXECUTED';
          const hashLookup = this.threatIntel.lookupHash(fileOut.sha256);
          if (hashLookup.disposition === 'KNOWN_BAD' && hashLookup.evidence) {
            evidence.push(hashLookup.evidence);
          }
        }
      }

      // 3. Aggregate and Score
      const stalenessDays = this.threatIntel.getStalenessDays();
      const scoreResult = this.riskScorer.calculate(evidence, stalenessDays, {
        inputType
      });

      // 4. Generate Explanation
      const explanation = this.explanationEngine.generate(
        scoreResult.category,
        scoreResult.recommendation,
        evidence
      );

      // 5. Extract Canonical Threats (sorted descending by threat weight)
      const threats: Threat[] = evidence
        .filter((e) => (e.scoreContribution ?? e.weight ?? 0) >= 40)
        .sort(
          (a, b) => (b.scoreContribution ?? b.weight ?? 0) - (a.scoreContribution ?? a.weight ?? 0)
        )
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
        engineVerdict: scoreResult.engineVerdict,
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
        detectorLayers,
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
