import {
  ActionRecommendation,
  AnalysisStatus,
  DetectionDisposition,
  DetectorLayer,
  DetectorLayerState,
  DetectorType,
  EngineVerdict,
  Evidence,
  ProcessInputMetadata,
  ProcessScanRequest,
  ProcessScanResult,
  SeverityLevel,
  Verdict
} from '../types';
import { RuleEngine } from '../rules/rule-engine';
import { ThreatIntel } from '../threat-intel/threat-intel';
import { RiskScorer } from '../scoring/risk-scorer';

export interface ProcessAnalysisOptions {
  readonly threatIntel?: ThreatIntel;
  readonly ruleEngine?: RuleEngine;
  readonly riskScorer?: RiskScorer;
}

/**
 * Canonical Phase B Process Input Analyzer Foundation (@private-protection/core).
 *
 * Evaluates static process telemetry (PID, PPID, process name, parent process name,
 * executable path, SHA-256 hash, digital signature status, and redacted CLI arguments)
 * without performing live OS process monitoring or termination (deferred to Phase F).
 */
export class ProcessAnalyzer {
  private static readonly SENSITIVE_CLI_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
    {
      pattern: /(--?(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|auth|bearer)\s*[=:]?\s*)(["']?[^\s"']+["']?)/gi,
      replacement: '$1[REDACTED]'
    },
    {
      pattern: /(https?:\/\/[^/\s:@]+:)([^@\s/]+)(@)/gi,
      replacement: '$1[REDACTED]$3'
    },
    {
      pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
      replacement: '[REDACTED_JWT]'
    }
  ];

  private static readonly HIGH_RISK_EXECUTION_DIRS = [
    /\\appdata\\local\\temp\\/i,
    /\\windows\\temp\\/i,
    /\\users\\[^\\]+\\downloads\\/i,
    /\\users\\public\\/i,
    /\\programdata\\[^\\]*$/i,
    /\/tmp\//i,
    /\/var\/tmp\//i
  ];

  private static readonly DOCUMENT_PARENTS = new Set([
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'acrord32.exe',
    'acrobat.exe',
    'mspub.exe',
    'visio.exe'
  ]);

  private static readonly SCRIPT_INTERPRETERS = new Set([
    'powershell.exe',
    'pwsh.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'rundll32.exe',
    'regsvr32.exe',
    'certutil.exe',
    'bitsadmin.exe'
  ]);

  /**
   * Redacts credentials, tokens, and secrets from a process command-line string
   * before analysis or structured evidence generation (Privacy Rule / Step 12).
   */
  public static sanitizeCommandLine(commandLine?: string): string | undefined {
    if (typeof commandLine !== 'string') return undefined;
    let sanitized = commandLine.slice(0, 4096);
    for (const { pattern, replacement } of this.SENSITIVE_CLI_PATTERNS) {
      sanitized = sanitized.replace(pattern, replacement);
    }
    return sanitized;
  }

  /**
   * Evaluates a ProcessScanRequest or ProcessInputMetadata and produces a canonical ProcessScanResult.
   */
  public static analyze(
    request: ProcessScanRequest | ProcessInputMetadata,
    options?: ProcessAnalysisOptions
  ): ProcessScanResult {
    const meta: ProcessInputMetadata | undefined =
      request && typeof request === 'object' && 'process' in request
        ? (request as { readonly process: ProcessInputMetadata }).process
        : (request as ProcessInputMetadata);

    const detectorLayers: Record<DetectorLayer, DetectorLayerState> = {
      [DetectorLayer.HASH_INTEL]: 'NOT_RUN',
      [DetectorLayer.SIGNATURE_ENGINE]: 'NOT_RUN',
      [DetectorLayer.METADATA_ANALYZER]: 'NOT_RUN',
      [DetectorLayer.STATIC_HEURISTIC]: 'NOT_RUN',
      [DetectorLayer.STRUCTURAL_PARSER]: 'UNAVAILABLE',
      [DetectorLayer.BEHAVIORAL_ENGINE]: 'NOT_RUN',
      [DetectorLayer.REPUTATION_LOCAL]: 'NOT_RUN',
      [DetectorLayer.CORRELATION_ENGINE]: 'NOT_RUN'
    };

    // Fail-closed validation on missing or invalid process metadata
    if (
      !meta ||
      typeof meta !== 'object' ||
      typeof meta.processName !== 'string' ||
      meta.processName.trim().length === 0 ||
      (meta.pid !== undefined &&
        (typeof meta.pid !== 'number' || !Number.isFinite(meta.pid) || meta.pid < 0))
    ) {
      const failDesc =
        'Process analysis failed: missing or invalid process metadata (fail-closed policy applied)';
      detectorLayers[DetectorLayer.METADATA_ANALYZER] = 'FAILED';
      return {
        pid: typeof meta?.pid === 'number' && Number.isFinite(meta.pid) ? meta.pid : -1,
        ppid: typeof meta?.ppid === 'number' && Number.isFinite(meta.ppid) ? meta.ppid : undefined,
        processName:
          typeof meta?.processName === 'string' && meta.processName ? meta.processName : 'unknown',
        parentName: meta?.parentName,
        executablePath: meta?.executablePath,
        sha256: meta?.sha256,
        isSigned: meta?.isSigned,
        signer: meta?.signer,
        sanitizedCommandLine: this.sanitizeCommandLine(meta?.commandLine),
        riskScore: 50,
        confidence: 0.5,
        severity: SeverityLevel.MEDIUM,
        verdict: Verdict.CAUTION,
        engineVerdict: EngineVerdict.WARN,
        actionRecommendation: ActionRecommendation.WARN,
        analysisStatus: 'ANALYSIS_FAILED',
        disposition: 'ANALYSIS_FAILED',
        threatName: 'PROCESS_ANALYSIS_FAILED_INVALID_INPUT',
        evidenceFactors: [failDesc],
        detectorLayers,
        errorReason: 'INVALID_PROCESS_METADATA',
        evidence: [
          {
            ruleId: 'proc-analysis-failed-input',
            detectorType: DetectorType.HEURISTIC,
            detectorLayer: DetectorLayer.METADATA_ANALYZER,
            source: 'PROCESS_ANALYZER',
            name: 'Process Analysis Failed',
            description: failDesc,
            reason: failDesc,
            severityLevel: SeverityLevel.MEDIUM,
            weight: 50,
            scoreContribution: 50,
            confidence: 0.9
          }
        ]
      };
    }

    const processName = meta.processName.trim();
    const lowerProcName = processName.toLowerCase();
    const lowerParentName = (meta.parentName || '').trim().toLowerCase();
    const executablePath = meta.executablePath || '';
    const sanitizedCommandLine = this.sanitizeCommandLine(meta.commandLine);

    const threatIntel = options?.threatIntel || new ThreatIntel();
    const ruleEngine = options?.ruleEngine || new RuleEngine();
    const riskScorer = options?.riskScorer || new RiskScorer();

    const evidence: Evidence[] = [];
    const evidenceFactors: string[] = [];
    let threatName = 'PROCESS_BENIGN';

    // 1. Layer 1: Hash Intelligence Lookup (if sha256 is provided)
    if (meta.sha256 && typeof meta.sha256 === 'string' && meta.sha256.trim().length > 0) {
      detectorLayers[DetectorLayer.HASH_INTEL] = 'EXECUTED';
      detectorLayers[DetectorLayer.REPUTATION_LOCAL] = 'EXECUTED';
      const hashLookup = threatIntel.lookupHash(meta.sha256);
      if (hashLookup.disposition === 'KNOWN_BAD' && hashLookup.evidence) {
        evidence.push(hashLookup.evidence);
        evidenceFactors.push(hashLookup.evidence.description);
        threatName = hashLookup.threatName || 'KNOWN_MALICIOUS_PROCESS_IMAGE';
      } else if (hashLookup.disposition === 'KNOWN_GOOD' && hashLookup.evidence) {
        evidence.push(hashLookup.evidence);
        evidenceFactors.push(hashLookup.evidence.description);
      }
    }

    // 2. Layer 2: Deterministic Signature & Command-Line Rules
    detectorLayers[DetectorLayer.SIGNATURE_ENGINE] = 'EXECUTED';
    const cliTarget = [processName, executablePath, sanitizedCommandLine || '']
      .filter(Boolean)
      .join(' ');
    const ruleEval = ruleEngine.evaluateProcess(cliTarget);
    for (const match of ruleEval.evidence) {
      evidence.push(match);
      evidenceFactors.push(match.description);
      if (threatName === 'PROCESS_BENIGN') {
        threatName = (match.ruleId || match.name || 'SUSPICIOUS_PROCESS_RULE')
          .toUpperCase()
          .replace(/-/g, '_');
      }
    }

    // 3. Layer 3 & 4: Static Process Metadata & Parent-Child Heuristics
    detectorLayers[DetectorLayer.METADATA_ANALYZER] = 'EXECUTED';
    detectorLayers[DetectorLayer.STATIC_HEURISTIC] = 'EXECUTED';

    const isUnsigned = meta.isSigned === false;
    const isSuspiciousPath = this.HIGH_RISK_EXECUTION_DIRS.some((rx) => rx.test(executablePath));

    if (isUnsigned && isSuspiciousPath) {
      const desc = `Unsigned process '${processName}' executing from high-risk user-writable directory (${executablePath}).`;
      evidenceFactors.push(desc);
      if (threatName === 'PROCESS_BENIGN') threatName = 'UNSIGNED_TEMP_EXECUTION';
      evidence.push({
        ruleId: 'proc-unsigned-writable-dir',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.METADATA_ANALYZER,
        source: 'PROCESS_ANALYZER',
        name: 'Unsigned Process in Writable Directory',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.HIGH,
        weight: 65,
        scoreContribution: 65,
        confidence: 0.9
      });
    } else if (isSuspiciousPath) {
      const desc = `Process '${processName}' executing from temporary or downloads directory (${executablePath}).`;
      evidenceFactors.push(desc);
      if (threatName === 'PROCESS_BENIGN') threatName = 'WRITABLE_DIR_EXECUTION';
      evidence.push({
        ruleId: 'proc-writable-dir-execution',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.METADATA_ANALYZER,
        source: 'PROCESS_ANALYZER',
        name: 'Execution From User-Writable Directory',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.MEDIUM,
        weight: 35,
        scoreContribution: 35,
        confidence: 0.85
      });
    } else if (isUnsigned) {
      const desc = `Process binary '${processName}' is not digitally signed.`;
      evidenceFactors.push(desc);
      evidence.push({
        ruleId: 'proc-unsigned-binary',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.METADATA_ANALYZER,
        source: 'PROCESS_ANALYZER',
        name: 'Unsigned Process Binary',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.LOW,
        weight: 15,
        scoreContribution: 15,
        confidence: 0.8
      });
    }

    // Office / Document Reader spawning a script interpreter or shell
    if (
      lowerParentName &&
      this.DOCUMENT_PARENTS.has(lowerParentName) &&
      this.SCRIPT_INTERPRETERS.has(lowerProcName)
    ) {
      const desc = `Suspicious parent-child process chain: document application '${meta.parentName}' spawned script interpreter '${processName}'.`;
      evidenceFactors.push(desc);
      threatName = 'MACRO_SHELL_SPAWN';
      evidence.push({
        ruleId: 'proc-office-shell-spawn',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.STATIC_HEURISTIC,
        source: 'PROCESS_ANALYZER',
        name: 'Document Reader Spawned Shell Interpreter',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.CRITICAL,
        weight: 88,
        scoreContribution: 88,
        confidence: 0.95,
        isCriticalOverride: true
      });
    }

    const hasKnownGoodHash = evidence.some((e) => e.isAllowed === true);
    const activeThreatEvidence = evidence.filter((e) => !e.isAllowed);
    const scoredEvidence = hasKnownGoodHash
      ? activeThreatEvidence.filter((e) => e.isCriticalOverride === true)
      : activeThreatEvidence;

    detectorLayers[DetectorLayer.CORRELATION_ENGINE] = 'EXECUTED';
    const scoreResult = riskScorer.calculateScore(scoredEvidence, 0, {
      inputType: 'PROCESS'
    });

    if (evidenceFactors.length === 0) {
      evidenceFactors.push('Process metadata inspected; no static threat indicators identified.');
    }

    const engineVerdict =
      scoreResult.engineVerdict ||
      (scoreResult.score >= 85
        ? EngineVerdict.CONTAIN_PROCESS
        : scoreResult.score >= 70
        ? EngineVerdict.BLOCK
        : scoreResult.score >= 50
        ? EngineVerdict.WARN
        : scoreResult.score >= 20
        ? EngineVerdict.INFORM
        : EngineVerdict.ALLOW);

    const disposition: DetectionDisposition =
      scoreResult.recommendation === ActionRecommendation.BLOCK
        ? 'MALICIOUS'
        : scoreResult.recommendation === ActionRecommendation.WARN ||
          scoreResult.recommendation === ActionRecommendation.INFORM
        ? 'SUSPICIOUS'
        : 'SAFE';

    const severityLevel: SeverityLevel =
      scoreResult.score >= 85
        ? SeverityLevel.CRITICAL
        : scoreResult.score >= 70
        ? SeverityLevel.HIGH
        : scoreResult.score >= 50
        ? SeverityLevel.MEDIUM
        : scoreResult.score >= 20
        ? SeverityLevel.LOW
        : SeverityLevel.NONE;

    return {
      pid: typeof meta.pid === 'number' && Number.isFinite(meta.pid) ? meta.pid : 0,
      ppid: meta.ppid,
      processName,
      parentName: meta.parentName,
      executablePath: meta.executablePath,
      sha256: meta.sha256,
      isSigned: meta.isSigned,
      signer: meta.signer,
      sanitizedCommandLine,
      riskScore: scoreResult.score,
      confidence: scoreResult.confidence,
      severity: severityLevel,
      verdict: scoreResult.verdict || Verdict.ALLOW,
      engineVerdict,
      actionRecommendation: scoreResult.recommendation,
      analysisStatus: 'COMPLETED' as AnalysisStatus,
      disposition,
      threatName,
      evidenceFactors,
      evidence,
      detectorLayers
    };
  }
}
