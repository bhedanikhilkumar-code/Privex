import {
  ActionRecommendation,
  DetectorLayer,
  DetectorType,
  EngineVerdict,
  Evidence,
  FrictionLevel,
  InputType,
  PrescribedAction,
  Recommendation,
  RiskAssessment,
  RiskCategory,
  Severity,
  SeverityLevel,
  Verdict
} from '../types';

export interface RiskCalculationOptions {
  readonly inputType?: InputType | string;
}

export interface ScoreResult {
  score: number;
  category: RiskCategory;
  severity: Severity | SeverityLevel | string;
  confidence: number;
  recommendation: ActionRecommendation;
  recommendedAction: string;
  engineVerdict: EngineVerdict;
  correlationSignals?: Evidence[];
  // Subsystem 9 Canonical RiskAssessment struct
  riskAssessment?: RiskAssessment;
  verdict?: Verdict;
  canonicalRecommendation?: Recommendation;
}

export class RiskScorer {
  /**
   * Detector plane base reliability weights (docs/RISK_ENGINE_ARCHITECTURE.md Section 2 & Phase B)
   */
  private detectorWeights: Record<string, number> = {
    // Canonical Phase B 8-Layer Weights
    [DetectorLayer.HASH_INTEL]: 1.0,
    [DetectorLayer.SIGNATURE_ENGINE]: 1.0,
    [DetectorLayer.CORRELATION_ENGINE]: 1.0,
    [DetectorLayer.BEHAVIORAL_ENGINE]: 0.95,
    [DetectorLayer.STRUCTURAL_PARSER]: 0.95,
    [DetectorLayer.METADATA_ANALYZER]: 0.90,
    [DetectorLayer.REPUTATION_LOCAL]: 0.85,
    [DetectorLayer.STATIC_HEURISTIC]: 0.80,
    // Legacy & Modality Source Weights
    RULE_ENGINE: 1.0,
    FILEHEADERANALYZER: 1.0,
    FILE_ANALYZER: 1.0,
    PROCESS_ANALYZER: 0.90,
    THREAT_INTEL: 0.95,
    DOM_ANALYZER: 0.90,
    URL_ANALYZER: 0.85,
    TEXT_ANALYZER: 0.75,
    ML_MODEL: 0.65,
    DEFAULT: 0.75
  };

  public calculate(
    evidence: Evidence[],
    stalenessDays: number = 0,
    options?: RiskCalculationOptions
  ): ScoreResult {
    return this.calculateScore(evidence, stalenessDays, options);
  }

  public calculateScore(
    evidence: any[],
    stalenessDays: number = 0,
    options?: RiskCalculationOptions
  ): ScoreResult {
    const safeStaleness =
      typeof stalenessDays === 'number' && Number.isFinite(stalenessDays) && stalenessDays >= 0
        ? stalenessDays
        : 0;

    if (!evidence || !Array.isArray(evidence) || evidence.length === 0) {
      const canonicalRec: Recommendation = {
        action: PrescribedAction.PROCEED,
        frictionLevel: FrictionLevel.NONE,
        suggestedAction: 'Content verified. Safe to proceed.',
        bypassPermitted: true
      };

      const emptyAssessment: RiskAssessment = {
        overallScore: 0,
        confidence: 1.0,
        severity: SeverityLevel.NONE,
        primaryThreatFactor: 'NONE',
        detectorContributions: {}
      };

      return {
        score: 0,
        category: RiskCategory.SAFE,
        severity: 'SAFE',
        confidence: 1.0,
        recommendation: ActionRecommendation.ALLOW,
        recommendedAction: 'allow',
        engineVerdict: EngineVerdict.ALLOW,
        correlationSignals: [],
        verdict: Verdict.ALLOW,
        riskAssessment: emptyAssessment,
        canonicalRecommendation: canonicalRec
      };
    }

    // 1. Normalize tokens, validate numeric bounds, and infer canonical DetectorLayer
    const detectorContributions: Record<string, number> = {};
    let primaryThreatFactor = 'UNKNOWN';
    let maxSignalValue = -1;
    let criticalOverrideScore = 0;
    let maxCriticalConfidence = 0;

    const normalizedTokens = evidence.map((e: any) => {
      if (!e || typeof e !== 'object') {
        return {
          rawScore: 50,
          baseWeight: 1.0,
          confidence: 0.85,
          effectiveSignal: 50,
          indicator: 'malformed-evidence-object',
          ruleId: 'malformed-evidence-object',
          source: 'RULE_ENGINE',
          layer: DetectorLayer.STATIC_HEURISTIC,
          isCritical: false
        };
      }

      const hasInvalidScoreContribution =
        e.scoreContribution !== undefined &&
        (typeof e.scoreContribution !== 'number' || !Number.isFinite(e.scoreContribution));
      const hasInvalidWeight =
        e.weight !== undefined &&
        (typeof e.weight !== 'number' || !Number.isFinite(e.weight));

      let rawScore: number;
      if (hasInvalidScoreContribution || hasInvalidWeight) {
        // Fail-closed invariant (GAP-22): Any NaN or Infinity on scoreContribution or weight
        // must NEVER fall through to 0 or ALLOW. Clamp to anomaly warning score 50.
        rawScore = 50;
      } else if (typeof e.scoreContribution === 'number') {
        rawScore = e.scoreContribution;
      } else if (typeof e.weight === 'number') {
        rawScore = e.weight;
      } else {
        rawScore = 50;
      }
      rawScore = Math.min(100, Math.max(0, rawScore));

      const layer = this.resolveDetectorLayer(e);
      const sourceKey = (
        e.detectorLayer ||
        e.source ||
        e.detectorType ||
        e.type ||
        'DEFAULT'
      )
        .toString()
        .toUpperCase();

      let baseWeight = this.detectorWeights[sourceKey];
      if (baseWeight === undefined || !Number.isFinite(baseWeight) || baseWeight <= 0) {
        if (sourceKey.includes('HASH')) baseWeight = this.detectorWeights[DetectorLayer.HASH_INTEL];
        else if (sourceKey.includes('SIGNATURE') || sourceKey.includes('RULE'))
          baseWeight = this.detectorWeights.RULE_ENGINE;
        else if (sourceKey.includes('THREAT') || sourceKey.includes('BLOOM'))
          baseWeight = this.detectorWeights.THREAT_INTEL;
        else if (sourceKey.includes('PROCESS')) baseWeight = this.detectorWeights.PROCESS_ANALYZER;
        else if (sourceKey.includes('FILE') || sourceKey.includes('STRUCTURAL'))
          baseWeight = this.detectorWeights.FILE_ANALYZER;
        else if (sourceKey.includes('DOM')) baseWeight = this.detectorWeights.DOM_ANALYZER;
        else if (sourceKey.includes('URL')) baseWeight = this.detectorWeights.URL_ANALYZER;
        else if (sourceKey.includes('TEXT')) baseWeight = this.detectorWeights.TEXT_ANALYZER;
        else if (sourceKey.includes('ML')) baseWeight = this.detectorWeights.ML_MODEL;
        else if (sourceKey === 'TEST') baseWeight = 1.0;
        else baseWeight = this.detectorWeights.DEFAULT;
      }

      const defaultConf =
        sourceKey === 'TEST' || sourceKey.includes('RULE') || sourceKey.includes('HASH')
          ? 1.0
          : 0.85;
      let confidence =
        typeof e.confidence === 'number' && Number.isFinite(e.confidence)
          ? e.confidence
          : defaultConf;
      confidence = Math.min(1.0, Math.max(0.01, confidence));

      const indicator = e.indicator || e.ruleId || e.name || 'threat-signal';
      const ruleId = (e.ruleId || e.indicator || e.name || 'signal').toString().toLowerCase();
      let effectiveSignal = rawScore * baseWeight * confidence;
      if (!Number.isFinite(effectiveSignal) || Number.isNaN(effectiveSignal)) {
        effectiveSignal = 50;
      }
      effectiveSignal = Math.min(100, Math.max(0, effectiveSignal));

      if (effectiveSignal > maxSignalValue) {
        maxSignalValue = effectiveSignal;
        primaryThreatFactor = e.indicator || e.name || 'threat-signal';
      }

      const isCritical =
        Boolean(e.isCriticalOverride) ||
        ((sourceKey.includes('THREAT') || sourceKey.includes('HASH')) && rawScore >= 90);

      if (isCritical && Number.isFinite(rawScore)) {
        criticalOverrideScore = Math.max(criticalOverrideScore, rawScore);
        maxCriticalConfidence = Math.max(maxCriticalConfidence, confidence);
      }

      const categorySource = e.source || e.detectorLayer || e.detectorType || 'RULE_ENGINE';
      detectorContributions[categorySource] =
        (detectorContributions[categorySource] || 0) + rawScore;

      return {
        rawScore,
        baseWeight,
        confidence,
        effectiveSignal,
        indicator,
        ruleId,
        source: categorySource,
        layer,
        isCritical
      };
    });

    // 2. Layer 8: Deterministic Cross-Layer Correlation Engine (Step 13)
    // Deduplicate signals by ruleId before computing cross-layer correlation so duplicate
    // emissions of the same rule never trigger synthetic multi-layer amplification.
    const uniqueLayerMaxScore = new Map<DetectorLayer, number>();
    const uniqueRuleIds = new Set<string>();
    for (const t of normalizedTokens) {
      if (t.rawScore <= 0) continue;
      uniqueRuleIds.add(t.ruleId);
      const prev = uniqueLayerMaxScore.get(t.layer) || 0;
      if (t.rawScore > prev) {
        uniqueLayerMaxScore.set(t.layer, t.rawScore);
      }
    }

    const correlationSignals: Evidence[] = [];
    const hashScore = Math.max(
      uniqueLayerMaxScore.get(DetectorLayer.HASH_INTEL) || 0,
      uniqueLayerMaxScore.get(DetectorLayer.REPUTATION_LOCAL) || 0
    );
    const structureScore = uniqueLayerMaxScore.get(DetectorLayer.STRUCTURAL_PARSER) || 0;
    const metadataScore = uniqueLayerMaxScore.get(DetectorLayer.METADATA_ANALYZER) || 0;
    const staticOrSigScore = Math.max(
      uniqueLayerMaxScore.get(DetectorLayer.STATIC_HEURISTIC) || 0,
      uniqueLayerMaxScore.get(DetectorLayer.SIGNATURE_ENGINE) || 0
    );

    if (hashScore >= 50 && structureScore >= 30) {
      const desc =
        'Cross-layer correlation: threat intelligence hash match combined with structural binary anomaly.';
      correlationSignals.push({
        ruleId: 'corr-hash-plus-structure',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.CORRELATION_ENGINE,
        source: DetectorLayer.CORRELATION_ENGINE,
        name: 'Correlated Hash & Structural Threat',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.CRITICAL,
        weight: 25,
        scoreContribution: 25,
        confidence: 0.99,
        isCriticalOverride: true
      });
      criticalOverrideScore = Math.max(criticalOverrideScore, 95);
      maxCriticalConfidence = Math.max(maxCriticalConfidence, 0.99);
    }

    if (metadataScore >= 35 && staticOrSigScore >= 50) {
      const desc =
        'Cross-layer correlation: suspicious file/process metadata combined with high-risk static or signature indicator.';
      correlationSignals.push({
        ruleId: 'corr-metadata-plus-static',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.CORRELATION_ENGINE,
        source: DetectorLayer.CORRELATION_ENGINE,
        name: 'Correlated Metadata & Static Threat',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.HIGH,
        weight: 20,
        scoreContribution: 20,
        confidence: 0.95
      });
    }

    // Multi-signal extortion / scam correlation (Urgency + Threat/Coercion + Payment/Crypto)
    let hasUrgency = false;
    let hasThreat = false;
    let hasPayment = false;
    for (const id of uniqueRuleIds) {
      if (id.includes('urgency')) hasUrgency = true;
      if (id.includes('threat') || id.includes('extortion') || id.includes('arrest')) hasThreat = true;
      if (id.includes('crypto') || id.includes('payment') || id.includes('bitcoin') || id.includes('financial')) hasPayment = true;
    }
    if (hasUrgency && (hasThreat || hasPayment) && uniqueRuleIds.size >= 2) {
      const boost = hasThreat && hasPayment ? 30 : 20;
      const desc =
        'Cross-layer correlation: multi-signal coercion/urgency combined with financial/extortion demand.';
      correlationSignals.push({
        ruleId: 'corr-multi-signal-extortion',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.CORRELATION_ENGINE,
        source: DetectorLayer.CORRELATION_ENGINE,
        name: 'Correlated Multi-Signal Extortion',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.HIGH,
        weight: boost,
        scoreContribution: boost,
        confidence: 0.92
      });
    }

    let activeLayersCount = 0;
    for (const s of uniqueLayerMaxScore.values()) {
      if (s >= 30) activeLayersCount++;
    }
    if (activeLayersCount >= 3) {
      const desc = `Cross-layer consensus: ${activeLayersCount} independent detection layers reported elevated risk.`;
      correlationSignals.push({
        ruleId: 'corr-multi-layer-consensus',
        detectorType: DetectorType.HEURISTIC,
        detectorLayer: DetectorLayer.CORRELATION_ENGINE,
        source: DetectorLayer.CORRELATION_ENGINE,
        name: 'Multi-Layer Threat Consensus',
        description: desc,
        reason: desc,
        severityLevel: SeverityLevel.HIGH,
        weight: 15,
        scoreContribution: 15,
        confidence: 0.95
      });
    }

    // 3. Bounded Non-Linear Diminishing-Returns Aggregation Model
    // R_raw = 100 * (1 - PRODUCT_{i=1}^n (1 - x_i / 100))
    let productTerm = 1.0;
    for (const token of normalizedTokens) {
      const x_i = token.effectiveSignal;
      productTerm *= 1.0 - x_i / 100.0;
    }
    for (const corr of correlationSignals) {
      const corrEffective = (corr.scoreContribution ?? corr.weight ?? 15) * (corr.confidence ?? 0.95);
      productTerm *= 1.0 - Math.min(100, Math.max(0, corrEffective)) / 100.0;
      detectorContributions[DetectorLayer.CORRELATION_ENGINE] =
        (detectorContributions[DetectorLayer.CORRELATION_ENGINE] || 0) +
        (corr.scoreContribution ?? corr.weight ?? 15);
    }

    let rawR = 100.0 * (1.0 - productTerm);
    if (!Number.isFinite(rawR) || Number.isNaN(rawR)) {
      rawR = 60.0; // Fail-closed on mathematical anomaly
    }
    let calculatedScore = Math.min(100, Math.max(0, Math.round(rawR)));

    // 4. Critical Rule Priority Override (Step 11)
    if (criticalOverrideScore > 0 && Number.isFinite(criticalOverrideScore)) {
      calculatedScore = Math.max(calculatedScore, Math.round(criticalOverrideScore));
    }
    if (!Number.isFinite(calculatedScore) || Number.isNaN(calculatedScore)) {
      calculatedScore = 75; // Fail-closed fallback
    }
    calculatedScore = Math.min(100, Math.max(0, calculatedScore));

    // 5. Multi-Factor Confidence & Signal-Dilution Defense (Step 11)
    // Weight confidence by signal strength so 50 benign/noise signals (weight 0-2, confidence 0.2)
    // cannot dilute a high-confidence critical detection below the 0.40 caution clamp threshold.
    let weightedConfNumerator = 0;
    let weightedConfDenominator = 0;
    for (const t of normalizedTokens) {
      const w = Math.max(1.0, t.effectiveSignal);
      weightedConfNumerator += t.confidence * w;
      weightedConfDenominator += w;
    }
    const avgConfidence =
      weightedConfDenominator > 0
        ? weightedConfNumerator / weightedConfDenominator
        : normalizedTokens.reduce((a, t) => a + t.confidence, 0) / normalizedTokens.length;

    // Staleness Penalty (Section 3.1)
    let stalenessPenalty = 0.0;
    if (safeStaleness > 7) {
      stalenessPenalty = Math.min(0.2, (safeStaleness - 7) / 100);
    }

    // Signal Agreement (A = 1.0 - stdDev / 100) across significant threat signals (rawScore >= 15)
    const significantTokens = normalizedTokens.filter((t) => t.rawScore >= 15);
    const agreementPool = significantTokens.length >= 2 ? significantTokens : normalizedTokens;
    let agreement = 1.0;
    if (agreementPool.length >= 2) {
      const meanScore =
        agreementPool.reduce((a, t) => a + t.rawScore, 0) / agreementPool.length;
      const variance =
        agreementPool.reduce((a, t) => a + Math.pow(t.rawScore - meanScore, 2), 0) /
        agreementPool.length;
      const stdDev = Math.sqrt(variance);
      agreement = Math.max(0.6, 1.0 - stdDev / 100.0);
    }

    const consensusBoost = significantTokens.length >= 2 ? 0.05 : 0.0;
    let finalConfidence = Math.min(
      1.0,
      Math.max(0.2, (avgConfidence + consensusBoost) * (1.0 - stalenessPenalty) * agreement)
    );

    // Signal-Dilution Floor: If a verified critical override (confidence >= 0.50) fired,
    // low-weight noise signals can never drag confidence below the critical signal's confidence.
    if (maxCriticalConfidence >= 0.5) {
      finalConfidence = Math.max(
        finalConfidence,
        Math.min(1.0, maxCriticalConfidence * (1.0 - stalenessPenalty))
      );
    }

    const roundedConfidence = Math.round(finalConfidence * 100) / 100;
    const uncertainty = Math.round((1.0 - roundedConfidence) * 100) / 100;

    // 6. Determine Verdict, Severity Level, Recommendations, and 6-Tier EngineVerdict (Step 10)
    const inputModality = (options?.inputType || '').toString().toUpperCase();
    const isProcessModality =
      inputModality === 'PROCESS' ||
      evidence.some(
        (e: any) =>
          e &&
          (e.source === 'PROCESS_ANALYZER' ||
            (typeof e.ruleId === 'string' && e.ruleId.startsWith('proc-')))
      );
    const isFileModality =
      !isProcessModality &&
      (inputModality === 'FILE' ||
        evidence.some(
          (e: any) =>
            e &&
            (e.source === 'FileHeaderAnalyzer' ||
              e.source === 'FILE_ANALYZER' ||
              (typeof e.ruleId === 'string' && e.ruleId.startsWith('file-')))
        ));

    let category = RiskCategory.SAFE;
    let severity: Severity | SeverityLevel | string = 'SAFE';
    let sevLevel = SeverityLevel.NONE;
    let recommendation = ActionRecommendation.ALLOW;
    let recommendedAction = 'allow';
    let verdict = Verdict.ALLOW;
    let engineVerdict = EngineVerdict.ALLOW;
    let canonicalAction = PrescribedAction.PROCEED;
    let friction = FrictionLevel.NONE;
    let suggestedAction = 'Content appears safe. Safe to proceed.';

    if (calculatedScore >= 85) {
      category = RiskCategory.MALWARE;
      severity = 'BLOCK';
      sevLevel = SeverityLevel.CRITICAL;
      verdict = Verdict.DANGEROUS;
      recommendation = ActionRecommendation.BLOCK;
      recommendedAction = 'block';
      if (isProcessModality) {
        engineVerdict = EngineVerdict.CONTAIN_PROCESS;
        canonicalAction = PrescribedAction.CONTAIN_PROCESS;
      } else if (isFileModality) {
        engineVerdict = EngineVerdict.QUARANTINE;
        canonicalAction = PrescribedAction.QUARANTINE_FILE;
      } else {
        engineVerdict = EngineVerdict.BLOCK;
        canonicalAction = PrescribedAction.BLOCK_NAVIGATION;
      }
      friction = FrictionLevel.HIGH;
      suggestedAction = 'Do not proceed. Threat poses imminent risk to security. Access blocked.';
    } else if (calculatedScore >= 70) {
      const isScam = evidence.some(
        (e: any) =>
          e &&
          ((e.name && e.name.toLowerCase().includes('scam')) ||
            (e.indicator && e.indicator.includes('scam')) ||
            e.type === 'text' ||
            e.source === 'TEXT_ANALYZER')
      );
      category = isFileModality || isProcessModality ? RiskCategory.MALWARE : isScam ? RiskCategory.SCAM : RiskCategory.PHISHING;
      severity = 'SUSPICIOUS';
      sevLevel = SeverityLevel.HIGH;
      verdict = Verdict.SUSPICIOUS;
      recommendation = ActionRecommendation.WARN;
      recommendedAction = 'warn';
      engineVerdict = isFileModality || isProcessModality ? EngineVerdict.BLOCK : EngineVerdict.WARN;
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.MEDIUM;
      suggestedAction = 'Suspicious indicators identified. Do not enter credentials or pay.';
    } else if (calculatedScore >= 50) {
      const isScam = evidence.some(
        (e: any) =>
          e &&
          ((e.name && e.name.toLowerCase().includes('scam')) ||
            (e.indicator && e.indicator.includes('scam')) ||
            e.type === 'text' ||
            e.source === 'TEXT_ANALYZER')
      );
      category = isScam ? RiskCategory.SCAM : RiskCategory.PHISHING;
      severity = 'WARNING';
      sevLevel = SeverityLevel.MEDIUM;
      verdict = Verdict.CAUTION;
      recommendation = ActionRecommendation.WARN;
      recommendedAction = 'warn';
      engineVerdict = EngineVerdict.WARN;
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.LOW;
      suggestedAction = 'Exercise caution. Multiple suspicious patterns identified.';
    } else if (calculatedScore >= 20) {
      category = RiskCategory.SUSPICIOUS;
      severity = 'LOW';
      sevLevel = SeverityLevel.LOW;
      verdict = Verdict.INFORM;
      recommendation = ActionRecommendation.INFORM;
      recommendedAction = 'inform';
      engineVerdict = EngineVerdict.INFORM;
      canonicalAction = PrescribedAction.WARN_USER;
      friction = FrictionLevel.LOW;
      suggestedAction = 'Low risk detected. Verify source if requesting information.';
    } else {
      category = RiskCategory.SAFE;
      severity = 'SAFE';
      sevLevel = SeverityLevel.NONE;
      verdict = Verdict.ALLOW;
      recommendation = ActionRecommendation.ALLOW;
      recommendedAction = 'allow';
      engineVerdict = EngineVerdict.ALLOW;
      canonicalAction = PrescribedAction.PROCEED;
      friction = FrictionLevel.NONE;
      suggestedAction = 'Content appears safe.';
    }

    // Edge-Case Safety Rule (docs/RISK_ENGINE_ARCHITECTURE.md Section 4):
    // If Score >= 70 but Confidence < 0.40, clamp verdict to CAUTION
    if (calculatedScore >= 70 && roundedConfidence < 0.4) {
      verdict = Verdict.CAUTION;
      engineVerdict = EngineVerdict.WARN;
      severity = 'WARNING';
      sevLevel = SeverityLevel.MEDIUM;
      friction = FrictionLevel.LOW;
    }

    const riskAssessment: RiskAssessment = {
      overallScore: calculatedScore,
      confidence: roundedConfidence,
      severity: sevLevel,
      primaryThreatFactor,
      detectorContributions,
      uncertainty
    };

    const canonicalRecommendation: Recommendation = {
      action: canonicalAction,
      frictionLevel: friction,
      suggestedAction,
      bypassPermitted: calculatedScore < 85
    };

    return {
      score: calculatedScore,
      category,
      severity,
      confidence: roundedConfidence,
      recommendation,
      recommendedAction,
      engineVerdict,
      correlationSignals,
      verdict,
      riskAssessment,
      canonicalRecommendation
    };
  }

  private resolveDetectorLayer(e: any): DetectorLayer {
    if (e.detectorLayer && Object.values(DetectorLayer).includes(e.detectorLayer)) {
      return e.detectorLayer;
    }
    const src = (e.source || e.detectorType || '').toString().toUpperCase();
    const ruleId = (e.ruleId || e.indicator || '').toString().toLowerCase();

    if (src.includes('HASH') || ruleId.includes('hash') || ruleId.includes('eicar-sha256')) {
      return DetectorLayer.HASH_INTEL;
    }
    if (src.includes('THREAT_INTEL') || src.includes('BLOOM') || src.includes('REPUTATION')) {
      return DetectorLayer.REPUTATION_LOCAL;
    }
    if (src.includes('CORRELATION') || ruleId.startsWith('corr-')) {
      return DetectorLayer.CORRELATION_ENGINE;
    }
    if (src.includes('BEHAVIOR')) {
      return DetectorLayer.BEHAVIORAL_ENGINE;
    }
    if (
      ruleId.includes('pe-header') ||
      ruleId.includes('elf-header') ||
      ruleId.includes('dex-header') ||
      ruleId.includes('disguised-executable') ||
      ruleId.includes('double-ext-binary')
    ) {
      return DetectorLayer.STRUCTURAL_PARSER;
    }
    if (
      ruleId.includes('double-extension') ||
      ruleId.includes('executable-extension') ||
      ruleId.includes('unsigned') ||
      ruleId.includes('writable-dir')
    ) {
      return DetectorLayer.METADATA_ANALYZER;
    }
    if (src.includes('RULE') || e.detectorType === DetectorType.RULE) {
      return DetectorLayer.SIGNATURE_ENGINE;
    }
    return DetectorLayer.STATIC_HEURISTIC;
  }
}
