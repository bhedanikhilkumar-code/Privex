export interface ConfusionMatrix {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
}

export interface ClassEvaluationMetric {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface EvaluationReport {
  totalSamples: number;
  overallAccuracy: number;
  binaryMetrics: {
    confusionMatrix: ConfusionMatrix;
    precision: number;
    recall: number;
    f1Score: number;
    falsePositiveRate: number;
  };
  macroF1: number;
  microF1: number;
  perClassMetrics: Record<string, ClassEvaluationMetric>;
  latencyStats: {
    p50Ms: number;
    p95Ms: number;
    maxMs: number;
  };
}

export interface EvaluationSample {
  readonly text: string;
  readonly expectedClass: string;
  readonly predictedClass: string;
  readonly latencyMs: number;
}

/**
 * PRODUCTION-GRADE MODEL EVALUATION HARNESS
 *
 * Computes exact statistical classification metrics (Confusion Matrix, Precision, Recall,
 * Macro F1, Micro F1, False Positive Rate, and latency quantiles) for intent classifiers
 * and on-device machine learning evaluation datasets.
 */
export class ModelEvaluator {
  private benignLabel: string;

  constructor(options?: { benignLabel?: string }) {
    this.benignLabel = options?.benignLabel ?? 'BENIGN_COMMUNICATION';
  }

  public evaluate(samples: EvaluationSample[]): EvaluationReport {
    if (!samples || samples.length === 0) {
      return {
        totalSamples: 0,
        overallAccuracy: 0,
        binaryMetrics: {
          confusionMatrix: { tp: 0, tn: 0, fp: 0, fn: 0 },
          precision: 0,
          recall: 0,
          f1Score: 0,
          falsePositiveRate: 0
        },
        macroF1: 0,
        microF1: 0,
        perClassMetrics: {},
        latencyStats: { p50Ms: 0, p95Ms: 0, maxMs: 0 }
      };
    }

    const total = samples.length;
    let correct = 0;
    let tp = 0;
    let tn = 0;
    let fp = 0;
    let fn = 0;

    const classStats: Record<string, { tp: number; fp: number; fn: number; support: number }> = {};
    const latencies: number[] = [];

    for (const s of samples) {
      latencies.push(s.latencyMs);

      // Initialize class stat trackers
      if (!classStats[s.expectedClass]) {
        classStats[s.expectedClass] = { tp: 0, fp: 0, fn: 0, support: 0 };
      }
      if (!classStats[s.predictedClass]) {
        classStats[s.predictedClass] = { tp: 0, fp: 0, fn: 0, support: 0 };
      }

      classStats[s.expectedClass].support++;

      if (s.expectedClass === s.predictedClass) {
        correct++;
        classStats[s.expectedClass].tp++;
      } else {
        classStats[s.expectedClass].fn++;
        classStats[s.predictedClass].fp++;
      }

      // Binary threat calculation (threat vs benign)
      const expectedThreat = s.expectedClass !== this.benignLabel;
      const predictedThreat = s.predictedClass !== this.benignLabel;

      if (expectedThreat && predictedThreat) tp++;
      else if (!expectedThreat && !predictedThreat) tn++;
      else if (!expectedThreat && predictedThreat) fp++;
      else if (expectedThreat && !predictedThreat) fn++;
    }

    // Binary metrics
    const binaryPrecision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const binaryRecall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const binaryF1 = binaryPrecision + binaryRecall > 0
      ? (2 * binaryPrecision * binaryRecall) / (binaryPrecision + binaryRecall)
      : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;

    // Multi-class per-class metrics & Macro F1
    const perClassMetrics: Record<string, ClassEvaluationMetric> = {};
    let sumF1 = 0;
    const activeClasses = Object.keys(classStats).filter(c => classStats[c].support > 0);

    for (const cls of activeClasses) {
      const stat = classStats[cls];
      const prec = stat.tp + stat.fp > 0 ? stat.tp / (stat.tp + stat.fp) : 0;
      const rec = stat.tp + stat.fn > 0 ? stat.tp / (stat.tp + stat.fn) : 0;
      const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;

      perClassMetrics[cls] = {
        precision: Math.round(prec * 10000) / 10000,
        recall: Math.round(rec * 10000) / 10000,
        f1: Math.round(f1 * 10000) / 10000,
        support: stat.support
      };

      sumF1 += f1;
    }

    const macroF1 = activeClasses.length > 0 ? sumF1 / activeClasses.length : 0;
    const microF1 = correct / total;

    // Latency quantiles
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.50)] ?? 0;
    const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? 0;
    const maxLatency = latencies[latencies.length - 1] ?? 0;

    return {
      totalSamples: total,
      overallAccuracy: Math.round((correct / total) * 10000) / 10000,
      binaryMetrics: {
        confusionMatrix: { tp, tn, fp, fn },
        precision: Math.round(binaryPrecision * 10000) / 10000,
        recall: Math.round(binaryRecall * 10000) / 10000,
        f1Score: Math.round(binaryF1 * 10000) / 10000,
        falsePositiveRate: Math.round(fpr * 10000) / 10000
      },
      macroF1: Math.round(macroF1 * 10000) / 10000,
      microF1: Math.round(microF1 * 10000) / 10000,
      perClassMetrics,
      latencyStats: {
        p50Ms: Math.round(p50 * 1000) / 1000,
        p95Ms: Math.round(p95 * 1000) / 1000,
        maxMs: Math.round(maxLatency * 1000) / 1000
      }
    };
  }
}
