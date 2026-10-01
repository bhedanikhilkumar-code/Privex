import { describe, it, expect } from 'vitest';
import { ModelEvaluator, EvaluationSample } from '../../evaluation/model-evaluator';

describe('ModelEvaluator Metric Engine', () => {
  const evaluator = new ModelEvaluator({ benignLabel: 'BENIGN' });

  it('should return empty baseline report when samples array is empty', () => {
    const report = evaluator.evaluate([]);
    expect(report.totalSamples).toBe(0);
    expect(report.overallAccuracy).toBe(0);
    expect(report.binaryMetrics.f1Score).toBe(0);
  });

  it('should accurately calculate TP, TN, FP, FN, precision, recall, and F1 on known evaluation dataset', () => {
    const samples: EvaluationSample[] = [
      // 3 True Positives (Expected: THREAT, Predicted: THREAT)
      { text: 'sample 1', expectedClass: 'PHISHING', predictedClass: 'PHISHING', latencyMs: 1.2 },
      { text: 'sample 2', expectedClass: 'SCAM', predictedClass: 'SCAM', latencyMs: 1.5 },
      { text: 'sample 3', expectedClass: 'EXTORTION', predictedClass: 'EXTORTION', latencyMs: 1.1 },

      // 3 True Negatives (Expected: BENIGN, Predicted: BENIGN)
      { text: 'sample 4', expectedClass: 'BENIGN', predictedClass: 'BENIGN', latencyMs: 0.9 },
      { text: 'sample 5', expectedClass: 'BENIGN', predictedClass: 'BENIGN', latencyMs: 1.0 },
      { text: 'sample 6', expectedClass: 'BENIGN', predictedClass: 'BENIGN', latencyMs: 0.8 },

      // 1 False Positive (Expected: BENIGN, Predicted: THREAT)
      { text: 'sample 7', expectedClass: 'BENIGN', predictedClass: 'SCAM', latencyMs: 1.4 },

      // 1 False Negative (Expected: THREAT, Predicted: BENIGN)
      { text: 'sample 8', expectedClass: 'PHISHING', predictedClass: 'BENIGN', latencyMs: 1.3 }
    ];

    const report = evaluator.evaluate(samples);

    expect(report.totalSamples).toBe(8);
    // Correct predictions: 6 / 8 = 0.75
    expect(report.overallAccuracy).toBe(0.75);

    // Binary metrics:
    // TP = 3, TN = 3, FP = 1, FN = 1
    expect(report.binaryMetrics.confusionMatrix.tp).toBe(3);
    expect(report.binaryMetrics.confusionMatrix.tn).toBe(3);
    expect(report.binaryMetrics.confusionMatrix.fp).toBe(1);
    expect(report.binaryMetrics.confusionMatrix.fn).toBe(1);

    // Precision = 3 / (3 + 1) = 0.75
    expect(report.binaryMetrics.precision).toBe(0.75);
    // Recall = 3 / (3 + 1) = 0.75
    expect(report.binaryMetrics.recall).toBe(0.75);
    // F1 = 0.75
    expect(report.binaryMetrics.f1Score).toBe(0.75);
    // FPR = 1 / (1 + 3) = 0.25
    expect(report.binaryMetrics.falsePositiveRate).toBe(0.25);

    // Latency stats
    expect(report.latencyStats.p50Ms).toBeGreaterThan(0);
    expect(report.latencyStats.p95Ms).toBeGreaterThanOrEqual(report.latencyStats.p50Ms);
    expect(report.latencyStats.maxMs).toBe(1.5);
  });

  it('should compute class-level breakdowns and macro F1 accurately', () => {
    const samples: EvaluationSample[] = [
      { text: 'a', expectedClass: 'CLASS_A', predictedClass: 'CLASS_A', latencyMs: 1.0 },
      { text: 'b', expectedClass: 'CLASS_B', predictedClass: 'CLASS_B', latencyMs: 2.0 },
      { text: 'c', expectedClass: 'CLASS_B', predictedClass: 'CLASS_A', latencyMs: 1.5 }
    ];

    const report = evaluator.evaluate(samples);
    expect(report.perClassMetrics['CLASS_A']).toBeDefined();
    expect(report.perClassMetrics['CLASS_B']).toBeDefined();
    expect(report.macroF1).toBeGreaterThan(0);
    expect(report.microF1).toBeCloseTo(2 / 3);
  });
});
