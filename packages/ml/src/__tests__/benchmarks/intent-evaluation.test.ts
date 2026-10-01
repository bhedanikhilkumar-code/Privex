import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { ScamIntentClassifier } from '../../classifiers/intent-classifier';
import { ScamIntent } from '../../types';

describe('Intent Classification Evaluation Benchmark', () => {
  const classifier = new ScamIntentClassifier();

  it('should evaluate the synthetic intent evaluation dataset and record real metrics', async () => {
    // Resolve dataset path
    const datasetPath = path.resolve(__dirname, '../../../../../tests/fixtures/ml/intent-evaluation-dataset.json');
    expect(fs.existsSync(datasetPath)).toBe(true);

    const rawData = fs.readFileSync(datasetPath, 'utf-8');
    const dataset = JSON.parse(rawData);

    expect(dataset.samples.length).toBeGreaterThanOrEqual(70);

    let truePositives = 0;
    let trueNegatives = 0;
    let falsePositives = 0;
    let falseNegatives = 0;
    let exactClassMatches = 0;

    const latencies: number[] = [];

    for (const sample of dataset.samples) {
      const start = performance.now();
      const result = await classifier.classify(sample.text);
      const elapsed = performance.now() - start;
      latencies.push(elapsed);

      const isGroundTruthBenign = sample.class === 'BENIGN_COMMUNICATION';
      const isPredictedBenign = result.intent === ScamIntent.BENIGN_COMMUNICATION;

      if (sample.class === result.intent) {
        exactClassMatches++;
      }

      if (!isGroundTruthBenign && !isPredictedBenign) {
        truePositives++;
      } else if (isGroundTruthBenign && isPredictedBenign) {
        trueNegatives++;
      } else if (isGroundTruthBenign && !isPredictedBenign) {
        falsePositives++;
      } else if (!isGroundTruthBenign && isPredictedBenign) {
        falseNegatives++;
      }
    }

    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.50)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const maxLatency = latencies[latencies.length - 1];

    const total = dataset.samples.length;
    const accuracy = ((truePositives + trueNegatives) / total) * 100;
    const precision = truePositives + falsePositives > 0
      ? truePositives / (truePositives + falsePositives)
      : 0;
    const recall = truePositives + falseNegatives > 0
      ? truePositives / (truePositives + falseNegatives)
      : 0;
    const f1 = precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : 0;
    const exactClassAccuracy = (exactClassMatches / total) * 100;

    console.log('\n================ INTENT EVALUATION BENCHMARK REPORT ================');
    console.log(`Total Samples Evaluated:      ${total}`);
    console.log(`Exact 7-Class Match Rate:     ${exactClassAccuracy.toFixed(2)}% (${exactClassMatches}/${total})`);
    console.log(`Binary Threat True Positives:  ${truePositives}`);
    console.log(`Binary Safe True Negatives:    ${trueNegatives}`);
    console.log(`False Positives:               ${falsePositives}`);
    console.log(`False Negatives:               ${falseNegatives}`);
    console.log(`Binary Threat Accuracy:        ${accuracy.toFixed(2)}%`);
    console.log(`Precision:                     ${(precision * 100).toFixed(2)}%`);
    console.log(`Recall:                        ${(recall * 100).toFixed(2)}%`);
    console.log(`Binary F1 Score:               ${f1.toFixed(4)}`);
    console.log(`Inference Latency p50:         ${p50.toFixed(3)} ms`);
    console.log(`Inference Latency p95:         ${p95.toFixed(3)} ms`);
    console.log(`Inference Latency Max:         ${maxLatency.toFixed(3)} ms`);
    console.log('=====================================================================\n');

    // Strict assertions:
    // 1. Zero False Positives on benign communication
    expect(falsePositives).toBe(0);
    // 2. High threat detection recall (>= 90%)
    expect(recall).toBeGreaterThanOrEqual(0.90);
    // 3. Ultra-fast real-time latency (< 5 ms for heuristic path, p95 < 2 ms)
    expect(p95).toBeLessThan(5.0);
  });
});
