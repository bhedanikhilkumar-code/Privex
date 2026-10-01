import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { ActionRecommendation, InputType } from '../../types';

interface BenchmarkSample {
  input: string;
  type: 'URL' | 'TEXT';
  label: 'BENIGN' | 'MALICIOUS';
}

interface BenchmarkDataset {
  description: string;
  version: string;
  samples: BenchmarkSample[];
}

describe('Detection Accuracy and Performance Benchmark', () => {
  const pipeline = new DetectionPipeline();

  const datasetPath = path.resolve(__dirname, '../../../../../threat-data/benchmark-dataset.json');
  const datasetRaw = fs.readFileSync(datasetPath, 'utf-8');
  const dataset: BenchmarkDataset = JSON.parse(datasetRaw);

  it('should evaluate dataset with high accuracy, low FPR, and real-time latency', async () => {
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    const latencies: number[] = [];
    const missedSamples: Array<{ input: string; score: number; type: string }> = [];

    for (const sample of dataset.samples) {
      const inputType = sample.type === 'URL' ? InputType.URL : InputType.TEXT;

      const tStart = performance.now();
      const result = await pipeline.scan({
        input: sample.input,
        inputType
      });
      const tElapsed = performance.now() - tStart;
      latencies.push(tElapsed);

      const isDetectedAsThreat =
        result.recommendation === ActionRecommendation.BLOCK ||
        result.recommendation === ActionRecommendation.WARN ||
        result.riskScore >= 60;

      if (sample.label === 'MALICIOUS') {
        if (isDetectedAsThreat) {
          tp++;
        } else {
          fn++;
          missedSamples.push({ input: sample.input, score: result.riskScore, type: sample.type });
        }
      } else {
        if (isDetectedAsThreat) {
          fp++;
        } else {
          tn++;
        }
      }
    }

    const total = dataset.samples.length;
    const accuracy = ((tp + tn) / total) * 100;
    const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 0;
    const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const fpr = tn + fp > 0 ? (fp / (tn + fp)) * 100 : 0;

    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];

    console.log('\n================ BENCHMARK REPORT ================');
    console.log(`Total Samples Evaluated: ${total}`);
    console.log(`True Positives (TP):     ${tp}`);
    console.log(`True Negatives (TN):     ${tn}`);
    console.log(`False Positives (FP):    ${fp}`);
    console.log(`False Negatives (FN):    ${fn}`);
    console.log(`Detection Accuracy:      ${accuracy.toFixed(2)}%`);
    console.log(`Precision:               ${precision.toFixed(2)}%`);
    console.log(`Recall:                  ${recall.toFixed(2)}%`);
    console.log(`F1 Score:                ${(f1 / 100).toFixed(4)}`);
    console.log(`False Positive Rate:     ${fpr.toFixed(2)}%`);
    console.log(`Latency p50:             ${p50.toFixed(2)} ms`);
    console.log(`Latency p95:             ${p95.toFixed(2)} ms`);
    if (missedSamples.length > 0) {
      console.log('Missed Samples:');
      missedSamples.forEach(m => console.log(`  [${m.type}] Score: ${m.score} -> "${m.input}"`));
    }
    console.log('==================================================\n');

    expect(total).toBe(100);
    expect(accuracy).toBeGreaterThanOrEqual(95);
    expect(fpr).toBeLessThanOrEqual(1.0);
    expect(recall).toBeGreaterThanOrEqual(90);
    expect(p95).toBeLessThan(50);
  });
});
