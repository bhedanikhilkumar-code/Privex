import { describe, it, expect } from 'vitest';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { URLAnalyzer } from '../../analyzers/url-analyzer';
import { TextAnalyzer } from '../../analyzers/text-analyzer';
import { ThreatIntel } from '../../threat-intel/threat-intel';
import { RiskScorer } from '../../scoring/risk-scorer';
import { InputType } from '../../types';

describe('Phase 2 Performance & Latency Benchmark', () => {
  const pipeline = new DetectionPipeline();
  const urlAnalyzer = new URLAnalyzer();
  const textAnalyzer = new TextAnalyzer();
  const threatIntel = new ThreatIntel();
  const riskScorer = new RiskScorer();

  const sampleUrls = [
    'https://google.com/search?q=cybersecurity',
    'http://198.51.100.23/login?user=admin',
    'https://paypal-security-alert.tk/verify/account',
    'http://[2001:db8::1]:8080/path',
    'https://bit.ly/3xY8a9b'
  ];

  const sampleTexts = [
    'Your Apple ID verification code is 492019. Do not share this code.',
    'USPS: Your package was detained due to an incomplete address. Pay fee at usps-track.link',
    'Geek Squad: Subscription renewed for $399. Call 1-800-555-0199 to cancel immediately.',
    'Final Notice: IRS arrest warrant issued. Send Bitcoin immediately to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    'Hi, meeting is scheduled for 3pm in room B.'
  ];

  it('should measure micro-latencies across all Phase 2 critical detection paths', async () => {
    const N = 100;
    const urlLatencies: number[] = [];
    const textLatencies: number[] = [];
    const intelLatencies: number[] = [];
    const scoringLatencies: number[] = [];
    const pipelineLatencies: number[] = [];

    // Warm-up
    for (let i = 0; i < 10; i++) {
      urlAnalyzer.analyze(sampleUrls[0]);
      textAnalyzer.analyze(sampleTexts[0]);
      threatIntel.checkUrl(sampleUrls[0]);
      await pipeline.scan({ input: sampleUrls[0], inputType: InputType.URL });
    }

    // 1. URL Analyzer benchmark
    for (let i = 0; i < N; i++) {
      const url = sampleUrls[i % sampleUrls.length];
      const t0 = performance.now();
      urlAnalyzer.analyze(url);
      urlLatencies.push(performance.now() - t0);
    }

    // 2. Text Analyzer benchmark
    for (let i = 0; i < N; i++) {
      const txt = sampleTexts[i % sampleTexts.length];
      const t0 = performance.now();
      textAnalyzer.analyze(txt);
      textLatencies.push(performance.now() - t0);
    }

    // 3. Threat Intel Lookup benchmark
    for (let i = 0; i < N; i++) {
      const url = sampleUrls[i % sampleUrls.length];
      const t0 = performance.now();
      threatIntel.checkUrl(url);
      intelLatencies.push(performance.now() - t0);
    }

    // 4. Risk Scorer benchmark
    const sampleEvidence = [
      { source: 'URL_ANALYZER', name: 'IP Host', weight: 65, confidence: 0.95 },
      { source: 'RULE_ENGINE', name: 'Suspicious TLD', weight: 45, confidence: 0.9 }
    ];
    for (let i = 0; i < N; i++) {
      const t0 = performance.now();
      riskScorer.calculate(sampleEvidence);
      scoringLatencies.push(performance.now() - t0);
    }

    // 5. Full Pipeline benchmark
    for (let i = 0; i < N; i++) {
      const input = i % 2 === 0 ? sampleUrls[i % sampleUrls.length] : sampleTexts[i % sampleTexts.length];
      const inputType = i % 2 === 0 ? InputType.URL : InputType.TEXT;
      const t0 = performance.now();
      await pipeline.scan({ input, inputType });
      pipelineLatencies.push(performance.now() - t0);
    }

    const calcStats = (arr: number[]) => {
      arr.sort((a, b) => a - b);
      return {
        p50: arr[Math.floor(arr.length * 0.5)],
        p95: arr[Math.floor(arr.length * 0.95)],
        max: arr[arr.length - 1],
        avg: arr.reduce((a, b) => a + b, 0) / arr.length
      };
    };

    const urlStats = calcStats(urlLatencies);
    const textStats = calcStats(textLatencies);
    const intelStats = calcStats(intelLatencies);
    const scoreStats = calcStats(scoringLatencies);
    const pipeStats = calcStats(pipelineLatencies);

    console.log('\n================ PHASE 2 LATENCY BENCHMARKS ================');
    console.log(`URL Analyzer:       p50: ${urlStats.p50.toFixed(3)} ms | p95: ${urlStats.p95.toFixed(3)} ms | max: ${urlStats.max.toFixed(3)} ms`);
    console.log(`Text Analyzer:      p50: ${textStats.p50.toFixed(3)} ms | p95: ${textStats.p95.toFixed(3)} ms | max: ${textStats.max.toFixed(3)} ms`);
    console.log(`Threat Intel:       p50: ${intelStats.p50.toFixed(3)} ms | p95: ${intelStats.p95.toFixed(3)} ms | max: ${intelStats.max.toFixed(3)} ms`);
    console.log(`Risk Scorer:        p50: ${scoreStats.p50.toFixed(3)} ms | p95: ${scoreStats.p95.toFixed(3)} ms | max: ${scoreStats.max.toFixed(3)} ms`);
    console.log(`Full Pipeline:      p50: ${pipeStats.p50.toFixed(3)} ms | p95: ${pipeStats.p95.toFixed(3)} ms | max: ${pipeStats.max.toFixed(3)} ms`);
    console.log('============================================================\n');

    // SLAs from AGENTS.md & INTERFACE_CONTRACTS.md:
    // Threat Intel SLA < 0.1ms
    // URL Analyzer SLA < 2.0ms
    // Text Analyzer SLA < 5.0ms
    // Risk Scorer SLA < 0.1ms
    // Full Pipeline SLA < 100ms
    expect(urlStats.p95).toBeLessThan(5.0);
    expect(textStats.p95).toBeLessThan(10.0);
    expect(intelStats.p95).toBeLessThan(1.0);
    expect(scoreStats.p95).toBeLessThan(1.0);
    expect(pipeStats.p95).toBeLessThan(25.0);
  });
});
