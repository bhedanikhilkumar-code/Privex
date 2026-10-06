import { describe, expect, it } from 'vitest';
import {
  BloomFilter,
  CoreFileAnalyzer,
  DetectionPipeline,
  DetectorLayer,
  InputType,
  RiskScorer,
  ThreatIntel
} from '../../index';

describe('Phase B — Core Detection Engine Hot-Path Performance Benchmarks', () => {
  it('verifies BloomFilter.has() < 0.02 ms, ThreatIntel.lookupHash() < 0.05 ms, RiskScorer.calculateScore() < 0.05 ms, and DetectionPipeline.scan() < 1.0 ms', async () => {
    const filter = new BloomFilter(100000, 0.0001);
    const intel = new ThreatIntel();
    const scorer = new RiskScorer();
    const pipeline = new DetectionPipeline({ threatIntel: intel, riskScorer: scorer });

    const sampleHex = ThreatIntel.EICAR_SHA256;
    filter.add(sampleHex);

    // Warm up JIT
    for (let i = 0; i < 200; i++) {
      filter.has(sampleHex);
      intel.lookupHash(sampleHex);
      scorer.calculateScore([
        {
          ruleId: 'warmup-sig',
          detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
          source: 'RULE_ENGINE',
          name: 'Warmup',
          description: 'Warmup',
          weight: 50,
          confidence: 0.9
        }
      ]);
    }

    const iterations = 2000;

    // Warmup BloomFilter.has()
    for (let i = 0; i < 200; i++) {
      filter.has(sampleHex);
    }

    // 1. BloomFilter.has() benchmark (target < 0.02 ms)
    const bloomStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      filter.has(sampleHex);
    }
    const bloomAvgMs = (performance.now() - bloomStart) / iterations;

    // 2. ThreatIntel.lookupHash() benchmark (target < 0.05 ms)
    const intelStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      intel.lookupHash(sampleHex);
    }
    const intelAvgMs = (performance.now() - intelStart) / iterations;

    // 3. RiskScorer.calculateScore() benchmark (target < 0.05 ms)
    const sampleEvidence = [
      {
        ruleId: 'proc-writable-dir-execution',
        detectorLayer: DetectorLayer.METADATA_ANALYZER,
        source: 'PROCESS_ANALYZER',
        name: 'Writable Dir',
        description: 'Temp dir',
        weight: 40,
        scoreContribution: 40,
        confidence: 0.9
      },
      {
        ruleId: 'proc-encoded-command',
        detectorLayer: DetectorLayer.SIGNATURE_ENGINE,
        source: 'RULE_ENGINE',
        name: 'Encoded Command',
        description: 'Encoded PowerShell',
        weight: 75,
        scoreContribution: 75,
        confidence: 0.95
      }
    ];
    // Warm up JIT for sample evidence shape
    for (let i = 0; i < 200; i++) {
      scorer.calculateScore(sampleEvidence, 0, { inputType: InputType.PROCESS });
    }
    const scorerStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      scorer.calculateScore(sampleEvidence, 0, { inputType: InputType.PROCESS });
    }
    const scorerAvgMs = (performance.now() - scorerStart) / iterations;

    // 4. DetectionPipeline.scan() benchmark across URL, TEXT, FILE, PROCESS (target < 1.0 ms avg)
    const scanIterations = 100;
    const fileBytes = new TextEncoder().encode(CoreFileAnalyzer.EICAR_SIGNATURE);
    const pipelineStart = performance.now();
    for (let i = 0; i < scanIterations; i++) {
      await pipeline.scan({
        inputType: InputType.URL,
        input: 'https://google.com/search?q=antivirus'
      });
      await pipeline.scan({
        inputType: InputType.TEXT,
        input: 'URGENT: Verify your bank account immediately or face suspension.'
      });
      await pipeline.scan({
        inputType: InputType.FILE,
        payload: fileBytes,
        metadata: { fileName: 'eicar.com', fileSize: '68', sha256: ThreatIntel.EICAR_SHA256 }
      });
      await pipeline.scan({
        inputType: InputType.PROCESS,
        processMetadata: {
          pid: 4400,
          ppid: 1200,
          processName: 'powershell.exe',
          parentName: 'WINWORD.EXE',
          executablePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
          commandLine: 'powershell.exe -EncodedCommand SQBFAFgA'
        }
      });
    }
    const pipelineAvgMs = (performance.now() - pipelineStart) / (scanIterations * 4);

    console.log('\n================ PHASE B HOT-PATH BENCHMARKS ================');
    console.log(`BloomFilter.has() (64-hex):     ${bloomAvgMs.toFixed(5)} ms (Target: < 0.02000 ms)`);
    console.log(`ThreatIntel.lookupHash():       ${intelAvgMs.toFixed(5)} ms (Target: < 0.05000 ms)`);
    console.log(`RiskScorer.calculateScore():    ${scorerAvgMs.toFixed(5)} ms (Target: < 0.05000 ms)`);
    console.log(`DetectionPipeline.scan() avg:   ${pipelineAvgMs.toFixed(4)} ms (Target: < 1.0000 ms)`);
    console.log('=============================================================\n');

    expect(bloomAvgMs).toBeLessThan(0.02);
    expect(intelAvgMs).toBeLessThan(0.05);
    expect(scorerAvgMs).toBeLessThan(0.05);
    expect(pipelineAvgMs).toBeLessThan(1.0);
  });
});
