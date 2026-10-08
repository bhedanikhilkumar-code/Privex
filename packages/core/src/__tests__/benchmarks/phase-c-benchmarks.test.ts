import { describe, it, expect } from 'vitest';
import { performance } from 'perf_hooks';
import { CleanFileCache } from '../../cache/clean-file-cache';
import { CoreFileAnalyzer } from '../../analyzers/file-analyzer';
import { PeAnalyzer } from '../../analyzers/pe-analyzer';
import { EntropyScanner } from '../../analyzers/entropy-scanner';
import { SignatureAutomaton } from '../../threat-intel/signature-automaton';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { InputType } from '../../types';

describe('Phase C — File Protection & Static Malware Engine Performance Benchmarks', () => {
  it('SLA 1: CleanFileCache lookup latency is under 0.08 ms', () => {
    const cache = CleanFileCache.getSharedInstance();
    cache.clear();

    const path = 'C:\\Windows\\System32\\notepad.exe';
    const size = 102400;
    const mtime = 1700000000;
    const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    cache.recordClean(path, size, mtime, sha256);

    // Warm-up
    for (let i = 0; i < 1000; i++) {
      cache.isClean(path, size, mtime);
    }

    const iterations = 50000;
    const t0 = performance.now();
    for (let i = 0; i < iterations; i++) {
      cache.isClean(path, size, mtime);
    }
    const t1 = performance.now();

    const avgMs = (t1 - t0) / iterations;
    expect(avgMs).toBeLessThan(0.08); // < 0.08 ms SLA
  });

  it('SLA 2: Stage 1 Fast Header Triage latency is under 0.50 ms', () => {
    const analyzer = new CoreFileAnalyzer();
    const cleanHeader = new Uint8Array(512);
    cleanHeader.fill(0x20); // plain ascii text spaces

    // Warm-up
    for (let i = 0; i < 100; i++) {
      analyzer.analyze({ path: 'test.txt', content: cleanHeader });
    }

    const iterations = 5000;
    const t0 = performance.now();
    for (let i = 0; i < iterations; i++) {
      analyzer.analyze({ path: 'test.txt', content: cleanHeader });
    }
    const t1 = performance.now();

    const avgMs = (t1 - t0) / iterations;
    expect(avgMs).toBeLessThan(0.50); // < 0.50 ms SLA
  });

  it('SLA 3: Deep Static Analysis (PE + Entropy + Automaton) is under 5.0 ms', () => {
    const analyzer = new CoreFileAnalyzer();

    // Construct a synthetic 8KB PE binary buffer
    const peBuffer = new Uint8Array(8192);
    peBuffer[0] = 0x4d; // 'M'
    peBuffer[1] = 0x5a; // 'Z'
    peBuffer[0x3c] = 0x80; // e_lfanew
    peBuffer[0x80] = 0x50; // 'P'
    peBuffer[0x81] = 0x45; // 'E'
    const view = new DataView(peBuffer.buffer);
    view.setUint16(0x84, 0x8664, true); // Machine x64
    view.setUint16(0x86, 2, true); // 2 sections
    view.setUint16(0x94, 0xf0, true); // Size of optional header
    view.setUint16(0x98, 0x20b, true); // PE32+

    // Section 1 (.text)
    const s1 = 0x80 + 24 + 0xf0;
    peBuffer.set(new TextEncoder().encode('.text\0\0\0'), s1);
    view.setUint32(s1 + 8, 4096, true);
    view.setUint32(s1 + 12, 0x1000, true);
    view.setUint32(s1 + 16, 4096, true);
    view.setUint32(s1 + 20, 512, true);
    view.setUint32(s1 + 36, 0x60000020, true); // R-X

    // Fill code with pattern
    for (let i = 512; i < 4608; i++) {
      peBuffer[i] = (i * 31) % 256;
    }

    // Warm-up
    for (let i = 0; i < 50; i++) {
      analyzer.analyze({ path: 'sample.exe', content: peBuffer });
    }

    const iterations = 1000;
    const t0 = performance.now();
    for (let i = 0; i < iterations; i++) {
      analyzer.analyze({ path: 'sample.exe', content: peBuffer });
    }
    const t1 = performance.now();

    const avgMs = (t1 - t0) / iterations;
    expect(avgMs).toBeLessThan(5.0); // < 5.0 ms SLA
  });

  it('SLA 4: DetectionPipeline FILE scan latency is under 5.0 ms p95', async () => {
    const pipeline = new DetectionPipeline();
    const cleanDoc = new TextEncoder().encode('Privex Secure Endpoint Document Verification');

    // Warm-up
    for (let i = 0; i < 50; i++) {
      await pipeline.scan({
        inputType: InputType.FILE,
        payload: 'test.txt',
        fileContent: cleanDoc
      });
    }

    const iterations = 500;
    const latencies: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      await pipeline.scan({
        inputType: InputType.FILE,
        payload: 'test.txt',
        fileContent: cleanDoc
      });
      const t1 = performance.now();
      latencies.push(t1 - t0);
    }

    latencies.sort((a, b) => a - b);
    const p95 = latencies[Math.floor(iterations * 0.95)];
    const avg = latencies.reduce((a, b) => a + b, 0) / iterations;

    expect(avg).toBeLessThan(1.0); // < 1.0 ms average
    expect(p95).toBeLessThan(5.0); // < 5.0 ms p95
  });
});
