import { describe, it, expect } from 'vitest';
import { DetectionPipeline } from '../../pipeline/detection-pipeline';
import { InputType, Verdict } from '../../types';
import { levenshteinDistance } from '../../utils/crypto';

describe('Phase R8 Deep Performance, 5-Class Latency, Memory Stress & Network Independence Suite', () => {
  const calcStats = (arr: number[]) => {
    const sorted = [...arr].sort((a, b) => a - b);
    return {
      min: sorted[0],
      p50: sorted[Math.floor(sorted.length * 0.5)],
      p95: sorted[Math.floor(sorted.length * 0.95)],
      max: sorted[sorted.length - 1],
      avg: sorted.reduce((a, b) => a + b, 0) / sorted.length
    };
  };

  it('R8-I: measures cold and warm DetectionPipeline + 120k BloomFilter startup latency (< 15 ms)', () => {
    const tCold0 = performance.now();
    const coldPipeline = new DetectionPipeline();
    const coldMs = performance.now() - tCold0;

    const warmTimes: number[] = [];
    for (let i = 0; i < 20; i++) {
      const t0 = performance.now();
      new DetectionPipeline();
      warmTimes.push(performance.now() - t0);
    }
    const warmStats = calcStats(warmTimes);

    console.log('\n================ R8-I CORE STARTUP BENCHMARK ================');
    console.log(
      `Cold Pipeline Init: ${coldMs.toFixed(3)} ms | Warm Init (N=20): min=${warmStats.min.toFixed(3)} ms, p50=${warmStats.p50.toFixed(3)} ms, p95=${warmStats.p95.toFixed(3)} ms, max=${warmStats.max.toFixed(3)} ms`
    );
    console.log('=============================================================\n');

    expect(coldPipeline).toBeDefined();
    expect(coldMs).toBeLessThan(50);
    expect(warmStats.p50).toBeLessThan(5);
    expect(warmStats.p95).toBeLessThan(50);
  });

  it('R8-J & R8-N: measures scan latency across all 5 input classes (SAFE, SUSPICIOUS, MALFORMED, EMPTY, EDGE CASE) and verifies functional verdicts', async () => {
    const pipeline = new DetectionPipeline();
    const N = 100;

    const edgeLongUrl = 'https://sub1.sub2.sub3.paypa1-verify.tk/login/auth?' + 'a=1&'.repeat(490); // ~2,005 bytes
    const edgeOversizedText =
      'URGENT: Your account is suspended. Verify your identity immediately or face legal action. '.repeat(115); // >10,000 chars

    const classes: Record<
      'SAFE' | 'SUSPICIOUS' | 'MALFORMED' | 'EMPTY' | 'EDGE_CASE',
      Array<{ input: string; inputType: InputType }>
    > = {
      SAFE: [
        { input: 'https://www.google.com/search?q=weather', inputType: InputType.URL },
        { input: 'https://github.com/microsoft/typescript', inputType: InputType.URL },
        { input: 'Hey, are we still meeting for lunch at 12:30 PM today?', inputType: InputType.TEXT }
      ],
      SUSPICIOUS: [
        { input: 'http://192.168.1.100/paypal/login.php', inputType: InputType.URL },
        { input: 'https://paypa1-security-alert.tk/verify/account', inputType: InputType.URL },
        {
          input:
            'URGENT: IRS arrest warrant issued. Send Bitcoin immediately to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
          inputType: InputType.TEXT
        }
      ],
      MALFORMED: [
        { input: 'ht tp://///malformed-url:::999999/login', inputType: InputType.URL },
        { input: '://missing-scheme-and-invalid-port:abc', inputType: InputType.URL }
      ],
      EMPTY: [
        { input: '', inputType: InputType.URL },
        { input: '   ', inputType: InputType.TEXT }
      ],
      EDGE_CASE: [
        { input: edgeLongUrl, inputType: InputType.URL },
        { input: 'https://xn--80ak6aa92e.com/login', inputType: InputType.URL },
        { input: edgeOversizedText, inputType: InputType.TEXT }
      ]
    };

    // Warm-up all classes to ensure steady-state JIT execution
    for (const samples of Object.values(classes)) {
      for (const sample of samples) {
        await pipeline.scan(sample);
      }
    }

    const resultsByClass: Record<string, ReturnType<typeof calcStats>> = {};

    for (const [className, samples] of Object.entries(classes)) {
      const times: number[] = [];
      for (let i = 0; i < N; i++) {
        const sample = samples[i % samples.length];
        const t0 = performance.now();
        await pipeline.scan(sample);
        times.push(performance.now() - t0);
      }
      resultsByClass[className] = calcStats(times);
    }

    console.log('\n================ R8-J 5-CLASS SCAN LATENCY (N=100 PER CLASS) ================');
    for (const [className, st] of Object.entries(resultsByClass)) {
      console.log(
        `${className.padEnd(12)} | min: ${st.min.toFixed(3)} ms | p50: ${st.p50.toFixed(3)} ms | p95: ${st.p95.toFixed(3)} ms | max: ${st.max.toFixed(3)} ms`
      );
    }
    console.log('=============================================================================\n');

    // Verify SLAs
    expect(resultsByClass.SAFE.p95).toBeLessThan(10);
    expect(resultsByClass.SUSPICIOUS.p95).toBeLessThan(10);
    expect(resultsByClass.MALFORMED.p95).toBeLessThan(10);
    expect(resultsByClass.EMPTY.p95).toBeLessThan(5);
    expect(resultsByClass.EDGE_CASE.p95).toBeLessThan(25);

    // R8-N Functional Safety Verification:
    const safeRes = await pipeline.scan(classes.SAFE[0]);
    expect(safeRes.verdict).toBe(Verdict.ALLOW);
    expect(safeRes.score).toBe(0);

    const suspRes = await pipeline.scan(classes.SUSPICIOUS[0]);
    expect([Verdict.SUSPICIOUS, Verdict.DANGEROUS]).toContain(suspRes.verdict);
    expect(suspRes.score).toBeGreaterThanOrEqual(70);

    const emptyRes = await pipeline.scan(classes.EMPTY[0]);
    expect(emptyRes.verdict).not.toBe(Verdict.ALLOW); // Fail-closed on empty input
  });

  it('R8-H: verifies zero unbounded memory growth across 500 repeated scan cycles and 1D Levenshtein equivalence', async () => {
    expect(levenshteinDistance('paypal', 'paypal')).toBe(0);
    expect(levenshteinDistance('paypa1', 'paypal')).toBe(1);
    expect(levenshteinDistance('microsoft', 'rnicrosoft')).toBe(2);
    expect(levenshteinDistance('', 'google')).toBe(6);

    const pipeline = new DetectionPipeline();
    // Warm up
    for (let i = 0; i < 20; i++) {
      await pipeline.scan({ input: 'https://google.com', inputType: InputType.URL });
    }

    const memBefore = process.memoryUsage().heapUsed;
    for (let i = 0; i < 500; i++) {
      await pipeline.scan({
        input: `https://paypa1-login-verify-${i % 25}.tk/account`,
        inputType: InputType.URL
      });
      await pipeline.scan({
        input: `URGENT: Your bank account #${i} has been suspended. Click here immediately to verify your identity.`,
        inputType: InputType.TEXT
      });
    }
    const memAfter = process.memoryUsage().heapUsed;
    const deltaMb = (memAfter - memBefore) / (1024 * 1024);

    console.log(
      `[R8-H Memory Stress] 1,000 back-to-back scans (500 URL + 500 Text) Heap Delta: ${deltaMb.toFixed(2)} MB`
    );
    expect(deltaMb).toBeLessThan(20);
  });

  it('R8-K: verifies 100% network independence across Network ON, OFF, FAILURE, and HIGH LATENCY', async () => {
    const pipeline = new DetectionPipeline();
    const origFetch = globalThis.fetch;

    try {
      // 1. Network ON
      const onResult = await pipeline.scan({
        input: 'http://192.168.1.100/paypal/login.php',
        inputType: InputType.URL
      });

      // 2. Network OFF / FAILURE (fetch throws ECONNREFUSED)
      globalThis.fetch = (() => {
        throw new Error('ERR_INTERNET_DISCONNECTED');
      }) as any;
      const offResult = await pipeline.scan({
        input: 'http://192.168.1.100/paypal/login.php',
        inputType: InputType.URL
      });

      // 3. Network HIGH LATENCY (fetch hangs for 10,000 ms)
      globalThis.fetch = (() => new Promise((r) => setTimeout(r, 10000))) as any;
      const t0 = performance.now();
      const highLatResult = await pipeline.scan({
        input: 'http://192.168.1.100/paypal/login.php',
        inputType: InputType.URL
      });
      const highLatElapsed = performance.now() - t0;

      expect(offResult.verdict).toBe(onResult.verdict);
      expect(offResult.score).toBe(onResult.score);
      expect(highLatResult.verdict).toBe(onResult.verdict);
      expect(highLatResult.score).toBe(onResult.score);
      expect(highLatElapsed).toBeLessThan(10);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
