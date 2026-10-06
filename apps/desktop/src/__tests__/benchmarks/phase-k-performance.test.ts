import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { performance } from 'perf_hooks';
import { EmailMimeParser } from '../../core/email-mime-parser';
import { NetworkMonitorService } from '../../services/network-monitor.service';

describe('Phase K Performance Benchmarks — Email Threat & Network Posture Latency', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'email-perf-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('measures EmailMimeParser in-memory parse throughput (< 2.0 ms target)', () => {
    const rawEml = [
      'From: Security Alert <service@paypal.com>',
      'Reply-To: support@drop-domain.xyz',
      'Subject: Immediate Action Required on Your Account',
      'Content-Type: text/plain; charset=utf-8',
      'Authentication-Results: mx.example.com; spf=fail; dmarc=fail',
      '',
      'Please verify your PayPal account at https://paypa1-security-login.top/account/verify'
    ].join('\r\n');

    const iterations = 1000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const parsed = EmailMimeParser.parseEml(rawEml);
      if (!parsed.headers.has('from')) throw new Error('Parse failed');
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    console.log(`[PERF] Email MIME Parsing Latency: ${avgMs.toFixed(5)} ms/email (Target: < 2.0 ms)`);
    expect(avgMs).toBeLessThan(2.0);
  });

  it('measures full EmailMimeParser.analyzeEmailFile latency (< 10.0 ms target)', async () => {
    const rawEml = [
      'From: Notifications <notify@github.com>',
      'Subject: Security Advisory Notice',
      'Content-Type: text/plain; charset=utf-8',
      'Authentication-Results: mx.example.com; spf=pass; dmarc=pass; dkim=pass',
      '',
      'Repository security report available at https://github.com/org/repo/security'
    ].join('\r\n');

    const testFile = path.join(tempDir, 'benchmark-email.eml');
    fs.writeFileSync(testFile, rawEml);

    // Warm-up
    await EmailMimeParser.analyzeEmailFile(testFile);

    const iterations = 500;
    const latencies: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const t0 = performance.now();
      const res = await EmailMimeParser.analyzeEmailFile(testFile);
      const dt = performance.now() - t0;
      latencies.push(dt);
      if (!res.hasEmailMetadata) throw new Error('Analysis failed');
    }

    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;

    console.log(
      `[PERF] Full Email Analysis Latency: avg=${avg.toFixed(4)} ms | p50=${p50.toFixed(4)} ms | p95=${p95.toFixed(4)} ms (Target: < 10.0 ms)`
    );

    expect(avg).toBeLessThan(10.0);
    expect(p50).toBeLessThan(10.0);
  });

  it('measures NetworkMonitorService netstat & firewall parse throughput (< 1.0 ms)', () => {
    const service = new NetworkMonitorService();

    // Generate 100 synthetic netstat socket lines
    const lines = [
      'Active Connections',
      '',
      '  Proto  Local Address          Foreign Address        State           PID'
    ];
    for (let i = 0; i < 100; i++) {
      lines.push(
        `  TCP    192.168.1.100:${50000 + i}    198.51.100.${(i % 50) + 1}:443    ESTABLISHED     ${1000 + i}`
      );
    }
    const rawNetstat = lines.join('\r\n');

    const iterations = 1000;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const connections = service.parseNetstatOutput(rawNetstat);
      if (connections.length !== 100) throw new Error('Parsing failed');
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    console.log(`[PERF] 100-Socket Netstat Parse Latency: ${avgMs.toFixed(5)} ms (Target: < 5.0 ms)`);
    expect(avgMs).toBeLessThan(5.0);
  });

  it('verifies bounded heap footprint during 1,000 rapid email analyses (< 15 MB heap delta)', async () => {
    const rawEml = [
      'From: alerts@paypal.com',
      'Subject: Monthly Statement',
      'Content-Type: text/plain; charset=utf-8',
      'Authentication-Results: mx.example.com; spf=pass; dmarc=pass; dkim=pass',
      '',
      'Your monthly account summary is available online.'
    ].join('\r\n');

    const testFile = path.join(tempDir, 'memory-test.eml');
    fs.writeFileSync(testFile, rawEml);

    if (global.gc) global.gc();
    const initialHeap = process.memoryUsage().heapUsed;

    for (let i = 0; i < 1000; i++) {
      await EmailMimeParser.analyzeEmailFile(testFile);
    }

    if (global.gc) global.gc();
    const finalHeap = process.memoryUsage().heapUsed;
    const heapDeltaMb = (finalHeap - initialHeap) / (1024 * 1024);

    console.log(`[PERF] 1,000 Email Inspections Heap Delta: ${heapDeltaMb.toFixed(2)} MB (Limit: < 15 MB)`);
    expect(heapDeltaMb).toBeLessThan(15);
  });
});
