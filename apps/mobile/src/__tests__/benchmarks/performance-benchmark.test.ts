import { describe, it, expect } from 'vitest';
import { MobileSecurityAdapter } from '../../adapters/mobile-security-adapter';
import { FileScannerService } from '../../services/file-scanner.service';
import { DeviceAuditService } from '../../services/device-audit.service';

describe('Phase 6 Mobile Performance & Latency Benchmark', () => {
  const adapter = new MobileSecurityAdapter();
  const fileService = new FileScannerService();
  const auditService = new DeviceAuditService();

  it('measures real micro-latencies across all mobile execution paths', async () => {
    const measure = async (fn: () => Promise<any> | any, iterations: number = 30) => {
      // Warm up
      for (let w = 0; w < 5; w++) {
        await fn();
      }
      const latencies: number[] = [];
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await fn();
        latencies.push(performance.now() - start);
      }
      latencies.sort((a, b) => a - b);
      return {
        p50: latencies[Math.floor(iterations * 0.5)],
        p95: latencies[Math.floor(iterations * 0.95)],
        max: latencies[latencies.length - 1]
      };
    };

    const urlBench = await measure(() => adapter.scanUrl('http://192.168.1.100/login.php'));
    const textBench = await measure(() => adapter.scanText('URGENT: Your account has been suspended! Send 0.1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'));
    const fileBench = await measure(() => fileService.inspectFile({
      name: 'invoice.pdf.exe',
      sizeBytes: 1024,
      mimeType: 'application/octet-stream',
      headerBytes: [0x4d, 0x5a, 0x90, 0x00]
    }));
    const auditBench = await measure(() => auditService.auditSecurityPosture());

    const mem = process.memoryUsage();
    const heapUsedMb = (mem.heapUsed / 1024 / 1024).toFixed(2);
    const rssMb = (mem.rss / 1024 / 1024).toFixed(2);

    console.log(`
================ PHASE 6 MOBILE LATENCY & PERFORMANCE BENCHMARKS ================
URL Threat Scan:       p50: ${urlBench.p50.toFixed(3)} ms | p95: ${urlBench.p95.toFixed(3)} ms | max: ${urlBench.max.toFixed(3)} ms
Message Text Scan:     p50: ${textBench.p50.toFixed(3)} ms | p95: ${textBench.p95.toFixed(3)} ms | max: ${textBench.max.toFixed(3)} ms
File Header Analysis:  p50: ${fileBench.p50.toFixed(3)} ms | p95: ${fileBench.p95.toFixed(3)} ms | max: ${fileBench.max.toFixed(3)} ms
Device Posture Audit:  p50: ${auditBench.p50.toFixed(3)} ms | p95: ${auditBench.p95.toFixed(3)} ms | max: ${auditBench.max.toFixed(3)} ms
----------------------------------------------------------------------------------
Memory Footprint:      Heap Used: ${heapUsedMb} MB | RSS: ${rssMb} MB
==================================================================================
`);

    // Verify SLAs (Hard SLA < 200ms under parallel synthetic load)
    expect(urlBench.p50).toBeLessThan(50);
    expect(textBench.p50).toBeLessThan(50);
    expect(fileBench.p50).toBeLessThan(20);
    expect(auditBench.p50).toBeLessThan(10);
  });
});
