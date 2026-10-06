import { describe, it, expect } from 'vitest';
import { NotificationService } from '../../services/notification.service';
import { DetectedThreat } from '../../types/desktop.types';

describe('Phase H Performance & Latency Benchmarks', () => {
  it('measures Notification dispatch + coalescing latency (< 0.50 ms per event)', () => {
    const service = new NotificationService({
      toastDispatcher: () => true
    });

    const sampleThreat: DetectedThreat = {
      id: 'perf-t-1',
      filePath: 'C:\\Downloads\\installer.exe',
      fileName: 'installer.exe',
      fileSize: 50000,
      sha256: 'b'.repeat(64),
      riskScore: 90,
      severity: 'critical',
      verdict: 'BLOCK',
      threatName: 'Trojan.Dropper.Win32',
      detectedAt: Date.now(),
      evidenceFactors: ['PE header mismatch'],
      quarantined: true
    };

    const iterations = 500;
    const tStart = performance.now();

    for (let i = 0; i < iterations; i++) {
      service.notifySecurityThreat(sampleThreat);
    }

    const tTotal = performance.now() - tStart;
    const avgLatencyMs = tTotal / iterations;

    console.log(`[PERF] Notification Dispatch Latency: ${avgLatencyMs.toFixed(4)} ms/event (Target: < 0.50 ms)`);
    expect(avgLatencyMs).toBeLessThan(0.50);
  });

  it('measures Token Bucket rate-limiter decision speed (< 0.01 ms)', () => {
    let virtualTime = 1000;
    const service = new NotificationService({
      clock: () => virtualTime,
      toastDispatcher: () => true
    });

    const iterations = 10000;
    const tStart = performance.now();

    for (let i = 0; i < iterations; i++) {
      virtualTime += 1;
      service.getAvailableTokens();
    }

    const tTotal = performance.now() - tStart;
    const avgTokenMs = tTotal / iterations;

    console.log(`[PERF] Token Bucket Evaluation Latency: ${avgTokenMs.toFixed(5)} ms (Target: < 0.01 ms)`);
    expect(avgTokenMs).toBeLessThan(0.01);
  });

  it('measures memory footprint under 1,000-event notification storm (< 25 MB heap delta)', () => {
    if (global.gc) {
      global.gc();
    }

    const heapBefore = process.memoryUsage().heapUsed;
    const service = new NotificationService({
      maxInboxSize: 1000,
      toastDispatcher: () => true
    });

    for (let i = 0; i < 1000; i++) {
      service.notify({
        title: `Storm Alert ${i}`,
        message: `High velocity threat blocked ${i}`,
        category: 'SECURITY_ALERT',
        severity: 'high'
      });
    }

    const inboxState = service.getInboxState();
    expect(inboxState.totalCount).toBe(1000);
    expect(inboxState.unreadCount).toBe(1000);

    const heapAfter = process.memoryUsage().heapUsed;
    const heapDeltaMb = (heapAfter - heapBefore) / (1024 * 1024);

    console.log(`[PERF] 1,000 Notification Storm Heap Delta: ${heapDeltaMb.toFixed(2)} MB (Limit: < 25 MB)`);
    expect(heapDeltaMb).toBeLessThan(25);
  });
});
