import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ScanProgressThrottler } from '../../core/scan-progress-throttler';
import { ScanProgress } from '../../types/desktop.types';

describe('ScanProgressThrottler (Phase P — 20 Hz IPC Rate Limiting)', () => {
  let emittedEvents: ScanProgress[] = [];
  let throttler: ScanProgressThrottler;

  const createSampleProgress = (filesScanned: number): ScanProgress => ({
    scanId: 'scan-123',
    scanType: 'full',
    status: 'running',
    filesScanned,
    threatsFound: 0,
    currentPath: `C:\\files\\item_${filesScanned}.txt`,
    bytesScanned: filesScanned * 1024,
    skippedCount: 0,
    errorCount: 0,
    startTime: Date.now() - 1000,
    elapsedMs: 1000,
    scanSpeedFilesPerSec: 100
  });

  beforeEach(() => {
    vi.useFakeTimers();
    emittedEvents = [];
    throttler = new ScanProgressThrottler(
      (progress) => emittedEvents.push(progress),
      { intervalMs: 50 } // 20 Hz cap
    );
  });

  afterEach(() => {
    throttler.dispose();
    vi.useRealTimers();
  });

  it('1. emits the very first progress event immediately for instant UI feedback', () => {
    throttler.push(createSampleProgress(1));
    expect(emittedEvents.length).toBe(1);
    expect(emittedEvents[0].filesScanned).toBe(1);
  });

  it('2. coalesces 10,000 rapid progress pushes within 50 ms down to 1 event', () => {
    for (let i = 1; i <= 10000; i++) {
      throttler.push(createSampleProgress(i));
    }

    // Only the first event should have fired immediately
    expect(emittedEvents.length).toBe(1);
    expect(emittedEvents[0].filesScanned).toBe(1);
    expect(throttler.getSuppressedCount()).toBe(9999);

    // Advance timer by 50 ms: delayed flush fires with the latest state (10,000)
    vi.advanceTimersByTime(50);
    expect(emittedEvents.length).toBe(2);
    expect(emittedEvents[1].filesScanned).toBe(10000);
  });

  it('3. guarantees final state is always delivered immediately upon flush()', () => {
    throttler.push(createSampleProgress(1));
    throttler.push(createSampleProgress(50));
    throttler.push(createSampleProgress(100));

    expect(emittedEvents.length).toBe(1);

    // Call flush immediately (e.g. before scan completion)
    throttler.flush();
    expect(emittedEvents.length).toBe(2);
    expect(emittedEvents[1].filesScanned).toBe(100);
  });

  it('4. emits steadily at max 20 Hz when updates are pushed continuously', () => {
    // 200 ms total duration
    for (let step = 0; step < 20; step++) {
      throttler.push(createSampleProgress(step * 10));
      vi.advanceTimersByTime(10); // 10ms intervals (100 Hz input rate)
    }

    // In 200 ms, 50ms interval allows at most ~4-5 events (20 Hz)
    expect(emittedEvents.length).toBeLessThanOrEqual(5);
    expect(emittedEvents.length).toBeGreaterThanOrEqual(4);
  });

  it('5. preserves latest progress state when multiple updates arrive during cooldown', () => {
    throttler.push(createSampleProgress(1)); // Immediate
    throttler.push(createSampleProgress(2));
    throttler.push(createSampleProgress(3));
    throttler.push(createSampleProgress(4));

    vi.advanceTimersByTime(50);

    expect(emittedEvents.length).toBe(2);
    expect(emittedEvents[1].filesScanned).toBe(4);
  });

  it('6. cleans up timers and pending state cleanly on dispose()', () => {
    throttler.push(createSampleProgress(1));
    throttler.push(createSampleProgress(2));

    throttler.dispose();
    vi.advanceTimersByTime(100);

    // No secondary event should fire after disposal
    expect(emittedEvents.length).toBe(1);
  });
});
