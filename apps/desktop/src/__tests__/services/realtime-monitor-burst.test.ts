import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';

describe('RealtimeMonitorService — Category 13 Real-Time Burst Suite', () => {
  let monitor: RealtimeMonitorService;
  let quarantine: QuarantineService;
  let workDir: string;
  let watchDir: string;
  let vaultDir: string;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-rt-burst-'));
    watchDir = path.join(workDir, 'watch');
    vaultDir = path.join(workDir, 'vault');
    fs.mkdirSync(watchDir, { recursive: true });
    fs.mkdirSync(vaultDir, { recursive: true });

    quarantine = new QuarantineService(vaultDir);
    monitor = new RealtimeMonitorService(
      {
        recursive: true,
        debounceMs: 5,
        stabilityCheckMs: 0,
        stabilityRetries: 1,
        autoQuarantineCritical: true,
        maxQueueSize: 10000,
        concurrencyLimit: 8
      },
      quarantine
    );
  });

  afterEach(() => {
    monitor.stop();
    if (fs.existsSync(workDir)) {
      try {
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup
      }
    }
  });

  // ============================================================
  // 1. EVENT DEDUPLICATION & COALESCING
  // ============================================================
  it('coalesces rapid multi-block writes to the same file into a single evaluation', async () => {
    monitor.start([watchDir]);

    let evaluatedCount = 0;
    monitor.on('fileScanned', () => {
      evaluatedCount++;
    });

    const targetFile = path.join(watchDir, 'growing_file.dat');

    // Simulate 20 rapid chunks written to the same file
    for (let i = 0; i < 20; i++) {
      fs.appendFileSync(targetFile, `Chunk ${i} of data...\n`);
    }

    // Wait for debounce and processing (polling to withstand heavy CPU load)
    const startWait = Date.now();
    while (evaluatedCount === 0 && Date.now() - startWait < 800) {
      await new Promise((r) => setTimeout(r, 20));
    }
    // Small buffer to ensure no duplicate event fires
    await new Promise((r) => setTimeout(r, 50));

    // Must be coalesced to 1 scan instead of 20
    expect(evaluatedCount).toBe(1);
  });

  // ============================================================
  // 2. BACKPRESSURE ENFORCEMENT & OVERFLOW
  // ============================================================
  it('enforces maxQueueSize boundary, emits backpressure warning, and maintains memory bounds', async () => {
    // Configure monitor with a small maxQueueSize to test backpressure trigger
    const smallQueueMonitor = new RealtimeMonitorService({
      recursive: true,
      maxQueueSize: 50,
      concurrencyLimit: 1
    });

    smallQueueMonitor.start([watchDir]);

    let backpressureFired = false;
    smallQueueMonitor.on('backpressure', (info) => {
      backpressureFired = true;
      expect(info.queueSize).toBeGreaterThanOrEqual(50);
    });

    // Flood the queue with 100 rapid file creations
    for (let i = 0; i < 100; i++) {
      const p = path.join(watchDir, `flood_${i}.txt`);
      fs.writeFileSync(p, `Flood payload ${i}\n`);
      smallQueueMonitor.enqueueFile(p, false);
    }

    await new Promise((r) => setTimeout(r, 150));

    smallQueueMonitor.stop();
    expect(backpressureFired).toBe(true);

    const stats = smallQueueMonitor.getQueueStats();
    expect(stats.droppedEventsCount).toBeGreaterThan(0);
  });

  // ============================================================
  // 3. 1,000 RAPID FILE BURST & ZERO DROPPED THREATS
  // ============================================================
  it('handles 1,000 rapid file events with bounded RSS (<200 MB) and zero dropped threats', async () => {
    monitor.start([watchDir]);

    const detectedThreats: DetectedThreat[] = [];
    monitor.on('threatDetected', (threat) => {
      detectedThreats.push(threat);
    });

    // Prepare 1,000 files:
    // 995 benign text files + 5 interspersed critical double-extension malware files
    const totalFiles = 1000;
    const threatIndices = new Set([100, 300, 500, 700, 900]);

    const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000', 'hex');
    const evilPayload = Buffer.from('powershell.exe -EncodedCommand VirtualAlloc Mimikatz', 'ascii');
    const threatBytes = Buffer.concat([mzHeader, evilPayload]);

    const startTime = Date.now();

    // Create 1,000 files and enqueue into priority queue
    for (let i = 0; i < totalFiles; i++) {
      if (threatIndices.has(i)) {
        const threatPath = path.join(watchDir, `burst_invoice_${i}.pdf.exe`);
        fs.writeFileSync(threatPath, threatBytes);
        monitor.enqueueFile(threatPath, true);
      } else {
        const safePath = path.join(watchDir, `safe_doc_${i}.txt`);
        fs.writeFileSync(safePath, `Safe file content line ${i}\n`);
        monitor.enqueueFile(safePath, false);
      }
    }

    // Wait for queue processing (all 5 threats are high-priority)
    const timeoutAt = Date.now() + 15000;
    while (detectedThreats.length < 5 && Date.now() < timeoutAt) {
      await new Promise((r) => setTimeout(r, 50));
    }

    const durationMs = Date.now() - startTime;
    const memAfter = process.memoryUsage();
    const rssMB = memAfter.rss / (1024 * 1024);

    // 1. Zero dropped threat detections: exactly all 5 threats must be detected and auto-quarantined
    expect(detectedThreats.length).toBe(5);
    for (const threat of detectedThreats) {
      expect(threat.verdict).toBe('BLOCK');
      expect(threat.quarantined).toBe(true);
      expect(fs.existsSync(threat.filePath)).toBe(false); // Quarantined and unlinked from user disk
    }

    // 2. Memory bound: RSS must be strictly < 200 MB
    expect(rssMB).toBeLessThan(200);

    const stats = monitor.getQueueStats();
    expect(stats.threatsDetectedCount).toBe(5);
    expect(stats.quarantinedCount).toBe(5);

    console.log(
      `[Category 13 Burst Benchmark] 1,000 files processed in ${durationMs} ms | Detected threats: ${detectedThreats.length}/5 | RSS: ${rssMB.toFixed(2)} MB (Limit: <200 MB)`
    );
  }, 25000);
});
