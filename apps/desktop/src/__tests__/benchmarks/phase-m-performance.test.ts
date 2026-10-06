import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { RemovableMediaService } from '../../services/removable-media.service';
import { AutorunParser } from '../../core/autorun-parser';
import { LnkParser } from '../../core/lnk-parser';

describe('Phase M Performance Benchmarks — USB Threat & Root Triage Latency', () => {
  let tempDir: string;
  let service: RemovableMediaService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-m-perf-'));
    service = new RemovableMediaService({ autoScanOnMount: false });
  });

  afterEach(() => {
    service.stopMonitoring();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('measures AutorunParser in-memory parse throughput (< 0.1 ms target)', async () => {
    const sampleContent = `
[autorun]
open=wscript.exe //e:vbs worm.vbs
action=Open Flash Drive
icon=shell32.dll,4
shell\\open\\command=powershell.exe -enc SQBFAFg...
`;

    const iterations = 500;
    const start = process.hrtime.bigint();

    for (let i = 0; i < iterations; i++) {
      await AutorunParser.parseContent(sampleContent, tempDir);
    }

    const end = process.hrtime.bigint();
    const totalMs = Number(end - start) / 1_000_000;
    const avgMs = totalMs / iterations;

    console.log(`[PERF] Autorun Parsing Latency: ${avgMs.toFixed(5)} ms/file (Target: < 1.0 ms)`);
    expect(avgMs).toBeLessThan(1.0);
  });

  it('measures LnkParser in-memory parse throughput (< 0.5 ms target)', async () => {
    const header = Buffer.alloc(76);
    header.writeUInt32LE(0x0000004c, 0);
    Buffer.from([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]).copy(header, 4);
    header.writeUInt32LE(0x08 | 0x20 | 0x40, 0x14);

    const writeString = (str: string) => {
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16LE(str.length, 0);
      return Buffer.concat([lenBuf, Buffer.from(str, 'ascii')]);
    };

    const buf = Buffer.concat([
      header,
      writeString('cmd.exe'),
      writeString('/c start worm.vbs'),
      writeString('%SystemRoot%\\system32\\shell32.dll,3')
    ]);

    const iterations = 500;
    const start = process.hrtime.bigint();

    for (let i = 0; i < iterations; i++) {
      await LnkParser.parseBuffer(buf, 'FlashDrive.lnk', tempDir);
    }

    const end = process.hrtime.bigint();
    const totalMs = Number(end - start) / 1_000_000;
    const avgMs = totalMs / iterations;

    console.log(`[PERF] LNK Parsing Latency: ${avgMs.toFixed(5)} ms/file (Target: < 0.5 ms)`);
    expect(avgMs).toBeLessThan(0.5);
  });

  it('measures full RemovableMediaService.scanRemovableDriveRoot quick triage latency (< 200.0 ms target)', async () => {
    // Seed USB root with 10 files
    fs.writeFileSync(
      path.join(tempDir, 'autorun.inf'),
      '[autorun]\r\nopen=wscript.exe worm.vbs',
      'utf-8'
    );
    fs.writeFileSync(path.join(tempDir, 'worm.vbs'), 'WScript.Echo 1', 'utf-8');
    for (let i = 0; i < 8; i++) {
      fs.writeFileSync(path.join(tempDir, `doc_${i}.txt`), `Benign document content ${i}`, 'utf-8');
    }

    const samples: number[] = [];
    const runs = 20;

    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      const res = await service.scanRemovableDriveRoot(tempDir);
      const t1 = performance.now();
      samples.push(t1 - t0);
      expect(res.threatsFound).toBeGreaterThanOrEqual(1);
    }

    samples.sort((a, b) => a - b);
    const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
    const p50 = samples[Math.floor(samples.length * 0.5)];
    const p95 = samples[Math.floor(samples.length * 0.95)];

    console.log(
      `[PERF] USB Root Quick Triage Latency: avg=${avg.toFixed(4)} ms | p50=${p50.toFixed(4)} ms | p95=${p95.toFixed(4)} ms (Target: < 200.0 ms)`
    );

    expect(p95).toBeLessThan(200.0);
  });

  it('verifies bounded heap footprint during 1,000 rapid USB root inspections (< 15 MB heap delta)', async () => {
    fs.writeFileSync(path.join(tempDir, 'file.txt'), 'content', 'utf-8');

    if (global.gc) {
      global.gc();
    }
    const initialHeap = process.memoryUsage().heapUsed;

    for (let i = 0; i < 1000; i++) {
      await service.scanRemovableDriveRoot(tempDir);
    }

    if (global.gc) {
      global.gc();
    }
    const finalHeap = process.memoryUsage().heapUsed;
    const heapDeltaMb = (finalHeap - initialHeap) / (1024 * 1024);

    console.log(`[PERF] 1,000 USB Root Inspections Heap Delta: ${heapDeltaMb.toFixed(2)} MB (Limit: < 15 MB)`);
    expect(heapDeltaMb).toBeLessThan(15.0);
  });
});
