import { describe, it, expect } from 'vitest';
import { PersistenceCommandParser } from '../../core/persistence-command-parser';
import { WindowsRegistryReader } from '../../core/windows-registry-reader';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';

describe('Phase L Performance & Latency Benchmarks', () => {
  it('BM-L-01: Command-line parser latency benchmark (< 0.1 ms per parse)', () => {
    const sampleCommand = '"C:\\Program Files\\Example Vendor\\Application.exe" /autostart --minimized';

    // Warm-up
    for (let i = 0; i < 50; i++) {
      PersistenceCommandParser.parseCommandLine(sampleCommand);
    }

    const iterations = 500;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      PersistenceCommandParser.parseCommandLine(sampleCommand);
    }
    const elapsed = performance.now() - start;
    const meanLatency = elapsed / iterations;

    console.log(`[Benchmark BM-L-01] PersistenceCommandParser Mean Latency: ${meanLatency.toFixed(4)} ms`);
    expect(meanLatency).toBeLessThan(0.1); // < 100 microseconds
  });

  it('BM-L-02: Registry output parsing throughput (1,000 entries < 5 ms)', () => {
    let mockOutput = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n';
    for (let i = 0; i < 1000; i++) {
      mockOutput += `    App${i}    REG_SZ    "C:\\Program Files\\App${i}\\app.exe" /arg${i}\n`;
    }

    const reader = new WindowsRegistryReader();

    const start = performance.now();
    const entries = reader.parseRegOutput(
      mockOutput,
      'HKCU',
      'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      false
    );
    const duration = performance.now() - start;

    console.log(`[Benchmark BM-L-02] 1,000 Registry Entries Parse Time: ${duration.toFixed(3)} ms`);
    expect(entries.length).toBe(1000);
    expect(duration).toBeLessThan(5.0); // < 5 ms for 1000 items
  });

  it('BM-L-03: Full persistence audit latency (< 100 ms SLA)', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    OneDrive    REG_SZ    "C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background
    Discord    REG_SZ    C:\\Users\\User\\AppData\\Local\\Discord\\app.exe
`,
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    SecurityHealth    REG_SZ    C:\\Windows\\System32\\SecurityHealthSystray.exe
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(null, registryReader);

    const start = performance.now();
    const result = await auditor.auditStartupLocations({
      customDirs: []
    });
    const duration = performance.now() - start;

    console.log(`[Benchmark BM-L-03] Full Persistence Audit Latency: ${duration.toFixed(3)} ms`);
    expect(result.items.length).toBe(3);
    expect(duration).toBeLessThan(100.0);
  });

  it('BM-L-04: Memory footprint across 1,000 persistence audit cycles (< 20 MB delta)', async () => {
    const mockRegistry: Record<string, string> = {
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': `
    App1    REG_SZ    "C:\\Program Files\\App1.exe"
    App2    REG_SZ    "C:\\Program Files\\App2.exe"
`
    };

    const registryReader = new WindowsRegistryReader({ customRegistryOutput: mockRegistry });
    const auditor = new PersistenceAuditorService(null, registryReader);

    if (global.gc) global.gc();
    const memBefore = process.memoryUsage().heapUsed;

    for (let i = 0; i < 1000; i++) {
      await auditor.auditStartupLocations({ customDirs: [] });
    }

    if (global.gc) global.gc();
    const memAfter = process.memoryUsage().heapUsed;
    const deltaMb = (memAfter - memBefore) / (1024 * 1024);

    console.log(`[Benchmark BM-L-04] Heap Used Delta across 1,000 audits: ${deltaMb.toFixed(2)} MB`);
    expect(deltaMb).toBeLessThan(20.0);
  }, 15000);
});
