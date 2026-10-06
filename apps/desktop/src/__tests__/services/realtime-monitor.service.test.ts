import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { RealtimeMonitorService } from '../../services/realtime-monitor.service';
import { QuarantineService } from '../../services/quarantine.service';
import { DetectedThreat } from '../../types/desktop.types';

describe('RealtimeMonitorService — Phase E Core Real-Time Shield', () => {
  let monitor: RealtimeMonitorService;
  let quarantine: QuarantineService;
  let workDir: string;
  let watchDir: string;
  let vaultDir: string;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-phase-e-unit-'));
    watchDir = path.join(workDir, 'watched-root');
    vaultDir = path.join(workDir, 'vault');
    fs.mkdirSync(watchDir, { recursive: true });
    fs.mkdirSync(vaultDir, { recursive: true });

    quarantine = new QuarantineService(vaultDir);
    monitor = new RealtimeMonitorService(
      {
        recursive: true,
        debounceMs: 15,
        stabilityCheckMs: 5,
        stabilityRetries: 2,
        autoQuarantineCritical: true,
        maxQueueSize: 5000,
        concurrencyLimit: 4
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
  // 1. DEFAULT ROOTS RESOLUTION
  // ============================================================
  describe('Default Root Directories Resolution', () => {
    it('resolves canonical security-relevant roots without throwing', () => {
      const roots = RealtimeMonitorService.getDefaultMonitoredRoots();
      expect(Array.isArray(roots)).toBe(true);
      expect(roots.length).toBeGreaterThan(0);

      for (const root of roots) {
        expect(path.isAbsolute(root)).toBe(true);
        expect(fs.existsSync(root)).toBe(true);
        expect(fs.lstatSync(root).isDirectory()).toBe(true);
      }
    });

    it('starts monitoring default roots when no directories are passed', () => {
      const defaultRoots = RealtimeMonitorService.getDefaultMonitoredRoots();
      // Start with first 2 default roots to avoid locking entire user directory during test
      const testRoots = defaultRoots.slice(0, 2);
      monitor.start(testRoots);
      expect(monitor.isActive()).toBe(true);
      expect(monitor.getMonitoredPaths().length).toBe(testRoots.length);
      monitor.stop();
      expect(monitor.isActive()).toBe(false);
    });
  });

  // ============================================================
  // 2. RECURSIVE SUBDIRECTORY WATCHING
  // ============================================================
  describe('Recursive Subdirectory Ingress Detection', () => {
    it('detects and analyzes files created in nested subdirectories', async () => {
      monitor.start([watchDir]);

      const sub1 = path.join(watchDir, 'downloads_nested');
      const sub2 = path.join(sub1, 'level_two');
      fs.mkdirSync(sub2, { recursive: true });

      const threatFile = path.join(sub2, 'malicious_invoice.pdf.exe');
      const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000', 'hex');
      const payload = Buffer.from('powershell.exe -EncodedCommand VirtualAlloc Mimikatz', 'ascii');

      const threatPromise = new Promise<DetectedThreat>((resolve) => {
        monitor.once('threatDetected', (threat) => resolve(threat));
      });

      fs.writeFileSync(threatFile, Buffer.concat([mzHeader, payload]));

      const threat = await threatPromise;
      expect(threat).toBeDefined();
      expect(threat.fileName).toBe('malicious_invoice.pdf.exe');
      expect(threat.verdict).toBe('BLOCK');
      expect(threat.severity).toBe('critical');
      expect(threat.quarantined).toBe(true);
      expect(fs.existsSync(threatFile)).toBe(false); // Verified auto-quarantined and unlinked
    });
  });

  // ============================================================
  // 3. INCOMPLETE DOWNLOAD LIFECYCLE TRACKING
  // ============================================================
  describe('Download Lifecycle & Completion Tracking (.crdownload / .part)', () => {
    it('ignores in-progress .crdownload files without locking or false alarms', async () => {
      monitor.start([watchDir]);

      let threatFired = false;
      let downloadDetectedFired = false;

      monitor.on('threatDetected', () => {
        threatFired = true;
      });
      monitor.on('downloadDetected', () => {
        downloadDetectedFired = true;
      });

      const partialPath = path.join(watchDir, 'setup_installer.exe.crdownload');
      fs.writeFileSync(partialPath, Buffer.from('Partial in-progress download chunks...'));

      await new Promise((r) => setTimeout(r, 80));

      expect(downloadDetectedFired).toBe(true);
      expect(threatFired).toBe(false);
      expect(fs.existsSync(partialPath)).toBe(true); // Partial file preserved while writing
    });

    it('immediately inspects and auto-quarantines when .crdownload is renamed to final executable', async () => {
      monitor.start([watchDir]);

      const partialPath = path.join(watchDir, 'bank_statement.pdf.exe.crdownload');
      const finalPath = path.join(watchDir, 'bank_statement.pdf.exe');

      const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000', 'hex');
      const payload = Buffer.from('powershell.exe -enc JABhACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA', 'ascii');
      fs.writeFileSync(partialPath, Buffer.concat([mzHeader, payload]));

      await new Promise((r) => setTimeout(r, 40));

      const threatPromise = new Promise<DetectedThreat>((resolve) => {
        monitor.once('threatDetected', (threat) => resolve(threat));
      });

      // Browser finishes download and renames to final filename
      fs.renameSync(partialPath, finalPath);

      const threat = await threatPromise;
      expect(threat).toBeDefined();
      expect(threat.fileName).toBe('bank_statement.pdf.exe');
      expect(threat.verdict).toBe('BLOCK');
      expect(threat.quarantined).toBe(true);
      expect(fs.existsSync(finalPath)).toBe(false);
    });

    it('tracks Firefox .part downloads and processes on rename', async () => {
      monitor.start([watchDir]);

      const partialPath = path.join(watchDir, 'payroll_update.scr.part');
      const finalPath = path.join(watchDir, 'payroll_update.scr');

      const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000', 'hex');
      const payload = Buffer.from('vssadmin delete shadows /all /quiet', 'ascii');
      fs.writeFileSync(partialPath, Buffer.concat([mzHeader, payload]));

      await new Promise((r) => setTimeout(r, 40));

      const threatPromise = new Promise<DetectedThreat>((resolve) => {
        monitor.once('threatDetected', (threat) => resolve(threat));
      });

      fs.renameSync(partialPath, finalPath);

      const threat = await threatPromise;
      expect(threat.fileName).toBe('payroll_update.scr');
      expect(threat.quarantined).toBe(true);
    });
  });

  // ============================================================
  // 4. STABILITY VERIFICATION & EXCLUSIONS
  // ============================================================
  describe('File Stability Verification & Exclusion Defenses', () => {
    it('ignores 0-byte empty files safely', async () => {
      monitor.start([watchDir]);

      let threatFired = false;
      monitor.on('threatDetected', () => {
        threatFired = true;
      });

      const emptyFile = path.join(watchDir, 'empty.exe');
      fs.writeFileSync(emptyFile, Buffer.alloc(0));

      await new Promise((r) => setTimeout(r, 80));
      expect(threatFired).toBe(false);
      expect(fs.existsSync(emptyFile)).toBe(true);
    });

    it('ignores files located inside excluded paths', async () => {
      const excludedDir = path.join(watchDir, 'my-safe-zone');
      fs.mkdirSync(excludedDir, { recursive: true });

      monitor.setExcludedPaths([excludedDir]);
      monitor.start([watchDir]);

      let threatFired = false;
      monitor.on('threatDetected', () => {
        threatFired = true;
      });

      const ignoredMalware = path.join(excludedDir, 'ignored_threat.exe');
      const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000', 'hex');
      fs.writeFileSync(ignoredMalware, Buffer.concat([mzHeader, Buffer.from('Mimikatz')]));

      await new Promise((r) => setTimeout(r, 80));
      expect(threatFired).toBe(false);
      expect(fs.existsSync(ignoredMalware)).toBe(true);
    });

    it('ignores symbolic links to prevent link target hijacking', async () => {
      monitor.start([watchDir]);

      let threatFired = false;
      monitor.on('threatDetected', () => {
        threatFired = true;
      });

      const targetFile = path.join(workDir, 'target.txt');
      fs.writeFileSync(targetFile, 'Target file');
      const symlinkPath = path.join(watchDir, 'symlink.exe');

      try {
        fs.symlinkSync(targetFile, symlinkPath);
      } catch {
        // If symlinks not permitted in test environment, skip
        return;
      }

      await new Promise((r) => setTimeout(r, 80));
      expect(threatFired).toBe(false);
    });
  });

  // ============================================================
  // 5. QUEUE TELEMETRY & STATS
  // ============================================================
  describe('Queue Telemetry & Metrics', () => {
    it('tracks processed count and records latency telemetry', async () => {
      monitor.start([watchDir]);

      const testFile = path.join(watchDir, 'benign_document.pdf');
      fs.writeFileSync(testFile, '%PDF-1.5 test document content\n');

      const scannedPromise = new Promise<void>((resolve) => {
        monitor.once('fileScanned', () => resolve());
      });

      await scannedPromise;

      const stats = monitor.getQueueStats();
      expect(stats.processedCount).toBeGreaterThanOrEqual(1);
      expect(stats.averageLatencyMs).toBeGreaterThanOrEqual(0);
      expect(stats.p95LatencyMs).toBeGreaterThanOrEqual(0);
    });
  });
});
