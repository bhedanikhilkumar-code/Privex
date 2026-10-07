import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScanSchedulerService } from '../../services/scan-scheduler.service';
import { ScannerService } from '../../services/scanner.service';
import { QuickScanService } from '../../services/quick-scan.service';
import { QuarantineService } from '../../services/quarantine.service';
import { NotificationService } from '../../services/notification.service';
import { PersistenceAuditorService } from '../../services/persistence-auditor.service';
import { ProcessAuditorService } from '../../services/process-auditor.service';

describe('Phase N Integration Suite — Scheduled & On-Demand Scanning End-to-End', () => {
  let tempDir: string;
  let vaultDir: string;
  let stagingDir: string;
  let scanner: ScannerService;
  let quickScanner: QuickScanService;
  let quarantine: QuarantineService;
  let notificationService: NotificationService;
  let persistenceAuditor: PersistenceAuditorService;
  let processAuditor: ProcessAuditorService;
  let scheduler: ScanSchedulerService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-sched-integ-'));
    vaultDir = path.join(tempDir, 'vault');
    stagingDir = path.join(tempDir, 'staging');
    fs.mkdirSync(stagingDir, { recursive: true });

    scanner = new ScannerService();
    quarantine = new QuarantineService(vaultDir);
    notificationService = new NotificationService({
      storageDir: tempDir
    });

    persistenceAuditor = new PersistenceAuditorService(quarantine);

    processAuditor = new ProcessAuditorService({
      processQueryProvider: async () => []
    });

    quickScanner = new QuickScanService({
      scanner,
      processAuditor,
      persistenceAuditor
    });

    scheduler = new ScanSchedulerService({
      configDir: tempDir,
      scanner,
      quickScanner,
      quarantineService: quarantine,
      notificationService,
      processAuditor,
      persistenceAuditor,
      batteryInspector: async () => ({ hasBattery: false, isCharging: true, percent: 100 }),
      cpuInspector: async () => ({ loadPct: 10, isAvailable: true })
    });
  });

  afterEach(() => {
    scheduler.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('runs end-to-end scheduled scan, detects synthetic malware, auto-quarantines to PPVAULT2, and dispatches notifications', async () => {
    // 1. Create a synthetic malware file in the staging directory (RTLO double extension spoofing)
    const spoofedMalware = path.join(stagingDir, 'urgent_invoice\u202Efdp.exe');
    fs.writeFileSync(spoofedMalware, 'MZ_DANGEROUS_SPOOFED_BINARY_PAYLOAD');

    // 2. Configure and trigger scheduled scan with autoQuarantine enabled
    scheduler.saveSchedule({
      enabled: true,
      frequency: 'daily',
      timeOfDay: '02:00',
      scanType: 'quick',
      autoQuarantine: true
    });

    const scanResult = await scheduler.executeScheduledScan('SCHEDULED', [stagingDir]);

    // 3. Verify scan findings
    expect(scanResult.status).toBe('completed');
    expect(scanResult.threats.length).toBeGreaterThanOrEqual(1);

    const detected = scanResult.threats.find((t) => t.fileName.includes('urgent_invoice'));
    expect(detected).toBeDefined();
    expect(detected?.quarantined).toBe(true);

    // 4. Verify original malicious file was removed from disk and isolated into PPVAULT2
    expect(fs.existsSync(spoofedMalware)).toBe(false);
    const quarantineList = quarantine.listQuarantine();
    expect(quarantineList.length).toBeGreaterThanOrEqual(1);
    expect(quarantineList.some((q) => q.originalPath.includes('urgent_invoice'))).toBe(true);

    // 5. Verify history record
    const history = scheduler.getHistory();
    expect(history.length).toBe(1);
    expect(history[0].finalStatus).toBe('COMPLETED_WITH_FINDINGS');
    expect(history[0].threatsFound).toBeGreaterThanOrEqual(1);
    expect(history[0].threatsQuarantined).toBeGreaterThanOrEqual(1);

    // 6. Verify notification was recorded in inbox
    const inbox = notificationService.getInboxState();
    expect(inbox.totalCount).toBeGreaterThanOrEqual(1);
  });

  it('executes missed-scan catch-up on service startup when previous scheduled scan was missed', async () => {
    // Save schedule configuration with missed run timestamp (e.g. yesterday)
    const yesterday = Date.now() - 26 * 60 * 60 * 1000;
    scheduler.saveSchedule({
      enabled: true,
      frequency: 'daily',
      timeOfDay: '02:00',
      runMissedOnStartup: true
    });

    // Manually simulate a missed lastScheduledRun in storage payload
    const schedPath = path.join(tempDir, 'schedule.enc');
    const rawEnc = fs.readFileSync(schedPath, 'utf8');
    const parsed = JSON.parse((scheduler as any).decrypt(rawEnc));
    parsed.lastScheduledRun = yesterday;
    fs.writeFileSync(schedPath, (scheduler as any).encrypt(JSON.stringify(parsed)), 'utf8');

    // Create fresh instance simulating app restart
    const restartedScheduler = new ScanSchedulerService({
      configDir: tempDir,
      scanner,
      quickScanner,
      quarantineService: quarantine,
      notificationService,
      batteryInspector: async () => ({ hasBattery: false, isCharging: true, percent: 100 }),
      cpuInspector: async () => ({ loadPct: 10, isAvailable: true })
    });

    let missedScanStarted = false;
    restartedScheduler.on('scheduledScanStarted', (info: any) => {
      if (info.trigger === 'MISSED_CATCHUP') {
        missedScanStarted = true;
      }
    });

    restartedScheduler.start();

    // Wait briefly for setImmediate catch-up dispatch
    await new Promise<void>((resolve) => setTimeout(resolve, 500));

    expect(missedScanStarted).toBe(true);
    restartedScheduler.stop();
  });
});
