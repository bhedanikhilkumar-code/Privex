import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  ScanSchedulerService,
  DEFAULT_SCHEDULE_CONFIG
} from '../../services/scan-scheduler.service';
import { ScannerService } from '../../services/scanner.service';
import { QuickScanService } from '../../services/quick-scan.service';
import { QuarantineService } from '../../services/quarantine.service';
import { NotificationService } from '../../services/notification.service';
import { ScanScheduleConfig } from '../../types/desktop.types';

describe('ScanSchedulerService (Unit & Lifecycle Tests)', () => {
  let tempDir: string;
  let scheduler: ScanSchedulerService;
  let scanner: ScannerService;
  let quickScanner: QuickScanService;
  let quarantine: QuarantineService;
  let notificationService: NotificationService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-sched-unit-'));
    scanner = new ScannerService();
    quickScanner = new QuickScanService(scanner);
    quarantine = new QuarantineService(path.join(tempDir, 'vault'));
    notificationService = new NotificationService({
      storageDir: tempDir
    });

    scheduler = new ScanSchedulerService({
      configDir: tempDir,
      scanner,
      quickScanner,
      quarantineService: quarantine,
      notificationService
    });
  });

  afterEach(() => {
    scheduler.stop();
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best-effort
    }
  });

  describe('1. Configuration & Persistence', () => {
    it('initializes with safe default configuration', () => {
      const state = scheduler.getState();
      expect(state.config.enabled).toBe(false);
      expect(state.config.frequency).toBe('daily');
      expect(state.config.timeOfDay).toBe('02:00');
      expect(state.config.scanType).toBe('quick');
      expect(state.config.pauseOnBattery).toBe(true);
      expect(state.config.runMissedOnStartup).toBe(true);
      expect(state.config.autoQuarantine).toBe(true);
      expect(state.isRunning).toBe(false);
    });

    it('saves and securely reloads schedule configuration across restarts', () => {
      const updated: Partial<ScanScheduleConfig> = {
        enabled: true,
        frequency: 'weekly',
        weekday: 3, // Wednesday
        timeOfDay: '04:30',
        scanType: 'full',
        maxCpuThresholdPct: 75,
        minBatteryThresholdPct: 25
      };

      scheduler.saveSchedule(updated);

      // Create new instance on same storage directory
      const reloaded = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner
      });

      const state = reloaded.getState();
      expect(state.config.enabled).toBe(true);
      expect(state.config.frequency).toBe('weekly');
      expect(state.config.weekday).toBe(3);
      expect(state.config.timeOfDay).toBe('04:30');
      expect(state.config.scanType).toBe('full');
      expect(state.config.maxCpuThresholdPct).toBe(75);
      expect(state.config.minBatteryThresholdPct).toBe(25);
      reloaded.stop();
    });

    it('recovers gracefully to default configuration if persisted file is corrupted', () => {
      const schedPath = path.join(tempDir, 'schedule.enc');
      fs.writeFileSync(schedPath, 'CORRUPTED_NON_JSON_DATA', 'utf8');

      const recoveryScheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner
      });

      const state = recoveryScheduler.getState();
      expect(state.config.enabled).toBe(false);
      expect(state.config.frequency).toBe('daily');
      recoveryScheduler.stop();
    });
  });

  describe('2. Timezone & DST-Safe Next Run Calculation', () => {
    it('calculates next daily run correctly when target time is in the future today', () => {
      const baseDate = new Date(2026, 9, 7, 10, 0, 0, 0); // Oct 7, 2026, 10:00 AM
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        frequency: 'daily',
        timeOfDay: '14:30' // 2:30 PM today
      };

      const nextRun = scheduler.calculateNextRun(config, baseDate.getTime());
      const nextDate = new Date(nextRun);

      expect(nextDate.getFullYear()).toBe(2026);
      expect(nextDate.getMonth()).toBe(9);
      expect(nextDate.getDate()).toBe(7); // same day
      expect(nextDate.getHours()).toBe(14);
      expect(nextDate.getMinutes()).toBe(30);
    });

    it('calculates next daily run for tomorrow when target time has already passed today', () => {
      const baseDate = new Date(2026, 9, 7, 16, 0, 0, 0); // Oct 7, 2026, 4:00 PM
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        frequency: 'daily',
        timeOfDay: '02:00' // 2:00 AM (already passed)
      };

      const nextRun = scheduler.calculateNextRun(config, baseDate.getTime());
      const nextDate = new Date(nextRun);

      expect(nextDate.getFullYear()).toBe(2026);
      expect(nextDate.getMonth()).toBe(9);
      expect(nextDate.getDate()).toBe(8); // tomorrow
      expect(nextDate.getHours()).toBe(2);
      expect(nextDate.getMinutes()).toBe(0);
    });

    it('calculates next weekly run correctly for a future day of week', () => {
      // Wednesday, Oct 7, 2026 (day 3)
      const baseDate = new Date(2026, 9, 7, 10, 0, 0, 0);
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        frequency: 'weekly',
        weekday: 5, // Friday (day 5)
        timeOfDay: '03:00'
      };

      const nextRun = scheduler.calculateNextRun(config, baseDate.getTime());
      const nextDate = new Date(nextRun);

      expect(nextDate.getDate()).toBe(9); // Friday Oct 9
      expect(nextDate.getDay()).toBe(5);
      expect(nextDate.getHours()).toBe(3);
      expect(nextDate.getMinutes()).toBe(0);
    });

    it('calculates next weekly run for next week when same day time has passed', () => {
      // Wednesday, Oct 7, 2026, 12:00 PM (day 3)
      const baseDate = new Date(2026, 9, 7, 12, 0, 0, 0);
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        frequency: 'weekly',
        weekday: 3, // Wednesday (today, but 04:00 has passed)
        timeOfDay: '04:00'
      };

      const nextRun = scheduler.calculateNextRun(config, baseDate.getTime());
      const nextDate = new Date(nextRun);

      expect(nextDate.getDate()).toBe(14); // Next Wednesday Oct 14
      expect(nextDate.getDay()).toBe(3);
      expect(nextDate.getHours()).toBe(4);
      expect(nextDate.getMinutes()).toBe(0);
    });
  });

  describe('3. Missed Scan Detection', () => {
    it('detects a missed daily scan correctly', () => {
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        runMissedOnStartup: true,
        frequency: 'daily',
        timeOfDay: '02:00'
      };

      // Last run was 2 days ago
      const lastRun = new Date(2026, 9, 5, 2, 0, 0, 0).getTime();
      const now = new Date(2026, 9, 7, 10, 0, 0, 0).getTime();

      const missed = scheduler.isMissedScan(config, lastRun, now);
      expect(missed).toBe(true);
    });

    it('returns false if scan was already executed for the current slot', () => {
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        runMissedOnStartup: true,
        frequency: 'daily',
        timeOfDay: '02:00'
      };

      // Last run was at 02:05 AM today
      const lastRun = new Date(2026, 9, 7, 2, 5, 0, 0).getTime();
      const now = new Date(2026, 9, 7, 10, 0, 0, 0).getTime();

      const missed = scheduler.isMissedScan(config, lastRun, now);
      expect(missed).toBe(false);
    });

    it('returns false if runMissedOnStartup is disabled', () => {
      const config: ScanScheduleConfig = {
        ...DEFAULT_SCHEDULE_CONFIG,
        enabled: true,
        runMissedOnStartup: false,
        frequency: 'daily',
        timeOfDay: '02:00'
      };

      const lastRun = new Date(2026, 9, 1, 2, 0, 0, 0).getTime();
      const now = new Date(2026, 9, 7, 10, 0, 0, 0).getTime();

      expect(scheduler.isMissedScan(config, lastRun, now)).toBe(false);
    });
  });

  describe('4. Resource Guards (Battery & CPU Load)', () => {
    it('defers scheduled scan when battery is low (< 20%) and discharging', async () => {
      const lowBatteryScheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        batteryInspector: async () => ({
          hasBattery: true,
          isCharging: false,
          percent: 14 // Low battery
        })
      });

      lowBatteryScheduler.saveSchedule({
        enabled: true,
        pauseOnBattery: true,
        minBatteryThresholdPct: 20
      });

      const result = await lowBatteryScheduler.executeScheduledScan('SCHEDULED');
      expect(result.status).toBe('cancelled');

      const history = lowBatteryScheduler.getHistory();
      expect(history.length).toBe(1);
      expect(history[0].finalStatus).toBe('DEFERRED_BATTERY');
      expect(history[0].deferredReason).toContain('Battery level is at 14%');

      lowBatteryScheduler.stop();
    });

    it('allows user-triggered manual scan even when battery is low', async () => {
      const lowBatteryScheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        batteryInspector: async () => ({
          hasBattery: true,
          isCharging: false,
          percent: 10
        })
      });

      const result = await lowBatteryScheduler.runNow([tempDir]);
      expect(result.status).toBe('completed');
      lowBatteryScheduler.stop();
    });

    it('defers scheduled scan when CPU load exceeds threshold (> 80%)', async () => {
      const highCpuScheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        cpuInspector: async () => ({
          loadPct: 88,
          isAvailable: true
        })
      });

      highCpuScheduler.saveSchedule({
        enabled: true,
        maxCpuThresholdPct: 80
      });

      const result = await highCpuScheduler.executeScheduledScan('SCHEDULED');
      expect(result.status).toBe('cancelled');

      const history = highCpuScheduler.getHistory();
      expect(history.length).toBe(1);
      expect(history[0].finalStatus).toBe('DEFERRED_CPU');
      expect(history[0].deferredReason).toContain('CPU load is at 88%');

      highCpuScheduler.stop();
    });
  });

  describe('5. Concurrency & Overlap Prevention', () => {
    it('skips scheduled scan with SKIPPED_ALREADY_RUNNING if a scan is already active', async () => {
      // Simulate active running scan in scanner
      vi.spyOn(scanner, 'getStatus').mockReturnValue('running');

      const result = await scheduler.executeScheduledScan('SCHEDULED');
      expect(result.status).toBe('cancelled');

      const history = scheduler.getHistory();
      expect(history.length).toBe(1);
      expect(history[0].finalStatus).toBe('SKIPPED_ALREADY_RUNNING');
      expect(history[0].deferredReason).toContain('Another scan is currently in progress');
    });
  });

  describe('6. History Recording & Capacity Limit', () => {
    it('records scan execution telemetry and limits history to MAX_HISTORY_RECORDS (100)', () => {
      for (let i = 0; i < 110; i++) {
        scheduler.recordHistory({
          scanId: `test-scan-${i}`,
          scanType: 'quick',
          trigger: 'SCHEDULED',
          startTime: Date.now() - 1000,
          completedAt: Date.now(),
          durationMs: 1000,
          totalFilesScanned: 50,
          totalBytesScanned: 10240,
          threatsFound: 0,
          threatsQuarantined: 0,
          skippedCount: 0,
          errorCount: 0,
          overallVerdict: 'ALLOW',
          finalStatus: 'COMPLETED'
        });
      }

      const history = scheduler.getHistory();
      expect(history.length).toBe(ScanSchedulerService.MAX_HISTORY_RECORDS);
      expect(history[0].scanId).toBe('test-scan-109');
    });
  });
});
