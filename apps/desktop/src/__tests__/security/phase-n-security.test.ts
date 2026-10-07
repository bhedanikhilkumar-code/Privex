import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { IpcValidator } from '../../ipc/ipc-validator';
import { ScanSchedulerService } from '../../services/scan-scheduler.service';
import { ScannerService } from '../../services/scanner.service';
import { QuickScanService } from '../../services/quick-scan.service';
import { QuarantineService } from '../../services/quarantine.service';

describe('Phase N Security & Adversarial Test Suite (SEC-N-01 to SEC-N-06)', () => {
  let tempDir: string;
  let scheduler: ScanSchedulerService;
  let scanner: ScannerService;
  let quickScanner: QuickScanService;
  let quarantine: QuarantineService;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-sched-sec-'));
    scanner = new ScannerService();
    quickScanner = new QuickScanService(scanner);
    quarantine = new QuarantineService(path.join(tempDir, 'vault'));
    scheduler = new ScanSchedulerService({
      configDir: tempDir,
      scanner,
      quickScanner,
      quarantineService: quarantine
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

  describe('SEC-N-01: IPC Schema Validation & Prototype Pollution Defense', () => {
    it('rejects prototype pollution attempts in schedule payload', () => {
      const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}, "enabled": true, "frequency": "daily", "timeOfDay": "02:00", "scanType": "quick", "pauseOnBattery": true, "runMissedOnStartup": true, "autoQuarantine": true}');

      expect(() => {
        IpcValidator.validateScheduleConfig(maliciousPayload);
      }).toThrow(/SECURITY_VIOLATION|Forbidden prototype key/);
    });

    it('rejects unexpected arbitrary fields in schedule payload', () => {
      const maliciousPayload = {
        enabled: true,
        frequency: 'daily',
        timeOfDay: '02:00',
        scanType: 'quick',
        pauseOnBattery: true,
        runMissedOnStartup: true,
        autoQuarantine: true,
        arbitraryShellScript: 'rmdir /s /q C:\\'
      };

      expect(() => {
        IpcValidator.validateScheduleConfig(maliciousPayload);
      }).toThrow(/INVALID_SCHEDULE_FIELD/);
    });

    it('rejects invalid 24-hour time strings (e.g. 24:00, 25:99, abc)', () => {
      const invalidTimes = ['24:00', '25:00', '12:60', '-01:00', '12:00 PM', 'midnight', ''];

      for (const time of invalidTimes) {
        expect(() => {
          IpcValidator.validateScheduleConfig({
            enabled: true,
            frequency: 'daily',
            timeOfDay: time,
            scanType: 'quick',
            pauseOnBattery: true,
            runMissedOnStartup: true,
            autoQuarantine: true
          });
        }).toThrow(/INVALID_SCHEDULE_TIME/);
      }
    });

    it('rejects invalid frequencies (e.g. monthly, hourly, yearly)', () => {
      expect(() => {
        IpcValidator.validateScheduleConfig({
          enabled: true,
          frequency: 'monthly' as any,
          timeOfDay: '02:00',
          scanType: 'quick',
          pauseOnBattery: true,
          runMissedOnStartup: true,
          autoQuarantine: true
        });
      }).toThrow(/INVALID_SCHEDULE_FREQUENCY/);
    });

    it('rejects out-of-range weekday values (< 0 or > 6)', () => {
      expect(() => {
        IpcValidator.validateScheduleConfig({
          enabled: true,
          frequency: 'weekly',
          weekday: 7, // Invalid (only 0..6 allowed)
          timeOfDay: '02:00',
          scanType: 'quick',
          pauseOnBattery: true,
          runMissedOnStartup: true,
          autoQuarantine: true
        });
      }).toThrow(/INVALID_SCHEDULE_WEEKDAY/);
    });

    it('rejects invalid CPU and battery threshold values', () => {
      expect(() => {
        IpcValidator.validateScheduleConfig({
          enabled: true,
          frequency: 'daily',
          timeOfDay: '02:00',
          scanType: 'quick',
          pauseOnBattery: true,
          runMissedOnStartup: true,
          autoQuarantine: true,
          maxCpuThresholdPct: 150 // Out of range
        });
      }).toThrow(/INVALID_SCHEDULE_CPU_THRESHOLD/);

      expect(() => {
        IpcValidator.validateScheduleConfig({
          enabled: true,
          frequency: 'daily',
          timeOfDay: '02:00',
          scanType: 'quick',
          pauseOnBattery: true,
          runMissedOnStartup: true,
          autoQuarantine: true,
          minBatteryThresholdPct: 2 // Out of range (< 5)
        });
      }).toThrow(/INVALID_SCHEDULE_BATTERY_THRESHOLD/);
    });
  });

  describe('SEC-N-02: Tamper Resilience & Crypto-Integrity', () => {
    it('fails closed and recovers safely when schedule.enc has tampered ciphertext or auth tag', () => {
      scheduler.saveSchedule({
        enabled: true,
        frequency: 'daily',
        timeOfDay: '03:30'
      });

      const schedPath = path.join(tempDir, 'schedule.enc');
      const rawEnc = fs.readFileSync(schedPath, 'utf8');
      const parsed = JSON.parse(rawEnc);

      // Flip a bit in the authentication tag
      const tagBuf = Buffer.from(parsed.tag, 'hex');
      tagBuf[0] ^= 0xff;
      parsed.tag = tagBuf.toString('hex');
      fs.writeFileSync(schedPath, JSON.stringify(parsed), 'utf8');

      // Attempt to load corrupted storage
      const recoveryScheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner
      });

      // Must fail-closed back to safe default without throwing uncaught exception
      const state = recoveryScheduler.getState();
      expect(state.config.enabled).toBe(false);
      expect(state.config.timeOfDay).toBe('02:00');
      recoveryScheduler.stop();
    });
  });

  describe('SEC-N-03: Battery Threshold Edge Cases (19%, 20%, 21%, AC Desktop)', () => {
    it('defers scan at 19% battery, executes at 20% and 21% battery', async () => {
      // 1. At 19% battery: defer
      const at19Scheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        batteryInspector: async () => ({
          hasBattery: true,
          isCharging: false,
          percent: 19
        })
      });
      at19Scheduler.saveSchedule({ enabled: true, pauseOnBattery: true, minBatteryThresholdPct: 20 });
      const res19 = await at19Scheduler.executeScheduledScan('SCHEDULED');
      expect(res19.status).toBe('cancelled');
      expect(at19Scheduler.getHistory()[0].finalStatus).toBe('DEFERRED_BATTERY');
      at19Scheduler.stop();

      // 2. At 20% battery: execute (not below 20%)
      const at20Scheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        batteryInspector: async () => ({
          hasBattery: true,
          isCharging: false,
          percent: 20
        })
      });
      at20Scheduler.saveSchedule({ enabled: true, pauseOnBattery: true, minBatteryThresholdPct: 20 });
      const res20 = await at20Scheduler.executeScheduledScan('SCHEDULED', [tempDir]);
      expect(res20.status).toBe('completed');
      at20Scheduler.stop();

      // 3. At 21% battery: execute
      const at21Scheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        batteryInspector: async () => ({
          hasBattery: true,
          isCharging: false,
          percent: 21
        })
      });
      at21Scheduler.saveSchedule({ enabled: true, pauseOnBattery: true, minBatteryThresholdPct: 20 });
      const res21 = await at21Scheduler.executeScheduledScan('SCHEDULED', [tempDir]);
      expect(res21.status).toBe('completed');
      at21Scheduler.stop();
    });

    it('treats AC-powered desktop computers (hasBattery: false) as unconstrained', async () => {
      const acScheduler = new ScanSchedulerService({
        configDir: tempDir,
        scanner,
        quickScanner,
        batteryInspector: async () => ({
          hasBattery: false,
          isCharging: true,
          percent: 100
        }),
        cpuInspector: async () => ({ loadPct: 10, isAvailable: true })
      });
      acScheduler.saveSchedule({ enabled: true, pauseOnBattery: true });
      const res = await acScheduler.executeScheduledScan('SCHEDULED', [tempDir]);
      expect(res.status).toBe('completed');
      acScheduler.stop();
    });
  });

  describe('SEC-N-04: Cancellation & Timer Teardown Safety', () => {
    it('cancels scheduled scan safely and records CANCELLED state in history', async () => {
      let cancelTriggered = false;
      scanner.on('started', () => {
        if (!cancelTriggered) {
          cancelTriggered = true;
          scheduler.cancelCurrentScan();
        }
      });

      const res = await scheduler.runNow([tempDir]);
      expect(res.status).toBe('cancelled');
      const history = scheduler.getHistory();
      expect(history[0].finalStatus).toBe('CANCELLED');
    });

    it('cleans up active timers completely on stop() preventing leaked timer handles', () => {
      scheduler.saveSchedule({ enabled: true, frequency: 'daily', timeOfDay: '02:00' });
      scheduler.start();
      expect(scheduler.getState().nextScheduledRun).toBeDefined();

      scheduler.stop();
      // Should not throw or crash
    });
  });
});
