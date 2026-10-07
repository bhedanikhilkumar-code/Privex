import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  ScanScheduleConfig,
  ScanHistoryRecord,
  ScanSchedulerState,
  ScanSchedulerOptions,
  ScheduleTrigger,
  ScheduleExecutionStatus,
  BatteryStatus,
  CpuLoadStatus,
  ScanResult
} from '../types/desktop.types';
import { ScannerService } from './scanner.service';
import { QuickScanService } from './quick-scan.service';
import { QuarantineService } from './quarantine.service';
import { NotificationService } from './notification.service';

export const DEFAULT_SCHEDULE_CONFIG: ScanScheduleConfig = {
  enabled: false,
  frequency: 'daily',
  timeOfDay: '02:00',
  weekday: 0, // Sunday
  scanType: 'quick',
  pauseOnBattery: true,
  runMissedOnStartup: true,
  autoQuarantine: true,
  maxCpuThresholdPct: 80,
  minBatteryThresholdPct: 20
};

export class ScanSchedulerService extends EventEmitter {
  private readonly configDir: string;
  private readonly schedulePath: string;
  private readonly historyPath: string;
  private readonly encryptionKey: Buffer;
  private readonly scanner: ScannerService;
  private readonly quickScanner: QuickScanService;
  private readonly quarantineService?: QuarantineService;
  private readonly notificationService?: NotificationService;
  private readonly customBatteryInspector?: () => Promise<BatteryStatus>;
  private readonly customCpuInspector?: () => Promise<CpuLoadStatus>;
  private readonly clock: () => number;

  private config: ScanScheduleConfig = { ...DEFAULT_SCHEDULE_CONFIG };
  private lastScheduledRun: number = 0;
  private lastSuccessfulRun: number = 0;
  private lastStatus?: ScheduleExecutionStatus;
  private nextScheduledRun?: number;
  private isScanRunning: boolean = false;
  private currentScanId?: string;
  private activeTimer: NodeJS.Timeout | null = null;
  private isStarted: boolean = false;

  private historyRecords: ScanHistoryRecord[] = [];
  public static readonly MAX_HISTORY_RECORDS = 100;

  constructor(options?: ScanSchedulerOptions) {
    super();
    this.configDir = path.resolve(
      options?.configDir || path.join(os.homedir(), '.private-protection')
    );
    this.schedulePath = path.join(this.configDir, 'schedule.enc');
    this.historyPath = path.join(this.configDir, 'scan-history.enc');
    this.scanner = options?.scanner || new ScannerService();
    this.quickScanner =
      options?.quickScanner ||
      new QuickScanService({
        scanner: this.scanner,
        processAuditor: options?.processAuditor,
        persistenceAuditor: options?.persistenceAuditor
      });
    this.quarantineService = options?.quarantineService;
    this.notificationService = options?.notificationService;
    this.customBatteryInspector = options?.batteryInspector;
    this.customCpuInspector = options?.cpuInspector;
    this.clock = options?.clock || (() => Date.now());

    this.encryptionKey = this.deriveEncryptionKey();
    this.initStorage();
    this.loadSchedule();
    this.loadHistory();
  }

  private initStorage(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
  }

  private deriveEncryptionKey(): Buffer {
    this.initStorage();
    const saltPath = path.join(this.configDir, '.storage.salt');
    let salt: Buffer | null = null;

    if (fs.existsSync(saltPath)) {
      try {
        const loaded = fs.readFileSync(saltPath);
        if (loaded.length >= 16) salt = loaded;
      } catch {
        salt = null;
      }
    }

    if (!salt) {
      salt = crypto.randomBytes(32);
      const tmpPath = `${saltPath}.tmp`;
      fs.writeFileSync(tmpPath, salt, { mode: 0o600 });
      try {
        fs.renameSync(tmpPath, saltPath);
      } catch {
        try {
          fs.copyFileSync(tmpPath, saltPath);
          fs.unlinkSync(tmpPath);
        } catch {
          // best-effort
        }
      }
    }

    const machineSecret = `${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}`;
    return crypto.pbkdf2Sync(machineSecret, salt, 100000, 32, 'sha256');
  }

  private encrypt(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return JSON.stringify({
      iv: iv.toString('hex'),
      tag: authTag.toString('hex'),
      data: encrypted.toString('hex')
    });
  }

  private decrypt(payloadStr: string): string {
    const parsed = JSON.parse(payloadStr);
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      typeof parsed.iv !== 'string' ||
      typeof parsed.tag !== 'string' ||
      typeof parsed.data !== 'string'
    ) {
      throw new Error('CORRUPT_ENCRYPTED_PAYLOAD');
    }
    const iv = Buffer.from(parsed.iv, 'hex');
    const authTag = Buffer.from(parsed.tag, 'hex');
    if (iv.length !== 12 || authTag.length !== 16) {
      throw new Error('INVALID_GCM_PARAMETERS');
    }
    const encrypted = Buffer.from(parsed.data, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final('utf8');
  }

  private writeAtomicFileSync(targetPath: string, content: string): void {
    this.initStorage();
    const tmpPath = `${targetPath}.tmp`;
    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
      fs.writeFileSync(fd, content, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.renameSync(tmpPath, targetPath);
    } catch {
      try {
        fs.copyFileSync(tmpPath, targetPath);
        fs.unlinkSync(tmpPath);
      } catch (err: any) {
        throw new Error(`ATOMIC_WRITE_FAILED: Failed to replace '${targetPath}': ${err.message}`);
      }
    }
  }

  // ============================================================
  // PERSISTENCE METHODS
  // ============================================================

  public loadSchedule(): ScanScheduleConfig {
    if (!fs.existsSync(this.schedulePath)) {
      this.config = { ...DEFAULT_SCHEDULE_CONFIG };
      this.saveSchedule(this.config);
      return this.config;
    }

    try {
      const rawEnc = fs.readFileSync(this.schedulePath, 'utf8');
      const decrypted = this.decrypt(rawEnc);
      const parsed = JSON.parse(decrypted);

      this.config = this.sanitizeLoadedConfig(parsed.config);
      this.lastScheduledRun = typeof parsed.lastScheduledRun === 'number' ? parsed.lastScheduledRun : 0;
      this.lastSuccessfulRun = typeof parsed.lastSuccessfulRun === 'number' ? parsed.lastSuccessfulRun : 0;
      this.lastStatus = parsed.lastStatus;
      this.recalculateNextRun();
      return this.config;
    } catch {
      // Fallback safely to defaults on corruption
      this.config = { ...DEFAULT_SCHEDULE_CONFIG };
      this.recalculateNextRun();
      return this.config;
    }
  }

  public saveSchedule(newConfig: Partial<ScanScheduleConfig>): ScanScheduleConfig {
    const validated = this.sanitizeLoadedConfig({ ...this.config, ...newConfig });
    this.config = validated;
    this.recalculateNextRun();

    const payload = JSON.stringify({
      config: this.config,
      lastScheduledRun: this.lastScheduledRun,
      lastSuccessfulRun: this.lastSuccessfulRun,
      lastStatus: this.lastStatus,
      updatedAt: this.clock()
    });

    const encrypted = this.encrypt(payload);
    this.writeAtomicFileSync(this.schedulePath, encrypted);

    // Write backup copy for crash resilience
    try {
      this.writeAtomicFileSync(`${this.schedulePath}.bak`, encrypted);
    } catch {
      // Non-blocking backup
    }

    if (this.isStarted) {
      this.armTimer();
    }

    this.emit('scheduleUpdated', this.getState());
    return this.config;
  }

  private sanitizeLoadedConfig(raw: unknown): ScanScheduleConfig {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { ...DEFAULT_SCHEDULE_CONFIG };
    }
    const obj = raw as Record<string, unknown>;

    const enabled = typeof obj.enabled === 'boolean' ? obj.enabled : DEFAULT_SCHEDULE_CONFIG.enabled;
    const frequency = obj.frequency === 'weekly' ? 'weekly' : 'daily';

    let timeOfDay = '02:00';
    if (typeof obj.timeOfDay === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(obj.timeOfDay.trim())) {
      timeOfDay = obj.timeOfDay.trim();
    }

    let weekday = 0;
    if (typeof obj.weekday === 'number' && Number.isInteger(obj.weekday) && obj.weekday >= 0 && obj.weekday <= 6) {
      weekday = obj.weekday;
    }

    const scanType = obj.scanType === 'full' ? 'full' : 'quick';
    const pauseOnBattery = typeof obj.pauseOnBattery === 'boolean' ? obj.pauseOnBattery : DEFAULT_SCHEDULE_CONFIG.pauseOnBattery;
    const runMissedOnStartup = typeof obj.runMissedOnStartup === 'boolean' ? obj.runMissedOnStartup : DEFAULT_SCHEDULE_CONFIG.runMissedOnStartup;
    const autoQuarantine = typeof obj.autoQuarantine === 'boolean' ? obj.autoQuarantine : DEFAULT_SCHEDULE_CONFIG.autoQuarantine;

    let maxCpuThresholdPct = 80;
    if (typeof obj.maxCpuThresholdPct === 'number' && Number.isFinite(obj.maxCpuThresholdPct)) {
      maxCpuThresholdPct = Math.min(100, Math.max(10, Math.floor(obj.maxCpuThresholdPct)));
    }

    let minBatteryThresholdPct = 20;
    if (typeof obj.minBatteryThresholdPct === 'number' && Number.isFinite(obj.minBatteryThresholdPct)) {
      minBatteryThresholdPct = Math.min(100, Math.max(5, Math.floor(obj.minBatteryThresholdPct)));
    }

    return {
      enabled,
      frequency,
      timeOfDay,
      weekday,
      scanType,
      pauseOnBattery,
      runMissedOnStartup,
      autoQuarantine,
      maxCpuThresholdPct,
      minBatteryThresholdPct
    };
  }

  private loadHistory(): void {
    if (!fs.existsSync(this.historyPath)) {
      this.historyRecords = [];
      return;
    }

    try {
      const rawEnc = fs.readFileSync(this.historyPath, 'utf8');
      const decrypted = this.decrypt(rawEnc);
      const parsed = JSON.parse(decrypted);
      if (Array.isArray(parsed)) {
        this.historyRecords = parsed.slice(0, ScanSchedulerService.MAX_HISTORY_RECORDS);
      }
    } catch {
      this.historyRecords = [];
    }
  }

  private saveHistory(): void {
    try {
      const payload = JSON.stringify(this.historyRecords);
      const encrypted = this.encrypt(payload);
      this.writeAtomicFileSync(this.historyPath, encrypted);
    } catch {
      // Non-blocking history save
    }
  }

  public recordHistory(record: ScanHistoryRecord): void {
    this.historyRecords.unshift(record);
    if (this.historyRecords.length > ScanSchedulerService.MAX_HISTORY_RECORDS) {
      this.historyRecords = this.historyRecords.slice(0, ScanSchedulerService.MAX_HISTORY_RECORDS);
    }
    this.saveHistory();
  }

  public getHistory(): ScanHistoryRecord[] {
    return [...this.historyRecords];
  }

  // ============================================================
  // SCHEDULE CALCULATION (TIMEZONE & DST AWARE)
  // ============================================================

  public calculateNextRun(config: ScanScheduleConfig, fromTimestamp: number): number {
    if (!config || !config.timeOfDay) {
      return fromTimestamp + 24 * 60 * 60 * 1000;
    }

    const parts = config.timeOfDay.split(':').map(Number);
    const targetHour = Number.isFinite(parts[0]) ? parts[0] : 2;
    const targetMinute = Number.isFinite(parts[1]) ? parts[1] : 0;

    const fromDate = new Date(fromTimestamp);

    if (config.frequency === 'daily') {
      const candidate = new Date(
        fromDate.getFullYear(),
        fromDate.getMonth(),
        fromDate.getDate(),
        targetHour,
        targetMinute,
        0,
        0
      );

      if (candidate.getTime() <= fromTimestamp) {
        candidate.setDate(candidate.getDate() + 1);
      }
      return candidate.getTime();
    } else {
      // Weekly schedule
      const targetWeekday = typeof config.weekday === 'number' ? config.weekday : 0;
      const currentWeekday = fromDate.getDay();

      let dayDelta = (targetWeekday - currentWeekday + 7) % 7;

      const candidate = new Date(
        fromDate.getFullYear(),
        fromDate.getMonth(),
        fromDate.getDate() + dayDelta,
        targetHour,
        targetMinute,
        0,
        0
      );

      if (candidate.getTime() <= fromTimestamp) {
        candidate.setDate(candidate.getDate() + 7);
      }
      return candidate.getTime();
    }
  }

  public recalculateNextRun(): number | undefined {
    if (!this.config.enabled) {
      this.nextScheduledRun = undefined;
      return undefined;
    }
    const next = this.calculateNextRun(this.config, this.clock());
    this.nextScheduledRun = next;
    return next;
  }

  public isMissedScan(
    config: ScanScheduleConfig,
    lastRunTimestamp: number,
    currentTimestamp: number
  ): boolean {
    if (!config.enabled || !config.runMissedOnStartup) {
      return false;
    }

    if (!lastRunTimestamp || lastRunTimestamp <= 0) {
      return false;
    }

    const parts = config.timeOfDay.split(':').map(Number);
    const targetHour = Number.isFinite(parts[0]) ? parts[0] : 2;
    const targetMinute = Number.isFinite(parts[1]) ? parts[1] : 0;

    const currDate = new Date(currentTimestamp);

    if (config.frequency === 'daily') {
      const todaySlot = new Date(
        currDate.getFullYear(),
        currDate.getMonth(),
        currDate.getDate(),
        targetHour,
        targetMinute,
        0,
        0
      ).getTime();

      let lastSlot = todaySlot;
      if (todaySlot > currentTimestamp) {
        // Last scheduled slot was yesterday
        const yesterday = new Date(currDate);
        yesterday.setDate(yesterday.getDate() - 1);
        lastSlot = new Date(
          yesterday.getFullYear(),
          yesterday.getMonth(),
          yesterday.getDate(),
          targetHour,
          targetMinute,
          0,
          0
        ).getTime();
      }

      return lastSlot > lastRunTimestamp;
    } else {
      // Weekly schedule
      const targetWeekday = typeof config.weekday === 'number' ? config.weekday : 0;
      const currentWeekday = currDate.getDay();

      let dayDelta = (currentWeekday - targetWeekday + 7) % 7;
      const recentWeeklyDate = new Date(currDate);
      recentWeeklyDate.setDate(recentWeeklyDate.getDate() - dayDelta);

      let lastSlot = new Date(
        recentWeeklyDate.getFullYear(),
        recentWeeklyDate.getMonth(),
        recentWeeklyDate.getDate(),
        targetHour,
        targetMinute,
        0,
        0
      ).getTime();

      if (lastSlot > currentTimestamp) {
        lastSlot -= 7 * 24 * 60 * 60 * 1000;
      }

      return lastSlot > lastRunTimestamp;
    }
  }

  // ============================================================
  // RESOURCE GUARDS: BATTERY & CPU LOAD
  // ============================================================

  public async checkBattery(): Promise<BatteryStatus> {
    if (this.customBatteryInspector) {
      return this.customBatteryInspector();
    }

    // Default inspection: On Windows desktop systems without battery,
    // hasBattery defaults to false (AC powered, unconstrained)
    return {
      hasBattery: false,
      isCharging: true,
      percent: 100
    };
  }

  public async checkCpu(): Promise<CpuLoadStatus> {
    if (this.customCpuInspector) {
      return this.customCpuInspector();
    }

    try {
      const cpus1 = os.cpus();
      if (!cpus1 || cpus1.length === 0) {
        return { loadPct: 0, isAvailable: false };
      }

      let idle1 = 0;
      let total1 = 0;
      for (const cpu of cpus1) {
        idle1 += cpu.times.idle;
        total1 += cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.idle + cpu.times.irq;
      }

      await new Promise<void>((resolve) => setTimeout(resolve, 80));

      const cpus2 = os.cpus();
      let idle2 = 0;
      let total2 = 0;
      for (const cpu of cpus2) {
        idle2 += cpu.times.idle;
        total2 += cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.idle + cpu.times.irq;
      }

      const idleDelta = idle2 - idle1;
      const totalDelta = total2 - total1;

      if (totalDelta <= 0) {
        return { loadPct: 0, isAvailable: true };
      }

      const busyRatio = Math.max(0, Math.min(1, 1 - idleDelta / totalDelta));
      const loadPct = Math.round(busyRatio * 100);

      return { loadPct, isAvailable: true };
    } catch {
      return { loadPct: 0, isAvailable: false };
    }
  }

  // ============================================================
  // LIFECYCLE & TIMER MANAGEMENT
  // ============================================================

  public start(): void {
    if (this.isStarted) return;
    this.isStarted = true;

    // Check for missed scan on startup if enabled
    if (this.config.enabled && this.config.runMissedOnStartup) {
      const isMissed = this.isMissedScan(this.config, this.lastScheduledRun, this.clock());
      if (isMissed) {
        // Run missed scan catchup asynchronously
        setImmediate(() => {
          this.executeScheduledScan('MISSED_CATCHUP').catch(() => {});
        });
      }
    }

    this.recalculateNextRun();
    this.armTimer();
  }

  public stop(): void {
    this.isStarted = false;
    if (this.activeTimer) {
      clearTimeout(this.activeTimer);
      this.activeTimer = null;
    }
  }

  private armTimer(): void {
    if (this.activeTimer) {
      clearTimeout(this.activeTimer);
      this.activeTimer = null;
    }

    if (!this.config.enabled || !this.isStarted) {
      return;
    }

    const nextRun = this.recalculateNextRun();
    if (!nextRun) return;

    const delayMs = Math.max(100, nextRun - this.clock());

    // Node.js setTimeout max delay is ~24.8 days (2147483647 ms)
    const cappedDelay = Math.min(delayMs, 2147483647);

    this.activeTimer = setTimeout(() => {
      this.executeScheduledScan('SCHEDULED').catch(() => {});
    }, cappedDelay);
  }

  // ============================================================
  // EXECUTION PIPELINE & CONCURRENCY
  // ============================================================

  public async runNow(customTargets?: string[]): Promise<ScanResult> {
    return this.executeScheduledScan('USER', customTargets);
  }

  public async executeScheduledScan(
    trigger: ScheduleTrigger = 'SCHEDULED',
    customTargets?: string[]
  ): Promise<ScanResult> {
    const startTime = this.clock();
    const scheduledTime = trigger === 'SCHEDULED' ? this.nextScheduledRun : undefined;

    // 1. Concurrency Guard: Check if a scan is already running
    if (this.isScanRunning || this.scanner.getStatus() === 'running') {
      const skippedRecord: ScanHistoryRecord = {
        scanId: `sched-${Date.now()}`,
        scanType: this.config.scanType,
        trigger,
        scheduledTime,
        startTime,
        completedAt: this.clock(),
        durationMs: 0,
        totalFilesScanned: 0,
        totalBytesScanned: 0,
        threatsFound: 0,
        threatsQuarantined: 0,
        skippedCount: 0,
        errorCount: 0,
        overallVerdict: 'ALLOW',
        finalStatus: 'SKIPPED_ALREADY_RUNNING',
        deferredReason: 'Another scan is currently in progress.'
      };
      this.recordHistory(skippedRecord);
      this.emit('scheduledScanDeferred', skippedRecord);

      // Re-arm timer for next interval if scheduled
      if (trigger === 'SCHEDULED') {
        this.recalculateNextRun();
        this.armTimer();
      }

      return {
        scanId: skippedRecord.scanId,
        scanType: this.config.scanType,
        status: 'cancelled',
        totalFilesScanned: 0,
        totalBytesScanned: 0,
        durationMs: 0,
        threats: [],
        skippedFiles: [{ path: 'ALL', reason: 'Scan skipped: another scan active' }],
        errors: [],
        overallVerdict: 'ALLOW',
        completedAt: this.clock()
      };
    }

    // 2. Resource Guard: Battery Check
    if (this.config.pauseOnBattery && trigger !== 'USER') {
      const battery = await this.checkBattery();
      const minThreshold = this.config.minBatteryThresholdPct || 20;

      if (battery.hasBattery && !battery.isCharging && battery.percent < minThreshold) {
        const deferredRecord: ScanHistoryRecord = {
          scanId: `sched-${Date.now()}`,
          scanType: this.config.scanType,
          trigger,
          scheduledTime,
          startTime,
          completedAt: this.clock(),
          durationMs: 0,
          totalFilesScanned: 0,
          totalBytesScanned: 0,
          threatsFound: 0,
          threatsQuarantined: 0,
          skippedCount: 0,
          errorCount: 0,
          overallVerdict: 'ALLOW',
          finalStatus: 'DEFERRED_BATTERY',
          deferredReason: `Battery level is at ${battery.percent}%, below safety threshold (${minThreshold}%).`
        };

        this.recordHistory(deferredRecord);
        this.lastStatus = 'DEFERRED_BATTERY';
        this.emit('scheduledScanDeferred', deferredRecord);

        if (this.notificationService) {
          this.notificationService.notify({
            title: 'Scheduled Scan Deferred',
            message: `Battery is low (${battery.percent}%). Scheduled scan deferred until connected to power.`,
            severity: 'low',
            category: 'SYSTEM_HEALTH'
          });
        }

        this.recalculateNextRun();
        this.armTimer();

        return {
          scanId: deferredRecord.scanId,
          scanType: this.config.scanType,
          status: 'cancelled',
          totalFilesScanned: 0,
          totalBytesScanned: 0,
          durationMs: 0,
          threats: [],
          skippedFiles: [{ path: 'ALL', reason: deferredRecord.deferredReason! }],
          errors: [],
          overallVerdict: 'ALLOW',
          completedAt: this.clock()
        };
      }
    }

    // 3. Resource Guard: CPU Load Check
    if (trigger !== 'USER') {
      const cpu = await this.checkCpu();
      const maxThreshold = this.config.maxCpuThresholdPct || 80;

      if (cpu.isAvailable && cpu.loadPct > maxThreshold) {
        const deferredRecord: ScanHistoryRecord = {
          scanId: `sched-${Date.now()}`,
          scanType: this.config.scanType,
          trigger,
          scheduledTime,
          startTime,
          completedAt: this.clock(),
          durationMs: 0,
          totalFilesScanned: 0,
          totalBytesScanned: 0,
          threatsFound: 0,
          threatsQuarantined: 0,
          skippedCount: 0,
          errorCount: 0,
          overallVerdict: 'ALLOW',
          finalStatus: 'DEFERRED_CPU',
          deferredReason: `CPU load is at ${cpu.loadPct}%, exceeding threshold (${maxThreshold}%).`
        };

        this.recordHistory(deferredRecord);
        this.lastStatus = 'DEFERRED_CPU';
        this.emit('scheduledScanDeferred', deferredRecord);

        if (this.notificationService) {
          this.notificationService.notify({
            title: 'Scheduled Scan Deferred',
            message: `System is under high CPU load (${cpu.loadPct}%). Scan deferred to prevent slowdown.`,
            severity: 'low',
            category: 'SYSTEM_HEALTH'
          });
        }

        this.recalculateNextRun();
        this.armTimer();

        return {
          scanId: deferredRecord.scanId,
          scanType: this.config.scanType,
          status: 'cancelled',
          totalFilesScanned: 0,
          totalBytesScanned: 0,
          durationMs: 0,
          threats: [],
          skippedFiles: [{ path: 'ALL', reason: deferredRecord.deferredReason! }],
          errors: [],
          overallVerdict: 'ALLOW',
          completedAt: this.clock()
        };
      }
    }

    // 4. Begin Execution
    this.isScanRunning = true;
    const scanId = `sched-${this.config.scanType}-${this.clock()}`;
    this.currentScanId = scanId;

    this.emit('scheduledScanStarted', {
      scanId,
      trigger,
      scanType: this.config.scanType,
      startTime
    });

    if (this.notificationService && trigger !== 'USER') {
      this.notificationService.notify({
        title: 'Scheduled Scan Started',
        message: `Running scheduled ${this.config.scanType === 'full' ? 'Full' : 'Quick'} scan...`,
        severity: 'info',
        category: 'SCAN_COMPLETE'
      });
    }

    let scanResult: ScanResult;
    let threatsQuarantined = 0;

    try {
      if (this.config.scanType === 'quick') {
        scanResult = await this.quickScanner.executeQuickScan(customTargets);
      } else {
        // Full Scan: scan quick targets plus root directory / user profile
        const fullTargets = customTargets && customTargets.length > 0
          ? customTargets
          : this.quickScanner.getQuickScanTargets();
        if (!customTargets) {
          const homeDir = os.homedir();
          if (fs.existsSync(homeDir) && !fullTargets.includes(homeDir)) {
            fullTargets.push(homeDir);
          }
        }
        scanResult = await this.scanner.scanPaths(fullTargets, 'full');
      }

      // 5. Canonical Auto-Quarantine Handling
      if (this.config.autoQuarantine && this.quarantineService && scanResult.threats.length > 0) {
        for (const threat of scanResult.threats) {
          if (threat.verdict === 'BLOCK' || threat.verdict === 'WARN') {
            try {
              if (threat.filePath && fs.existsSync(threat.filePath)) {
                const quarantineItem = await this.quarantineService.isolateFile(threat);
                if (quarantineItem && quarantineItem.quarantineId) {
                  threat.quarantined = true;
                  threatsQuarantined++;
                }
              }
            } catch {
              // Non-blocking quarantine error
            }
          }
        }
      }

      const completedAt = this.clock();
      const durationMs = completedAt - startTime;

      let finalStatus: ScheduleExecutionStatus = 'COMPLETED';
      if (scanResult.status === 'cancelled') {
        finalStatus = 'CANCELLED';
      } else if (scanResult.threats.length > 0) {
        finalStatus = 'COMPLETED_WITH_FINDINGS';
      } else if (scanResult.errors.length > 0) {
        finalStatus = 'COMPLETED';
      }

      const historyRecord: ScanHistoryRecord = {
        scanId: scanResult.scanId || scanId,
        scanType: this.config.scanType,
        trigger,
        scheduledTime,
        startTime,
        completedAt,
        durationMs,
        totalFilesScanned: scanResult.totalFilesScanned,
        totalBytesScanned: scanResult.totalBytesScanned,
        threatsFound: scanResult.threats.length,
        threatsQuarantined,
        skippedCount: scanResult.skippedFiles.length,
        errorCount: scanResult.errors.length,
        overallVerdict: scanResult.overallVerdict,
        finalStatus
      };

      this.recordHistory(historyRecord);
      this.lastScheduledRun = completedAt;
      if (finalStatus !== 'CANCELLED') {
        this.lastSuccessfulRun = completedAt;
      }
      this.lastStatus = finalStatus;

      // Persist last run metadata
      this.saveSchedule(this.config);

      this.emit('scheduledScanCompleted', {
        result: scanResult,
        history: historyRecord
      });

      if (this.notificationService) {
        if (scanResult.threats.length > 0) {
          this.notificationService.notify({
            title: 'Threats Detected During Scan',
            message: `Found ${scanResult.threats.length} threat(s). ${threatsQuarantined} automatically quarantined.`,
            severity: 'critical',
            category: 'SECURITY_ALERT',
            metadata: {
              count: scanResult.threats.length,
              threatName: scanResult.threats[0]?.threatName
            },
            forceToast: true
          });
        } else {
          this.notificationService.notify({
            title: 'Scan Finished Clean',
            message: `Scanned ${scanResult.totalFilesScanned} files. No threats found.`,
            severity: 'info',
            category: 'SCAN_COMPLETE'
          });
        }
      }

      return scanResult;
    } catch (err: any) {
      const completedAt = this.clock();
      const durationMs = completedAt - startTime;

      const failedRecord: ScanHistoryRecord = {
        scanId,
        scanType: this.config.scanType,
        trigger,
        scheduledTime,
        startTime,
        completedAt,
        durationMs,
        totalFilesScanned: 0,
        totalBytesScanned: 0,
        threatsFound: 0,
        threatsQuarantined: 0,
        skippedCount: 0,
        errorCount: 1,
        overallVerdict: 'WARN',
        finalStatus: 'FAILED',
        errorReason: err.message || 'Unknown scan failure'
      };

      this.recordHistory(failedRecord);
      this.lastStatus = 'FAILED';
      this.emit('scheduledScanFailed', failedRecord);

      if (this.notificationService) {
        this.notificationService.notify({
          title: 'Scheduled Scan Failed',
          message: `Scan failed: ${err.message || 'Internal error'}.`,
          severity: 'high',
          category: 'SYSTEM_HEALTH'
        });
      }

      throw err;
    } finally {
      this.isScanRunning = false;
      this.currentScanId = undefined;
      this.recalculateNextRun();
      this.armTimer();
    }
  }

  public cancelCurrentScan(): void {
    if (this.isScanRunning) {
      this.scanner.cancelScan();
    }
  }

  public getState(): ScanSchedulerState {
    return {
      config: { ...this.config },
      lastScheduledRun: this.lastScheduledRun || undefined,
      lastSuccessfulRun: this.lastSuccessfulRun || undefined,
      lastStatus: this.lastStatus,
      nextScheduledRun: this.nextScheduledRun,
      isRunning: this.isScanRunning,
      currentScanId: this.currentScanId
    };
  }
}
