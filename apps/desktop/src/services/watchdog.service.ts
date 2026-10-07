import {
  WatchdogStatus,
  WatchdogComponentStatus,
  WatchdogSubsystemHealth
} from '../types/desktop.types';
import { AuditLoggerService } from './audit-logger.service';

export interface WatchdogProbeRegistration {
  name: string;
  checkHealth: () => Promise<boolean> | boolean;
  recover?: () => Promise<boolean> | boolean;
}

export interface WatchdogOptions {
  heartbeatIntervalMs?: number;
  circuitBreakerThreshold?: number;
  circuitBreakerWindowMs?: number;
  auditLogger?: AuditLoggerService;
  onShieldReEnable?: () => Promise<void> | void;
  clock?: () => number;
}

export class WatchdogService {
  private readonly heartbeatIntervalMs: number;
  private readonly circuitBreakerThreshold: number;
  private readonly circuitBreakerWindowMs: number;
  private readonly auditLogger?: AuditLoggerService;
  private readonly onShieldReEnable?: () => Promise<void> | void;
  private readonly clock: () => number;

  private isRunning: boolean = false;
  private timer: NodeJS.Timeout | null = null;
  private safeMinimalMode: boolean = false;

  private probes = new Map<string, WatchdogProbeRegistration>();
  private componentStates = new Map<
    string,
    {
      status: WatchdogSubsystemHealth;
      failureCount: number;
      lastHeartbeat: number;
      lastRecoveryTime?: number;
      isIsolated: boolean;
      recentFailures: number[];
    }
  >();

  private crashHistory: { component: string; timestamp: number }[] = [];

  // Shield snooze auto-re-enable timer
  private snoozeActive: boolean = false;
  private snoozeStartTime: number = 0;
  private snoozeDurationMs: number = 0;
  private snoozeTimer: NodeJS.Timeout | null = null;

  public static readonly DEFAULT_HEARTBEAT_MS = 2000;
  public static readonly DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 3;
  public static readonly DEFAULT_CIRCUIT_BREAKER_WINDOW_MS = 120000; // 120 seconds

  constructor(options?: WatchdogOptions) {
    this.heartbeatIntervalMs = options?.heartbeatIntervalMs || WatchdogService.DEFAULT_HEARTBEAT_MS;
    this.circuitBreakerThreshold = options?.circuitBreakerThreshold || WatchdogService.DEFAULT_CIRCUIT_BREAKER_THRESHOLD;
    this.circuitBreakerWindowMs = options?.circuitBreakerWindowMs || WatchdogService.DEFAULT_CIRCUIT_BREAKER_WINDOW_MS;
    this.auditLogger = options?.auditLogger;
    this.onShieldReEnable = options?.onShieldReEnable;
    this.clock = options?.clock || (() => Date.now());
  }

  public registerComponent(registration: WatchdogProbeRegistration): void {
    const now = this.clock();
    this.probes.set(registration.name, registration);
    if (!this.componentStates.has(registration.name)) {
      this.componentStates.set(registration.name, {
        status: 'HEALTHY',
        failureCount: 0,
        lastHeartbeat: now,
        isIsolated: false,
        recentFailures: []
      });
    }
  }

  public unregisterComponent(name: string): void {
    this.probes.delete(name);
    this.componentStates.delete(name);
  }

  public start(): void {
    if (this.isRunning) return;
    this.isRunning = true;

    if (this.auditLogger) {
      try {
        this.auditLogger.log({
          category: 'WATCHDOG',
          severity: 'INFO',
          action: 'WATCHDOG_STARTED',
          actor: 'WatchdogService',
          targetSummary: `Watchdog heartbeat started at ${this.heartbeatIntervalMs}ms interval`,
          metadata: {
            heartbeatIntervalMs: this.heartbeatIntervalMs,
            registeredComponents: Array.from(this.probes.keys()).join(', ')
          }
        });
      } catch {
        // continue
      }
    }

    this.timer = setInterval(() => {
      void this.executeHeartbeat();
    }, this.heartbeatIntervalMs);
  }

  public stop(): void {
    this.isRunning = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.cancelSnooze();
  }

  /**
   * Executes a single heartbeat cycle over all registered components.
   */
  public async executeHeartbeat(): Promise<void> {
    const now = this.clock();

    for (const [name, probe] of this.probes.entries()) {
      const state = this.componentStates.get(name);
      if (!state) continue;

      if (state.isIsolated) {
        continue;
      }

      let isHealthy = false;
      try {
        const timeoutPromise = new Promise<boolean>((_, reject) =>
          setTimeout(() => reject(new Error('PROBE_TIMEOUT')), 1500)
        );
        const checkPromise = Promise.resolve(probe.checkHealth());
        isHealthy = await Promise.race([checkPromise, timeoutPromise]);
      } catch {
        isHealthy = false;
      }

      if (isHealthy) {
        state.status = 'HEALTHY';
        state.lastHeartbeat = now;
      } else {
        await this.handleComponentFailure(name, probe, state, now);
      }
    }
  }

  private async handleComponentFailure(
    name: string,
    probe: WatchdogProbeRegistration,
    state: {
      status: WatchdogSubsystemHealth;
      failureCount: number;
      lastHeartbeat: number;
      lastRecoveryTime?: number;
      isIsolated: boolean;
      recentFailures: number[];
    },
    now: number
  ): Promise<void> {
    state.failureCount++;
    state.recentFailures.push(now);
    // Filter to sliding window
    state.recentFailures = state.recentFailures.filter(t => now - t <= this.circuitBreakerWindowMs);

    this.crashHistory.push({ component: name, timestamp: now });
    if (this.crashHistory.length > 100) {
      this.crashHistory = this.crashHistory.slice(-100);
    }

    // Check circuit breaker condition
    if (state.recentFailures.length >= this.circuitBreakerThreshold) {
      state.isIsolated = true;
      state.status = 'ISOLATED';
      this.safeMinimalMode = true;

      if (this.auditLogger) {
        try {
          this.auditLogger.log({
            category: 'WATCHDOG',
            severity: 'CRITICAL',
            action: 'WATCHDOG_CIRCUIT_BREAKER_TRIGGERED',
            actor: 'WatchdogService',
            targetSummary: `Component ${name} isolated after ${state.recentFailures.length} crashes in ${this.circuitBreakerWindowMs}ms`,
            metadata: {
              component: name,
              failureCount: state.failureCount,
              safeMinimalMode: true
            }
          });
        } catch {
          // continue
        }
      }
      return;
    }

    // Attempt auto-recovery
    state.status = 'RECOVERING';
    if (probe.recover) {
      try {
        const recovered = await probe.recover();
        if (recovered) {
          state.status = 'HEALTHY';
          state.lastRecoveryTime = now;
          state.lastHeartbeat = now;

          if (this.auditLogger) {
            this.auditLogger.log({
              category: 'WATCHDOG',
              severity: 'WARN',
              action: 'WATCHDOG_RECOVERY',
              actor: 'WatchdogService',
              targetSummary: `Component ${name} successfully recovered`,
              metadata: { component: name, attempt: state.failureCount }
            });
          }
          return;
        }
      } catch {
        // Recovery failed
      }
    }

    state.status = 'FAILED';
    if (this.auditLogger) {
      try {
        this.auditLogger.log({
          category: 'WATCHDOG',
          severity: 'ERROR',
          action: 'WATCHDOG_RECOVERY_FAILED',
          actor: 'WatchdogService',
          targetSummary: `Automatic recovery failed for component ${name}`,
          metadata: { component: name, failureCount: state.failureCount }
        });
      } catch {
        // continue
      }
    }
  }

  /**
   * Arms a Real-Time Shield Snooze Auto-Re-Enable countdown timer (RULE-19).
   */
  public snoozeShield(durationMs: number): void {
    this.cancelSnooze();

    const boundedDuration = Math.max(1000, Math.min(86400000, durationMs));
    this.snoozeActive = true;
    this.snoozeStartTime = this.clock();
    this.snoozeDurationMs = boundedDuration;

    if (this.auditLogger) {
      try {
        this.auditLogger.log({
          category: 'WATCHDOG',
          severity: 'WARN',
          action: 'SHIELD_SNOOZE_ARMED',
          actor: 'WatchdogService',
          targetSummary: `Real-time shield paused with auto-re-enable timer for ${boundedDuration}ms`,
          metadata: { durationMs: boundedDuration }
        });
      } catch {
        // continue
      }
    }

    this.snoozeTimer = setTimeout(() => {
      void this.triggerShieldReEnable();
    }, boundedDuration);
  }

  public cancelSnooze(): void {
    if (this.snoozeTimer) {
      clearTimeout(this.snoozeTimer);
      this.snoozeTimer = null;
    }
    this.snoozeActive = false;
    this.snoozeStartTime = 0;
    this.snoozeDurationMs = 0;
  }

  private async triggerShieldReEnable(): Promise<void> {
    this.cancelSnooze();

    if (this.onShieldReEnable) {
      try {
        await this.onShieldReEnable();
      } catch {
        // continue
      }
    }

    if (this.auditLogger) {
      try {
        this.auditLogger.log({
          category: 'WATCHDOG',
          severity: 'INFO',
          action: 'SHIELD_AUTO_REENABLED',
          actor: 'WatchdogService',
          targetSummary: 'Real-time shield automatically re-enabled by Watchdog timer',
          metadata: { autoReenabled: true }
        });
      } catch {
        // continue
      }
    }
  }

  public resetComponentIsolation(name: string): boolean {
    const state = this.componentStates.get(name);
    if (state) {
      state.isIsolated = false;
      state.status = 'HEALTHY';
      state.recentFailures = [];
      state.failureCount = 0;

      // If no other component is isolated, disable safe minimal mode
      let anyIsolated = false;
      for (const s of this.componentStates.values()) {
        if (s.isIsolated) anyIsolated = true;
      }
      if (!anyIsolated) {
        this.safeMinimalMode = false;
      }

      if (this.auditLogger) {
        try {
          this.auditLogger.log({
            category: 'WATCHDOG',
            severity: 'INFO',
            action: 'WATCHDOG_ISOLATION_RESET',
            actor: 'WatchdogService',
            targetSummary: `Component ${name} manual isolation cleared`,
            metadata: { component: name }
          });
        } catch {
          // continue
        }
      }
      return true;
    }
    return false;
  }

  public getStatus(): WatchdogStatus {
    const now = this.clock();
    const monitored: WatchdogComponentStatus[] = [];

    for (const [name, state] of this.componentStates.entries()) {
      monitored.push({
        name,
        status: state.status,
        failureCount: state.failureCount,
        lastHeartbeat: state.lastHeartbeat,
        lastRecoveryTime: state.lastRecoveryTime,
        isIsolated: state.isIsolated
      });
    }

    let remainingSnooze = 0;
    if (this.snoozeActive && this.snoozeDurationMs > 0) {
      const elapsed = now - this.snoozeStartTime;
      remainingSnooze = Math.max(0, this.snoozeDurationMs - elapsed);
    }

    return {
      isActive: this.isRunning,
      heartbeatIntervalMs: this.heartbeatIntervalMs,
      monitoredComponents: monitored,
      safeMinimalMode: this.safeMinimalMode,
      shieldSnoozeActive: this.snoozeActive,
      shieldSnoozeRemainingMs: remainingSnooze,
      shieldSnoozeTotalMs: this.snoozeDurationMs,
      crashHistory: [...this.crashHistory]
    };
  }
}
