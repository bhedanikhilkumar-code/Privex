import {
  HealthState,
  SystemHealthReport,
  SubsystemHealthStatus,
  HealthRemediationAction
} from '../types/desktop.types';
import { AuditLoggerService } from './audit-logger.service';
import { WatchdogService } from './watchdog.service';
import { TamperDetectorService } from './tamper-detector.service';
import { SecureStorageService } from './secure-storage.service';
import { ThreatIntelManagerService } from './threat-intel-manager.service';
import { RealtimeMonitorService } from './realtime-monitor.service';
import { RansomwareShieldService } from './ransomware-shield.service';
import { QuarantineService } from './quarantine.service';

export interface HealthMonitorOptions {
  auditLogger?: AuditLoggerService;
  watchdog?: WatchdogService;
  tamperDetector?: TamperDetectorService;
  storageService?: SecureStorageService;
  threatIntelManager?: ThreatIntelManagerService;
  realtimeMonitor?: RealtimeMonitorService;
  ransomwareShield?: RansomwareShieldService;
  quarantineService?: QuarantineService;
  clock?: () => number;
}

export class HealthMonitorService {
  private readonly auditLogger?: AuditLoggerService;
  private readonly watchdog?: WatchdogService;
  private readonly tamperDetector?: TamperDetectorService;
  private readonly storageService?: SecureStorageService;
  private readonly threatIntelManager?: ThreatIntelManagerService;
  private readonly realtimeMonitor?: RealtimeMonitorService;
  private readonly ransomwareShield?: RansomwareShieldService;
  private readonly quarantineService?: QuarantineService;
  private readonly clock: () => number;

  private cachedReport: SystemHealthReport | null = null;
  private lastReportTimestamp: number = 0;

  constructor(options?: HealthMonitorOptions) {
    this.auditLogger = options?.auditLogger;
    this.watchdog = options?.watchdog;
    this.tamperDetector = options?.tamperDetector;
    this.storageService = options?.storageService;
    this.threatIntelManager = options?.threatIntelManager;
    this.realtimeMonitor = options?.realtimeMonitor;
    this.ransomwareShield = options?.ransomwareShield;
    this.quarantineService = options?.quarantineService;
    this.clock = options?.clock || (() => Date.now());
  }

  /**
   * Evaluates system health across all subsystems and computes the canonical 4-state report.
   */
  public evaluateHealth(): SystemHealthReport {
    const now = this.clock();
    const subsystems: SubsystemHealthStatus[] = [];
    const issues: string[] = [];
    const remediations: HealthRemediationAction[] = [];

    // 1. Evaluate Configuration & Tamper Protection
    let configState: HealthState = 'HEALTHY';
    let configMsg = 'Configuration and security storage integrity verified';

    if (this.tamperDetector) {
      const tamperStatus = this.tamperDetector.getStatus();
      if (tamperStatus.tamperDetected) {
        configState = 'CRITICAL';
        configMsg = `Tamper detected in: ${tamperStatus.tamperedComponents.join(', ')}`;
        issues.push(`Security boundary compromised: ${tamperStatus.details.join('; ')}`);
        remediations.push({
          actionId: 'RESTORE_SAFE_DEFAULTS',
          title: 'Restore Default Configuration',
          description: 'Re-initialize configuration storage to maximum security defaults.',
          subsystem: 'Configuration',
          autoExecutable: true
        });
      }
    }
    subsystems.push({
      name: 'Configuration',
      state: configState,
      message: configMsg,
      lastCheckTime: now
    });

    // 2. Evaluate Audit Log Hash Chain
    let auditState: HealthState = 'HEALTHY';
    let auditMsg = 'HMAC-SHA256 audit log chain verified';

    if (this.auditLogger) {
      const auditResult = this.auditLogger.verifyChainIntegrity();
      if (!auditResult.isValid) {
        auditState = 'CRITICAL';
        auditMsg = `Audit chain corruption at record ${auditResult.corruptedIndex}: ${auditResult.reason}`;
        issues.push(`Audit log integrity violation: ${auditResult.tamperDetails || auditResult.reason}`);
        remediations.push({
          actionId: 'RESET_AUDIT_EPOCH',
          title: 'Archive and Reset Audit Log',
          description: 'Archive damaged audit file and establish a new verified genesis chain.',
          subsystem: 'AuditLogger',
          autoExecutable: false
        });
      }
    }
    subsystems.push({
      name: 'AuditLogger',
      state: auditState,
      message: auditMsg,
      lastCheckTime: now
    });

    // 3. Evaluate Real-Time Shield
    let shieldState: HealthState = 'HEALTHY';
    let shieldMsg = 'Active filesystem protection online';

    if (this.realtimeMonitor) {
      const isMonitoring = this.realtimeMonitor.isActive();
      const isSnoozed = Boolean(this.watchdog?.getStatus().shieldSnoozeActive);
      if (isSnoozed) {
        shieldState = 'WARNING';
        shieldMsg = 'Real-time protection is temporarily snoozed';
      } else if (!isMonitoring) {
        shieldState = 'DEGRADED';
        shieldMsg = 'Real-time protection is paused or stopped';
        issues.push('Real-time file monitoring is inactive');
        remediations.push({
          actionId: 'START_REALTIME_SHIELD',
          title: 'Enable Real-Time Protection',
          description: 'Start active background file and download interception.',
          subsystem: 'RealtimeShield',
          autoExecutable: true
        });
      }
    } else if (this.storageService) {
      const settings = this.storageService.getSettings();
      if (!settings.realtimeShieldEnabled) {
        shieldState = 'DEGRADED';
        shieldMsg = 'Real-time shield disabled in settings';
        issues.push('Real-time shield setting is disabled');
        remediations.push({
          actionId: 'START_REALTIME_SHIELD',
          title: 'Enable Real-Time Protection',
          description: 'Update settings to enable real-time shield.',
          subsystem: 'RealtimeShield',
          autoExecutable: true
        });
      }
    }
    subsystems.push({
      name: 'RealtimeShield',
      state: shieldState,
      message: shieldMsg,
      lastCheckTime: now
    });

    // 4. Evaluate Threat Intelligence DB
    let threatIntelState: HealthState = 'HEALTHY';
    let threatIntelMsg = 'Threat signatures active and up-to-date';

    if (this.threatIntelManager) {
      const tiStatus = this.threatIntelManager.getStatus();
      if (tiStatus.stalenessState === 'EXPIRED_CACHE') {
        threatIntelState = 'DEGRADED';
        threatIntelMsg = `Threat definitions expired (${tiStatus.stalenessDays} days old)`;
        issues.push('Threat intelligence cache expired');
        remediations.push({
          actionId: 'UPDATE_THREAT_INTEL',
          title: 'Import Threat Update',
          description: 'Import a signed threat definitions bundle (.ppdb).',
          subsystem: 'ThreatIntelligence',
          autoExecutable: false
        });
      } else if (tiStatus.stalenessState === 'STALE') {
        threatIntelState = 'WARNING';
        threatIntelMsg = `Threat definitions outdated (${tiStatus.stalenessDays} days old)`;
        issues.push('Threat intelligence is stale');
      }
    }
    subsystems.push({
      name: 'ThreatIntelligence',
      state: threatIntelState,
      message: threatIntelMsg,
      lastCheckTime: now
    });

    // 5. Evaluate Watchdog & Continuity Supervisor
    let watchdogState: HealthState = 'HEALTHY';
    let watchdogMsg = 'Continuity supervisor monitoring active';

    if (this.watchdog) {
      const wdStatus = this.watchdog.getStatus();
      if (wdStatus.safeMinimalMode) {
        watchdogState = 'DEGRADED';
        watchdogMsg = 'Safe Minimal Mode active due to recurring component failures';
        issues.push('Watchdog circuit breaker engaged; some components isolated');
        remediations.push({
          actionId: 'RESET_WATCHDOG_ISOLATIONS',
          title: 'Reset Component Isolation',
          description: 'Clear isolation flags and attempt full subsystem recovery.',
          subsystem: 'Watchdog',
          autoExecutable: true
        });
      } else if (wdStatus.shieldSnoozeActive) {
        watchdogState = 'WARNING';
        watchdogMsg = `Real-time shield snoozed (auto-re-enable in ${Math.round(wdStatus.shieldSnoozeRemainingMs / 1000)}s)`;
      }
    }
    subsystems.push({
      name: 'Watchdog',
      state: watchdogState,
      message: watchdogMsg,
      lastCheckTime: now
    });

    // 6. Evaluate Quarantine Vault
    let quarantineState: HealthState = 'HEALTHY';
    let quarantineMsg = 'Quarantine isolation vault operational';

    if (this.quarantineService) {
      try {
        const items = this.quarantineService.listQuarantine();
        quarantineMsg = `Quarantine active (${items.length} isolated items)`;
      } catch (err) {
        quarantineState = 'WARNING';
        quarantineMsg = 'Quarantine manifest inaccessible';
        issues.push('Quarantine vault manifest error');
      }
    }
    subsystems.push({
      name: 'QuarantineVault',
      state: quarantineState,
      message: quarantineMsg,
      lastCheckTime: now
    });

    // 7. Evaluate Ransomware Shield & Decoy Canaries
    let ransomwareState: HealthState = 'HEALTHY';
    let ransomwareMsg = 'Ransomware shield operational';

    if (this.ransomwareShield) {
      const rStatus = this.ransomwareShield.getStatus();
      if (rStatus.active) {
        if (rStatus.activeCanariesCount === 0 && rStatus.protectedFolders.length > 0) {
          ransomwareState = 'WARNING';
          ransomwareMsg = 'No canary decoy files deployed in protected folders';
        } else {
          ransomwareState = 'HEALTHY';
          ransomwareMsg = `Ransomware shield active (${rStatus.protectedFolders.length} folders, ${rStatus.activeCanariesCount} canaries)`;
        }
      } else {
        ransomwareState = 'HEALTHY';
        ransomwareMsg = 'Ransomware shield standby';
      }
    }
    subsystems.push({
      name: 'RansomwareShield',
      state: ransomwareState,
      message: ransomwareMsg,
      lastCheckTime: now
    });

    // Compute Overall Health State
    // Precedence: CRITICAL > DEGRADED > WARNING > HEALTHY
    let overallState: HealthState = 'HEALTHY';
    for (const sub of subsystems) {
      if (sub.state === 'CRITICAL') {
        overallState = 'CRITICAL';
        break;
      } else if (sub.state === 'DEGRADED') {
        overallState = 'DEGRADED';
      } else if (sub.state === 'WARNING' && overallState !== 'DEGRADED') {
        overallState = 'WARNING';
      }
    }

    const report: SystemHealthReport = {
      overallState,
      subsystems,
      issues,
      recommendedRemediations: remediations,
      timestamp: now
    };

    this.cachedReport = report;
    this.lastReportTimestamp = now;

    // Log significant health degradations to audit log
    if (overallState === 'CRITICAL' || overallState === 'DEGRADED') {
      if (this.auditLogger) {
        try {
          this.auditLogger.log({
            category: 'HEALTH_CHECK',
            severity: overallState === 'CRITICAL' ? 'CRITICAL' : 'WARN',
            action: overallState === 'CRITICAL' ? 'HEALTH_FAILED' : 'HEALTH_DEGRADED',
            actor: 'HealthMonitorService',
            targetSummary: `System health state is ${overallState} with ${issues.length} issues`,
            metadata: {
              overallState,
              issueCount: issues.length,
              remediationCount: remediations.length
            }
          });
        } catch {
          // continue
        }
      }
    }

    return report;
  }

  public getHealth(): SystemHealthReport {
    if (!this.cachedReport || this.clock() - this.lastReportTimestamp > 2000) {
      return this.evaluateHealth();
    }
    return this.cachedReport;
  }
}
