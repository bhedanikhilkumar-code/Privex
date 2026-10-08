import {
  RealtimeDownloadStatus,
  DownloadCatchUpReport
} from '../types/mobile.types';

/**
 * RealtimeDownloadProtectionService (Phase T5 Client):
 *
 * Provides high-level TypeScript access to native Android MediaStore download observation,
 * stabilization, event deduplication, and catch-up reconciliation.
 *
 * TRUTHFUL PLATFORM CAPABILITY:
 * - Scans supported downloads as soon as Android makes the file available for inspection.
 * - Explicitly discloses that system-wide pre-open interception is not supported on Android for 3rd-party apps.
 */
export class RealtimeDownloadProtectionService {
  private static simulatedActive: boolean = false;
  private static simulatedProcessed: number = 0;
  private static simulatedThreats: number = 0;

  /**
   * Starts active real-time download observation via the native Android bridge.
   */
  public static async startProtection(): Promise<boolean> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.startRealtimeDownloadProtection === 'function') {
        return bridge.startRealtimeDownloadProtection();
      }
    }

    // Web simulation fallback
    this.simulatedActive = true;
    return true;
  }

  /**
   * Stops real-time download observation.
   */
  public static async stopProtection(): Promise<boolean> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.stopRealtimeDownloadProtection === 'function') {
        return bridge.stopRealtimeDownloadProtection();
      }
    }

    // Web simulation fallback
    this.simulatedActive = false;
    return true;
  }

  /**
   * Queries current real-time protection runtime status and platform limitations.
   */
  public static async getStatus(): Promise<RealtimeDownloadStatus> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.getRealtimeDownloadProtectionStatus === 'function') {
        try {
          const raw = bridge.getRealtimeDownloadProtectionStatus();
          return JSON.parse(raw);
        } catch {
          // Fall through to default
        }
      }
    }

    // Web simulation fallback
    return {
      isMonitoringActive: this.simulatedActive,
      lastEventTimestamp: this.simulatedActive ? Date.now() : 0,
      lastReconciliationTimestamp: this.simulatedActive ? Date.now() : 0,
      eventsProcessed: this.simulatedProcessed,
      threatsDetected: this.simulatedThreats,
      deduplicatorStats: {
        cachedEntries: this.simulatedProcessed,
        maxCapacity: 5000
      },
      cleanCacheCount: 0,
      isPreOpenInterceptionSupported: false,
      platformLimitationNotice:
        'Privex scans supported downloads as soon as Android makes the file available for inspection. System-wide pre-open interception is not supported by Android for third-party applications.'
    };
  }

  /**
   * Triggers catch-up reconciliation for files modified while the app was inactive.
   */
  public static async reconcileCatchUp(): Promise<DownloadCatchUpReport> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.reconcileDownloadCatchUp === 'function') {
        try {
          const raw = bridge.reconcileDownloadCatchUp();
          return JSON.parse(raw);
        } catch (e: any) {
          return {
            discovered: 0,
            rescanned: 0,
            skipped: 0,
            threatsFound: 0,
            durationMs: 0,
            timestamp: Date.now(),
            error: e?.message || 'PARSE_ERROR'
          };
        }
      }
    }

    // Web simulation fallback
    return {
      discovered: 5,
      rescanned: 5,
      skipped: 0,
      threatsFound: 0,
      durationMs: 12,
      timestamp: Date.now()
    };
  }
}
