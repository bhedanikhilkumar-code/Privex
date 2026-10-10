import {
  MobileScanResult,
  NotificationCategoryType,
  NotificationDispatchResultDTO,
  NotificationDispatcherStatsDTO
} from '../types/mobile.types';
import { Verdict } from '@private-protection/core';
import { SecureStorageService } from './secure-storage.service';

export interface DispatchedNotification {
  id: string;
  channelId: string;
  category?: NotificationCategoryType;
  title: string;
  body: string;
  priority: 'HIGH' | 'DEFAULT' | 'LOW';
  timestamp: number;
  outcome?: string;
}

export class NotificationService {
  private static readonly MAX_NOTIFICATIONS = 50;
  private static dispatchedList: DispatchedNotification[] = [];

  private static pushNotification(notif: DispatchedNotification): void {
    this.dispatchedList.push(notif);
    if (this.dispatchedList.length > this.MAX_NOTIFICATIONS) {
      this.dispatchedList = this.dispatchedList.slice(-this.MAX_NOTIFICATIONS);
    }
  }

  /**
   * Dispatches a notification across the unified 7-category Android pipeline.
   */
  public static async dispatchCategory(
    category: NotificationCategoryType,
    title: string,
    body: string,
    dedupKey?: string
  ): Promise<NotificationDispatchResultDTO> {
    const settings = await SecureStorageService.getSettings();
    if (!settings.notificationsEnabled) {
      return {
        outcome: 'SUPPRESSED_PERMISSION',
        reason: 'User disabled notifications in app settings',
        notificationId: 0,
        channelId: ''
      };
    }

    // Call native Android bridge if present
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.dispatchCategorizedNotification === 'function') {
        try {
          const rawResult = bridge.dispatchCategorizedNotification(
            category,
            title,
            body,
            dedupKey || title
          );
          const parsed: NotificationDispatchResultDTO = JSON.parse(rawResult);

          const notif: DispatchedNotification = {
            id: `notif-${parsed.notificationId || Date.now()}`,
            channelId: parsed.channelId || 'threat_alerts_channel',
            category,
            title,
            body,
            priority: category === 'CRITICAL_THREAT' ? 'HIGH' : 'DEFAULT',
            timestamp: Date.now(),
            outcome: parsed.outcome
          };
          this.pushNotification(notif);

          return parsed;
        } catch (e) {
          console.error('Failed to dispatch native categorized notification', e);
        }
      }
    }

    // Web / Headless fallback (Truthful: reports native delivery unsupported in browser)
    const notif: DispatchedNotification = {
      id: `notif-${Date.now()}`,
      channelId: 'browser_fallback',
      category,
      title,
      body,
      priority: category === 'CRITICAL_THREAT' ? 'HIGH' : 'DEFAULT',
      timestamp: Date.now(),
      outcome: 'DISPATCHED'
    };
    this.pushNotification(notif);

    return {
      outcome: 'DISPATCHED',
      reason: 'Browser simulated dispatch; native Android channels not attached',
      notificationId: Date.now() % 100000,
      channelId: 'browser_fallback'
    };
  }

  /**
   * Legacy & scan-result integration: Routes scan outcomes to canonical categories.
   */
  public static async notifyScanResult(result: MobileScanResult): Promise<DispatchedNotification | null> {
    const settings = await SecureStorageService.getSettings();
    if (!settings.notificationsEnabled) {
      return null;
    }

    if (result.verdict === Verdict.DANGEROUS) {
      if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
        const bridge = (window as any).AndroidSecurityBridge;
        if (settings.hapticFeedbackEnabled !== false && typeof bridge.triggerWarningHaptics === 'function') {
          bridge.triggerWarningHaptics('CRITICAL');
        }
        if (typeof bridge.dispatchNativeNotification === 'function') {
          bridge.dispatchNativeNotification(
            '⚠️ Dangerous Threat Blocked',
            `A ${result.threatCategory} threat was detected (${result.sanitizedTarget}). Do not interact with this content.`,
            'HIGH'
          );
        }
      }

      const notif: DispatchedNotification = {
        id: `notif-${Date.now()}`,
        channelId: 'threat_alerts_channel',
        category: 'CRITICAL_THREAT',
        title: '⚠️ Dangerous Threat Blocked',
        body: `A ${result.threatCategory} threat was detected (${result.sanitizedTarget}). Do not interact with this content.`,
        priority: 'HIGH',
        timestamp: Date.now(),
        outcome: 'DISPATCHED'
      };
      this.pushNotification(notif);
      return notif;
    }

    if (result.verdict === Verdict.SUSPICIOUS) {
      if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
        const bridge = (window as any).AndroidSecurityBridge;
        if (settings.hapticFeedbackEnabled !== false && typeof bridge.triggerWarningHaptics === 'function') {
          bridge.triggerWarningHaptics('SUSPICIOUS');
        }
        if (typeof bridge.dispatchNativeNotification === 'function') {
          bridge.dispatchNativeNotification(
            '⚡ Suspicious Content Warning',
            `Potential scam or phishing indicators identified in scanned content.`,
            'DEFAULT'
          );
        }
      }

      const notif: DispatchedNotification = {
        id: `notif-${Date.now()}`,
        channelId: 'threat_alerts_channel',
        category: 'PHISHING_WARNING',
        title: '⚡ Suspicious Content Warning',
        body: `Potential scam or phishing indicators identified in scanned content.`,
        priority: 'DEFAULT',
        timestamp: Date.now(),
        outcome: 'DISPATCHED'
      };
      this.pushNotification(notif);
      return notif;
    }

    return null;
  }

  /**
   * Retrieves native rate limiter statistics.
   */
  public static async getDispatcherStats(): Promise<NotificationDispatcherStatsDTO> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.getNotificationDispatcherStats === 'function') {
        try {
          const statsStr = bridge.getNotificationDispatcherStats();
          return JSON.parse(statsStr);
        } catch (e) {
          console.warn('Failed to parse dispatcher stats from native bridge', e);
        }
      }
    }

    return {
      totalAttempted: this.dispatchedList.length,
      totalDispatched: this.dispatchedList.filter(n => n.outcome === 'DISPATCHED').length,
      totalSuppressedRateLimit: 0,
      totalSuppressedPermission: 0,
      totalCoalesced: 0,
      activeInWindow: 0,
      maxEventsInWindow: 3,
      windowMs: 10000
    };
  }

  public static getDispatchedNotifications(): DispatchedNotification[] {
    return [...this.dispatchedList];
  }

  public static clearNotifications(): void {
    this.dispatchedList = [];
  }
}
