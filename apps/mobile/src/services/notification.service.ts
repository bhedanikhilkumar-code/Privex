import { MobileScanResult } from '../types/mobile.types';
import { Verdict } from '@private-protection/core';
import { SecureStorageService } from './secure-storage.service';

export interface DispatchedNotification {
  id: string;
  channelId: string;
  title: string;
  body: string;
  priority: 'HIGH' | 'DEFAULT' | 'LOW';
  timestamp: number;
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
        channelId: 'threat_alerts',
        title: '⚠️ Dangerous Threat Blocked',
        body: `A ${result.threatCategory} threat was detected (${result.sanitizedTarget}). Do not interact with this content.`,
        priority: 'HIGH',
        timestamp: Date.now()
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
        channelId: 'threat_alerts',
        title: '⚡ Suspicious Content Warning',
        body: `Potential scam or phishing indicators identified in scanned content.`,
        priority: 'DEFAULT',
        timestamp: Date.now()
      };
      this.pushNotification(notif);
      return notif;
    }

    return null;
  }

  public static getDispatchedNotifications(): DispatchedNotification[] {
    return [...this.dispatchedList];
  }

  public static clearNotifications(): void {
    this.dispatchedList = [];
  }
}
