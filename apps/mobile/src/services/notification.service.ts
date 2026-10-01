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
  private static dispatchedList: DispatchedNotification[] = [];

  public static async notifyScanResult(result: MobileScanResult): Promise<DispatchedNotification | null> {
    const settings = await SecureStorageService.getSettings();
    if (!settings.notificationsEnabled) {
      return null;
    }

    if (result.verdict === Verdict.DANGEROUS) {
      const notif: DispatchedNotification = {
        id: `notif-${Date.now()}`,
        channelId: 'threat_alerts',
        title: '⚠️ Dangerous Threat Blocked',
        body: `A ${result.threatCategory} threat was detected (${result.sanitizedTarget}). Do not interact with this content.`,
        priority: 'HIGH',
        timestamp: Date.now()
      };
      this.dispatchedList.push(notif);
      return notif;
    }

    if (result.verdict === Verdict.SUSPICIOUS) {
      const notif: DispatchedNotification = {
        id: `notif-${Date.now()}`,
        channelId: 'threat_alerts',
        title: '⚡ Suspicious Content Warning',
        body: `Potential scam or phishing indicators identified in scanned content.`,
        priority: 'DEFAULT',
        timestamp: Date.now()
      };
      this.dispatchedList.push(notif);
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
