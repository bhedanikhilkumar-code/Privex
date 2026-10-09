import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NotificationService } from '../../services/notification.service';
import { SecureStorageService } from '../../services/secure-storage.service';
import { Verdict, SeverityLevel, ActionRecommendation, FrictionLevel } from '@private-protection/core';
import { MobileScanResult } from '../../types/mobile.types';

describe('NotificationService (Security Alerts & Channels)', () => {
  beforeEach(async () => {
    NotificationService.clearNotifications();
    await SecureStorageService.saveSettings({ notificationsEnabled: true });
  });

  const baseResult: MobileScanResult = {
    scanId: 'sc-1',
    targetType: 'URL',
    rawInput: 'http://test.com',
    sanitizedTarget: 'test.com',
    verdict: Verdict.ALLOW,
    overallScore: 10,
    severity: SeverityLevel.NONE,
    confidence: 0.95,
    threatCategory: 'NONE',
    evidence: [],
    recommendation: { action: ActionRecommendation.ALLOW, frictionLevel: FrictionLevel.NONE, suggestedAction: 'Proceed', bypassPermitted: true },
    timestamp: Date.now(),
    overridden: false,
    executionTimeMs: 1
  };

  it('dispatches a high-priority notification for dangerous threats', async () => {
    const dangerous = {
      ...baseResult,
      verdict: Verdict.DANGEROUS,
      threatCategory: 'MALICIOUS_PHISH',
      overallScore: 90
    };

    const notif = await NotificationService.notifyScanResult(dangerous);
    expect(notif).not.toBeNull();
    expect(notif?.channelId).toBe('threat_alerts_channel');
    expect(notif?.priority).toBe('HIGH');
    expect(notif?.title).toContain('Dangerous Threat Blocked');
  });

  it('dispatches a default priority alert for suspicious threats', async () => {
    const suspicious = {
      ...baseResult,
      verdict: Verdict.SUSPICIOUS,
      overallScore: 65
    };

    const notif = await NotificationService.notifyScanResult(suspicious);
    expect(notif).not.toBeNull();
    expect(notif?.priority).toBe('DEFAULT');
  });

  it('does not dispatch notifications for safe allowed verdicts', async () => {
    const notif = await NotificationService.notifyScanResult(baseResult);
    expect(notif).toBeNull();
    expect(NotificationService.getDispatchedNotifications().length).toBe(0);
  });

  it('respects user disabling notifications in settings', async () => {
    await SecureStorageService.saveSettings({ notificationsEnabled: false });

    const dangerous = {
      ...baseResult,
      verdict: Verdict.DANGEROUS
    };

    const notif = await NotificationService.notifyScanResult(dangerous);
    expect(notif).toBeNull();
  });

  it('invokes native Android bridge haptics and dispatchNotification when available', async () => {
    const triggerWarningHaptics = vi.fn();
    const dispatchNativeNotification = vi.fn().mockReturnValue(true);

    (window as any).AndroidSecurityBridge = {
      triggerWarningHaptics,
      dispatchNativeNotification
    };

    const dangerous = {
      ...baseResult,
      verdict: Verdict.DANGEROUS,
      threatCategory: 'CRYPTO_EXTORTION',
      overallScore: 95
    };

    const notif = await NotificationService.notifyScanResult(dangerous);
    expect(notif).not.toBeNull();
    expect(triggerWarningHaptics).toHaveBeenCalledWith('CRITICAL');
    expect(dispatchNativeNotification).toHaveBeenCalledWith(
      expect.stringContaining('Dangerous Threat Blocked'),
      expect.stringContaining('CRYPTO_EXTORTION'),
      'HIGH'
    );

    delete (window as any).AndroidSecurityBridge;
  });

  it('respects hapticFeedbackEnabled=false while still dispatching notification (DEFECT-ANDROID-01)', async () => {
    await SecureStorageService.saveSettings({
      notificationsEnabled: true,
      hapticFeedbackEnabled: false
    });

    const triggerWarningHaptics = vi.fn();
    const dispatchNativeNotification = vi.fn().mockReturnValue(true);

    (window as any).AndroidSecurityBridge = {
      triggerWarningHaptics,
      dispatchNativeNotification
    };

    const dangerous = {
      ...baseResult,
      verdict: Verdict.DANGEROUS,
      threatCategory: 'CREDENTIAL_PHISHING',
      overallScore: 92
    };

    const notif = await NotificationService.notifyScanResult(dangerous);
    expect(notif).not.toBeNull();
    expect(triggerWarningHaptics).not.toHaveBeenCalled();
    expect(dispatchNativeNotification).toHaveBeenCalled();

    delete (window as any).AndroidSecurityBridge;
  });

  // ==========================================
  // PHASE T13: CATEGORIZED DISPATCH & STATS
  // ==========================================

  it('dispatches categorized notifications across all seven canonical categories', async () => {
    const categories: Array<'CRITICAL_THREAT' | 'APP_INSTALL_WARNING' | 'DOWNLOAD_BLOCKED' | 'PHISHING_WARNING' | 'SCAN_COMPLETE' | 'PROTECTION_DEGRADED' | 'UPDATE_AVAILABLE'> = [
      'CRITICAL_THREAT',
      'APP_INSTALL_WARNING',
      'DOWNLOAD_BLOCKED',
      'PHISHING_WARNING',
      'SCAN_COMPLETE',
      'PROTECTION_DEGRADED',
      'UPDATE_AVAILABLE'
    ];

    for (const cat of categories) {
      const res = await NotificationService.dispatchCategory(cat, `Title for ${cat}`, `Body for ${cat}`);
      expect(res.outcome).toBe('DISPATCHED');
    }

    const list = NotificationService.getDispatchedNotifications();
    expect(list.length).toBe(7);
  });

  it('delegates to native bridge dispatchCategorizedNotification when available', async () => {
    const dispatchCategorizedNotification = vi.fn().mockReturnValue(JSON.stringify({
      outcome: 'DISPATCHED',
      reason: 'Dispatched successfully',
      notificationId: 12345,
      channelId: 'threat_alerts_channel'
    }));

    (window as any).AndroidSecurityBridge = {
      dispatchCategorizedNotification
    };

    const res = await NotificationService.dispatchCategory(
      'CRITICAL_THREAT',
      'Malware Alert',
      'Trojan detected'
    );

    expect(dispatchCategorizedNotification).toHaveBeenCalledWith(
      'CRITICAL_THREAT',
      'Malware Alert',
      'Trojan detected',
      'Malware Alert'
    );
    expect(res.outcome).toBe('DISPATCHED');
    expect(res.notificationId).toBe(12345);

    delete (window as any).AndroidSecurityBridge;
  });

  it('fetches dispatcher stats from native bridge', async () => {
    const mockStats = {
      totalAttempted: 10,
      totalDispatched: 3,
      totalSuppressedRateLimit: 7,
      totalSuppressedPermission: 0,
      totalCoalesced: 1,
      activeInWindow: 3,
      maxEventsInWindow: 3,
      windowMs: 10000
    };

    (window as any).AndroidSecurityBridge = {
      getNotificationDispatcherStats: vi.fn().mockReturnValue(JSON.stringify(mockStats))
    };

    const stats = await NotificationService.getDispatcherStats();
    expect(stats.totalAttempted).toBe(10);
    expect(stats.totalDispatched).toBe(3);
    expect(stats.totalSuppressedRateLimit).toBe(7);
    expect(stats.totalCoalesced).toBe(1);

    delete (window as any).AndroidSecurityBridge;
  });
});
