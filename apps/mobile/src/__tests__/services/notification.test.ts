import { describe, it, expect, beforeEach } from 'vitest';
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
    expect(notif?.channelId).toBe('threat_alerts');
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
});
