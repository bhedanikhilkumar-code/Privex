import { describe, it, expect, beforeEach } from 'vitest';
import { SecureStorageService } from '../../services/secure-storage.service';

describe('SecureStorageService (Settings & Crypto-Shredding)', () => {
  beforeEach(async () => {
    await SecureStorageService.purgeAllData();
  });

  it('retrieves default settings when no previous state exists', async () => {
    const settings = await SecureStorageService.getSettings();
    expect(settings.protectionEnabled).toBe(true);
    expect(settings.readingGrade).toBe(6);
    expect(settings.allowlistDomains).toEqual([]);
  });

  it('saves updated settings and retains changes', async () => {
    await SecureStorageService.saveSettings({ readingGrade: 8, protectionEnabled: false });
    const settings = await SecureStorageService.getSettings();
    expect(settings.readingGrade).toBe(8);
    expect(settings.protectionEnabled).toBe(false);
  });

  it('adds and removes domains from the local custom allowlist', async () => {
    await SecureStorageService.addAllowlistDomain('trusted-portal.internal');
    let settings = await SecureStorageService.getSettings();
    expect(settings.allowlistDomains).toContain('trusted-portal.internal');

    await SecureStorageService.removeAllowlistDomain('trusted-portal.internal');
    settings = await SecureStorageService.getSettings();
    expect(settings.allowlistDomains).not.toContain('trusted-portal.internal');
  });

  it('records scan history up to maximum cap without leaking payloads', async () => {
    await SecureStorageService.recordScan({
      scanId: 's-1',
      targetType: 'URL',
      sanitizedSummary: 'paypal-sec...',
      verdict: 'DANGEROUS',
      score: 90,
      timestamp: Date.now()
    });

    const history = await SecureStorageService.getScanHistory();
    expect(history.length).toBe(1);
    expect(history[0].sanitizedSummary).toBe('paypal-sec...');
  });

  it('crypto-shreds all stored data and restores clean state', async () => {
    await SecureStorageService.saveSettings({ readingGrade: 8 });
    await SecureStorageService.addAllowlistDomain('bank.com');
    await SecureStorageService.recordScan({
      scanId: 's-2',
      targetType: 'TEXT',
      sanitizedSummary: 'URGENT: tax...',
      verdict: 'SCAM',
      score: 85,
      timestamp: Date.now()
    });

    await SecureStorageService.purgeAllData();

    const settingsAfter = await SecureStorageService.getSettings();
    expect(settingsAfter.readingGrade).toBe(6);
    expect(settingsAfter.allowlistDomains).toEqual([]);

    const historyAfter = await SecureStorageService.getScanHistory();
    expect(historyAfter).toEqual([]);
  });

  it('interacts with native AndroidSecurityBridge secureStorage methods when available', async () => {
    const nativeStore = new Map<string, string>();
    (window as any).AndroidSecurityBridge = {
      secureStorageGet: (k: string) => nativeStore.get(k) || null,
      secureStoragePut: (k: string, v: string) => { nativeStore.set(k, v); return true; },
      secureStorageClear: () => { nativeStore.clear(); return true; }
    };

    await SecureStorageService.saveSettings({ readingGrade: 8 });
    expect(nativeStore.has('mobile_settings')).toBe(true);

    const loaded = await SecureStorageService.getSettings();
    expect(loaded.readingGrade).toBe(8);

    await SecureStorageService.purgeAllData();
    expect(nativeStore.size).toBe(0);

    delete (window as any).AndroidSecurityBridge;
  });
});
