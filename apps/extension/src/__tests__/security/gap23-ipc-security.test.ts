import { describe, it, expect, beforeEach } from 'vitest';
import { MessageType, createMessage } from '../../shared/messages';
import { MessageRouter } from '../../background/message-router';
import { NavigationInterceptor } from '../../background/navigation-interceptor';
import { ExtensionStorage } from '../../shared/storage';
import * as fs from 'fs';
import * as path from 'path';

describe('GAP-23 & SEC-05: Extension Privileged Origin Validation & CSP Hardening', () => {
  let router: MessageRouter;

  beforeEach(async () => {
    await ExtensionStorage.clearAllStorage();
    const interceptor = new NavigationInterceptor();
    router = new MessageRouter(interceptor);
  });

  describe('GAP-23: MessageRouter Privileged Origin Validation', () => {
    it('allows UPDATE_SETTINGS from trusted extension context (no tab, e.g. popup)', async () => {
      const msg = createMessage(MessageType.UPDATE_SETTINGS, { enabled: false });
      const trustedSender = {}; // No sender.tab means direct extension UI context

      const res = await router.handleMessage(msg, trustedSender as any);
      expect(res.success).toBe(true);

      const settings = await ExtensionStorage.getSettings();
      expect(settings.enabled).toBe(false);
    });

    it('rejects UPDATE_SETTINGS from untrusted content script (web tab origin)', async () => {
      const msg = createMessage(MessageType.UPDATE_SETTINGS, { enabled: false });
      const untrustedSender = {
        tab: { id: 101 },
        url: 'https://evil-phishing-site.com/exploit.html'
      };

      const res = await router.handleMessage(msg, untrustedSender as any);
      expect(res.success).toBe(false);
      expect(res.error).toContain('Unauthorized');

      const settings = await ExtensionStorage.getSettings();
      expect(settings.enabled).toBe(true); // Must remain untouched
    });

    it('rejects CLEAR_ALL_DATA from untrusted content script', async () => {
      const msg = createMessage(MessageType.CLEAR_ALL_DATA, {});
      const untrustedSender = {
        tab: { id: 102 },
        url: 'https://compromised-site.com/attack'
      };

      const res = await router.handleMessage(msg, untrustedSender as any);
      expect(res.success).toBe(false);
      expect(res.error).toContain('Unauthorized');
    });

    it('allows CLEAR_ALL_DATA from trusted extension options page', async () => {
      const msg = createMessage(MessageType.CLEAR_ALL_DATA, {});
      const trustedSender = {
        tab: { id: 99 },
        url: 'chrome-extension://my-extension-id/options.html'
      };

      const res = await router.handleMessage(msg, trustedSender as any);
      expect(res.success).toBe(true);
    });

    it('rejects REQUEST_OVERRIDE from untrusted content script', async () => {
      await ExtensionStorage.setTabState(105, {
        tabId: 105,
        url: 'https://malicious-bank.com',
        domain: 'malicious-bank.com',
        verdict: 'DANGEROUS' as any,
        overallScore: 95,
        severity: 'CRITICAL' as any,
        confidence: 0.99,
        threatCategory: 'PHISHING',
        evidence: [],
        recommendation: { action: 'BLOCK' as any, frictionLevel: 'HIGH' as any, suggestedAction: 'Block', bypassPermitted: false },
        timestamp: Date.now(),
        overridden: false
      });

      const msg = createMessage(MessageType.REQUEST_OVERRIDE, {
        tabId: 105,
        targetUrl: 'https://malicious-bank.com'
      });
      const untrustedSender = {
        tab: { id: 105 },
        url: 'https://malicious-bank.com/exploit'
      };

      const res = await router.handleMessage(msg, untrustedSender as any);
      expect(res.success).toBe(false);
      expect(res.error).toContain('Unauthorized');

      const state = await ExtensionStorage.getTabState(105);
      expect(state?.overridden).toBe(false);
    });

    it('allows REQUEST_OVERRIDE from extension interstitial page matching tabId', async () => {
      await ExtensionStorage.setTabState(106, {
        tabId: 106,
        url: 'https://malicious-bank.com',
        domain: 'malicious-bank.com',
        verdict: 'DANGEROUS' as any,
        overallScore: 95,
        severity: 'CRITICAL' as any,
        confidence: 0.99,
        threatCategory: 'PHISHING',
        evidence: [],
        recommendation: { action: 'BLOCK' as any, frictionLevel: 'HIGH' as any, suggestedAction: 'Block', bypassPermitted: false },
        timestamp: Date.now(),
        overridden: false
      });

      const msg = createMessage(MessageType.REQUEST_OVERRIDE, {
        tabId: 106,
        targetUrl: 'https://malicious-bank.com'
      });
      const interstitialSender = {
        tab: { id: 106 },
        url: 'chrome-extension://my-extension-id/interstitial.html?tabId=106'
      };

      const res = await router.handleMessage(msg, interstitialSender as any);
      expect(res.success).toBe(true);
      expect(res.proceedUrl).toBe('https://malicious-bank.com');

      const state = await ExtensionStorage.getTabState(106);
      expect(state?.overridden).toBe(true);
    });

    it('rejects REQUEST_OVERRIDE if interstitial tabId does not match target tabId', async () => {
      const msg = createMessage(MessageType.REQUEST_OVERRIDE, {
        tabId: 200,
        targetUrl: 'https://target.com'
      });
      const mismatchedSender = {
        tab: { id: 107 }, // Tab 107 trying to override Tab 200
        url: 'chrome-extension://my-extension-id/interstitial.html?tabId=107'
      };

      const res = await router.handleMessage(msg, mismatchedSender as any);
      expect(res.success).toBe(false);
      expect(res.error).toContain('Mismatched tabId');
    });
  });

  describe('SEC-05: Extension CSP Audit', () => {
    it('enforces connect-src none and object-src none in manifest.json', () => {
      const manifestPath = path.resolve(__dirname, '../../../manifest.json');
      const manifestContent = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      const csp = manifestContent.content_security_policy?.extension_pages || '';

      expect(csp).toContain("connect-src 'none'");
      expect(csp).toContain("object-src 'none'");
      expect(csp).not.toContain("object-src 'self'");
    });
  });
});
