import {
  MessageType,
  validateInboundMessage
} from '../shared/messages';
import { ExtensionStorage } from '../shared/storage';
import { NavigationInterceptor } from './navigation-interceptor';
import { SeverityLevel, Verdict, Evidence } from '@private-protection/core';

export class MessageRouter {
  constructor(private interceptor: NavigationInterceptor) {}

  private isPrivilegedSender(sender: chrome.runtime.MessageSender): boolean {
    if (!sender) return false;

    // Reject if sender has an ID that does not match our extension
    if (typeof chrome !== 'undefined' && chrome.runtime?.id && sender.id && sender.id !== chrome.runtime.id) {
      return false;
    }

    // Direct extension contexts (e.g. popup, background) have no tab
    if (!sender.tab) {
      return true;
    }

    // If sender is hosted in a tab, verify its URL is an internal extension page
    if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getURL === 'function') {
      const extensionBase = chrome.runtime.getURL('');
      if (sender.url && sender.url.startsWith(extensionBase)) {
        return true;
      }
    }

    if (sender.url && (sender.url.startsWith('chrome-extension://') || sender.url.startsWith('moz-extension://'))) {
      return true;
    }

    return false;
  }

  public async handleMessage(rawMessage: any, sender: chrome.runtime.MessageSender): Promise<any> {
    const validation = validateInboundMessage(rawMessage);
    if (!validation.valid || !validation.message) {
      return { success: false, error: validation.error || 'Invalid message' };
    }

    const { type, payload } = validation.message;

    switch (type) {
      case MessageType.GET_TAB_STATUS: {
        const tabId = payload?.tabId ?? sender.tab?.id;
        if (typeof tabId !== 'number') {
          return { success: false, error: 'Missing tabId' };
        }
        const state = await ExtensionStorage.getTabState(tabId);
        return { success: true, state };
      }

      case MessageType.REPORT_DOM_SIGNALS: {
        const tabId = sender.tab?.id;
        if (typeof tabId !== 'number') {
          return { success: false, error: 'No tab associated with sender' };
        }

        const settings = await ExtensionStorage.getSettings();
        if (!settings.enabled) {
          return { success: true };
        }

        const signals = payload;
        if (signals?.hasPasswordInput && signals?.isFormInsecure) {
          const currentState = await ExtensionStorage.getTabState(tabId);
          if (currentState) {
            // Elevate risk due to insecure password submission over unencrypted HTTP
            const insecureFormEvidence: Evidence = {
              source: 'CONTENT_SCRIPT_DOM',
              name: 'Insecure Password Form Submission',
              indicator: 'insecure-http-password-action',
              type: 'SUSPICIOUS_DOM',
              scoreContribution: 80,
              weight: 80,
              confidence: 0.99,
              description: `Password field transmits credentials over insecure plaintext: ${signals.formActionUrl || 'http://'}`
            };

            const updatedState = {
              ...currentState,
              overallScore: Math.max(currentState.overallScore, 85),
              verdict: Verdict.DANGEROUS,
              severity: SeverityLevel.HIGH,
              threatCategory: 'INSECURE_CREDENTIAL_FORM',
              evidence: [...currentState.evidence, insecureFormEvidence]
            };
            await ExtensionStorage.setTabState(tabId, updatedState);
            return {
              success: true,
              updatedState,
              actionRequired: settings.showShadowDomBanners !== false ? 'SHOW_SHADOW_BANNER' : undefined
            };
          }
        }
        return { success: true };
      }

      case MessageType.REQUEST_OVERRIDE: {
        const { tabId, targetUrl } = payload || {};
        if (typeof tabId !== 'number' || !targetUrl) {
          return { success: false, error: 'Invalid override parameters' };
        }

        // GAP-23: Privileged Origin Validation
        if (!this.isPrivilegedSender(sender)) {
          return { success: false, error: 'Unauthorized: Override requests cannot be initiated by content scripts' };
        }

        // If from internal tab page (e.g. interstitial), sender tab must match requested tabId
        if (sender.tab && typeof sender.tab.id === 'number' && sender.tab.id !== tabId) {
          return { success: false, error: 'Unauthorized: Mismatched tabId for override request' };
        }

        const state = await ExtensionStorage.getTabState(tabId);
        if (state) {
          state.overridden = true;
          await ExtensionStorage.setTabState(tabId, state);
          await ExtensionStorage.addAuditLog({
            id: `audit-${Date.now()}`,
            timestamp: Date.now(),
            action: 'OVERRIDDEN',
            domainPrefix: state.domain.substring(0, 15),
            verdict: state.verdict,
            riskScore: state.overallScore,
            threatCategory: state.threatCategory
          });
        }

        return { success: true, proceedUrl: targetUrl };
      }

      case MessageType.ANALYZE_URL_MANUAL: {
        const { url } = payload || {};
        if (!url || typeof url !== 'string') {
          return { success: false, error: 'Missing URL parameter' };
        }
        const { state } = await this.interceptor.evaluateUrl(-1, url);
        return { success: true, result: state };
      }

      case MessageType.GET_SETTINGS: {
        const settings = await ExtensionStorage.getSettings();
        return { success: true, settings };
      }

      case MessageType.UPDATE_SETTINGS: {
        // GAP-23: Privileged Origin Validation
        if (!this.isPrivilegedSender(sender)) {
          return { success: false, error: 'Unauthorized: Settings can only be updated by extension UI' };
        }
        if (!payload || typeof payload !== 'object') {
          return { success: false, error: 'Invalid settings payload' };
        }
        await ExtensionStorage.saveSettings(payload);
        return { success: true };
      }

      case MessageType.CLEAR_ALL_DATA: {
        // GAP-23: Privileged Origin Validation
        if (!this.isPrivilegedSender(sender)) {
          return { success: false, error: 'Unauthorized: Storage can only be cleared by extension UI' };
        }
        await ExtensionStorage.clearAllStorage();
        return { success: true };
      }

      default:
        return { success: false, error: `Unhandled message type: ${type}` };
    }
  }
}
