import { NavigationInterceptor } from './navigation-interceptor';
import { MessageRouter } from './message-router';
import { ExtensionStorage } from '../shared/storage';

const interceptor = new NavigationInterceptor();
const router = new MessageRouter(interceptor);

// 1. Pre-Navigation Interceptor (Main-Frame Navigations)
if (typeof chrome !== 'undefined' && chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only inspect top-level main frame navigations (frameId 0)
    if (details.frameId !== 0) return;

    try {
      const evaluation = await interceptor.evaluateUrl(details.tabId, details.url);

      if ((evaluation.action === 'BLOCK' || evaluation.action === 'WARN') && evaluation.redirectUrl) {
        chrome.tabs.update(details.tabId, { url: evaluation.redirectUrl });
      }
    } catch (err) {
      // Fail-closed/safe: do not crash background service worker
      console.error('[Private Protection Background] Navigation scan error:', err);
    }
  });
}

// 2. Message Dispatcher
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    router
      .handleMessage(message, sender)
      .then((response) => sendResponse(response))
      .catch((err) => sendResponse({ success: false, error: err?.message || 'Router execution error' }));

    // Keep message channel open for async response
    return true;
  });
}

// 3. Tab Cleanup
if (typeof chrome !== 'undefined' && chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    ExtensionStorage.clearTabState(tabId).catch(() => {});
  });
}

export { interceptor, router };
