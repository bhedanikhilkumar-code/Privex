import { DomAnalyzer } from './dom-analyzer';
import { ShadowBanner } from './shadow-banner';
import { MessageType, createMessage } from '../shared/messages';

function scanDomAndReport() {
  try {
    const signals = DomAnalyzer.extractSignals(document, window);

    // Only dispatch message if significant DOM signals exist (reduces IPC overhead)
    if (signals.hasPasswordInput || signals.hasHiddenIframes) {
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        const message = createMessage(MessageType.REPORT_DOM_SIGNALS, signals);
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) return;
          if (response?.actionRequired === 'SHOW_SHADOW_BANNER') {
            ShadowBanner.showInsecurePasswordWarning(signals.formActionUrl);
          }
        });
      }
    }
  } catch (err) {
    // Fail silently in content script to prevent website script interference
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scanDomAndReport);
} else {
  scanDomAndReport();
}

export { scanDomAndReport };
