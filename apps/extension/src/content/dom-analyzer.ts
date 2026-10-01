import { PageDomSignals } from '../shared/types';

export class DomAnalyzer {
  public static extractSignals(doc: Document = document, win: Window = window): PageDomSignals {
    let hasPasswordInput = false;
    let formActionUrl: string | undefined = undefined;
    let isFormInsecure = false;
    let isCrossOriginAction = false;
    let hasHiddenIframes = false;

    const currentOrigin = win.location.origin;
    const forms = doc.querySelectorAll('form');

    for (const form of Array.from(forms)) {
      const passwordField = form.querySelector('input[type="password"]');
      if (passwordField) {
        hasPasswordInput = true;
        const rawAction = form.getAttribute('action') || '';

        try {
          // Resolve relative actions to full URL
          const resolvedAction = new URL(rawAction, win.location.href);
          formActionUrl = resolvedAction.href;

          // Check if target is plaintext HTTP (while page or form requires secure submission)
          if (resolvedAction.protocol === 'http:' && !resolvedAction.hostname.includes('localhost')) {
            isFormInsecure = true;
          }

          // Check cross-origin form action
          if (resolvedAction.origin !== currentOrigin) {
            isCrossOriginAction = true;
          }
        } catch {
          // Insecure or malformed action
          if (rawAction.toLowerCase().startsWith('http://')) {
            isFormInsecure = true;
          }
        }
      }
    }

    // Inspect for deceptive clickjacking / hidden iframe overlays
    const iframes = doc.querySelectorAll('iframe');
    for (const iframe of Array.from(iframes)) {
      const style = win.getComputedStyle(iframe);
      const isHiddenOverlay =
        (style.position === 'fixed' || style.position === 'absolute') &&
        (parseFloat(style.opacity) < 0.1 || style.visibility === 'hidden') &&
        (parseInt(style.zIndex, 10) > 100);

      if (isHiddenOverlay) {
        hasHiddenIframes = true;
        break;
      }
    }

    return {
      hasPasswordInput,
      formActionUrl,
      isFormInsecure,
      isCrossOriginAction,
      hasHiddenIframes,
      detectedFormsCount: forms.length,
      title: doc.title ? doc.title.substring(0, 100) : ''
    };
  }
}
