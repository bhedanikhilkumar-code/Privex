import { ClientScanner } from '../scanner/client-scanner';
import { UserPreferences } from '../scanner/types';

/**
 * DETECTION WEB WORKER
 *
 * Executes CPU-intensive lexical, heuristic, and assistant synthesis off the main browser thread.
 * Guarantees zero UI freezing, 60fps animations, and zero server network requests.
 */

const scanner = new ClientScanner();

self.addEventListener('message', async (event: MessageEvent) => {
  const { id, type, payload } = event.data || {};

  try {
    if (type === 'SCAN_URL') {
      const { url, prefs } = payload as { url: string; prefs?: UserPreferences };
      const result = await scanner.scanUrl(url, prefs);
      self.postMessage({ id, type: 'SCAN_RESULT', result });
    } else if (type === 'SCAN_TEXT') {
      const { text, prefs } = payload as { text: string; prefs?: UserPreferences };
      const result = await scanner.scanText(text, prefs);
      self.postMessage({ id, type: 'SCAN_RESULT', result });
    } else {
      self.postMessage({ id, type: 'SCAN_ERROR', error: `UnknownWorkerMessageType: ${type}` });
    }
  } catch (err: any) {
    self.postMessage({
      id,
      type: 'SCAN_ERROR',
      error: err?.message || 'WorkerScanExecutionError'
    });
  }
});
