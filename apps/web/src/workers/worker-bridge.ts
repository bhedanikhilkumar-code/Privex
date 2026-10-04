import { ClientScanner } from '../scanner/client-scanner';
import { ScanResultViewData, UserPreferences } from '../scanner/types';

export class WorkerBridge {
  private fallbackScanner?: ClientScanner;
  private worker?: Worker;
  private pendingRequests: Map<
    string,
    {
      resolve: (val: ScanResultViewData) => void;
      reject: (err: any) => void;
      timeoutId: ReturnType<typeof setTimeout>;
    }
  >;
  private workerAvailable: boolean;

  constructor() {
    this.pendingRequests = new Map();
    this.workerAvailable = false;

    // In modern browser environments, check Worker availability
    if (typeof window !== 'undefined' && typeof Worker !== 'undefined') {
      try {
        this.worker = new Worker(
          new URL('./detection-worker.ts', import.meta.url),
          { type: 'module' }
        );
        this.worker.addEventListener('message', this.handleWorkerMessage.bind(this));
        this.worker.addEventListener('error', this.handleWorkerError.bind(this));
        this.workerAvailable = true;
      } catch {
        // Fallback to in-thread direct scanning
        this.workerAvailable = false;
      }
    }
  }

  private getFallbackScanner(): ClientScanner {
    if (!this.fallbackScanner) {
      this.fallbackScanner = new ClientScanner();
    }
    return this.fallbackScanner;
  }

  public async scanUrl(url: string, prefs?: UserPreferences): Promise<ScanResultViewData> {
    if (!this.workerAvailable || prefs?.enableWorkerOffloading === false) {
      return this.getFallbackScanner().scanUrl(url, prefs);
    }

    return this.dispatchToWorker('SCAN_URL', { url, prefs });
  }

  public async scanText(text: string, prefs?: UserPreferences): Promise<ScanResultViewData> {
    if (!this.workerAvailable || prefs?.enableWorkerOffloading === false) {
      return this.getFallbackScanner().scanText(text, prefs);
    }

    return this.dispatchToWorker('SCAN_TEXT', { text, prefs });
  }

  private dispatchToWorker(type: 'SCAN_URL' | 'SCAN_TEXT', payload: any): Promise<ScanResultViewData> {
    const id = `req-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

    return new Promise<ScanResultViewData>((resolve, reject) => {
      // 5-second worker timeout safety boundary
      const timeoutId = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          // Fallback to in-thread scan if worker stalls
          const fallback = this.getFallbackScanner();
          if (type === 'SCAN_URL') {
            fallback.scanUrl(payload.url, payload.prefs).then(resolve).catch(reject);
          } else {
            fallback.scanText(payload.text, payload.prefs).then(resolve).catch(reject);
          }
        }
      }, 5000);

      this.pendingRequests.set(id, {
        timeoutId,
        resolve: (val) => {
          clearTimeout(timeoutId);
          resolve(val);
        },
        reject: (err) => {
          clearTimeout(timeoutId);
          reject(err);
        }
      });

      this.worker?.postMessage({ id, type, payload });
    });
  }

  private handleWorkerMessage(event: MessageEvent): void {
    const { id, type, result, error } = event.data || {};
    const pending = this.pendingRequests.get(id);

    if (pending) {
      this.pendingRequests.delete(id);
      if (type === 'SCAN_RESULT' && result) {
        pending.resolve(result);
      } else {
        pending.reject(new Error(error || 'WorkerExecutionError'));
      }
    }
  }

  private handleWorkerError(err: ErrorEvent): void {
    // Stash error and fail over pending to main thread
    for (const [id, req] of this.pendingRequests.entries()) {
      clearTimeout(req.timeoutId);
      req.reject(new Error(err.message || 'WorkerCrashedError'));
      this.pendingRequests.delete(id);
    }
  }

  public terminate(): void {
    for (const [, req] of this.pendingRequests.entries()) {
      clearTimeout(req.timeoutId);
    }
    this.pendingRequests.clear();
    if (this.worker) {
      this.worker.terminate();
      this.worker = undefined;
      this.workerAvailable = false;
    }
  }
}
