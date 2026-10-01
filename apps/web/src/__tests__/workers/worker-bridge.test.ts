import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { WorkerBridge } from '../../workers/worker-bridge';
import { UserPreferences } from '../../scanner/types';
import { Verdict } from '@private-protection/core';

describe('WorkerBridge (Web Worker Dispatcher & Main-Thread Fallback)', () => {
  let bridge: WorkerBridge;
  const mockPrefs: UserPreferences = {
    cognitiveReadingGrade: 6,
    enableWorkerOffloading: true,
    allowlistDomains: []
  };

  beforeEach(() => {
    bridge = new WorkerBridge();
  });

  afterEach(() => {
    bridge.terminate();
  });

  it('scans URLs safely via in-thread fallback when Worker is simulated as unavailable', async () => {
    const result = await bridge.scanUrl('http://192.168.1.1/login.php', mockPrefs);

    expect(result.id).toBeDefined();
    expect(result.scanType).toBe('URL');
    expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
    expect(result.overallScore).toBeGreaterThanOrEqual(75);
    expect(result.privacyGuarantee).toContain('100% processed on-device');
  });

  it('scans text messages safely via in-thread fallback', async () => {
    const scamText = 'URGENT: Verify your bank password now or your account will be frozen permanently!';
    const result = await bridge.scanText(scamText, mockPrefs);

    expect(result.id).toBeDefined();
    expect(result.scanType).toBe('TEXT');
    expect(result.overallScore).toBeGreaterThanOrEqual(50);
    expect(result.aiExplanation?.headline).toBeDefined();
  });

  it('handles empty inputs safely without crashing', async () => {
    const result = await bridge.scanUrl('', mockPrefs);
    expect(result.verdict).toBe(Verdict.DANGEROUS);
    expect(result.overallScore).toBe(100);
  });

  it('dispatches to real Worker when available and offloading enabled', async () => {
    class MockWorker {
      listeners: Record<string, Function[]> = {};
      postMessage(data: any) {
        setTimeout(() => {
          this.listeners['message']?.forEach(cb =>
            cb({
              data: {
                id: data.id,
                type: 'SCAN_RESULT',
                result: {
                  id: 'mock-worker-res',
                  scanType: data.type === 'SCAN_URL' ? 'URL' : 'TEXT',
                  verdict: Verdict.ALLOW,
                  overallScore: 0,
                  severity: 'NONE',
                  confidence: 0.99,
                  threatCategory: 'NONE',
                  matchedRules: [],
                  evidenceList: [],
                  executionTimeMs: 1,
                  privacyGuarantee: '100% processed on-device in isolated volatile RAM'
                }
              }
            })
          );
        }, 5);
      }
      addEventListener(event: string, cb: Function) {
        this.listeners[event] = this.listeners[event] || [];
        this.listeners[event].push(cb);
      }
      terminate = vi.fn();
    }

    const origWorker = (global as any).Worker;
    (global as any).Worker = MockWorker;

    try {
      const workerBridge = new WorkerBridge();
      const res = await workerBridge.scanUrl('https://example.com', {
        cognitiveReadingGrade: 6,
        enableWorkerOffloading: true,
        allowlistDomains: []
      });

      expect(res.id).toBe('mock-worker-res');

      const textRes = await workerBridge.scanText('hello safe world', {
        cognitiveReadingGrade: 6,
        enableWorkerOffloading: true,
        allowlistDomains: []
      });
      expect(textRes.id).toBe('mock-worker-res');

      workerBridge.terminate();
    } finally {
      (global as any).Worker = origWorker;
    }
  });

  it('handles worker error events by rejecting pending requests', async () => {
    let capturedErrorListener: Function | undefined;

    class FailingWorker {
      addEventListener(event: string, cb: Function) {
        if (event === 'error') capturedErrorListener = cb;
      }
      postMessage() {
        setTimeout(() => {
          if (capturedErrorListener) {
            capturedErrorListener({ message: 'SimulatedWorkerCrash' });
          }
        }, 5);
      }
      terminate = vi.fn();
    }

    const origWorker = (global as any).Worker;
    (global as any).Worker = FailingWorker;

    try {
      const workerBridge = new WorkerBridge();
      await expect(
        workerBridge.scanUrl('https://example.com', {
          cognitiveReadingGrade: 6,
          enableWorkerOffloading: true,
          allowlistDomains: []
        })
      ).rejects.toThrow('SimulatedWorkerCrash');
    } finally {
      (global as any).Worker = origWorker;
    }
  });
});
