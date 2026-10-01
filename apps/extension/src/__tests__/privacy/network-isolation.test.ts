import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NavigationInterceptor } from '../../background/navigation-interceptor';
import { MessageRouter } from '../../background/message-router';
import { MessageType } from '../../shared/messages';

describe('Network Isolation Audit (Extension Real-Time Protection)', () => {
  let fetchSpy: any;
  let xhrOpenSpy: any;
  let beaconSpy: any;

  beforeEach(() => {
    fetchSpy = vi.fn().mockImplementation(() => {
      throw new Error('NETWORK_VIOLATION: fetch() called in zero-cloud extension');
    });
    globalThis.fetch = fetchSpy;

    xhrOpenSpy = vi.fn().mockImplementation(() => {
      throw new Error('NETWORK_VIOLATION: XMLHttpRequest called in zero-cloud extension');
    });
    (globalThis as any).XMLHttpRequest = class {
      open = xhrOpenSpy;
      send = vi.fn();
    };

    beaconSpy = vi.fn();
    if (typeof navigator !== 'undefined') {
      (navigator as any).sendBeacon = beaconSpy;
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('evaluates safe URLs without making any outbound network requests', async () => {
    const interceptor = new NavigationInterceptor();
    await interceptor.evaluateUrl(1, 'https://www.example.com/products');

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('evaluates and blocks dangerous phishing links with zero outbound network calls', async () => {
    const interceptor = new NavigationInterceptor();
    await interceptor.evaluateUrl(2, 'http://192.168.1.1/paypal/security/verify.php');

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('handles message router manual analysis without network leakage', async () => {
    const interceptor = new NavigationInterceptor();
    const router = new MessageRouter(interceptor);

    const msg = {
      id: 'manual-1',
      type: MessageType.ANALYZE_URL_MANUAL,
      payload: { url: 'http://paypa1-urgent-action.buzz' },
      timestamp: Date.now()
    };

    await router.handleMessage(msg, {});

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });
});
