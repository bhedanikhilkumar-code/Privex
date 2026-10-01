import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MobileSecurityAdapter } from '../../adapters/mobile-security-adapter';
import { FileScannerService } from '../../services/file-scanner.service';

describe('Network Isolation & Zero-Exfiltration Audit (Mobile Client)', () => {
  let fetchSpy: any;
  let xhrOpenSpy: any;
  let beaconSpy: any;

  beforeEach(() => {
    fetchSpy = vi.fn().mockImplementation(() => {
      throw new Error('NETWORK_VIOLATION: fetch() invoked in zero-cloud mobile client');
    });
    globalThis.fetch = fetchSpy;

    xhrOpenSpy = vi.fn().mockImplementation(() => {
      throw new Error('NETWORK_VIOLATION: XMLHttpRequest invoked in zero-cloud mobile client');
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

  it('guarantees 0 outbound network requests during on-device URL threat scanning', async () => {
    const adapter = new MobileSecurityAdapter();
    const result = await adapter.scanUrl('https://paypal-security-update.com/verify');

    expect(result).toBeDefined();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('guarantees 0 outbound network requests during message text scanning', async () => {
    const adapter = new MobileSecurityAdapter();
    const result = await adapter.scanText('URGENT: Verify your bank credentials at http://bank.com');

    expect(result).toBeDefined();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('guarantees 0 outbound network requests during file inspection', () => {
    const fileService = new FileScannerService();
    const result = fileService.inspectFile({
      name: 'invoice.pdf.exe',
      sizeBytes: 1024,
      mimeType: 'application/octet-stream',
      headerBytes: [0x4d, 0x5a, 0x90, 0x00]
    });

    expect(result).toBeDefined();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrOpenSpy).not.toHaveBeenCalled();
  });
});
