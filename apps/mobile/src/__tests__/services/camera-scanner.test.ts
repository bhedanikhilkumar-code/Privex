import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CameraScannerService } from '../../services/camera-scanner.service';
import { MobileSecurityAdapter } from '../../adapters/mobile-security-adapter';
import { Verdict } from '@private-protection/core';

describe('CameraScannerService & QR Threat Analysis', () => {
  let adapter: MobileSecurityAdapter;
  let cameraScanner: CameraScannerService;

  beforeEach(() => {
    adapter = new MobileSecurityAdapter();
    cameraScanner = new CameraScannerService(adapter);
    vi.restoreAllMocks();
  });

  it('detects camera availability via native Android bridge', async () => {
    (window as any).AndroidSecurityBridge = {
      hasCameraPermission: () => true,
      requestCameraPermission: vi.fn()
    };

    const status = await cameraScanner.checkCameraSupport();
    expect(status.isAvailable).toBe(true);
    expect(status.hasPermission).toBe(true);
    expect(status.source).toBe('NATIVE_BRIDGE');

    const granted = await cameraScanner.requestCameraPermission();
    expect(granted).toBe(true);

    delete (window as any).AndroidSecurityBridge;
  });

  it('scans a phishing URL extracted from a QR code', async () => {
    const maliciousQr = 'http://paypal-security-update.suspicious-login.com/verify';
    const result = await cameraScanner.scanQrPayload(maliciousQr);

    expect(result.targetType).toBe('URL');
    expect(result.rawInput).toBe(maliciousQr);
    expect([Verdict.DANGEROUS, Verdict.SUSPICIOUS]).toContain(result.verdict);
    expect(result.overallScore).toBeGreaterThanOrEqual(70);
  });

  it('scans a deep link embedded within a QR code', async () => {
    const deepLinkQr = 'privateprotection://scan?url=https%3A%2F%2Ftrusted-bank.example.com';
    const result = await cameraScanner.scanQrPayload(deepLinkQr);

    expect(result.targetType).toBe('URL');
    expect(result.rawInput).toBe('https://trusted-bank.example.com');
  });

  it('scans scam message text extracted from a QR code', async () => {
    const scamTextQr = 'URGENT: Your account has been suspended! Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately!';
    const result = await cameraScanner.scanQrPayload(scamTextQr);

    expect(result.targetType).toBe('TEXT');
    expect(result.verdict).toBe(Verdict.DANGEROUS);
    expect(result.overallScore).toBeGreaterThanOrEqual(80);
  });

  it('rejects empty or oversized QR codes', async () => {
    await expect(cameraScanner.scanQrPayload('')).rejects.toThrow('QR_PAYLOAD_REQUIRED');

    const hugePayload = 'A'.repeat(15000);
    await expect(cameraScanner.scanQrPayload(hugePayload)).rejects.toThrow('QR_PAYLOAD_TOO_LARGE');
  });

  it('rejects unauthorized command deep links inside QR code', async () => {
    const badDeepLink = 'privateprotection://bypass?token=evil';
    await expect(cameraScanner.scanQrPayload(badDeepLink)).rejects.toThrow('INVALID_DEEP_LINK_QR');
  });
});
