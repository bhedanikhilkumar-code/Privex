import { MobileSecurityAdapter } from '../adapters/mobile-security-adapter';
import { MobileScanResult } from '../types/mobile.types';
import { UrlScannerService } from './url-scanner.service';
import { TextScannerService } from './text-scanner.service';
import { DeepLinkValidatorService } from './deep-link-validator.service';

export interface CameraSupportStatus {
  isAvailable: boolean;
  hasPermission: boolean;
  source: 'NATIVE_BRIDGE' | 'WEB_MEDIA_DEVICES' | 'UNAVAILABLE';
}

export class CameraScannerService {
  private urlScanner: UrlScannerService;
  private textScanner: TextScannerService;

  constructor(private adapter: MobileSecurityAdapter) {
    this.urlScanner = new UrlScannerService(adapter);
    this.textScanner = new TextScannerService(adapter);
  }

  /**
   * Checks if camera hardware and permissions are available.
   */
  public async checkCameraSupport(): Promise<CameraSupportStatus> {
    // 1. Check native Android bridge first
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      const hasPermission = typeof bridge.hasCameraPermission === 'function' ? bridge.hasCameraPermission() : false;
      return {
        isAvailable: true,
        hasPermission,
        source: 'NATIVE_BRIDGE'
      };
    }

    // 2. Check standard web mediaDevices
    if (typeof navigator !== 'undefined' && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      try {
        if (navigator.permissions && navigator.permissions.query) {
          const perm = await navigator.permissions.query({ name: 'camera' as PermissionName });
          return {
            isAvailable: true,
            hasPermission: perm.state === 'granted',
            source: 'WEB_MEDIA_DEVICES'
          };
        }
      } catch {
        // Permissions query not supported, mediaDevices exists
      }
      return {
        isAvailable: true,
        hasPermission: false,
        source: 'WEB_MEDIA_DEVICES'
      };
    }

    return {
      isAvailable: false,
      hasPermission: false,
      source: 'UNAVAILABLE'
    };
  }

  /**
   * Requests camera permission through native bridge or browser API.
   */
  public async requestCameraPermission(): Promise<boolean> {
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge) {
      const bridge = (window as any).AndroidSecurityBridge;
      if (typeof bridge.requestCameraPermission === 'function') {
        bridge.requestCameraPermission();
        return true;
      }
    }

    if (typeof navigator !== 'undefined' && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        stream.getTracks().forEach((track) => track.stop());
        return true;
      } catch {
        return false;
      }
    }

    return false;
  }

  /**
   * Scans a decoded QR code payload on-device.
   * Handles URLs, deep links, and plain text with strict size bounds and no external network calls.
   */
  public async scanQrPayload(
    rawPayload: string,
    readingGrade: 6 | 8 = 6,
    customAllowlist: string[] = []
  ): Promise<MobileScanResult> {
    if (!rawPayload || rawPayload.trim().length === 0) {
      throw new Error('QR_PAYLOAD_REQUIRED: Scanned QR code returned empty data.');
    }

    const payload = rawPayload.trim();

    // 1. Guard against oversized malicious QR codes
    if (payload.length > 10000) {
      throw new Error('QR_PAYLOAD_TOO_LARGE: Scanned QR code data exceeds maximum threshold (10KB).');
    }

    // 2. Check for privateprotection:// deep link
    if (payload.startsWith('privateprotection:')) {
      const parsed = DeepLinkValidatorService.parseAndValidate(payload);
      if (!parsed.valid || !parsed.target) {
        throw new Error(`INVALID_DEEP_LINK_QR: ${parsed.error || 'Failed to parse deep link in QR code'}`);
      }
      if (parsed.action === 'SCAN_URL') {
        return await this.urlScanner.scanUrl(parsed.target, readingGrade, customAllowlist);
      }
      return await this.textScanner.scanText(parsed.target, readingGrade);
    }

    // 3. Check for URL patterns
    if (payload.startsWith('http://') || payload.startsWith('https://') || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(payload)) {
      return await this.urlScanner.scanUrl(payload, readingGrade, customAllowlist);
    }

    // 4. Default to scanning as text/scam message
    return await this.textScanner.scanText(payload, readingGrade);
  }
}
