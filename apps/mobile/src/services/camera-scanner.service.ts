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

export interface QrFrameDecodeResult {
  detected: boolean;
  payload: string | null;
  error?: string;
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
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        stream.getTracks().forEach((track) => track.stop());
        return true;
      } catch {
        return false;
      }
    }

    return false;
  }

  /**
   * Starts a real camera video stream attached to an HTMLVideoElement.
   */
  public async startCameraStream(videoElement: HTMLVideoElement): Promise<MediaStream> {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error('CAMERA_UNAVAILABLE: Camera hardware or video capture API not supported on this device.');
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: false
      });

      videoElement.srcObject = stream;
      videoElement.setAttribute('playsinline', 'true');
      await videoElement.play();
      return stream;
    } catch (err: any) {
      if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
        throw new Error('CAMERA_PERMISSION_DENIED: Camera access was denied by user or OS policy.');
      }
      throw new Error(`CAMERA_STREAM_ERROR: ${err.message || 'Failed to start camera video stream.'}`);
    }
  }

  /**
   * Safely stops and cleans up an active camera MediaStream.
   */
  public stopCameraStream(stream: MediaStream | null): void {
    if (!stream) return;
    try {
      stream.getTracks().forEach((track) => {
        track.stop();
      });
    } catch {
      // Ignore cleanup error
    }
  }

  /**
   * Captures a single image frame from a live HTMLVideoElement as a base64 JPEG data URL.
   */
  public captureFrameFromVideo(videoElement: HTMLVideoElement): string | null {
    if (!videoElement || videoElement.videoWidth === 0 || videoElement.videoHeight === 0) {
      return null;
    }

    try {
      const canvas = document.createElement('canvas');
      canvas.width = videoElement.videoWidth;
      canvas.height = videoElement.videoHeight;
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;

      ctx.drawImage(videoElement, 0, 0, canvas.width, canvas.height);
      return canvas.toDataURL('image/jpeg', 0.85);
    } catch {
      return null;
    }
  }

  /**
   * Real computer vision QR decoding pipeline.
   * Decodes an image frame (base64 string or live video element) to extract a QR barcode payload.
   * 
   * Strategy:
   * 1. Native Android Security Bridge (ZXing QrCodeDecoder) if running inside Android APK.
   * 2. Browser native BarcodeDetector API if supported in WebView.
   * 3. Clean null return if no barcode is detected in the frame.
   */
  public async decodeFrame(
    frameSource: string | HTMLVideoElement
  ): Promise<QrFrameDecodeResult> {
    let base64Image: string | null = null;

    if (typeof frameSource === 'string') {
      base64Image = frameSource;
    } else if (frameSource instanceof HTMLVideoElement) {
      base64Image = this.captureFrameFromVideo(frameSource);
    }

    if (!base64Image) {
      return { detected: false, payload: null };
    }

    // 1. Try Native Android Bridge (ZXing decoder in Java)
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.decodeQrFrame) {
      try {
        const decoded = (window as any).AndroidSecurityBridge.decodeQrFrame(base64Image);
        if (decoded && typeof decoded === 'string' && decoded.trim().length > 0) {
          return { detected: true, payload: decoded.trim() };
        }
      } catch (err: any) {
        // Fallback to web detector
      }
    }

    // 2. Try Web BarcodeDetector API (standard Chromium feature in modern WebViews)
    if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
      try {
        const barcodeDetector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });
        const img = new Image();
        img.src = base64Image;
        await new Promise((resolve) => { img.onload = resolve; img.onerror = resolve; });

        const barcodes = await barcodeDetector.detect(img);
        if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
          return { detected: true, payload: barcodes[0].rawValue.trim() };
        }
      } catch {
        // Fallback
      }
    }

    return { detected: false, payload: null };
  }

  /**
   * Scans a decoded QR code payload on-device through the canonical Core DetectionPipeline.
   * Handles URLs, deep links, and plain text with strict size bounds and zero cloud leakage.
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
