import React, { useState, useEffect, useRef } from 'react';
import { CameraScannerService, CameraSupportStatus } from '../services/camera-scanner.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { NotificationService } from '../services/notification.service';
import { MobileScanResult } from '../types/mobile.types';
import { ScanResultScreen } from './ScanResultScreen';

interface QrScannerScreenProps {
  cameraService: CameraScannerService;
  onNavigateHome: () => void;
}

export const QrScannerScreen: React.FC<QrScannerScreenProps> = ({ cameraService, onNavigateHome }) => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const pollingTimerRef = useRef<any>(null);
  const isMountedRef = useRef<boolean>(true);
  const isDecodingRef = useRef<boolean>(false);

  const [support, setSupport] = useState<CameraSupportStatus | null>(null);
  const [isCameraActive, setIsCameraActive] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string>('Ready to scan');
  const [scanResult, setScanResult] = useState<MobileScanResult | null>(null);

  useEffect(() => {
    isMountedRef.current = true;
    cameraService.checkCameraSupport().then((s) => {
      if (isMountedRef.current) setSupport(s);
    });
    return () => {
      isMountedRef.current = false;
      stopCamera();
    };
  }, []);

  const startCamera = async () => {
    setError(null);
    setStatusMessage('Requesting camera access...');
    try {
      const hasPerm = await cameraService.requestCameraPermission();
      if (!isMountedRef.current) return;
      if (!hasPerm) {
        setError('CAMERA_PERMISSION_DENIED: Please enable Camera permission in Android settings.');
        return;
      }

      if (!videoRef.current) return;
      const stream = await cameraService.startCameraStream(videoRef.current);
      if (!isMountedRef.current) {
        cameraService.stopCameraStream(stream);
        return;
      }
      streamRef.current = stream;
      setIsCameraActive(true);
      setStatusMessage('Camera active — Point at a QR code');

      // Start frame scanning loop
      startFramePolling();
    } catch (err: any) {
      if (!isMountedRef.current) return;
      setError(err.message || 'Failed to start camera.');
      setIsCameraActive(false);
    }
  };

  const stopCamera = () => {
    if (pollingTimerRef.current) {
      clearInterval(pollingTimerRef.current);
      pollingTimerRef.current = null;
    }
    if (streamRef.current) {
      cameraService.stopCameraStream(streamRef.current);
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    isDecodingRef.current = false;
    setIsCameraActive(false);
  };

  const startFramePolling = () => {
    if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);

    pollingTimerRef.current = setInterval(async () => {
      if (!isMountedRef.current || !videoRef.current || isProcessing || isDecodingRef.current) return;

      isDecodingRef.current = true;
      try {
        const result = await cameraService.decodeFrame(videoRef.current);
        if (result.detected && result.payload && isMountedRef.current) {
          stopCamera();
          await processDecodedPayload(result.payload);
        }
      } catch (err: any) {
        // Continue scanning
      } finally {
        isDecodingRef.current = false;
      }
    }, 300);
  };

  const processDecodedPayload = async (payload: string) => {
    setIsProcessing(true);
    setStatusMessage('Analyzing QR payload on-device...');
    setError(null);

    try {
      const settings = await SecureStorageService.getSettings();
      const result = await cameraService.scanQrPayload(
        payload,
        settings.readingGrade,
        settings.allowlistDomains
      );

      setScanResult(result);

      // Record non-sensitive metadata
      const summary = payload.length > 20 ? payload.substring(0, 20) + '...' : payload;
      await SecureStorageService.recordScan({
        scanId: result.scanId,
        targetType: 'URL',
        sanitizedSummary: `QR: ${summary}`,
        verdict: result.verdict,
        score: result.overallScore,
        timestamp: Date.now()
      });

      // Dispatch native notification & haptics if threat detected
      await NotificationService.notifyScanResult(result);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze QR payload.');
    } finally {
      setIsProcessing(false);
    }
  };

  if (scanResult) {
    return (
      <ScanResultScreen
        result={scanResult}
        onReset={() => {
          setScanResult(null);
          setStatusMessage('Ready to scan');
        }}
        onDone={onNavigateHome}
      />
    );
  }

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#38bdf8' }}>
          On-Device QR Code Scanner
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Captures camera video frames, executes ZXing computer vision decoding, and routes payloads through the local core engine.
        </p>
      </div>

      {/* Video Viewfinder Container */}
      <div
        style={{
          position: 'relative',
          width: '100%',
          aspectRatio: '4/3',
          backgroundColor: '#0f172a',
          borderRadius: '16px',
          overflow: 'hidden',
          border: '2px solid #334155',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <video
          ref={videoRef}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            display: isCameraActive ? 'block' : 'none'
          }}
        />

        {!isCameraActive && (
          <div style={{ textAlign: 'center', padding: '1.5rem', color: '#94a3b8' }}>
            <span style={{ fontSize: '3rem', display: 'block', marginBottom: '0.5rem' }}>📷</span>
            <p style={{ margin: 0, fontSize: '0.9rem' }}>Camera preview is currently inactive.</p>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
              {support?.source === 'NATIVE_BRIDGE' ? 'Android Native Bridge Ready' : 'Web MediaDevices Ready'}
            </span>
          </div>
        )}

        {/* Viewfinder Target Reticle with Animated Laser Line */}
        {isCameraActive && (
          <div
            style={{
              position: 'absolute',
              width: '60%',
              aspectRatio: '1/1',
              border: '2px solid rgba(56, 189, 248, 0.6)',
              borderRadius: '16px',
              boxShadow: '0 0 0 9999px rgba(0, 0, 0, 0.45)',
              pointerEvents: 'none',
              overflow: 'hidden'
            }}
          >
            {/* Animated Laser Sweep Line */}
            <div className="motion-laser-line" />
          </div>
        )}
      </div>

      {/* Status Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem' }}>
        <span style={{ color: '#cbd5e1' }}>Status: {statusMessage}</span>
        {isProcessing && <span style={{ color: '#38bdf8', fontWeight: 600 }}>Analyzing...</span>}
      </div>

      {error && (
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', fontSize: '0.85rem' }}>
          {error}
        </div>
      )}

      {/* Camera Toggle Button */}
      {!isCameraActive ? (
        <button
          type="button"
          onClick={startCamera}
          style={{
            padding: '0.85rem',
            backgroundColor: '#38bdf8',
            color: '#0f172a',
            fontWeight: 700,
            borderRadius: '12px',
            border: 'none',
            cursor: 'pointer',
            fontSize: '1rem'
          }}
        >
          Start Camera Scanner
        </button>
      ) : (
        <button
          type="button"
          onClick={stopCamera}
          style={{
            padding: '0.85rem',
            backgroundColor: '#ef4444',
            color: '#f8fafc',
            fontWeight: 700,
            borderRadius: '12px',
            border: 'none',
            cursor: 'pointer',
            fontSize: '1rem'
          }}
        >
          Stop Camera
        </button>
      )}

      {/* Synthetic Test Scenarios (Master Prompt Requirement) */}
      <div style={{ borderTop: '1px solid #334155', paddingTop: '1rem' }}>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600 }}>Synthetic Test QR Payloads:</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={() => processDecodedPayload('https://google.com')}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#34d399',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            ✓ Safe QR Link: https://google.com
          </button>

          <button
            type="button"
            onClick={() => processDecodedPayload('http://192.168.1.100/login.php')}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f87171',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            🛑 IP Phishing QR: http://192.168.1.100/login.php
          </button>

          <button
            type="button"
            onClick={() => processDecodedPayload('https://paypal-security-update.com/verify')}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#fcd34d',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            ⚡ Brand Spoof QR: https://paypal-security-update.com/verify
          </button>

          <button
            type="button"
            onClick={() => processDecodedPayload('URGENT: Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours or files deleted')}
            style={{
              padding: '0.6rem 0.75rem',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f87171',
              fontSize: '0.8rem',
              cursor: 'pointer',
              textAlign: 'left'
            }}
          >
            ☠️ Extortion QR: Crypto ransom demand
          </button>
        </div>
      </div>
    </div>
  );
};
