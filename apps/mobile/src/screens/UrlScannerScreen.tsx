import React, { useState } from 'react';
import { UrlScannerService } from '../services/url-scanner.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { NotificationService } from '../services/notification.service';
import { MobileScanResult } from '../types/mobile.types';
import { ScanResultScreen } from './ScanResultScreen';

interface UrlScannerScreenProps {
  scannerService: UrlScannerService;
  onNavigateHome: () => void;
  initialUrl?: string;
  autoScan?: boolean;
}

export const UrlScannerScreen: React.FC<UrlScannerScreenProps> = ({
  scannerService,
  onNavigateHome,
  initialUrl,
  autoScan
}) => {
  const [urlInput, setUrlInput] = useState<string>(initialUrl || '');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<MobileScanResult | null>(null);

  React.useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
      if (autoScan) {
        handleScan(initialUrl);
      }
    }
  }, [initialUrl, autoScan]);

  const handleScan = async (targetUrl?: string) => {
    const candidate = targetUrl || urlInput;
    if (!candidate.trim()) {
      setError('Please provide a URL to scan.');
      return;
    }

    setIsScanning(true);
    setError(null);

    try {
      const settings = await SecureStorageService.getSettings();
      const result = await scannerService.scanUrl(
        candidate,
        settings.readingGrade,
        settings.allowlistDomains
      );

      setScanResult(result);

      // Record non-sensitive metadata
      let domainSummary = candidate;
      try {
        const u = new URL(candidate.startsWith('http') ? candidate : `http://${candidate}`);
        domainSummary = u.hostname.substring(0, 15);
      } catch {
        domainSummary = candidate.substring(0, 15);
      }

      await SecureStorageService.recordScan({
        scanId: result.scanId,
        targetType: 'URL',
        sanitizedSummary: domainSummary,
        verdict: result.verdict,
        score: result.overallScore,
        timestamp: Date.now()
      });

      // Dispatch notification if flagged
      await NotificationService.notifyScanResult(result);
    } catch (err: any) {
      setError(err.message || 'Scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  if (scanResult) {
    return (
      <ScanResultScreen
        result={scanResult}
        onReset={() => {
          setScanResult(null);
          setUrlInput('');
        }}
        onDone={onNavigateHome}
      />
    );
  }

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#38bdf8' }}>
          On-Device URL Scanner
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Evaluates lexical structures, entropy, and offline threat intelligence without transmitting links to the cloud.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <label htmlFor="url-input" style={{ fontSize: '0.85rem', fontWeight: 600, color: '#cbd5e1' }}>
          Website or Link to Analyze:
        </label>
        <input
          id="url-input"
          type="text"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          placeholder="https://example.com or suspicious-link.ru"
          style={{
            padding: '0.85rem 1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '12px',
            color: '#f8fafc',
            fontSize: '0.95rem',
            width: '100%',
            boxSizing: 'border-box'
          }}
        />
      </div>

      {error && (
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', fontSize: '0.85rem' }}>
          {error}
        </div>
      )}

      <button
        type="button"
        disabled={isScanning}
        onClick={() => handleScan()}
        style={{
          padding: '0.85rem',
          backgroundColor: '#38bdf8',
          color: '#0f172a',
          fontWeight: 700,
          borderRadius: '12px',
          border: 'none',
          cursor: isScanning ? 'not-allowed' : 'pointer',
          fontSize: '1rem',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
        }}
      >
        {isScanning ? 'Analyzing On-Device...' : 'Scan URL'}
      </button>

      {/* Test Sample Chips */}
      <div style={{ borderTop: '1px solid #334155', paddingTop: '1rem' }}>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600 }}>Test Scenarios:</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={() => {
              setUrlInput('https://google.com');
              handleScan('https://google.com');
            }}
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
            ✓ Safe Baseline: https://google.com
          </button>

          <button
            type="button"
            onClick={() => {
              setUrlInput('http://192.168.1.100/login.php');
              handleScan('http://192.168.1.100/login.php');
            }}
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
            🛑 IP Phishing: http://192.168.1.100/login.php
          </button>

          <button
            type="button"
            onClick={() => {
              setUrlInput('https://paypal-security-update.com/verify');
              handleScan('https://paypal-security-update.com/verify');
            }}
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
            ⚡ Brand Spoof: https://paypal-security-update.com/verify
          </button>
        </div>
      </div>
    </div>
  );
};
