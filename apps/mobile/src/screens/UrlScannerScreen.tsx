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
      {/* Header Bar with Back navigation & Sentry label */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button
          type="button"
          onClick={onNavigateHome}
          aria-label="Back to Dashboard"
          style={{
            background: 'transparent',
            border: 'none',
            color: '#f8fafc',
            fontSize: '1.25rem',
            cursor: 'pointer',
            padding: '0.25rem',
            display: 'flex',
            alignItems: 'center'
          }}
        >
          ←
        </button>
        <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          PRIVEX SENTRY
        </span>
        <button
          type="button"
          onClick={() => {
            alert('Privex Sentry verifies URL syntax, homographs, entropy, and local offline threat bloom databases.');
          }}
          aria-label="Scanner Information"
          style={{
            background: 'transparent',
            border: 'none',
            color: '#94a3b8',
            fontSize: '1.1rem',
            cursor: 'pointer'
          }}
        >
          ⓘ
        </button>
      </div>

      <div>
        <h1 style={{ margin: '0 0 0.25rem 0', fontSize: '1.75rem', fontWeight: 800, color: '#f8fafc' }}>
          Link Scanner
        </h1>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          On-Device URL Scanner • Paste a suspicious URL to perform a multi-layer phishing and malware analysis.
        </p>
      </div>

      {/* Target URL Input Card */}
      <div
        style={{
          backgroundColor: '#111b2e',
          border: '1px solid #27364b',
          borderRadius: '16px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <label htmlFor="url-input" style={{ fontSize: '0.75rem', fontWeight: 800, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            TARGET URL
          </label>
          <button
            type="button"
            onClick={async () => {
              try {
                if (navigator.clipboard?.readText) {
                  const clip = await navigator.clipboard.readText();
                  if (clip) setUrlInput(clip.trim());
                }
              } catch {
                // Clipboard read fallback
              }
            }}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#38bdf8',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.3rem'
            }}
          >
            📋 Paste Link
          </button>
        </div>

        <div>
          <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', display: 'block', marginBottom: '0.4rem' }}>
            URL Address
          </span>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <span style={{ position: 'absolute', left: '1rem', color: '#64748b', fontSize: '1rem' }}>🌐</span>
            <input
              id="url-input"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/path..."
              style={{
                padding: '0.85rem 1rem 0.85rem 2.6rem',
                backgroundColor: '#0b1220',
                border: '1px solid #27364b',
                borderRadius: '12px',
                color: '#f8fafc',
                fontSize: '0.92rem',
                width: '100%',
                boxSizing: 'border-box'
              }}
            />
          </div>
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
            marginTop: '0.5rem',
            padding: '0.85rem',
            backgroundColor: '#38bdf8',
            color: '#0b1220',
            fontWeight: 800,
            borderRadius: '12px',
            border: 'none',
            cursor: isScanning ? 'not-allowed' : 'pointer',
            fontSize: '0.95rem',
            boxShadow: '0 4px 12px rgba(56, 189, 248, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem'
          }}
        >
          🔍 {isScanning ? 'Analyzing On-Device...' : 'Scan Link'}
        </button>
      </div>

      {/* Security Protocol Information Cards */}
      <div>
        <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
          Security Protocol
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '12px', padding: '1rem', display: 'flex', gap: '0.85rem', alignItems: 'flex-start' }}>
            <div style={{ padding: '0.5rem', backgroundColor: 'rgba(56, 189, 248, 0.1)', borderRadius: '8px', fontSize: '1.1rem' }}>
              🛡️
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', color: '#f8fafc', display: 'block' }}>On-Device Analysis</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4, display: 'block', marginTop: '0.2rem' }}>
                Analysis runs locally. Privex does not log your browsing history or full URL content.
              </span>
            </div>
          </div>

          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '12px', padding: '1rem', display: 'flex', gap: '0.85rem', alignItems: 'flex-start' }}>
            <div style={{ padding: '0.5rem', backgroundColor: 'rgba(16, 185, 129, 0.1)', borderRadius: '8px', fontSize: '1.1rem' }}>
              ⚡
            </div>
            <div>
              <strong style={{ fontSize: '0.9rem', color: '#f8fafc', display: 'block' }}>Threat Intelligence</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4, display: 'block', marginTop: '0.2rem' }}>
                Cross-references against offline cryptographic threat database updated via zero-knowledge channels.
              </span>
            </div>
          </div>
        </div>
      </div>

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
