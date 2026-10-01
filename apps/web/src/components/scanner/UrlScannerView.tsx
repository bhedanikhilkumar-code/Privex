import React, { useState } from 'react';
import { WorkerBridge } from '../../workers/worker-bridge';
import { ScanResultViewData, UserPreferences } from '../../scanner/types';
import { ResultCard } from './ResultCard';

interface UrlScannerViewProps {
  scannerBridge: WorkerBridge;
  preferences: UserPreferences;
}

export const UrlScannerView: React.FC<UrlScannerViewProps> = ({ scannerBridge, preferences }) => {
  const [urlInput, setUrlInput] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResultViewData | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const targetUrl = urlInput.trim();
    if (!targetUrl) return;

    setIsScanning(true);
    setErrorMessage(null);

    try {
      const result = await scannerBridge.scanUrl(targetUrl, preferences);
      setScanResult(result);
    } catch (err: any) {
      setErrorMessage(err?.message || 'An error occurred during local URL analysis.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleQuickFill = (exampleUrl: string) => {
    setUrlInput(exampleUrl);
    setScanResult(null);
    setErrorMessage(null);
  };

  return (
    <section aria-labelledby="url-scanner-heading" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 id="url-scanner-heading" style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          On-Device URL Security Scanner
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Inspect suspicious links, domain spoofing, typosquatting, and deceptive redirects before visiting.
          All lexical and threat intelligence calculations run 100% locally in your browser.
        </p>
      </div>

      <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <input
            type="text"
            id="url-scan-input"
            aria-label="URL to scan for cyber threats"
            placeholder="Enter or paste web address (e.g. https://example.com/login)..."
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            disabled={isScanning}
            style={{
              flex: '1 1 300px',
              padding: '0.85rem 1rem',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.5rem',
              color: 'var(--text-primary)',
              fontSize: '1rem',
              outline: 'none'
            }}
          />
          <button
            type="submit"
            disabled={isScanning || !urlInput.trim()}
            style={{
              padding: '0.85rem 1.75rem',
              backgroundColor: isScanning || !urlInput.trim() ? '#1e293b' : 'var(--color-brand)',
              color: isScanning || !urlInput.trim() ? 'var(--text-muted)' : '#ffffff',
              border: 'none',
              borderRadius: '0.5rem',
              fontSize: '0.95rem',
              fontWeight: 600,
              cursor: isScanning || !urlInput.trim() ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            {isScanning ? 'Scanning Locally...' : 'Scan URL'}
          </button>
        </div>

        {/* Quick Test Links */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.75rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Quick Test Samples:</span>
          <button
            type="button"
            onClick={() => handleQuickFill('https://www.google.com/search')}
            style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#34d399', borderRadius: '0.25rem', cursor: 'pointer' }}
          >
            Safe Domain
          </button>
          <button
            type="button"
            onClick={() => handleQuickFill('http://192.168.1.100/account/login')}
            style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#f87171', borderRadius: '0.25rem', cursor: 'pointer' }}
          >
            IP Host Phish
          </button>
          <button
            type="button"
            onClick={() => handleQuickFill('http://paypal-security-update.buzz/login/verify')}
            style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#fb923c', borderRadius: '0.25rem', cursor: 'pointer' }}
          >
            Brand Deception
          </button>
        </div>
      </form>

      {errorMessage && (
        <div
          role="alert"
          style={{
            marginTop: '1rem',
            padding: '0.75rem 1rem',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid #ef4444',
            borderRadius: '0.5rem',
            color: '#fca5a5',
            fontSize: '0.85rem'
          }}
        >
          {errorMessage}
        </div>
      )}

      {scanResult && (
        <ResultCard
          result={scanResult}
          onReset={() => {
            setScanResult(null);
            setUrlInput('');
          }}
        />
      )}
    </section>
  );
};
