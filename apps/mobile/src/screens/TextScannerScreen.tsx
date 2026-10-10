import React, { useState } from 'react';
import { TextScannerService } from '../services/text-scanner.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { NotificationService } from '../services/notification.service';
import { MobileScanResult } from '../types/mobile.types';
import { ScanResultScreen } from './ScanResultScreen';

interface TextScannerScreenProps {
  scannerService: TextScannerService;
  onNavigateHome: () => void;
  initialText?: string;
  autoScan?: boolean;
}

export const TextScannerScreen: React.FC<TextScannerScreenProps> = ({
  scannerService,
  onNavigateHome,
  initialText,
  autoScan
}) => {
  const [textInput, setTextInput] = useState<string>(initialText || '');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<MobileScanResult | null>(null);

  React.useEffect(() => {
    if (initialText) {
      setTextInput(initialText);
      if (autoScan) {
        handleScan(initialText);
      }
    }
  }, [initialText, autoScan]);

  const handleScan = async (sampleText?: string) => {
    const candidate = sampleText || textInput;
    if (!candidate.trim()) {
      setError('Please paste message text to scan.');
      return;
    }

    setIsScanning(true);
    setError(null);

    try {
      const settings = await SecureStorageService.getSettings();
      const result = await scannerService.scanText(candidate, settings.readingGrade);

      setScanResult(result);

      // Record non-sensitive metadata (truncated summary)
      await SecureStorageService.recordScan({
        scanId: result.scanId,
        targetType: 'TEXT',
        sanitizedSummary: candidate.substring(0, 15) + '...',
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
          setTextInput('');
        }}
        onDone={onNavigateHome}
      />
    );
  }

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#818cf8' }}>
          On-Device Message & SMS Scanner
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Paste suspicious text directly. Content is evaluated in volatile RAM and is never uploaded or saved.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <label htmlFor="text-input" style={{ fontSize: '0.85rem', fontWeight: 600, color: '#cbd5e1' }}>
            Message Text to Analyze:
          </label>
          <button
            type="button"
            onClick={async () => {
              try {
                if (navigator.clipboard?.readText) {
                  const clip = await navigator.clipboard.readText();
                  if (clip) setTextInput(clip.trim());
                }
              } catch {
                // Clipboard fallback
              }
            }}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#818cf8',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.3rem'
            }}
          >
            📋 Paste Text
          </button>
        </div>
        <textarea
          id="text-input"
          rows={5}
          value={textInput}
          onChange={(e) => setTextInput(e.target.value)}
          placeholder="Paste SMS, WhatsApp, email, or direct message text here..."
          style={{
            padding: '0.85rem 1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '12px',
            color: '#f8fafc',
            fontSize: '0.9rem',
            width: '100%',
            boxSizing: 'border-box',
            fontFamily: 'inherit'
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
          backgroundColor: '#818cf8',
          color: '#ffffff',
          fontWeight: 700,
          borderRadius: '12px',
          border: 'none',
          cursor: isScanning ? 'not-allowed' : 'pointer',
          fontSize: '1rem'
        }}
      >
        {isScanning ? 'Analyzing On-Device...' : 'Scan Message'}
      </button>

      {/* Test Sample Chips */}
      <div style={{ borderTop: '1px solid #334155', paddingTop: '1rem' }}>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600 }}>Test Scenarios:</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={() => {
              const text = 'URGENT: Your bank account will be suspended within 2 hours. Send 0.5 BTC immediately to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
              setTextInput(text);
              handleScan(text);
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
            🛑 Crypto Extortion: "Send 0.5 BTC within 2 hours..."
          </button>

          <button
            type="button"
            onClick={() => {
              const text = 'USPS: Your package could not be delivered due to an unpaid $1.50 customs fee. Verify address at http://usps-tracking-fee.com';
              setTextInput(text);
              handleScan(text);
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
            ⚡ Postal Scam: "Your package has unpaid customs fee..."
          </button>

          <button
            type="button"
            onClick={() => {
              const text = 'Hi Mom, I will be home around 6pm for dinner. See you soon!';
              setTextInput(text);
              handleScan(text);
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
            ✓ Safe Message: "Hi Mom, I will be home for dinner..."
          </button>
        </div>
      </div>
    </div>
  );
};
