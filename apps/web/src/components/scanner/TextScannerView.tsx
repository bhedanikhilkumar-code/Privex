import React, { useState } from 'react';
import { WorkerBridge } from '../../workers/worker-bridge';
import { ScanResultViewData, UserPreferences } from '../../scanner/types';
import { ResultCard } from './ResultCard';

interface TextScannerViewProps {
  scannerBridge: WorkerBridge;
  preferences: UserPreferences;
}

export const TextScannerView: React.FC<TextScannerViewProps> = ({ scannerBridge, preferences }) => {
  const [textInput, setTextInput] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResultViewData | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanText = textInput.trim();
    if (!cleanText) return;

    setIsScanning(true);
    setErrorMessage(null);

    try {
      const result = await scannerBridge.scanText(cleanText, preferences);
      setScanResult(result);
    } catch (err: any) {
      setErrorMessage(err?.message || 'An error occurred during local message analysis.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleQuickFill = (exampleText: string) => {
    setTextInput(exampleText);
    setScanResult(null);
    setErrorMessage(null);
  };

  return (
    <section aria-labelledby="text-scanner-heading" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 id="text-scanner-heading" style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          On-Device Message & Text Scam Analyzer
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Paste suspicious SMS texts, emails, WhatsApp messages, or extortion demands.
          Evaluated for urgency pressure, cryptocurrency extortion, task scams, and fake invoices directly on your device.
        </p>
      </div>

      <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          <textarea
            id="text-scan-input"
            aria-label="Message content to scan for scams and digital threats"
            placeholder="Paste suspicious text message or email content here..."
            rows={5}
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            disabled={isScanning}
            style={{
              width: '100%',
              padding: '0.85rem 1rem',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.5rem',
              color: 'var(--text-primary)',
              fontSize: '0.95rem',
              lineHeight: 1.5,
              outline: 'none',
              resize: 'vertical'
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#64748b' }}>
            <span>🔒 Text stays 100% in volatile memory</span>
            <span>{textInput.length} / 10,000 characters</span>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          {/* Quick Test Samples */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.75rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Quick Samples:</span>
            <button
              type="button"
              onClick={() => handleQuickFill('Hi Sarah, see you tomorrow at lunch around 12:30 PM.')}
              style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#34d399', borderRadius: '0.25rem', cursor: 'pointer' }}
            >
              Benign Chat
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill('Work from home task! Earn $500 daily rating apps on Telegram. Deposit $50 to unlock commission.')}
              style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#fb923c', borderRadius: '0.25rem', cursor: 'pointer' }}
            >
              Task Scam
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill('USPS: Your package is detained due to incomplete address. Pay $1.99 redelivery fee at usps-redelivery.info')}
              style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#f87171', borderRadius: '0.25rem', cursor: 'pointer' }}
            >
              Postal Fraud
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill('Invoice #49281: Your Geek Squad subscription renewed for $499. Call support immediately to refund.')}
              style={{ padding: '0.2rem 0.5rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: '#eab308', borderRadius: '0.25rem', cursor: 'pointer' }}
            >
              Fake Invoice
            </button>
          </div>

          <button
            type="submit"
            disabled={isScanning || !textInput.trim()}
            style={{
              padding: '0.75rem 1.75rem',
              backgroundColor: isScanning || !textInput.trim() ? '#1e293b' : 'var(--color-brand)',
              color: isScanning || !textInput.trim() ? 'var(--text-muted)' : '#ffffff',
              border: 'none',
              borderRadius: '0.5rem',
              fontSize: '0.95rem',
              fontWeight: 600,
              cursor: isScanning || !textInput.trim() ? 'not-allowed' : 'pointer'
            }}
          >
            {isScanning ? 'Analyzing Locally...' : 'Analyze Message'}
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
            setTextInput('');
          }}
        />
      )}
    </section>
  );
};
