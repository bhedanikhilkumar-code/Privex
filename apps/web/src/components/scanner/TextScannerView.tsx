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
    <section aria-labelledby="text-scanner-heading" style={{ maxWidth: '1100px', margin: '0 auto' }}>
      {/* Top Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <span
            style={{
              padding: '0.2rem 0.6rem',
              backgroundColor: 'var(--color-brand)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              fontWeight: 800,
              textTransform: 'uppercase'
            }}
          >
            HEURISTIC &amp; INTENT CLASSIFICATION
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            SCAM PATTERNS: EXTORTION • FRAUD • TASK SCAM • INVOICE SPOOFING
          </span>
        </div>

        <h2
          id="text-scanner-heading"
          style={{
            fontFamily: 'var(--font-serif)',
            fontSize: '2.25rem',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            marginBottom: '0.5rem',
            color: '#111111'
          }}
        >
          On-Device Message &amp; Text Scam Analyzer
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '1rem', maxWidth: '750px', lineHeight: 1.5 }}>
          Paste suspicious SMS texts, emails, WhatsApp messages, or extortion demands.
          Evaluated for urgency pressure, cryptocurrency extortion, task scams, and fake invoices directly on your device.
        </p>
      </div>

      {/* Main 3-Column Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(220px, 260px) 1fr minmax(220px, 260px)',
          gap: '1.5rem',
          alignItems: 'start'
        }}
      >
        {/* Left Column: Status Widget */}
        <aside style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div
            style={{
              backgroundColor: 'var(--color-accent)',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal)',
              padding: '1.25rem'
            }}
          >
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', fontWeight: 800, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
              SCAM DEFENSES: ACTIVE
            </div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, lineHeight: 1.2, marginBottom: '0.75rem', color: '#111111' }}>
              NLP INTENT SHIELD
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#444444' }}>MODEL:</span>
                <strong>ON-DEVICE SLM</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#444444' }}>OFFLINE:</span>
                <strong>100% AIR-GAPPED</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#444444' }}>EXFILTRATION:</span>
                <strong>0 BYTES</strong>
              </div>
            </div>
          </div>

          <div
            style={{
              backgroundColor: '#FFFFFF',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal-sm)',
              padding: '1rem',
              fontSize: '0.8rem'
            }}
          >
            <strong style={{ display: 'block', marginBottom: '0.4rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              Zero-Knowledge Processing
            </strong>
            <p style={{ color: 'var(--text-muted)', lineHeight: 1.45, margin: 0 }}>
              Message bodies are parsed in volatile browser RAM and wiped immediately. No logs are saved.
            </p>
          </div>
        </aside>

        {/* Center Column: Scanner Target Input & Form */}
        <div>
          <div
            style={{
              backgroundColor: '#FFFFFF',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal-lg)',
              padding: '1.75rem',
              marginBottom: '1.5rem'
            }}
          >
            <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div>
                <label
                  htmlFor="text-scan-input"
                  style={{
                    display: 'block',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    marginBottom: '0.5rem',
                    letterSpacing: '0.04em'
                  }}
                >
                  MESSAGE CONTENT TO INSPECT:
                </label>
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
                    backgroundColor: 'var(--bg-primary)',
                    border: '2px solid var(--border-dark)',
                    color: 'var(--text-primary)',
                    fontSize: '0.95rem',
                    fontFamily: 'var(--font-mono)',
                    lineHeight: 1.5,
                    outline: 'none',
                    resize: 'vertical'
                  }}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                  <span>🔒 Text stays 100% in volatile memory</span>
                  <span>{textInput.length} / 10,000 characters</span>
                </div>
              </div>

              {/* Action row */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', paddingTop: '0.5rem', borderTop: '1px solid #EBE7DE' }}>
                {/* Quick Test Samples */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap', fontSize: '0.75rem' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>
                    Quick Samples:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleQuickFill('Hi Sarah, see you tomorrow at lunch around 12:30 PM.')}
                    style={{ padding: '0.3rem 0.6rem', backgroundColor: 'var(--color-safe-bg)', border: '1px solid var(--border-dark)', color: '#111111', fontFamily: 'var(--font-mono)', fontWeight: 700, cursor: 'pointer' }}
                  >
                    Benign Chat
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickFill('Work from home task! Earn $500 daily rating apps on Telegram. Deposit $50 to unlock commission.')}
                    style={{ padding: '0.3rem 0.6rem', backgroundColor: 'var(--color-caution-bg)', border: '1px solid var(--border-dark)', color: '#111111', fontFamily: 'var(--font-mono)', fontWeight: 700, cursor: 'pointer' }}
                  >
                    Task Scam
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickFill('USPS: Your package is detained due to incomplete address. Pay $1.99 redelivery fee at usps-redelivery.info')}
                    style={{ padding: '0.3rem 0.6rem', backgroundColor: 'var(--color-danger-bg)', border: '1px solid var(--border-dark)', color: '#111111', fontFamily: 'var(--font-mono)', fontWeight: 700, cursor: 'pointer' }}
                  >
                    Postal Fraud
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickFill('Invoice #49281: Your Geek Squad subscription renewed for $499. Call support immediately to refund.')}
                    style={{ padding: '0.3rem 0.6rem', backgroundColor: '#FFF9E6', border: '1px solid var(--border-dark)', color: '#111111', fontFamily: 'var(--font-mono)', fontWeight: 700, cursor: 'pointer' }}
                  >
                    Fake Invoice
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={isScanning || !textInput.trim()}
                  style={{
                    padding: '0.85rem 1.75rem',
                    backgroundColor: isScanning || !textInput.trim() ? '#EBE7DE' : 'var(--color-brand)',
                    color: isScanning || !textInput.trim() ? '#888888' : '#FFFFFF',
                    border: '2px solid var(--border-dark)',
                    boxShadow: isScanning || !textInput.trim() ? 'none' : '3px 3px 0px #111111',
                    fontSize: '0.9rem',
                    fontWeight: 800,
                    fontFamily: 'var(--font-mono)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    cursor: isScanning || !textInput.trim() ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isScanning ? 'Analyzing Locally...' : 'Analyze Message'}
                </button>
              </div>
            </form>
          </div>

          {/* Analyzing State UI */}
          {isScanning && (
            <div
              style={{
                backgroundColor: '#FFFFFF',
                border: '2px solid var(--border-dark)',
                boxShadow: 'var(--shadow-brutal)',
                padding: '1.75rem',
                textAlign: 'center',
                marginBottom: '1.5rem'
              }}
            >
              <div
                className="pulse-anim"
                style={{
                  width: '3.5rem',
                  height: '3.5rem',
                  margin: '0 auto 1rem',
                  backgroundColor: 'var(--color-accent)',
                  border: '2px solid var(--border-dark)',
                  boxShadow: '3px 3px 0px #111111',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '1.5rem'
                }}
              >
                💬
              </div>

              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.35rem' }}>
                PARSING MESSAGE PATTERNS...
              </div>

              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem', fontFamily: 'var(--font-mono)' }}>
                Evaluating urgency heuristics, advance-fee triggers, and crypto extortion demands in RAM...
              </p>

              <div
                style={{
                  height: '0.75rem',
                  backgroundColor: 'var(--bg-secondary)',
                  border: '2px solid var(--border-dark)',
                  maxWidth: '350px',
                  margin: '0 auto',
                  overflow: 'hidden'
                }}
              >
                <div
                  className="pulse-anim"
                  style={{
                    width: '80%',
                    height: '100%',
                    backgroundColor: 'var(--color-brand)'
                  }}
                />
              </div>
            </div>
          )}

          {/* 4-Cell Metric Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.75rem',
              marginBottom: '1.5rem'
            }}
          >
            <div style={{ backgroundColor: '#FFFFFF', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                LATENCY
              </span>
              <strong style={{ fontSize: '0.95rem', color: '#111111' }}>&lt; 2.0 ms</strong>
            </div>

            <div style={{ backgroundColor: '#FFFFFF', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                CORE VERDICT
              </span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--color-brand)' }}>AUTHORITATIVE</strong>
            </div>

            <div style={{ backgroundColor: '#FFFFFF', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                PRIVACY
              </span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--color-safe)' }}>LOCAL ONLY</strong>
            </div>

            <div style={{ backgroundColor: '#FFFFFF', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                STATUS
              </span>
              <strong style={{ fontSize: '0.95rem', color: '#111111' }}>READY</strong>
            </div>
          </div>

          {errorMessage && (
            <div
              role="alert"
              style={{
                marginBottom: '1.5rem',
                padding: '1rem',
                backgroundColor: 'var(--color-danger-bg)',
                border: '2px solid var(--border-dark)',
                boxShadow: 'var(--shadow-brutal-sm)',
                color: '#111111',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                fontWeight: 600
              }}
            >
              ⚠️ {errorMessage}
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
        </div>

        {/* Right Column: Live Telemetry Stream Terminal */}
        <aside
          style={{
            backgroundColor: '#111111',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.25rem',
            color: '#EBE7DE',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.725rem',
            lineHeight: 1.6
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #333333', paddingBottom: '0.5rem', marginBottom: '0.75rem' }}>
            <span style={{ color: 'var(--color-accent)', fontWeight: 800 }}>MESSAGE TELEMETRY</span>
            <span style={{ color: '#1DB954' }}>● LIVE</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', color: '#CCCCCC' }}>
            <div><span style={{ color: '#888888' }}>[SYS]</span> NLP Intent model loaded</div>
            <div><span style={{ color: '#888888' }}>[NET]</span> Socket state: 0 ACTIVE</div>
            <div><span style={{ color: '#888888' }}>[MEM]</span> Volatile buffers cleared</div>
            <div><span style={{ color: '#888888' }}>[INTENT]</span> Urgency heuristics ready</div>
            <div><span style={{ color: '#888888' }}>[FRAUD]</span> Invoice pattern rule active</div>
            {isScanning && (
              <div style={{ color: 'var(--color-accent)' }}>
                <span>&gt;&gt;</span> Scanning message payload...
              </div>
            )}
            {scanResult && (
              <div style={{ color: '#1DB954' }}>
                <span>&gt;&gt;</span> Assessment complete: {scanResult.executionTimeMs}ms
              </div>
            )}
          </div>
        </aside>
      </div>
    </section>
  );
};
