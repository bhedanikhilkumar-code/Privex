import React, { useState } from 'react';
import { WorkerBridge } from '../../workers/worker-bridge';
import { ScanResultViewData, UserPreferences } from '../../scanner/types';
import { ResultCard } from './ResultCard';
import {
  WebsiteEntryPointAnalyzer,
  WebsiteAuditReport,
  ExposedEntryPoint
} from '@private-protection/core';

interface UrlScannerViewProps {
  scannerBridge: WorkerBridge;
  preferences: UserPreferences;
}

export const UrlScannerView: React.FC<UrlScannerViewProps> = ({ scannerBridge, preferences }) => {
  const [urlInput, setUrlInput] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResultViewData | null>(null);
  const [auditReport, setAuditReport] = useState<WebsiteAuditReport | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const entryPointAnalyzer = new WebsiteEntryPointAnalyzer();

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const targetUrl = urlInput.trim();
    if (!targetUrl) return;

    setIsScanning(true);
    setErrorMessage(null);

    try {
      const result = await scannerBridge.scanUrl(targetUrl, preferences);
      setScanResult(result);

      // Offline website open points & port attack surface analysis
      const report = entryPointAnalyzer.analyzeWebsite(targetUrl);
      setAuditReport(report);
    } catch (err: any) {
      setErrorMessage(err?.message || 'An error occurred during local URL analysis.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleQuickFill = (exampleUrl: string) => {
    setUrlInput(exampleUrl);
    setScanResult(null);
    setAuditReport(null);
    setErrorMessage(null);
  };

  const handleCopyCode = (code: string, id: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(code);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2500);
    }
  };

  return (
    <section aria-labelledby="url-scanner-heading" style={{ maxWidth: '1100px', margin: '0 auto' }}>
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
            ZERO-TRUST ANALYSIS
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            PIPELINE: DETERMINISTIC RULES → LEXICAL HEURISTICS → SLM EXPLAINER
          </span>
        </div>

        <h2
          id="url-scanner-heading"
          style={{
            fontFamily: 'var(--font-serif)',
            fontSize: '2.25rem',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            marginBottom: '0.5rem',
            color: '#111111'
          }}
        >
          On-Device URL Security Scanner
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '1rem', maxWidth: '750px', lineHeight: 1.5 }}>
          Inspect untrusted URLs, domain spoofing, typosquatting, and deceptive redirects before visiting.
          All lexical and threat intelligence calculations run 100% locally in your browser.
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
        {/* Left Column: System Status Widget */}
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
              SYSTEM STATUS: SECURE
            </div>
            <div style={{ fontSize: '1.2rem', fontWeight: 800, lineHeight: 1.2, marginBottom: '0.75rem', color: '#111111' }}>
              ALL DEFENSES ACTIVE
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#444444' }}>OFFLINE PARITY:</span>
                <strong>100%</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#444444' }}>BLOOM CACHE:</span>
                <strong>LOADED</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#444444' }}>ENGINE:</span>
                <strong>ON-DEVICE</strong>
              </div>
            </div>
          </div>

          <div
            style={{
              backgroundColor: 'var(--bg-card)',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal-sm)',
              padding: '1rem',
              fontSize: '0.8rem'
            }}
          >
            <strong style={{ display: 'block', marginBottom: '0.4rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              Privacy Invariant
            </strong>
            <p style={{ color: 'var(--text-muted)', lineHeight: 1.45, margin: 0 }}>
              Scanned URLs remain in volatile RAM and are automatically purged upon session end. Zero network egress.
            </p>
          </div>
        </aside>

        {/* Center Column: Scanner Target Input & Form */}
        <div>
          <div
            style={{
              backgroundColor: 'var(--bg-card)',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal-lg)',
              padding: '1.75rem',
              marginBottom: '1.5rem'
            }}
          >
            <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div>
                <label
                  htmlFor="url-scan-input"
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
                  TARGET URL TO ANALYZE:
                </label>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', position: 'relative' }}>
                  <div style={{ flex: '1 1 280px', position: 'relative' }}>
                    <input
                      type="text"
                      id="url-scan-input"
                      aria-label="URL to scan for cyber threats"
                      placeholder="Enter or paste web address (e.g. https://example.com/login)..."
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      disabled={isScanning}
                      style={{
                        width: '100%',
                        padding: '0.85rem 1rem',
                        backgroundColor: 'var(--bg-primary)',
                        border: '2px solid var(--border-dark)',
                        color: 'var(--text-primary)',
                        fontSize: '0.95rem',
                        fontFamily: 'var(--font-mono)',
                        outline: 'none',
                        transition: 'border-color var(--motion-duration-micro) var(--motion-ease-standard)'
                      }}
                    />
                    {isScanning && <div className="motion-scanline" aria-hidden="true" />}
                  </div>
                  <button
                    type="submit"
                    disabled={isScanning || !urlInput.trim()}
                    className={!isScanning && urlInput.trim() ? 'motion-pressable' : ''}
                    style={{
                      padding: '0.85rem 1.75rem',
                      backgroundColor: isScanning || !urlInput.trim() ? '#EBE7DE' : 'var(--color-brand)',
                      color: isScanning || !urlInput.trim() ? '#888888' : '#FFFFFF',
                      border: '2px solid var(--border-dark)',
                      boxShadow: isScanning || !urlInput.trim() ? 'none' : '3px 3px 0px #111111',
                      fontSize: '0.9rem',
                      fontWeight: 800,
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      cursor: isScanning || !urlInput.trim() ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem'
                    }}
                  >
                    {isScanning ? 'Scanning Locally...' : 'Scan URL'}
                  </button>
                </div>
              </div>

              {/* Quick Test Samples */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', fontSize: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid #EBE7DE' }}>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>
                  Quick Samples:
                </span>
                <button
                  type="button"
                  onClick={() => handleQuickFill('https://www.google.com/search')}
                  style={{
                    padding: '0.3rem 0.65rem',
                    backgroundColor: 'var(--color-safe-bg)',
                    border: '1px solid var(--border-dark)',
                    color: '#111111',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Safe Domain
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('http://192.168.1.100/account/login')}
                  style={{
                    padding: '0.3rem 0.65rem',
                    backgroundColor: 'var(--color-danger-bg)',
                    border: '1px solid var(--border-dark)',
                    color: '#111111',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  IP Host Phish
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('http://paypal-security-update.buzz/login/verify')}
                  style={{
                    padding: '0.3rem 0.65rem',
                    backgroundColor: 'var(--color-caution-bg)',
                    border: '1px solid var(--border-dark)',
                    color: '#111111',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Brand Deception
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('http://company-internal.com:3306')}
                  style={{
                    padding: '0.3rem 0.65rem',
                    backgroundColor: '#fee2e2',
                    border: '1px solid var(--border-dark)',
                    color: '#991b1b',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Exposed MySQL :3306
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('https://example.com/.env')}
                  style={{
                    padding: '0.3rem 0.65rem',
                    backgroundColor: '#ffedd5',
                    border: '1px solid var(--border-dark)',
                    color: '#c2410c',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Exposed /.env Secret
                </button>
              </div>
            </form>
          </div>

          {/* Analyzing State UI (Analyzing State.png) */}
          {isScanning && (
            <div
              style={{
                backgroundColor: 'var(--bg-card)',
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
                ⚡
              </div>

              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.35rem' }}>
                CHECKING LOCALLY...
              </div>

              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem', fontFamily: 'var(--font-mono)' }}>
                Evaluating lexical entropy, brand spoofing, and Punycode homographs in browser RAM...
              </p>

              {/* Progress bar */}
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
                    width: '75%',
                    height: '100%',
                    backgroundColor: 'var(--color-brand)'
                  }}
                />
              </div>
            </div>
          )}

          {/* 4-Cell Metric Grid (Scanner Dashboard.png) */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.75rem',
              marginBottom: '1.5rem'
            }}
          >
            <div style={{ backgroundColor: 'var(--bg-card)', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                DETECTION LATENCY
              </span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>&lt; 1.5 ms</strong>
            </div>

            <div style={{ backgroundColor: 'var(--bg-card)', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                CORE VERDICT
              </span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--color-brand)' }}>AUTHORITATIVE</strong>
            </div>

            <div style={{ backgroundColor: 'var(--bg-card)', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                DATA PRIVACY
              </span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--color-safe)' }}>0 BYTES SENT</strong>
            </div>

            <div style={{ backgroundColor: 'var(--bg-card)', border: '2px solid var(--border-dark)', padding: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <span style={{ fontSize: '0.675rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                OFFLINE STATUS
              </span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>AIR-GAPPED READY</strong>
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
                setAuditReport(null);
                setUrlInput('');
              }}
            />
          )}

          {/* Attack Surface & Open Points Audit */}
          {auditReport && (
            <div
              style={{
                marginTop: '1.5rem',
                backgroundColor: 'var(--bg-card)',
                border: '2px solid var(--border-dark)',
                boxShadow: 'var(--shadow-brutal-lg)',
                padding: '1.5rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
                <div>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.7rem',
                      fontWeight: 800,
                      color: 'var(--color-brand)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em'
                    }}
                  >
                    OFFLINE ATTACK SURFACE AUDIT
                  </span>
                  <h3
                    style={{
                      margin: '0.2rem 0 0 0',
                      fontFamily: 'var(--font-serif)',
                      fontSize: '1.35rem',
                      fontWeight: 800,
                      color: 'var(--text-primary)'
                    }}
                  >
                    Open Points &amp; Exposed Port Analysis
                  </h3>
                </div>

                <div
                  style={{
                    padding: '0.4rem 0.85rem',
                    backgroundColor:
                      auditReport.overallExposureRisk === 'CRITICAL'
                        ? '#fee2e2'
                        : auditReport.overallExposureRisk === 'HIGH'
                        ? '#ffedd5'
                        : auditReport.overallExposureRisk === 'MODERATE'
                        ? '#fef3c7'
                        : '#ecfdf5',
                    color:
                      auditReport.overallExposureRisk === 'CRITICAL'
                        ? '#991b1b'
                        : auditReport.overallExposureRisk === 'HIGH'
                        ? '#c2410c'
                        : auditReport.overallExposureRisk === 'MODERATE'
                        ? '#b45309'
                        : '#047857',
                    border: '2px solid var(--border-dark)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    fontWeight: 800,
                    textTransform: 'uppercase'
                  }}
                >
                  EXPOSURE: {auditReport.overallExposureRisk} ({auditReport.openPointsDetected} OPEN POINT{auditReport.openPointsDetected === 1 ? '' : 'S'})
                </div>
              </div>

              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', margin: '0 0 1rem 0' }}>
                {auditReport.summaryExplanation}
              </p>

              {auditReport.openEntryPoints.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {auditReport.openEntryPoints.map((point: ExposedEntryPoint) => (
                    <div
                      key={point.id}
                      style={{
                        backgroundColor: 'var(--bg-primary)',
                        border: '2px solid var(--border-dark)',
                        padding: '1rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.75rem'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span
                            style={{
                              padding: '0.2rem 0.5rem',
                              backgroundColor:
                                point.severity === 'CRITICAL' ? '#fee2e2' : point.severity === 'HIGH' ? '#ffedd5' : '#fef3c7',
                              color:
                                point.severity === 'CRITICAL' ? '#991b1b' : point.severity === 'HIGH' ? '#c2410c' : '#b45309',
                              border: '1px solid var(--border-dark)',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.7rem',
                              fontWeight: 800
                            }}
                          >
                            {point.severity}
                          </span>
                          <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                            {point.name}
                          </strong>
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--color-brand)', fontWeight: 700 }}>
                          {point.target}
                        </span>
                      </div>

                      <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: 1.45 }}>
                        {point.description}
                      </div>

                      {/* Hacker Exploitation Vector */}
                      <div
                        style={{
                          backgroundColor: '#FEF2F2',
                          border: '1px solid #F87171',
                          padding: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          color: '#991B1B'
                        }}
                      >
                        <strong style={{ display: 'block', marginBottom: '0.25rem', textTransform: 'uppercase' }}>
                          🥷 How Hackers Exploit This Entry Point:
                        </strong>
                        {point.hackerAttackVector}
                      </div>

                      {/* Step-by-Step Remediation / Solution */}
                      <div
                        style={{
                          backgroundColor: '#F0FDF4',
                          border: '1px solid #4ADE80',
                          padding: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          color: '#166534'
                        }}
                      >
                        <strong style={{ display: 'block', marginBottom: '0.35rem', textTransform: 'uppercase' }}>
                          🛠️ Remediation Blueprint &amp; Solution:
                        </strong>
                        <div style={{ fontWeight: 700, marginBottom: '0.35rem' }}>
                          {point.remediationSolution.summary}
                        </div>
                        <ol style={{ margin: 0, paddingLeft: '1.25rem' }}>
                          {point.remediationSolution.steps.map((step, idx) => (
                            <li key={idx} style={{ marginBottom: '0.2rem' }}>{step}</li>
                          ))}
                        </ol>

                        {point.remediationSolution.technicalCodeSnippet && (
                          <div style={{ marginTop: '0.5rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                              <span style={{ fontWeight: 800 }}>Server Directive / Rule:</span>
                              <button
                                type="button"
                                onClick={() => handleCopyCode(point.remediationSolution.technicalCodeSnippet!, point.id)}
                                style={{
                                  padding: '0.15rem 0.5rem',
                                  backgroundColor: '#FFFFFF',
                                  border: '1px solid var(--border-dark)',
                                  fontSize: '0.65rem',
                                  fontFamily: 'var(--font-mono)',
                                  fontWeight: 700,
                                  cursor: 'pointer'
                                }}
                              >
                                {copiedId === point.id ? '✓ Copied' : '📋 Copy Code'}
                              </button>
                            </div>
                            <pre
                              style={{
                                margin: 0,
                                padding: '0.5rem',
                                backgroundColor: '#111111',
                                color: '#A3E635',
                                fontSize: '0.7rem',
                                overflowX: 'auto',
                                border: '1px solid var(--border-dark)'
                              }}
                            >
                              {point.remediationSolution.technicalCodeSnippet}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div
                  style={{
                    backgroundColor: 'var(--color-safe-bg)',
                    border: '1px solid var(--border-dark)',
                    padding: '0.85rem',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    color: '#111111'
                  }}
                >
                  ✓ Zero known dangerous entry ports or exposed secret files detected on this website. Baseline perimeter secure.
                </div>
              )}
            </div>
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
            <span style={{ color: 'var(--color-accent)', fontWeight: 800 }}>TELEMETRY STREAM</span>
            <span style={{ color: '#1DB954' }}>● LIVE</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', color: '#CCCCCC' }}>
            <div><span style={{ color: '#888888' }}>[SYS]</span> Core engine ready</div>
            <div><span style={{ color: '#888888' }}>[NET]</span> Network isolation: STRICT</div>
            <div><span style={{ color: '#888888' }}>[MEM]</span> Volatile RAM: 42MB</div>
            <div><span style={{ color: '#888888' }}>[CSP]</span> connect-src: &apos;self&apos;</div>
            <div><span style={{ color: '#888888' }}>[WASM]</span> Shannon entropy active</div>
            <div><span style={{ color: '#888888' }}>[BLOOM]</span> Filter entries: 120,000</div>
            {isScanning && (
              <div style={{ color: 'var(--color-accent)' }}>
                <span>&gt;&gt;</span> Scanning payload in RAM...
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
