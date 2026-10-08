import React, { useState, useMemo, useEffect } from 'react';
import { ActiveTab, UserPreferences } from '../scanner/types';
import { WorkerBridge } from '../workers/worker-bridge';
import { PreferenceStorage } from '../lib/storage';
import { Header } from '../components/layout/Header';
import { Navigation } from '../components/layout/Navigation';
import { Footer } from '../components/layout/Footer';
import { UrlScannerView } from '../components/scanner/UrlScannerView';
import { TextScannerView } from '../components/scanner/TextScannerView';
import { AssistantView } from '../components/assistant/AssistantView';
import { PrivacyView } from '../components/privacy/PrivacyView';
import { SettingsView } from '../components/settings/SettingsView';
import { SecurityDashboardView } from '../components/security/SecurityDashboardView';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('HOME');
  const [preferences, setPreferences] = useState<UserPreferences>(() => PreferenceStorage.loadPreferences());
  const [isOnline, setIsOnline] = useState<boolean>(typeof navigator !== 'undefined' ? navigator.onLine : true);

  // Initialize WorkerBridge
  const scannerBridge = useMemo(() => new WorkerBridge(), []);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      scannerBridge.terminate();
    };
  }, [scannerBridge]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-primary)' }}>
      <Header />
      <Navigation activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Air-gapped / Offline alert banner if offline */}
      {!isOnline && (
        <aside
          role="status"
          aria-label="Offline Mode Active"
          style={{
            backgroundColor: 'var(--color-caution)',
            borderBottom: '2px solid var(--border-dark)',
            padding: '0.75rem 2rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 700,
            color: '#111111'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '1.1rem' }}>⚡</span>
            <span>Disconnected, but not Defenseless. 100% On-Device Threat Detection Active.</span>
          </div>
          <span style={{ backgroundColor: '#111111', color: '#FFFFFF', padding: '0.2rem 0.6rem', fontSize: '0.75rem' }}>
            AIR-GAPPED PARITY
          </span>
        </aside>
      )}

      <main
        role="main"
        id={`panel-${activeTab.toLowerCase()}`}
        tabIndex={-1}
        style={{
          flex: 1,
          padding: '2.5rem 2rem',
          maxWidth: '1200px',
          width: '100%',
          margin: '0 auto',
          outline: 'none'
        }}
      >
        {activeTab === 'HOME' && (
          <section aria-labelledby="home-heading" style={{ maxWidth: '1020px', margin: '0 auto' }}>
            {/* Hero Section */}
            <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '0.35rem 0.85rem',
                  backgroundColor: 'var(--color-accent)',
                  border: '2px solid var(--border-dark)',
                  boxShadow: '2px 2px 0px #111111',
                  color: '#111111',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.75rem',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  marginBottom: '1.25rem',
                  letterSpacing: '0.04em'
                }}
              >
                <span>🚀</span> Zero-Install • Local-First • Privacy-First
              </div>

              <h2
                id="home-heading"
                style={{
                  fontFamily: 'var(--font-serif)',
                  fontSize: '3rem',
                  fontWeight: 800,
                  letterSpacing: '-0.03em',
                  lineHeight: 1.15,
                  marginBottom: '1rem',
                  color: '#111111'
                }}
              >
                Neutralize digital threats before they reach your data.
              </h2>

              <p
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.9rem',
                  color: 'var(--color-brand)',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  marginBottom: '0.75rem'
                }}
              >
                On-Device Threat &amp; Scam Protection
              </p>

              <p
                style={{
                  fontSize: '1.15rem',
                  color: 'var(--text-muted)',
                  maxWidth: '720px',
                  margin: '0 auto',
                  lineHeight: 1.6
                }}
              >
                Instant, on-device analysis for links, messages, and communications. Zero cloud logging.
                Pure endpoint intelligence executed in volatile RAM.
              </p>
            </div>

            {/* Featured Sample Card (from Landing Page design) */}
            <div
              style={{
                backgroundColor: '#FFFFFF',
                border: '2px solid var(--border-dark)',
                boxShadow: 'var(--shadow-brutal-lg)',
                padding: '1.5rem',
                marginBottom: '3rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '1.25rem'
              }}
            >
              <div style={{ flex: '1 1 500px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                  <span
                    style={{
                      backgroundColor: 'var(--color-safe)',
                      color: '#FFFFFF',
                      padding: '0.2rem 0.6rem',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.725rem',
                      fontWeight: 800,
                      border: '1px solid var(--border-dark)',
                      textTransform: 'uppercase'
                    }}
                  >
                    SAFE / VERIFIED
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 700 }}>
                    amazon.com/order-history
                  </span>
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0 }}>
                  Legitimate e-commerce portal verified. Clean certificate chain, zero redirect anomalies, verified brand identity.
                </p>
              </div>

              <button
                type="button"
                onClick={() => setActiveTab('URL_SCAN')}
                style={{
                  padding: '0.75rem 1.5rem',
                  backgroundColor: 'var(--color-brand)',
                  color: '#FFFFFF',
                  border: '2px solid var(--border-dark)',
                  boxShadow: '3px 3px 0px #111111',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.85rem',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  cursor: 'pointer'
                }}
              >
                Launch Scanner →
              </button>
            </div>

            {/* Quick Launch Cards */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                gap: '1.5rem',
                marginBottom: '3rem'
              }}
            >
              <div
                onClick={() => setActiveTab('URL_SCAN')}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter') setActiveTab('URL_SCAN'); }}
                style={{
                  padding: '1.75rem',
                  backgroundColor: '#FFFFFF',
                  border: '2px solid var(--border-dark)',
                  boxShadow: 'var(--shadow-brutal)',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease'
                }}
              >
                <div style={{ fontSize: '2.25rem', marginBottom: '0.75rem' }}>🔗</div>
                <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.35rem', fontWeight: 800, marginBottom: '0.4rem' }}>
                  URL &amp; Link Scanner
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.55 }}>
                  Inspect suspicious links for brand spoofing, typosquatting distance, Punycode homographs, and deceptive IP targets.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('TEXT_SCAN')}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter') setActiveTab('TEXT_SCAN'); }}
                style={{
                  padding: '1.75rem',
                  backgroundColor: '#FFFFFF',
                  border: '2px solid var(--border-dark)',
                  boxShadow: 'var(--shadow-brutal)',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease'
                }}
              >
                <div style={{ fontSize: '2.25rem', marginBottom: '0.75rem' }}>💬</div>
                <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.35rem', fontWeight: 800, marginBottom: '0.4rem' }}>
                  Message &amp; Scam Analyzer
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.55 }}>
                  Paste suspicious text messages, invoice notices, task scam solicitations, or urgent cryptocurrency extortion demands.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('ASSISTANT')}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter') setActiveTab('ASSISTANT'); }}
                style={{
                  padding: '1.75rem',
                  backgroundColor: '#FFFFFF',
                  border: '2px solid var(--border-dark)',
                  boxShadow: 'var(--shadow-brutal)',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease'
                }}
              >
                <div style={{ fontSize: '2.25rem', marginBottom: '0.75rem' }}>🤖</div>
                <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.35rem', fontWeight: 800, marginBottom: '0.4rem' }}>
                  AI Security Assistant
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.55 }}>
                  Receive Grade 6 jargon-free explanations detailing why content is deceptive and specific defensive steps to take.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('SECURITY_MONITOR')}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter') setActiveTab('SECURITY_MONITOR'); }}
                style={{
                  padding: '1.75rem',
                  backgroundColor: '#FFFFFF',
                  border: '2px solid var(--border-dark)',
                  boxShadow: 'var(--shadow-brutal)',
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease'
                }}
              >
                <div style={{ fontSize: '2.25rem', marginBottom: '0.75rem' }}>🛡️</div>
                <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.35rem', fontWeight: 800, marginBottom: '0.4rem' }}>
                  Password &amp; Network Protection
                </h3>
                <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.55 }}>
                  Check password security, generate high-entropy keys, monitor outbound application requests, and detect traffic spikes.
                </p>
              </div>
            </div>

            {/* CORE PRINCIPLES (From Landing Page.png) */}
            <div style={{ marginBottom: '3rem' }}>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.8rem',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  color: 'var(--text-muted)',
                  marginBottom: '1rem'
                }}
              >
                CORE PRINCIPLES
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                  gap: '1.25rem'
                }}
              >
                <div
                  style={{
                    backgroundColor: 'var(--bg-secondary)',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '3px 3px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', marginBottom: '0.35rem' }}>
                    01 • ZERO CLOUD DEPENDENCY
                  </div>
                  <h4 style={{ fontSize: '1.05rem', fontWeight: 800, marginBottom: '0.35rem' }}>
                    100% Volatile RAM
                  </h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Every byte evaluated directly on this device. No telemetry containing raw user payloads ever leaves your hardware.
                  </p>
                </div>

                <div
                  style={{
                    backgroundColor: 'var(--bg-secondary)',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '3px 3px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', marginBottom: '0.35rem' }}>
                    02 • DETERMINISTIC CORE
                  </div>
                  <h4 style={{ fontSize: '1.05rem', fontWeight: 800, marginBottom: '0.35rem' }}>
                    Rules Lead, AI Explains
                  </h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Security decisions are mathematically proven by deterministic rules and Bloom filters. The AI assistant has zero authority to override verdicts.
                  </p>
                </div>

                <div
                  style={{
                    backgroundColor: 'var(--bg-secondary)',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '3px 3px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', marginBottom: '0.35rem' }}>
                    03 • AIR-GAPPED PARITY
                  </div>
                  <h4 style={{ fontSize: '1.05rem', fontWeight: 800, marginBottom: '0.35rem' }}>
                    Offline Functional
                  </h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    Full threat detection capabilities operate without an active internet connection, preventing network-based tracking.
                  </p>
                </div>
              </div>
            </div>

            {/* How Private Protection Works (4-Step Pipeline from Landing Page & How It Works designs) */}
            <div style={{ marginBottom: '3rem' }}>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.8rem',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  color: 'var(--text-muted)',
                  marginBottom: '1rem'
                }}
              >
                HOW PRIVATE PROTECTION WORKS
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '1rem'
                }}
              >
                {[
                  { step: '01', title: 'Ingestion & Parsing', desc: 'Strict byte limits, Unicode NFKD normalization, punycode decoding in RAM.' },
                  { step: '02', title: 'Rule & Reputation', desc: 'Deterministic regex matching, raw IP hosts, high-abuse TLDs, and Bloom filters.' },
                  { step: '03', title: 'Local ML Classifier', desc: 'Quantized on-device intent classifiers evaluate pressure and extortion signals.' },
                  { step: '04', title: 'Risk Synthesis', desc: 'Bounded Bayesian aggregation produces immutable score (0-100) and action recommendation.' }
                ].map((item) => (
                  <div
                    key={item.step}
                    style={{
                      backgroundColor: '#FFFFFF',
                      border: '2px solid var(--border-dark)',
                      boxShadow: '2px 2px 0px #111111',
                      padding: '1.25rem'
                    }}
                  >
                    <div style={{ fontFamily: 'var(--font-serif)', fontSize: '1.5rem', fontWeight: 800, color: 'var(--color-brand)', marginBottom: '0.25rem' }}>
                      {item.step}
                    </div>
                    <h5 style={{ fontSize: '0.95rem', fontWeight: 800, marginBottom: '0.35rem' }}>
                      {item.title}
                    </h5>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.45, margin: 0 }}>
                      {item.desc}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Supported Platforms & Direct Downloads */}
            <div style={{ marginBottom: '3rem' }}>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.8rem',
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  color: 'var(--text-muted)',
                  marginBottom: '1rem'
                }}
              >
                SUPPORTED PLATFORMS &amp; DIRECT DOWNLOADS
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '1rem'
                }}
              >
                <div
                  style={{
                    backgroundColor: '#FFFFFF',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '2px 2px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontSize: '1.5rem', marginBottom: '0.35rem' }}>🌐</div>
                  <h5 style={{ fontSize: '0.95rem', fontWeight: 800, marginBottom: '0.25rem' }}>
                    Web Application
                  </h5>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem', lineHeight: 1.4 }}>
                    Zero-install client PWA. Runs in browser memory with full air-gapped offline support.
                  </p>
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--color-safe)' }}>
                    ● ACTIVE IN BROWSER
                  </span>
                </div>

                <div
                  style={{
                    backgroundColor: '#FFFFFF',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '2px 2px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontSize: '1.5rem', marginBottom: '0.35rem' }}>📱</div>
                  <h5 style={{ fontSize: '0.95rem', fontWeight: 800, marginBottom: '0.25rem' }}>
                    Android Mobile
                  </h5>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem', lineHeight: 1.4 }}>
                    Direct APK sideload for Android 8.0+. Live QR scanning and SMS notification filter.
                  </p>
                  <a
                    href="/downloads/private-protection-mobile-0.1.1.apk"
                    download="private-protection-mobile-0.1.1.apk"
                    style={{
                      display: 'inline-block',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 800,
                      color: 'var(--color-brand)',
                      textDecoration: 'underline'
                    }}
                  >
                    Direct APK (1.0 MB) →
                  </a>
                </div>

                <div
                  style={{
                    backgroundColor: '#FFFFFF',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '2px 2px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontSize: '1.5rem', marginBottom: '0.35rem' }}>💻</div>
                  <h5 style={{ fontSize: '0.95rem', fontWeight: 800, marginBottom: '0.25rem' }}>
                    Windows Desktop
                  </h5>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem', lineHeight: 1.4 }}>
                    Windows 10/11 x64 installer &amp; portable. Downloads watcher and quarantine vault.
                  </p>
                  <a
                    href="https://github.com/bhedanikhilkumar-code/Private-Protection/releases/tag/v0.1.1"
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'inline-block',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 800,
                      color: 'var(--color-brand)',
                      textDecoration: 'underline'
                    }}
                  >
                    Desktop Downloads →
                  </a>
                </div>

                <div
                  style={{
                    backgroundColor: '#FFFFFF',
                    border: '2px solid var(--border-dark)',
                    boxShadow: '2px 2px 0px #111111',
                    padding: '1.25rem'
                  }}
                >
                  <div style={{ fontSize: '1.5rem', marginBottom: '0.35rem' }}>🧩</div>
                  <h5 style={{ fontSize: '0.95rem', fontWeight: 800, marginBottom: '0.25rem' }}>
                    Browser Extension
                  </h5>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem', lineHeight: 1.4 }}>
                    Chromium Manifest V3 zip. Pre-navigation link interceptor and phishing shield.
                  </p>
                  <a
                    href="/downloads/private-protection-extension-0.1.1.zip"
                    download="private-protection-extension-0.1.1.zip"
                    style={{
                      display: 'inline-block',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 800,
                      color: 'var(--color-brand)',
                      textDecoration: 'underline'
                    }}
                  >
                    Extension ZIP (100 KB) →
                  </a>
                </div>
              </div>
            </div>

            {/* Browser Security Status Bar */}
            <div
              style={{
                padding: '1.25rem 1.5rem',
                backgroundColor: '#FFFFFF',
                border: '2px solid var(--border-dark)',
                boxShadow: 'var(--shadow-brutal)',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '1.25rem',
                fontSize: '0.85rem',
                fontFamily: 'var(--font-mono)'
              }}
            >
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                  Network Connectivity
                </span>
                <strong style={{ color: isOnline ? '#1DB954' : '#FFB800' }}>
                  {isOnline ? '🟢 Connected (Zero Cloud Requests)' : '🟡 Air-Gapped (100% Operational)'}
                </strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                  Processing Sandbox
                </span>
                <strong style={{ color: 'var(--color-brand)' }}>Client Browser Volatile RAM</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                  Defense Invariant
                </span>
                <strong style={{ color: '#111111' }}>Core &gt; ML &gt; AI Assistant</strong>
              </div>
            </div>
          </section>
        )}

        {activeTab === 'URL_SCAN' && (
          <UrlScannerView scannerBridge={scannerBridge} preferences={preferences} />
        )}

        {activeTab === 'TEXT_SCAN' && (
          <TextScannerView scannerBridge={scannerBridge} preferences={preferences} />
        )}

        {activeTab === 'ASSISTANT' && (
          <AssistantView preferences={preferences} />
        )}

        {activeTab === 'SECURITY_MONITOR' && (
          <SecurityDashboardView />
        )}

        {activeTab === 'PRIVACY' && (
          <PrivacyView />
        )}

        {activeTab === 'SETTINGS' && (
          <SettingsView preferences={preferences} onPreferencesChange={setPreferences} />
        )}
      </main>

      <Footer />
    </div>
  );
};
