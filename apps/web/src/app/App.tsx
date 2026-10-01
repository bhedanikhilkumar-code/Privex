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
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header />
      <Navigation activeTab={activeTab} onTabChange={setActiveTab} />

      <main
        role="main"
        id={`panel-${activeTab.toLowerCase()}`}
        tabIndex={-1}
        style={{
          flex: 1,
          padding: '2rem',
          maxWidth: '1200px',
          width: '100%',
          margin: '0 auto',
          outline: 'none'
        }}
      >
        {activeTab === 'HOME' && (
          <section aria-labelledby="home-heading" style={{ maxWidth: '850px', margin: '0 auto' }}>
            <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '0.35rem 0.85rem',
                  backgroundColor: 'rgba(59, 130, 246, 0.1)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  borderRadius: '9999px',
                  color: '#93c5fd',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  marginBottom: '1rem'
                }}
              >
                <span>🚀</span> Zero-Install • Local-First • Privacy-First
              </div>

              <h2 id="home-heading" style={{ fontSize: '2.25rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '0.75rem' }}>
                On-Device Threat & Scam Protection
              </h2>

              <p style={{ fontSize: '1.05rem', color: 'var(--text-muted)', maxWidth: '650px', margin: '0 auto', lineHeight: 1.6 }}>
                Instantly detect phishing links, deceptive messages, extortion attempts, and scams directly
                in your browser without transmitting sensitive user data to the cloud.
              </p>
            </div>

            {/* Quick Launch Cards */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                gap: '1.25rem',
                marginBottom: '2.5rem'
              }}
            >
              <div
                onClick={() => setActiveTab('URL_SCAN')}
                style={{
                  padding: '1.5rem',
                  backgroundColor: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '0.75rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
              >
                <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>🔗</div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                  URL & Link Scanner
                </h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Inspect suspicious links for brand spoofing, typosquatting, Punycode homographs, and high-abuse TLDs.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('TEXT_SCAN')}
                style={{
                  padding: '1.5rem',
                  backgroundColor: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '0.75rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
              >
                <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>💬</div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                  Message & Scam Analyzer
                </h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Paste suspicious text messages, invoice notices, employment task scams, or crypto extortion threats.
                </p>
              </div>

              <div
                onClick={() => setActiveTab('ASSISTANT')}
                style={{
                  padding: '1.5rem',
                  backgroundColor: 'var(--bg-card)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '0.75rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
              >
                <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>🤖</div>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                  AI Security Assistant
                </h3>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Receive Grade 6 jargon-free explanations detailing why content is deceptive and what defensive steps to take.
                </p>
              </div>
            </div>

            {/* Browser Security Status Bar */}
            <div
              style={{
                padding: '1.25rem',
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border-color)',
                borderRadius: '0.5rem',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '1rem',
                fontSize: '0.85rem'
              }}
            >
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Network Connectivity</span>
                <strong style={{ color: isOnline ? '#34d399' : '#f59e0b' }}>
                  {isOnline ? '🟢 Connected (Zero Cloud Requests)' : '🟡 Air-Gapped (100% Operational)'}
                </strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Processing Sandbox</span>
                <strong style={{ color: '#60a5fa' }}>Client Browser Volatile RAM</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem' }}>Defense Invariant</span>
                <strong style={{ color: '#a78bfa' }}>Core &gt; ML &gt; AI Assistant</strong>
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
