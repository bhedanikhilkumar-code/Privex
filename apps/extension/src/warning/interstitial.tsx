import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { TabSecurityState } from '../shared/types';
import { MessageType, createMessage } from '../shared/messages';
import { formatRiskScore, formatVerdict } from '../shared/formatters';

export const InterstitialApp: React.FC = () => {
  const [tabId, setTabId] = useState<number>(-1);
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [tabState, setTabState] = useState<TabSecurityState | null>(null);
  const [countdown, setCountdown] = useState<number>(5);
  const [showOverrideConfirm, setShowOverrideConfirm] = useState<boolean>(false);
  const [isOverriding, setIsOverriding] = useState<boolean>(false);

  useEffect(() => {
    // 1. Parse URL query params
    const params = new URLSearchParams(window.location.search);
    const parsedTabId = parseInt(params.get('tabId') || '-1', 10);
    const parsedTarget = decodeURIComponent(params.get('target') || '');

    setTabId(parsedTabId);
    setTargetUrl(parsedTarget);

    // 2. Fetch Tab Security State from background
    if (parsedTabId !== -1 && typeof chrome !== 'undefined' && chrome.runtime) {
      const msg = createMessage(MessageType.GET_TAB_STATUS, { tabId: parsedTabId });
      chrome.runtime.sendMessage(msg, (response) => {
        if (response?.success && response?.state) {
          setTabState(response.state);
        }
      });
    }

    // 3. Friction Gate Countdown Timer (5 seconds)
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const handleGoBack = () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  };

  const handleProceedOverride = () => {
    if (countdown > 0) return;
    setIsOverriding(true);

    if (typeof chrome !== 'undefined' && chrome.runtime) {
      const msg = createMessage(MessageType.REQUEST_OVERRIDE, { tabId, targetUrl });
      chrome.runtime.sendMessage(msg, (res) => {
        if (res?.success && res.proceedUrl) {
          window.location.href = res.proceedUrl;
        } else {
          setIsOverriding(false);
        }
      });
    } else {
      setIsOverriding(false);
    }
  };

  const scoreVisual = formatRiskScore(tabState?.overallScore ?? 90);

  return (
    <main
      role="main"
      className="interstitial-panel"
      style={{
        maxWidth: '750px',
        margin: '3rem auto',
        padding: '2.5rem',
        backgroundColor: 'var(--bg-card)',
        borderRadius: '1rem',
        border: '2px solid #ef4444',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(239, 68, 68, 0.2)'
      }}
    >
      {/* Warning Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <div
          className="interstitial-shield-icon"
          style={{
            width: '3.5rem',
            height: '3.5rem',
            borderRadius: '0.75rem',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid #ef4444',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.75rem'
          }}
        >
          🛑
        </div>
        <div>
          <span
            style={{
              display: 'inline-block',
              fontSize: '0.75rem',
              fontWeight: 800,
              letterSpacing: '0.05em',
              color: '#f87171',
              textTransform: 'uppercase',
              marginBottom: '0.2rem'
            }}
          >
            {formatVerdict(tabState?.verdict as any || 'DANGEROUS')}
          </span>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 800, margin: 0, color: '#fef2f2' }}>
            Dangerous Website Blocked
          </h1>
        </div>
      </div>

      {/* Target URL Preview */}
      <div
        style={{
          padding: '0.75rem 1rem',
          backgroundColor: 'rgba(0, 0, 0, 0.3)',
          border: '1px solid var(--border-color)',
          borderRadius: '0.5rem',
          fontSize: '0.85rem',
          fontFamily: 'monospace',
          color: '#fca5a5',
          wordBreak: 'break-all',
          marginBottom: '1.5rem'
        }}
      >
        <span>Destination: </span>
        <strong>{targetUrl || 'Unknown Suspicious Destination'}</strong>
      </div>

      {/* Threat Summary & Score */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', padding: '1rem', backgroundColor: 'rgba(239, 68, 68, 0.08)', borderRadius: '0.5rem', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
        <div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>Primary Threat Vector</span>
          <strong style={{ fontSize: '1.1rem', color: '#f87171' }}>
            {tabState?.threatCategory || 'MALICIOUS_PHISHING'}
          </strong>
        </div>
        <div style={{ textAlign: 'right' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>Threat Risk Index</span>
          <strong style={{ fontSize: '1.5rem', color: scoreVisual.color }}>
            {tabState?.overallScore ?? 95} / 100
          </strong>
        </div>
      </div>

      {/* AI Security Assistant Plain-Language Explanation */}
      {tabState?.aiExplanation ? (
        <div style={{ marginBottom: '1.5rem', padding: '1.25rem', backgroundColor: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.25)', borderRadius: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <span>🤖</span>
            <strong style={{ fontSize: '0.9rem', color: '#93c5fd' }}>
              Why This Website Is Dangerous (AI Assistant Briefing)
            </strong>
          </div>
          <p style={{ margin: '0 0 0.75rem 0', fontSize: '0.9rem', color: '#e2e8f0', lineHeight: 1.5 }}>
            {tabState.aiExplanation.summaryParagraph}
          </p>

          {tabState.aiExplanation.dangerFactors.length > 0 && (
            <div style={{ marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.8rem', color: '#fca5a5', fontWeight: 600 }}>Detected Risk Factors:</span>
              <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
                {tabState.aiExplanation.dangerFactors.map((df: string, i: number) => (
                  <li key={i}>{df}</li>
                ))}
              </ul>
            </div>
          )}

          {tabState.aiExplanation.recommendedSteps.length > 0 && (
            <div>
              <span style={{ fontSize: '0.8rem', color: '#6ee7b7', fontWeight: 600 }}>Recommended Defensive Action:</span>
              <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
                {tabState.aiExplanation.recommendedSteps.map((step: string, i: number) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        /* Fallback Structured Evidence Display */
        <div style={{ marginBottom: '1.5rem', padding: '1rem', backgroundColor: 'rgba(239, 68, 68, 0.05)', borderRadius: '0.5rem', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
          <strong style={{ fontSize: '0.85rem', color: '#fca5a5' }}>Security Engine Evidence:</strong>
          <ul style={{ margin: '0.5rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
            {tabState?.evidence?.map((ev, i) => (
              <li key={i}>
                <strong>{ev.name}:</strong> {ev.description}
              </li>
            )) || (
              <li>This web destination exhibits strong indicators of brand spoofing or credential theft.</li>
            )}
          </ul>
        </div>
      )}

      {/* Action Buttons */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderTop: '1px solid var(--border-color)', paddingTop: '1.5rem' }}>
        <button
          type="button"
          onClick={handleGoBack}
          style={{
            padding: '0.75rem 1.75rem',
            backgroundColor: '#10b981',
            color: '#ffffff',
            border: 'none',
            borderRadius: '0.5rem',
            fontSize: '1rem',
            fontWeight: 700,
            cursor: 'pointer',
            boxShadow: '0 4px 6px -1px rgba(16, 185, 129, 0.3)'
          }}
        >
          🛡️ Back to Safety (Recommended)
        </button>

        {/* Override Control */}
        {!showOverrideConfirm ? (
          <button
            type="button"
            onClick={() => setShowOverrideConfirm(true)}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'transparent',
              border: 'none',
              color: '#94a3b8',
              fontSize: '0.85rem',
              cursor: 'pointer',
              textDecoration: 'underline'
            }}
          >
            Advanced / Override Options
          </button>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              type="button"
              disabled={countdown > 0 || isOverriding}
              onClick={handleProceedOverride}
              style={{
                padding: '0.75rem 1.25rem',
                backgroundColor: countdown > 0 ? '#1e293b' : 'rgba(239, 68, 68, 0.2)',
                border: `1px solid ${countdown > 0 ? '#475569' : '#ef4444'}`,
                color: countdown > 0 ? '#64748b' : '#fca5a5',
                borderRadius: '0.5rem',
                fontSize: '0.85rem',
                fontWeight: 600,
                cursor: countdown > 0 ? 'not-allowed' : 'pointer'
              }}
            >
              {countdown > 0
                ? `Wait ${countdown}s (Safety Gate)`
                : isOverriding
                ? 'Proceeding...'
                : 'I Understand the Risks (Proceed Anyway)'}
            </button>
          </div>
        )}
      </div>
    </main>
  );
};

const rootEl = document.getElementById('root');
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(<InterstitialApp />);
}
