import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { TabSecurityState, ExtensionSettings, DEFAULT_SETTINGS } from '../shared/types';
import { MessageType, createMessage } from '../shared/messages';
import { formatRiskScore, formatVerdict } from '../shared/formatters';

export const PopupApp: React.FC = () => {
  const [tabState, setTabState] = useState<TabSecurityState | null>(null);
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = useState<boolean>(true);
  const [manualUrl, setManualUrl] = useState<string>('');
  const [manualResult, setManualResult] = useState<TabSecurityState | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);

  useEffect(() => {
    // 1. Query active tab
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.runtime) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const activeTab = tabs[0];
        if (activeTab?.id) {
          const msg = createMessage(MessageType.GET_TAB_STATUS, { tabId: activeTab.id });
          chrome.runtime.sendMessage(msg, (response) => {
            if (response?.success && response?.state) {
              setTabState(response.state);
            } else {
              // Synthetic state if tab not yet scanned (e.g. initial load)
              setTabState({
                tabId: activeTab.id!,
                url: activeTab.url || 'about:blank',
                domain: activeTab.url ? new URL(activeTab.url).hostname : 'current-tab',
                verdict: 'ALLOW' as any,
                overallScore: 0,
                severity: 'NONE' as any,
                confidence: 1.0,
                threatCategory: 'UNSCANNED',
                evidence: [],
                recommendation: {
                  action: 'ALLOW' as any,
                  frictionLevel: 'NONE' as any,
                  suggestedAction: 'Ready to evaluate.',
                  bypassPermitted: true
                },
                timestamp: Date.now(),
                overridden: false,
                isRestrictedUrl: activeTab.url?.startsWith('chrome://') || activeTab.url?.startsWith('about:')
              });
            }
            setLoading(false);
          });
        } else {
          setLoading(false);
        }
      });

      // 2. Fetch current settings
      const settingsMsg = createMessage(MessageType.GET_SETTINGS, {});
      chrome.runtime.sendMessage(settingsMsg, (res) => {
        if (res?.success && res.settings) {
          setSettings(res.settings);
        }
      });
    } else {
      setLoading(false);
    }
  }, []);

  const handleManualScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualUrl.trim()) return;

    setIsScanning(true);
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      const msg = createMessage(MessageType.ANALYZE_URL_MANUAL, { url: manualUrl.trim() });
      chrome.runtime.sendMessage(msg, (res) => {
        setIsScanning(false);
        if (res?.success && res.result) {
          setManualResult(res.result);
        }
      });
    } else {
      setIsScanning(false);
    }
  };

  const handleAllowlistCurrent = () => {
    if (!tabState?.domain) return;
    const updated = {
      ...settings,
      allowlistDomains: [...new Set([...settings.allowlistDomains, tabState.domain])]
    };
    setSettings(updated);
    setTabState({
      ...tabState,
      verdict: 'ALLOW' as any,
      overallScore: 0,
      severity: 'NONE' as any,
      threatCategory: 'CUSTOM_ALLOWLIST',
      evidence: [],
      aiExplanation: undefined,
      overridden: true
    });
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      const msg = createMessage(MessageType.UPDATE_SETTINGS, updated);
      chrome.runtime.sendMessage(msg);
    }
  };

  const openOptions = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime?.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  };

  if (loading) {
    return <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>Checking on-device security...</div>;
  }

  const scoreVisual = formatRiskScore(tabState?.overallScore ?? 0);

  return (
    <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.65rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span style={{ fontSize: '1.25rem' }}>🛡️</span>
          <strong style={{ fontSize: '0.95rem', letterSpacing: '-0.02em' }}>PRIVEX</strong>
        </div>
        <button
          onClick={openOptions}
          style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.8rem' }}
          title="Open Extension Settings"
        >
          ⚙️ Settings
        </button>
      </div>

      {/* Restricted Page Notice */}
      {tabState?.isRestrictedUrl ? (
        <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.375rem', fontSize: '0.8rem', color: '#93c5fd' }}>
          🔒 <strong>Browser System Page</strong>
          <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.75rem' }}>
            Internal browser protocols (chrome://, about:) run inside native sandboxes and cannot be monitored.
          </p>
        </div>
      ) : (
        /* Active Tab Status Card */
        <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {tabState?.domain || 'Active Page'}
            </span>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                padding: '0.2rem 0.5rem',
                borderRadius: '0.25rem',
                backgroundColor: `${scoreVisual.color}20`,
                color: scoreVisual.color,
                border: `1px solid ${scoreVisual.color}40`
              }}
            >
              {formatVerdict(tabState?.verdict as any)}
            </span>
          </div>

          {/* Risk Score Meter */}
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.75rem', fontWeight: 800, color: scoreVisual.color, lineHeight: 1 }}>
              {tabState?.overallScore ?? 0}
            </span>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>/ 100 Risk Index ({scoreVisual.label})</span>
          </div>

          {/* Threat Indicators */}
          {tabState?.evidence && tabState.evidence.length > 0 && (
            <div style={{ fontSize: '0.75rem', color: '#fca5a5', borderTop: '1px solid var(--border-color)', paddingTop: '0.4rem' }}>
              <strong>Detected Signals:</strong>
              <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1rem', color: '#94a3b8' }}>
                {tabState.evidence.slice(0, 3).map((ev, i) => (
                  <li key={i}>{ev.name}</li>
                ))}
              </ul>
            </div>
          )}

          {/* AI Explanation Briefing */}
          {tabState?.aiExplanation && (
            <div style={{ fontSize: '0.75rem', backgroundColor: 'rgba(59, 130, 246, 0.08)', padding: '0.5rem', borderRadius: '0.25rem', border: '1px solid rgba(59, 130, 246, 0.2)' }}>
              <div style={{ color: '#93c5fd', fontWeight: 600, marginBottom: '0.2rem' }}>
                🤖 AI Threat Briefing:
              </div>
              <div style={{ color: '#cbd5e1', lineHeight: 1.4 }}>
                {tabState.aiExplanation.summaryParagraph}
              </div>
            </div>
          )}

          {/* Quick Trust Button */}
          {tabState && tabState.overallScore > 0 && (
            <button
              onClick={handleAllowlistCurrent}
              style={{
                padding: '0.35rem 0.65rem',
                backgroundColor: 'transparent',
                border: '1px solid var(--border-color)',
                color: '#93c5fd',
                borderRadius: '0.25rem',
                fontSize: '0.75rem',
                cursor: 'pointer',
                alignSelf: 'flex-start',
                marginTop: '0.25rem'
              }}
            >
              + Trust This Domain Locally
            </button>
          )}
        </div>
      )}

      {/* Manual URL Quick Scanner */}
      <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
        <form onSubmit={handleManualScan} style={{ display: 'flex', gap: '0.35rem' }}>
          <input
            type="text"
            placeholder="Scan another link..."
            value={manualUrl}
            onChange={(e) => setManualUrl(e.target.value)}
            style={{
              flex: 1,
              padding: '0.4rem 0.6rem',
              backgroundColor: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '0.25rem',
              color: 'var(--text-primary)',
              fontSize: '0.8rem',
              outline: 'none'
            }}
          />
          <button
            type="submit"
            disabled={isScanning || !manualUrl.trim()}
            style={{
              padding: '0.4rem 0.75rem',
              backgroundColor: 'var(--color-brand)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '0.25rem',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: isScanning || !manualUrl.trim() ? 'not-allowed' : 'pointer'
            }}
          >
            {isScanning ? '...' : 'Scan'}
          </button>
        </form>

        {manualResult && (
          <div style={{ marginTop: '0.5rem', padding: '0.5rem', backgroundColor: 'var(--bg-card)', borderRadius: '0.25rem', fontSize: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: formatRiskScore(manualResult.overallScore).color, fontWeight: 700 }}>
              <span>{formatVerdict(manualResult.verdict)}</span>
              <span>Score: {manualResult.overallScore}</span>
            </div>
            {manualResult.aiExplanation && (
              <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8' }}>
                {manualResult.aiExplanation.headline}
              </p>
            )}
          </div>
        )}
      </div>

      {/* Footer Guarantees */}
      <div style={{ fontSize: '0.7rem', color: '#64748b', textAlign: 'center', borderTop: '1px solid var(--border-color)', paddingTop: '0.5rem' }}>
        🔒 100% On-Device Processing • Zero Browsing History Collected
      </div>
    </div>
  );
};

const rootEl = document.getElementById('root');
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(<PopupApp />);
}
