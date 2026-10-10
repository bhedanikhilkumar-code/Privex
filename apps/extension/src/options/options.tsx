import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { ExtensionSettings, DEFAULT_SETTINGS, AuditLogEvent } from '../shared/types';
import { ExtensionStorage } from '../shared/storage';
import { MessageType, createMessage } from '../shared/messages';

export const OptionsApp: React.FC = () => {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [auditLogs, setAuditLogs] = useState<AuditLogEvent[]>([]);
  const [newDomain, setNewDomain] = useState<string>('');
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  useEffect(() => {
    ExtensionStorage.getSettings().then((s) => setSettings(s));
    ExtensionStorage.getAuditLogs().then((logs) => setAuditLogs(logs));
  }, []);

  const handleToggleEnabled = () => {
    const updated = { ...settings, enabled: !settings.enabled };
    updateSettings(updated);
  };

  const handleReadingGradeChange = (grade: number) => {
    const updated = { ...settings, readingGrade: grade };
    updateSettings(updated);
  };

  const handleBannerToggle = () => {
    const updated = { ...settings, showShadowDomBanners: !settings.showShadowDomBanners };
    updateSettings(updated);
  };

  const updateSettings = async (updated: ExtensionSettings) => {
    setSettings(updated);
    await ExtensionStorage.saveSettings(updated);

    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage(createMessage(MessageType.UPDATE_SETTINGS, updated));
    }

    setSaveStatus('Preferences saved locally.');
    setTimeout(() => setSaveStatus(null), 2500);
  };

  const handleAddDomain = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newDomain.trim().toLowerCase().replace(/^(https?:\/\/)?/, '').replace(/\/.*$/, '');
    if (!clean) return;

    if (!settings.allowlistDomains.includes(clean)) {
      const updated = {
        ...settings,
        allowlistDomains: [...settings.allowlistDomains, clean]
      };
      updateSettings(updated);
    }
    setNewDomain('');
  };

  const handleRemoveDomain = (domain: string) => {
    const updated = {
      ...settings,
      allowlistDomains: settings.allowlistDomains.filter((d) => d !== domain)
    };
    updateSettings(updated);
  };

  const handleClearAllData = async () => {
    if (confirm('Are you sure you want to crypto-shred and reset all local settings and audit history?')) {
      await ExtensionStorage.clearAllStorage();
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.sendMessage(createMessage(MessageType.CLEAR_ALL_DATA, {}));
      }
      setSettings(DEFAULT_SETTINGS);
      setAuditLogs([]);
      setSaveStatus('All local storage permanently shredded.');
      setTimeout(() => setSaveStatus(null), 3000);
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '2rem auto', padding: '0 1.5rem', color: 'var(--text-primary)' }}>
      {/* Page Heading */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem' }}>
        <img
          src="icons/icon-48.png"
          alt="PRIVEX"
          style={{ width: '40px', height: '40px', objectFit: 'contain' }}
        />
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, margin: 0 }}>Privex Settings</h1>
          <p style={{ margin: '0.25rem 0 0 0', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Manage on-device threat interception, plain-language AI explanation complexity, and local domain allowlists.
          </p>
        </div>
      </div>

      {saveStatus && (
        <div style={{ padding: '0.75rem 1rem', backgroundColor: '#065f46', border: '1px solid #10b981', color: '#a7f3d0', borderRadius: '0.5rem', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
          ✓ {saveStatus}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* 1. Protection Toggle */}
        <div style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem', fontWeight: 700 }}>Real-Time Navigation Defense</h3>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.825rem' }}>
              Intercepts malicious web destinations, typosquatted brands, and phishing IP hosts before connection.
            </p>
          </div>
          <button
            type="button"
            onClick={handleToggleEnabled}
            style={{
              padding: '0.5rem 1.25rem',
              backgroundColor: settings.enabled ? '#065f46' : 'var(--border-color)',
              color: settings.enabled ? '#6ee7b7' : 'var(--text-muted)',
              border: 'none',
              borderRadius: '0.375rem',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {settings.enabled ? 'Protection Active' : 'Protection Paused'}
          </button>
        </div>

        {/* 2. Reading Level */}
        <div style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem' }}>
          <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem', fontWeight: 700 }}>AI Security Assistant Reading Complexity</h3>
          <p style={{ margin: '0 0 0.75rem 0', color: 'var(--text-muted)', fontSize: '0.825rem' }}>
            Choose the reading grade level used when synthesizing explanations of cyber threats.
          </p>
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button
              type="button"
              onClick={() => handleReadingGradeChange(6)}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: settings.readingGrade === 6 ? 'var(--color-brand)' : 'transparent',
                color: '#ffffff',
                border: '1px solid var(--border-color)',
                borderRadius: '0.375rem',
                fontSize: '0.85rem',
                cursor: 'pointer',
                fontWeight: settings.readingGrade === 6 ? 700 : 400
              }}
            >
              Grade 6 (Plain Language, Recommended)
            </button>
            <button
              type="button"
              onClick={() => handleReadingGradeChange(8)}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: settings.readingGrade === 8 ? 'var(--color-brand)' : 'transparent',
                color: '#ffffff',
                border: '1px solid var(--border-color)',
                borderRadius: '0.375rem',
                fontSize: '0.85rem',
                cursor: 'pointer',
                fontWeight: settings.readingGrade === 8 ? 700 : 400
              }}
            >
              Grade 8 (Standard Technical Detail)
            </button>
          </div>
        </div>

        {/* 3. Shadow DOM Banner Toggle */}
        <div style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem', fontWeight: 700 }}>In-Page Credential Warning Banners</h3>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.825rem' }}>
              Injects a closed-mode Shadow DOM banner if a page attempts to transmit password inputs over plaintext HTTP.
            </p>
          </div>
          <button
            type="button"
            onClick={handleBannerToggle}
            style={{
              padding: '0.5rem 1.25rem',
              backgroundColor: settings.showShadowDomBanners ? '#065f46' : 'var(--border-color)',
              color: settings.showShadowDomBanners ? '#6ee7b7' : 'var(--text-muted)',
              border: 'none',
              borderRadius: '0.375rem',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {settings.showShadowDomBanners ? 'Enabled' : 'Disabled'}
          </button>
        </div>

        {/* 4. Local Domain Allowlist */}
        <div style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem' }}>
          <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem', fontWeight: 700 }}>Trusted Local Domains (Allowlist)</h3>
          <p style={{ margin: '0 0 0.75rem 0', color: 'var(--text-muted)', fontSize: '0.825rem' }}>
            Specify internal corporate domains, intranets, or local test servers that should bypass threat checks.
          </p>

          <form onSubmit={handleAddDomain} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <input
              type="text"
              placeholder="e.g. internal.corp.local"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              style={{
                flex: 1,
                padding: '0.5rem 0.75rem',
                backgroundColor: 'var(--bg-main)',
                border: '1px solid var(--border-color)',
                borderRadius: '0.375rem',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
                outline: 'none'
              }}
            />
            <button
              type="submit"
              disabled={!newDomain.trim()}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: 'var(--color-brand)',
                color: '#ffffff',
                border: 'none',
                borderRadius: '0.375rem',
                fontSize: '0.85rem',
                fontWeight: 600,
                cursor: !newDomain.trim() ? 'not-allowed' : 'pointer'
              }}
            >
              Add Domain
            </button>
          </form>

          {settings.allowlistDomains.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {settings.allowlistDomains.map((d) => (
                <span
                  key={d}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    padding: '0.25rem 0.6rem',
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    borderRadius: '0.25rem',
                    fontSize: '0.8rem',
                    color: '#93c5fd'
                  }}
                >
                  {d}
                  <button
                    type="button"
                    aria-label={`Remove ${d}`}
                    onClick={() => handleRemoveDomain(d)}
                    style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', fontSize: '0.85rem' }}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          ) : (
            <span style={{ fontSize: '0.8rem', color: '#64748b' }}>No custom allowlisted domains configured.</span>
          )}
        </div>

        {/* 5. Local Audit Log Viewer */}
        <div style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem' }}>
          <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem', fontWeight: 700 }}>Local Threat Interception Log (Device-Only)</h3>
          <p style={{ margin: '0 0 0.75rem 0', color: 'var(--text-muted)', fontSize: '0.825rem' }}>
            Stored strictly in local browser memory. Never transmitted or uploaded.
          </p>

          {auditLogs.length > 0 ? (
            <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '0.375rem' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-main)', borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.5rem' }}>Time</th>
                    <th style={{ padding: '0.5rem' }}>Action</th>
                    <th style={{ padding: '0.5rem' }}>Domain Prefix</th>
                    <th style={{ padding: '0.5rem' }}>Score</th>
                    <th style={{ padding: '0.5rem' }}>Threat Factor</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.5rem', color: 'var(--text-muted)' }}>
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: '0.5rem', fontWeight: 700, color: log.action === 'BLOCKED' ? '#ef4444' : log.action === 'WARNED' ? '#f97316' : '#34d399' }}>
                        {log.action}
                      </td>
                      <td style={{ padding: '0.5rem', fontFamily: 'monospace' }}>{log.domainPrefix}...</td>
                      <td style={{ padding: '0.5rem' }}>{log.riskScore}</td>
                      <td style={{ padding: '0.5rem', color: 'var(--text-muted)' }}>{log.threatCategory}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <span style={{ fontSize: '0.8rem', color: '#64748b' }}>No threat interception events recorded.</span>
          )}
        </div>

        {/* 6. Crypto-Shred Local Storage */}
        <div style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '0.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1rem', fontWeight: 700, color: '#f87171' }}>
              Crypto-Shred All Local Data
            </h3>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.825rem' }}>
              Permanently purges all extension settings, allowlists, and local audit logs.
            </p>
          </div>
          <button
            type="button"
            onClick={handleClearAllData}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid #ef4444',
              color: '#fca5a5',
              borderRadius: '0.375rem',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            Clear All Local Data
          </button>
        </div>
      </div>
    </div>
  );
};

const rootEl = document.getElementById('root');
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(<OptionsApp />);
}
