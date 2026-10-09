import React, { useState, useEffect } from 'react';
import { SecureStorageService } from '../services/secure-storage.service';
import { MobileSettings, DEFAULT_MOBILE_SETTINGS } from '../types/mobile.types';

export const SettingsScreen: React.FC = () => {
  const [settings, setSettings] = useState<MobileSettings>(DEFAULT_MOBILE_SETTINGS);
  const [newDomain, setNewDomain] = useState<string>('');
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    SecureStorageService.getSettings().then(setSettings);
  }, []);

  const handleToggle = async (key: keyof MobileSettings, value: any) => {
    const updated = await SecureStorageService.saveSettings({ [key]: value });
    setSettings(updated);
  };

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return;
    const clean = newDomain.trim().toLowerCase();
    const updated = await SecureStorageService.addAllowlistDomain(clean);
    setSettings((prev) => ({ ...prev, allowlistDomains: updated }));
    setNewDomain('');
    setMessage(`Added ${clean} to trusted allowlist.`);
    setTimeout(() => setMessage(null), 3000);
  };

  const handleRemoveDomain = async (domain: string) => {
    const updated = await SecureStorageService.removeAllowlistDomain(domain);
    setSettings((prev) => ({ ...prev, allowlistDomains: updated }));
    setMessage(`Removed ${domain} from allowlist.`);
    setTimeout(() => setMessage(null), 3000);
  };

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#38bdf8' }}>
          Mobile Protection Settings
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Configure detection behavior, notifications, and custom trusted domains.
        </p>
      </div>

      {message && (
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(56, 189, 248, 0.2)', border: '1px solid #38bdf8', borderRadius: '8px', color: '#7dd3fc', fontSize: '0.85rem' }}>
          {message}
        </div>
      )}

      {/* Main Feature Toggles */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem' }}>Real-Time Scanning Engine</strong>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Enables on-device detection rules and heuristics</span>
          </div>
          <input
            type="checkbox"
            checked={settings.protectionEnabled}
            onChange={(e) => handleToggle('protectionEnabled', e.target.checked)}
            style={{ width: '20px', height: '20px', cursor: 'pointer' }}
          />
        </div>

        <div style={{ borderTop: '1px solid #334155', paddingTop: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem' }}>Security Notification Alerts</strong>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Instant heads-up alert for dangerous threat verdicts</span>
          </div>
          <input
            type="checkbox"
            checked={settings.notificationsEnabled}
            onChange={(e) => handleToggle('notificationsEnabled', e.target.checked)}
            style={{ width: '20px', height: '20px', cursor: 'pointer' }}
          />
        </div>

        <div style={{ borderTop: '1px solid #334155', paddingTop: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem' }}>Haptic Motor Warning</strong>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Distinct physical vibration alert upon threat detection</span>
          </div>
          <input
            type="checkbox"
            checked={settings.hapticFeedbackEnabled}
            onChange={(e) => handleToggle('hapticFeedbackEnabled', e.target.checked)}
            style={{ width: '20px', height: '20px', cursor: 'pointer' }}
          />
        </div>
      </div>

      {/* AI Assistant Reading Level */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem' }}>
        <strong style={{ display: 'block', fontSize: '0.95rem', marginBottom: '0.25rem' }}>
          AI Explanation Complexity
        </strong>
        <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.75rem' }}>
          Flesch-Kincaid cognitive grade for plain-language threat explanations
        </span>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            onClick={() => handleToggle('readingGrade', 6)}
            style={{
              flex: 1,
              padding: '0.65rem',
              backgroundColor: settings.readingGrade === 6 ? '#38bdf8' : '#0f172a',
              color: settings.readingGrade === 6 ? '#0f172a' : '#f8fafc',
              fontWeight: 700,
              borderRadius: '8px',
              border: '1px solid #334155',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Grade 6 (Accessible)
          </button>
          <button
            type="button"
            onClick={() => handleToggle('readingGrade', 8)}
            style={{
              flex: 1,
              padding: '0.65rem',
              backgroundColor: settings.readingGrade === 8 ? '#38bdf8' : '#0f172a',
              color: settings.readingGrade === 8 ? '#0f172a' : '#f8fafc',
              fontWeight: 700,
              borderRadius: '8px',
              border: '1px solid #334155',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Grade 8 (Standard)
          </button>
        </div>
      </div>

      {/* Custom Allowlist */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem' }}>
        <strong style={{ display: 'block', fontSize: '0.95rem', marginBottom: '0.25rem' }}>
          Trusted Domains Allowlist
        </strong>
        <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.75rem' }}>
          Domains that always bypass warning checks
        </span>

        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="example.com"
            style={{
              flex: 1,
              padding: '0.65rem 0.75rem',
              backgroundColor: '#0f172a',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f8fafc',
              fontSize: '0.85rem'
            }}
          />
          <button
            type="button"
            onClick={handleAddDomain}
            style={{
              padding: '0.65rem 1rem',
              backgroundColor: '#38bdf8',
              color: '#0f172a',
              fontWeight: 700,
              borderRadius: '8px',
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Add
          </button>
        </div>

        {settings.allowlistDomains.length === 0 ? (
          <p style={{ margin: 0, fontSize: '0.8rem', color: '#64748b' }}>
            No custom allowlisted domains.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {settings.allowlistDomains.map((domain, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.4rem 0.65rem',
                  backgroundColor: '#0f172a',
                  borderRadius: '6px',
                  fontSize: '0.85rem'
                }}
              >
                <span>{domain}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveDomain(domain)}
                  style={{
                    backgroundColor: 'transparent',
                    border: 'none',
                    color: '#f87171',
                    cursor: 'pointer',
                    fontSize: '0.8rem',
                    fontWeight: 600
                  }}
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
