import React, { useState, useEffect } from 'react';
import { SecureStorageService } from '../services/secure-storage.service';
import { MobileSettings, DEFAULT_MOBILE_SETTINGS } from '../types/mobile.types';

interface SettingsScreenProps {
  onBack?: () => void;
}

export const SettingsScreen: React.FC<SettingsScreenProps> = ({ onBack }) => {
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem', color: '#f8fafc' }}>
      {/* Top Header matching Settings.png */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {onBack && (
            <button
              type="button"
              onClick={onBack}
              aria-label="Back"
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                backgroundColor: '#111b2e',
                border: '1px solid #27364b',
                color: '#38bdf8',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: '1rem'
              }}
            >
              ←
            </button>
          )}
          <div>
            <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              PRIVEX SECURITY
            </span>
            <h1 style={{ margin: '0.1rem 0 0 0', fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
              Mobile Protection Settings
            </h1>
          </div>
        </div>
      </div>

      {message && (
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(56, 189, 248, 0.2)', border: '1px solid #38bdf8', borderRadius: '10px', color: '#7dd3fc', fontSize: '0.85rem' }}>
          {message}
        </div>
      )}

      {/* PROTECTION SECTION matching Settings.png */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          PROTECTION
        </span>
        <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '20px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong style={{ display: 'block', fontSize: '0.95rem', color: '#f8fafc' }}>Real-Time Scanning Engine</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Enables on-device detection rules and heuristics</span>
            </div>
            <input
              type="checkbox"
              checked={settings.protectionEnabled}
              onChange={(e) => handleToggle('protectionEnabled', e.target.checked)}
              style={{ width: '20px', height: '20px', cursor: 'pointer', accentColor: '#38bdf8' }}
            />
          </div>

          <div style={{ borderTop: '1px solid #1e293b', paddingTop: '0.85rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong style={{ display: 'block', fontSize: '0.95rem', color: '#f8fafc' }}>Automated Quarantine</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Isolate confirmed malware files into vault</span>
            </div>
            <input
              type="checkbox"
              checked={true}
              readOnly
              style={{ width: '20px', height: '20px', cursor: 'pointer', accentColor: '#38bdf8' }}
            />
          </div>
        </div>
      </div>

      {/* NOTIFICATIONS & ALERTS SECTION matching Settings.png */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          NOTIFICATIONS &amp; FEEDBACK
        </span>
        <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '20px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong style={{ display: 'block', fontSize: '0.95rem', color: '#f8fafc' }}>Security Notification Alerts</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Instant heads-up alert for dangerous threat verdicts</span>
            </div>
            <input
              type="checkbox"
              checked={settings.notificationsEnabled}
              onChange={(e) => handleToggle('notificationsEnabled', e.target.checked)}
              style={{ width: '20px', height: '20px', cursor: 'pointer', accentColor: '#38bdf8' }}
            />
          </div>

          <div style={{ borderTop: '1px solid #1e293b', paddingTop: '0.85rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <strong style={{ display: 'block', fontSize: '0.95rem', color: '#f8fafc' }}>Haptic Motor Warning</strong>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Distinct physical vibration alert upon threat detection</span>
            </div>
            <input
              type="checkbox"
              checked={settings.hapticFeedbackEnabled}
              onChange={(e) => handleToggle('hapticFeedbackEnabled', e.target.checked)}
              style={{ width: '20px', height: '20px', cursor: 'pointer', accentColor: '#38bdf8' }}
            />
          </div>
        </div>
      </div>

      {/* Notification Storm Defense Channels */}
      <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '20px', padding: '1.25rem' }}>
        <strong style={{ display: 'block', fontSize: '0.95rem', marginBottom: '0.25rem', color: '#38bdf8' }}>
          🛡️ Notification Channels &amp; Storm Defense
        </strong>
        <p style={{ margin: '0 0 0.75rem 0', fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
          Token-bucket rate limiting caps alerts at 3 per 10s window. Rapid bursts coalesce into a summary notification.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.78rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.45rem 0.65rem', backgroundColor: '#0f172a', borderRadius: '8px' }}>
            <span><strong>Critical Threats:</strong> Malicious APKs, Trojans</span>
            <span style={{ color: '#f87171', fontWeight: 700 }}>IMPORTANCE_HIGH</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.45rem 0.65rem', backgroundColor: '#0f172a', borderRadius: '8px' }}>
            <span><strong>Download Shield:</strong> Quarantined files</span>
            <span style={{ color: '#fbbf24', fontWeight: 700 }}>IMPORTANCE_HIGH</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.45rem 0.65rem', backgroundColor: '#0f172a', borderRadius: '8px' }}>
            <span><strong>Web &amp; Phishing:</strong> Deceptive links</span>
            <span style={{ color: '#fbbf24', fontWeight: 700 }}>IMPORTANCE_HIGH</span>
          </div>
        </div>
      </div>

      {/* AI ASSISTANT COMPLEXITY SECTION matching Settings.png */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          AI SECURITY ASSISTANT
        </span>
        <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '20px', padding: '1.25rem' }}>
          <strong style={{ display: 'block', fontSize: '0.95rem', marginBottom: '0.2rem', color: '#f8fafc' }}>
            AI Explanation Complexity
          </strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.85rem' }}>
            Flesch-Kincaid cognitive grade for plain-language threat explanations
          </span>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              onClick={() => handleToggle('readingGrade', 6)}
              style={{
                flex: 1,
                padding: '0.65rem',
                backgroundColor: settings.readingGrade === 6 ? '#2563eb' : '#0f172a',
                color: '#ffffff',
                fontWeight: 700,
                borderRadius: '10px',
                border: '1px solid #27364b',
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
                backgroundColor: settings.readingGrade === 8 ? '#2563eb' : '#0f172a',
                color: '#ffffff',
                fontWeight: 700,
                borderRadius: '10px',
                border: '1px solid #27364b',
                cursor: 'pointer',
                fontSize: '0.85rem'
              }}
            >
              Grade 8 (Standard)
            </button>
          </div>
        </div>
      </div>

      {/* CUSTOM ALLOWLIST SECTION matching Settings.png */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          TRUSTED OVERRIDES
        </span>
        <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '20px', padding: '1.25rem' }}>
          <strong style={{ display: 'block', fontSize: '0.95rem', marginBottom: '0.2rem', color: '#f8fafc' }}>
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
              placeholder="e.g. internal-portal.corp"
              style={{
                flex: 1,
                padding: '0.65rem 0.75rem',
                backgroundColor: '#0f172a',
                border: '1px solid #27364b',
                borderRadius: '10px',
                color: '#f8fafc',
                fontSize: '0.85rem'
              }}
            />
            <button
              type="button"
              onClick={handleAddDomain}
              style={{
                padding: '0.65rem 1rem',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                fontWeight: 700,
                borderRadius: '10px',
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
                    padding: '0.5rem 0.75rem',
                    backgroundColor: '#0f172a',
                    borderRadius: '8px',
                    fontSize: '0.85rem'
                  }}
                >
                  <span style={{ color: '#cbd5e1' }}>{domain}</span>
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

      {/* App Version Footer */}
      <div style={{ textAlign: 'center', padding: '1rem 0', color: '#64748b', fontSize: '0.75rem' }}>
        <div>PRIVEX MOBILE • Build 1.0.0 (Release)</div>
        <div style={{ marginTop: '0.2rem' }}>Zero-Knowledge On-Device Protection Engine</div>
      </div>
    </div>
  );
};
