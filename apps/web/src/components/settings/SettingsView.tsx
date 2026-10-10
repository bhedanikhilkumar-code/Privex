import React, { useState } from 'react';
import { UserPreferences, AppTheme } from '../../scanner/types';
import { PreferenceStorage } from '../../lib/storage';
import { IntroStorage } from '../intro/IntroStorage';

interface SettingsViewProps {
  preferences: UserPreferences;
  onPreferencesChange: (newPrefs: UserPreferences) => void;
  onReplayIntro?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ preferences, onPreferencesChange, onReplayIntro }) => {
  const [newDomain, setNewDomain] = useState<string>('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const handleThemeChange = (newTheme: AppTheme) => {
    const updated: UserPreferences = { ...preferences, theme: newTheme };
    onPreferencesChange(updated);
    PreferenceStorage.saveTheme(newTheme);
    showNotice(`Theme updated to ${newTheme.toUpperCase()} mode.`);
  };

  const handleGradeChange = (grade: 6 | 8) => {
    const updated: UserPreferences = { ...preferences, cognitiveReadingGrade: grade };
    onPreferencesChange(updated);
    PreferenceStorage.savePreferences(updated);
    showNotice(`Explanation complexity set to Grade ${grade}.`);
  };

  const handleWorkerToggle = () => {
    const updated: UserPreferences = {
      ...preferences,
      enableWorkerOffloading: !preferences.enableWorkerOffloading
    };
    onPreferencesChange(updated);
    PreferenceStorage.savePreferences(updated);
    showNotice(
      updated.enableWorkerOffloading
        ? 'Web Worker background offloading enabled.'
        : 'Main thread direct scanning enabled.'
    );
  };

  const handleAddDomain = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newDomain.trim().toLowerCase();
    if (!clean || preferences.allowlistDomains.includes(clean)) return;

    const updated: UserPreferences = {
      ...preferences,
      allowlistDomains: [...preferences.allowlistDomains, clean]
    };
    onPreferencesChange(updated);
    PreferenceStorage.savePreferences(updated);
    setNewDomain('');
    showNotice(`Added '${clean}' to local allowlist.`);
  };

  const handleRemoveDomain = (domainToRemove: string) => {
    const updated: UserPreferences = {
      ...preferences,
      allowlistDomains: preferences.allowlistDomains.filter((d) => d !== domainToRemove)
    };
    onPreferencesChange(updated);
    PreferenceStorage.savePreferences(updated);
    showNotice(`Removed '${domainToRemove}' from local allowlist.`);
  };

  const handleClearAll = () => {
    PreferenceStorage.clearAllData();
    const resetPrefs: UserPreferences = {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: true,
      allowlistDomains: [],
      theme: 'light'
    };
    onPreferencesChange(resetPrefs);
    PreferenceStorage.saveTheme('light');
    showNotice('All local preferences cleared and reset to defaults.');
  };

  const showNotice = (msg: string) => {
    setStatusMessage(msg);
    setTimeout(() => setStatusMessage(null), 3000);
  };

  return (
    <section aria-labelledby="settings-heading" style={{ maxWidth: '950px', margin: '0 auto' }}>
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
            LOCAL CONFIGURATION
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            TIER 2 DATA • PERSISTED ONLY ON THIS DEVICE
          </span>
        </div>

        <h2
          id="settings-heading"
          style={{
            fontFamily: 'var(--font-serif)',
            fontSize: '2.25rem',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            marginBottom: '0.5rem',
            color: '#111111'
          }}
        >
          Dashboard Settings &amp; Preferences
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '1rem', maxWidth: '750px', lineHeight: 1.5 }}>
          Customize on-device scanner behavior, reading levels, and local allowlists.
          All settings reside in browser storage and are never uploaded.
        </p>
      </div>

      {statusMessage && (
        <div
          role="status"
          style={{
            padding: '0.85rem 1.25rem',
            backgroundColor: 'var(--color-accent)',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal-sm)',
            color: '#111111',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 700,
            marginBottom: '1.5rem'
          }}
        >
          {statusMessage}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
        {/* Appearance & Color Theme */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
            APPEARANCE &amp; THEME
          </div>
          <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
            Interface Color Mode
          </h3>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
            Choose between classic brutalist Light mode, cyber-defense Dark mode, or AMOLED pitch-black Night mode.
          </p>

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            {(['light', 'dark', 'night'] as const).map((mode) => {
              const isSelected = (preferences.theme || 'light') === mode;
              const icons = { light: '☀️', dark: '🌙', night: '🌑' };
              const labels = { light: 'Light Mode', dark: 'Dark Mode', night: 'Night Mode' };
              return (
                <button
                  key={mode}
                  type="button"
                  role="radio"
                  aria-checked={isSelected}
                  onClick={() => handleThemeChange(mode)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.65rem 1.25rem',
                    backgroundColor: isSelected ? 'var(--color-brand)' : 'var(--bg-secondary)',
                    color: isSelected ? '#FFFFFF' : 'var(--text-primary)',
                    border: '2px solid var(--border-dark)',
                    boxShadow: isSelected ? '3px 3px 0px var(--border-dark)' : '1px 1px 0px var(--border-dark)',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    fontFamily: 'var(--font-mono)',
                    textTransform: 'uppercase',
                    cursor: 'pointer'
                  }}
                >
                  <span aria-hidden="true">{icons[mode]}</span>
                  <span>{labels[mode]}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* 1. Cognitive Reading Grade Level */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
            ASSISTANT COMPREHENSION
          </div>
          <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
            Explanation Reading Level
          </h3>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
            Select the cognitive complexity for threat explanations generated by the AI Security Assistant.
          </p>

          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => handleGradeChange(6)}
              style={{
                padding: '0.65rem 1.25rem',
                backgroundColor: preferences.cognitiveReadingGrade === 6 ? 'var(--color-brand)' : 'var(--bg-secondary)',
                color: preferences.cognitiveReadingGrade === 6 ? '#FFFFFF' : 'var(--text-primary)',
                border: '2px solid var(--border-dark)',
                boxShadow: preferences.cognitiveReadingGrade === 6 ? '3px 3px 0px var(--border-dark)' : '1px 1px 0px var(--border-dark)',
                fontSize: '0.85rem',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                cursor: 'pointer'
              }}
            >
              Grade 6 (Plain Language, Recommended)
            </button>
            <button
              type="button"
              onClick={() => handleGradeChange(8)}
              style={{
                padding: '0.65rem 1.25rem',
                backgroundColor: preferences.cognitiveReadingGrade === 8 ? 'var(--color-brand)' : 'var(--bg-secondary)',
                color: preferences.cognitiveReadingGrade === 8 ? '#FFFFFF' : 'var(--text-primary)',
                border: '2px solid var(--border-dark)',
                boxShadow: preferences.cognitiveReadingGrade === 8 ? '3px 3px 0px var(--border-dark)' : '1px 1px 0px var(--border-dark)',
                fontSize: '0.85rem',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                cursor: 'pointer'
              }}
            >
              Grade 8 (Standard Technical Detail)
            </button>
          </div>
        </div>

        {/* 2. Web Worker Execution */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                PERFORMANCE ENGINE
              </div>
              <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
                Web Worker Background Processing
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0 }}>
                Offloads entropy calculations and token parsing to an isolated background thread.
              </p>
            </div>
            <button
              type="button"
              onClick={handleWorkerToggle}
              style={{
                padding: '0.65rem 1.25rem',
                backgroundColor: preferences.enableWorkerOffloading ? 'var(--color-accent)' : 'var(--bg-secondary)',
                color: '#111111',
                border: '2px solid var(--border-dark)',
                boxShadow: '3px 3px 0px var(--border-dark)',
                fontSize: '0.85rem',
                fontWeight: 800,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                cursor: 'pointer'
              }}
            >
              {preferences.enableWorkerOffloading ? 'Enabled (Smooth 60fps)' : 'Disabled (Main Thread)'}
            </button>
          </div>
        </div>

        {/* 3. Custom Local Allowlist */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
            USER EXCLUSIONS
          </div>
          <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
            Custom Local Allowlists
          </h3>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
            Specify trusted internal domains or intranet addresses that should always be allowed.
          </p>

          <form onSubmit={handleAddDomain} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              placeholder="e.g. internal.corp.local"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              style={{
                flex: '1 1 250px',
                padding: '0.65rem 1rem',
                backgroundColor: 'var(--bg-primary)',
                border: '2px solid var(--border-dark)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                outline: 'none'
              }}
            />
            <button
              type="submit"
              disabled={!newDomain.trim()}
              style={{
                padding: '0.65rem 1.25rem',
                backgroundColor: !newDomain.trim() ? 'var(--bg-secondary)' : 'var(--color-brand)',
                color: !newDomain.trim() ? 'var(--text-muted)' : '#FFFFFF',
                border: '2px solid var(--border-dark)',
                boxShadow: !newDomain.trim() ? 'none' : '2px 2px 0px var(--border-dark)',
                fontSize: '0.85rem',
                fontWeight: 800,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                cursor: !newDomain.trim() ? 'not-allowed' : 'pointer'
              }}
            >
              Add Domain
            </button>
          </form>

          {preferences.allowlistDomains.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {preferences.allowlistDomains.map((d) => (
                <span
                  key={d}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.35rem 0.75rem',
                    backgroundColor: 'var(--bg-secondary)',
                    border: '1px solid var(--border-dark)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    fontWeight: 700,
                    color: 'var(--text-primary)'
                  }}
                >
                  {d}
                  <button
                    type="button"
                    aria-label={`Remove ${d}`}
                    onClick={() => handleRemoveDomain(d)}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--color-danger)',
                      cursor: 'pointer',
                      fontSize: '1rem',
                      fontWeight: 900,
                      lineHeight: 1,
                      padding: 0
                    }}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          ) : (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              No custom allowlisted domains configured.
            </span>
          )}
        </div>

        {/* 4. Crypto-Shred & Reset */}
        <div
          style={{
            backgroundColor: 'var(--bg-card)',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}
        >
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-danger)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
              ZERO-KNOWLEDGE PURGE
            </div>
            <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', fontWeight: 800, color: 'var(--color-danger)', marginBottom: '0.35rem' }}>
              Clear Local Client State
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0 }}>
              Crypto-shreds and wipes all local browser settings and allowlist domains.
            </p>
          </div>
          <button
            type="button"
            onClick={handleClearAll}
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: 'var(--color-danger)',
              border: '2px solid var(--border-dark)',
              boxShadow: '3px 3px 0px var(--border-dark)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
              fontWeight: 800,
              textTransform: 'uppercase',
              cursor: 'pointer'
            }}
          >
            Clear All Local Data
          </button>
        </div>

        {/* 5. Cinematic Intro Replay */}
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}
        >
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, color: 'var(--color-brand)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
              VISUAL STORYTELLING
            </div>
            <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.25rem', fontWeight: 800, color: '#111111', marginBottom: '0.35rem' }}>
              Cinematic Intro Animation
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0 }}>
              Watch the PRIVEX on-device threat protection story animation again.
            </p>
          </div>
          <button
            type="button"
            aria-label="Replay intro animation from settings"
            onClick={() => {
              IntroStorage.resetIntro();
              if (onReplayIntro) onReplayIntro();
            }}
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: 'var(--color-brand)',
              border: '2px solid var(--border-dark)',
              boxShadow: '3px 3px 0px #111111',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
              fontWeight: 800,
              textTransform: 'uppercase',
              cursor: 'pointer'
            }}
          >
            🎬 Replay Intro
          </button>
        </div>
      </div>
    </section>
  );
};
