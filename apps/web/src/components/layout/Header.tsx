import React, { useState, useEffect } from 'react';
import { ThemeToggle } from './ThemeToggle';
import { AppTheme } from '../../scanner/types';

export interface HeaderProps {
  theme?: AppTheme;
  onThemeChange?: (theme: AppTheme) => void;
}

export const Header: React.FC<HeaderProps> = ({ theme, onThemeChange }) => {
  const [installPrompt, setInstallPrompt] = useState<any>(null);
  const [isInstalled, setIsInstalled] = useState<boolean>(false);

  useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setInstallPrompt(e);
    };

    const handleAppInstalled = () => {
      setIsInstalled(true);
      setInstallPrompt(null);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  const handleInstallClick = async () => {
    if (!installPrompt) return;
    installPrompt.prompt();
    const { outcome } = await installPrompt.userChoice;
    if (outcome === 'accepted') {
      setIsInstalled(true);
    }
    setInstallPrompt(null);
  };

  return (
    <header
      role="banner"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '1rem 2rem',
        backgroundColor: 'var(--bg-card)',
        borderBottom: '2px solid var(--border-dark)',
        flexWrap: 'wrap',
        gap: '1rem'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <div
          aria-hidden="true"
          style={{
            width: '2.5rem',
            height: '2.5rem',
            backgroundColor: '#090d16',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal-sm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2px',
            overflow: 'hidden'
          }}
        >
          <img
            src="/privex-logo.svg"
            alt="PRIVEX logo"
            style={{ width: '100%', height: '100%', objectFit: 'contain' }}
          />
        </div>
        <div>
          <h1
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: '1.4rem',
              fontWeight: 800,
              letterSpacing: '-0.02em',
              lineHeight: 1.1,
              color: 'var(--text-primary)'
            }}
          >
            PRIVEX
          </h1>
          <p
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.725rem',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              marginTop: '0.15rem'
            }}
          >
            Zero-Install Client-Side Cyber Threat Dashboard
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <ThemeToggle theme={theme} onThemeChange={onThemeChange} />


        {installPrompt && !isInstalled && (
          <button
            type="button"
            onClick={handleInstallClick}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.4rem 0.9rem',
              backgroundColor: 'var(--color-brand)',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px #111111',
              fontSize: '0.75rem',
              color: '#ffffff',
              fontWeight: 700,
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)'
            }}
          >
            <span>📥</span> Install Web App
          </button>
        )}

      </div>
    </header>
  );
};
