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
        padding: '0.85rem 2rem',
        backgroundColor: 'var(--bg-card)',
        borderBottom: '2px solid var(--border-dark)',
        boxShadow: 'var(--shadow-brutal-sm)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        flexWrap: 'wrap',
        gap: '1rem'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <div
          aria-hidden="true"
          className="motion-card"
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
            src="/privex-icon.png"
            alt="PRIVEX logo"
            style={{ width: '100%', height: '100%', objectFit: 'contain' }}
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).src = '/privex-logo.svg';
            }}
          />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <h1
              style={{
                fontFamily: 'var(--font-serif)',
                fontSize: '1.45rem',
                fontWeight: 800,
                letterSpacing: '-0.02em',
                lineHeight: 1.1,
                color: 'var(--text-primary)',
                margin: 0
              }}
            >
              PRIVEX
            </h1>
            <span
              style={{
                backgroundColor: 'var(--color-safe-bg, #003914)',
                color: 'var(--color-safe, #53e076)',
                border: '1px solid var(--color-safe, #53e076)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.625rem',
                fontWeight: 700,
                padding: '0.1rem 0.45rem',
                letterSpacing: '0.08em',
                textTransform: 'uppercase'
              }}
            >
              LOCAL ONLY (RAM)
            </span>
          </div>
          <p
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.725rem',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              margin: '0.2rem 0 0 0'
            }}
          >
            Zero-Install Client-Side Cyber Threat Dashboard
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <ThemeToggle theme={theme} onThemeChange={onThemeChange} />

        <a
          href="/stitch_privex_security_web_ui/privex_enclave_authentication/code.html"
          title="Open Enclave Authentication Session"
          className="cut-corner-btn"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.45rem 0.85rem',
            backgroundColor: 'var(--bg-secondary)',
            border: '2px solid var(--border-dark)',
            boxShadow: '2px 2px 0px var(--border-dark)',
            fontSize: '0.75rem',
            color: 'var(--text-primary)',
            fontWeight: 700,
            textDecoration: 'none',
            fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase',
            letterSpacing: '0.04em'
          }}
        >
          <span>🔐</span> ENCLAVE
        </a>

        {installPrompt && !isInstalled && (
          <button
            type="button"
            onClick={handleInstallClick}
            className="cut-corner-btn"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.45rem 0.9rem',
              backgroundColor: 'var(--color-brand)',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px var(--border-dark)',
              fontSize: '0.75rem',
              color: '#ffffff',
              fontWeight: 700,
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em'
            }}
          >
            <span>📥</span> Install Web App
          </button>
        )}
      </div>
    </header>
  );
};
