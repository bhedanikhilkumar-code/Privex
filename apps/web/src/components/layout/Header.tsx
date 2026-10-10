import React, { useState, useEffect } from 'react';

export const Header: React.FC = () => {
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
        backgroundColor: '#FFFFFF',
        borderBottom: '2px solid var(--border-dark)',
        flexWrap: 'wrap',
        gap: '1rem'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <div
          aria-hidden="true"
          style={{
            width: '2.4rem',
            height: '2.4rem',
            backgroundColor: 'var(--color-brand)',
            border: '2px solid var(--border-dark)',
            boxShadow: '2px 2px 0px #111111',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.25rem',
            color: '#ffffff'
          }}
        >
          🛡️
        </div>
        <div>
          <h1
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: '1.4rem',
              fontWeight: 800,
              letterSpacing: '-0.02em',
              lineHeight: 1.1,
              color: '#111111'
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
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.35rem 0.75rem',
            backgroundColor: 'var(--bg-secondary)',
            border: '2px solid var(--border-dark)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.725rem',
            fontWeight: 700,
            color: '#111111'
          }}
        >
          <span>ENGINE: v0.1.1</span>
          <span style={{ opacity: 0.4 }}>|</span>
          <span>RAM: 42MB</span>
          <span style={{ opacity: 0.4 }}>|</span>
          <span>LATENCY: &lt;1ms</span>
        </div>

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
