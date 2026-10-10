import React from 'react';

interface FooterProps {
  onReplayIntro?: () => void;
}

export const Footer: React.FC<FooterProps> = ({ onReplayIntro }) => {
  return (
    <footer
      role="contentinfo"
      style={{
        marginTop: 'auto',
        padding: '1.75rem 2rem',
        backgroundColor: 'var(--surface-container-lowest, #0c0e12)',
        borderTop: '2px solid var(--border-dark)',
        fontSize: '0.75rem',
        color: 'var(--text-primary)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        fontFamily: 'var(--font-mono)'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <span style={{ fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-primary)' }}>
              HARDWARE LEVEL ENCLAVE GUARANTEE
            </span>
            <span
              style={{
                padding: '0.15rem 0.45rem',
                backgroundColor: 'var(--bg-card)',
                color: 'var(--color-accent)',
                border: '1px solid var(--border-dark)',
                fontSize: '0.65rem',
                letterSpacing: '0.06em'
              }}
            >
              SHA-256: 7F9A..B281
            </span>
          </div>
          <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '0.75rem', maxWidth: '650px', lineHeight: 1.45 }}>
            Zero cloud telemetry. Client-side heuristic execution only. No sockets open. All dynamic payloads execute in temporary volatile RAM.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {onReplayIntro && (
            <button
              type="button"
              onClick={onReplayIntro}
              aria-label="Replay intro animation"
              className="cut-corner-btn"
              style={{
                padding: '0.4rem 0.85rem',
                backgroundColor: 'var(--bg-card)',
                color: 'var(--text-primary)',
                border: '2px solid var(--border-dark)',
                boxShadow: '2px 2px 0px var(--border-dark)',
                cursor: 'pointer',
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                textTransform: 'uppercase',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem'
              }}
            >
              <span>🎬</span> <span>Intro</span>
            </button>
          )}

          <div style={{ textAlign: 'right', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
            <div>CRYPTOGRAPHIC BUILD 4.9.1-GAP</div>
            <div style={{ color: 'var(--color-safe)' }}>CORE STATUS: COMPLIANT</div>
          </div>
        </div>
      </div>

      <div
        style={{
          borderTop: '1px solid var(--border-dark)',
          paddingTop: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          color: 'var(--text-muted)'
        }}
      >
        <div>
          <span style={{ fontWeight: 700, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>PRIVEX v0.1.1</span>
          <span style={{ margin: '0 0.5rem', opacity: 0.5 }}>•</span>
          <span>Engine: </span>
          <code style={{ color: 'var(--color-accent)', backgroundColor: 'var(--bg-card)', padding: '0.15rem 0.4rem', border: '1px solid var(--border-dark)' }}>
            @private-protection/core &amp; ml
          </code>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: 'var(--color-safe)' }}>
            <span>●</span> Zero Cloud Persistence
          </span>
          <span aria-hidden="true" style={{ opacity: 0.4 }}>•</span>
          <span>100% Offline Air-Gapped Capable</span>
          <span aria-hidden="true" style={{ opacity: 0.4 }}>•</span>
          <span>WCAG 2.1 AA Compliant</span>
        </div>
      </div>
    </footer>
  );
};
