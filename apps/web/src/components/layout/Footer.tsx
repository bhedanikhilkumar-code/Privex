import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer
      role="contentinfo"
      style={{
        marginTop: 'auto',
        padding: '1.5rem 2rem',
        backgroundColor: '#111111',
        borderTop: '2px solid #111111',
        fontSize: '0.75rem',
        color: '#EBE7DE',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
        fontFamily: 'var(--font-mono)'
      }}
    >
      <div>
        <span style={{ fontWeight: 700, letterSpacing: '0.04em' }}>PRIVATE PROTECTION v0.1.1</span>
        <span style={{ margin: '0 0.5rem', opacity: 0.5 }}>•</span>
        <span>Engine: </span>
        <code style={{ color: 'var(--color-accent)', backgroundColor: 'rgba(255,255,255,0.1)', padding: '0.2rem 0.4rem', border: '1px solid rgba(255,255,255,0.2)' }}>
          @private-protection/core &amp; ml
        </code>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
          <span style={{ color: '#1DB954' }}>●</span> Zero Cloud Persistence
        </span>
        <span aria-hidden="true" style={{ opacity: 0.4 }}>•</span>
        <span>100% Offline Air-Gapped Capable</span>
        <span aria-hidden="true" style={{ opacity: 0.4 }}>•</span>
        <span>WCAG 2.1 AA Compliant</span>
      </div>
    </footer>
  );
};
