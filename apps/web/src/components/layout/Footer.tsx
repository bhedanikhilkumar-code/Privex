import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer
      role="contentinfo"
      style={{
        marginTop: 'auto',
        padding: '1.25rem 2rem',
        backgroundColor: 'var(--bg-secondary)',
        borderTop: '1px solid var(--border-color)',
        fontSize: '0.75rem',
        color: 'var(--text-muted)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.75rem'
      }}
    >
      <div>
        <span>PRIVATE PROTECTION v0.1.0 • Engine: </span>
        <code style={{ color: '#93c5fd', backgroundColor: 'rgba(255,255,255,0.05)', padding: '0.1rem 0.3rem', borderRadius: '0.2rem' }}>
          @private-protection/core & ml
        </code>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <span>Zero Cloud Persistence</span>
        <span aria-hidden="true">•</span>
        <span>100% Offline Air-Gapped Capable</span>
        <span aria-hidden="true">•</span>
        <span>WCAG 2.1 AA Compliant</span>
      </div>
    </footer>
  );
};
