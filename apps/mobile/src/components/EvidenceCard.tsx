import React from 'react';
import { Evidence } from '@private-protection/core';

interface EvidenceCardProps {
  evidence: Evidence[];
}

export const EvidenceCard: React.FC<EvidenceCardProps> = ({ evidence }) => {
  if (!evidence || evidence.length === 0) {
    return (
      <div style={{ padding: '1rem', backgroundColor: '#1e293b', borderRadius: '12px', color: '#94a3b8', fontSize: '0.9rem' }}>
        No malicious threat signals detected.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      {evidence.map((item, idx) => (
        <div
          key={idx}
          style={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '12px',
            padding: '1rem'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
            <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.95rem' }}>
              {item.name}
            </span>
            <span
              style={{
                fontSize: '0.75rem',
                backgroundColor: item.weight >= 70 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                color: item.weight >= 70 ? '#fca5a5' : '#fcd34d',
                padding: '0.2rem 0.5rem',
                borderRadius: '6px',
                fontWeight: 600
              }}
            >
              Weight: {item.weight}/100
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.4 }}>
            {item.description}
          </p>
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#64748b' }}>
            Source: {item.source} • Confidence: {Math.round(item.confidence * 100)}%
          </div>
        </div>
      ))}
    </div>
  );
};
