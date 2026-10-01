import React from 'react';
import { Verdict, SeverityLevel } from '@private-protection/core';

interface SecurityBadgeProps {
  verdict: Verdict;
  severity?: SeverityLevel;
  score?: number;
}

export const SecurityBadge: React.FC<SecurityBadgeProps> = ({ verdict, severity: _severity, score }) => {
  let bgColor = '#10b981'; // Green
  let textColor = '#ffffff';
  let label = 'SAFE / ALLOWED';

  switch (verdict) {
    case Verdict.DANGEROUS:
      bgColor = '#dc2626'; // Red
      label = 'DANGEROUS / MALICIOUS';
      break;
    case Verdict.SUSPICIOUS:
      bgColor = '#ea580c'; // Orange
      label = 'SUSPICIOUS THREAT';
      break;
    case Verdict.CAUTION:
      bgColor = '#d97706'; // Amber
      label = 'CAUTION ADVISED';
      break;
    case Verdict.INFORM:
      bgColor = '#2563eb'; // Blue
      label = 'INFORMATIONAL';
      break;
    default:
      bgColor = '#059669';
      label = 'SAFE / ALLOWED';
  }

  return (
    <div
      role="status"
      aria-label={`Security status: ${label}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.35rem 0.75rem',
        borderRadius: '9999px',
        backgroundColor: bgColor,
        color: textColor,
        fontWeight: 700,
        fontSize: '0.875rem',
        letterSpacing: '0.025em'
      }}
    >
      <span>{label}</span>
      {score !== undefined && (
        <span style={{ marginLeft: '0.5rem', opacity: 0.9, fontSize: '0.8rem' }}>
          ({score}/100)
        </span>
      )}
    </div>
  );
};
