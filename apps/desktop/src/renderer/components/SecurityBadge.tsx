import React from 'react';
import { ThreatSeverity } from '../../types/desktop.types';

interface SecurityBadgeProps {
  severity: ThreatSeverity;
  size?: 'sm' | 'md' | 'lg';
}

export const SecurityBadge: React.FC<SecurityBadgeProps> = ({ severity, size = 'md' }) => {
  const getColors = () => {
    switch (severity) {
      case 'critical':
        return { bg: '#fee2e2', text: '#991b1b', border: '#f87171', label: 'CRITICAL THREAT' };
      case 'dangerous':
        return { bg: '#ffedd5', text: '#9a3412', border: '#fb923c', label: 'DANGEROUS' };
      case 'suspicious':
        return { bg: '#fef3c7', text: '#92400e', border: '#fcd34d', label: 'SUSPICIOUS' };
      case 'low':
        return { bg: '#e0f2fe', text: '#0369a1', border: '#7dd3fc', label: 'LOW RISK' };
      case 'safe':
      default:
        return { bg: '#dcfce7', text: '#166534', border: '#86efac', label: 'SECURE' };
    }
  };

  const style = getColors();
  const padding = size === 'sm' ? '2px 8px' : size === 'lg' ? '6px 16px' : '4px 12px';
  const fontSize = size === 'sm' ? '11px' : size === 'lg' ? '14px' : '12px';

  return (
    <span
      role="status"
      style={{
        backgroundColor: style.bg,
        color: style.text,
        border: `1px solid ${style.border}`,
        borderRadius: '12px',
        padding,
        fontSize,
        fontWeight: 'bold',
        display: 'inline-block',
        textTransform: 'uppercase',
        letterSpacing: '0.5px'
      }}
    >
      {style.label}
    </span>
  );
};
