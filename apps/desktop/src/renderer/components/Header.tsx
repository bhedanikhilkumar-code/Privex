import React from 'react';
import { SecurityBadge } from './SecurityBadge';

interface HeaderProps {
  threatsCount: number;
  engineActive: boolean;
  offline: boolean;
}

export const Header: React.FC<HeaderProps> = ({ threatsCount, engineActive, offline }) => {
  return (
    <header
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 24px',
        backgroundColor: '#ffffff',
        borderBottom: '1px solid #e2e8f0'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <h1 style={{ fontSize: '18px', fontWeight: 'bold', margin: 0, color: '#0f172a' }}>
          PRIVATE PROTECTION
        </h1>
        <span style={{ fontSize: '12px', color: '#64748b', backgroundColor: '#f1f5f9', padding: '2px 8px', borderRadius: '4px' }}>
          PC CLIENT v1.0
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <SecurityBadge severity={threatsCount > 0 ? 'critical' : 'safe'} size="sm" />
        <span style={{ fontSize: '12px', color: engineActive ? '#16a34a' : '#dc2626' }}>
          {engineActive ? '● Real-Time Shield Active' : '○ Shield Offline'}
        </span>
        <span style={{ fontSize: '12px', color: offline ? '#0284c7' : '#64748b' }}>
          {offline ? '🛡️ Air-Gapped Mode' : '🌐 Connected'}
        </span>
      </div>
    </header>
  );
};
