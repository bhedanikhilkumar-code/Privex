import React from 'react';
import { DeviceSecurityPosture } from '../types/mobile.types';

interface DevicePostureCardProps {
  posture: DeviceSecurityPosture;
  onRefresh?: () => void;
}

export const DevicePostureCard: React.FC<DevicePostureCardProps> = ({ posture, onRefresh: _onRefresh }) => {
  let badgeColor = '#10b981';
  let badgeLabel = 'HEALTHY BASELINE';

  if (posture.overallHealth === 'RISK') {
    badgeColor = '#ef4444';
    badgeLabel = 'SECURITY ATTENTION NEEDED';
  } else if (posture.overallHealth === 'WARNING') {
    badgeColor = '#f59e0b';
    badgeLabel = 'MODERATE POSTURE';
  } else if (posture.overallHealth === 'UNKNOWN') {
    badgeColor = '#64748b';
    badgeLabel = 'POSTURE UNKNOWN';
  }

  return (
    <div
      style={{
        backgroundColor: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '16px',
        padding: '1.25rem',
        color: '#f8fafc'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Device Security Posture</h4>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Configuration audit (non-invasive)</span>
        </div>
        <span
          style={{
            fontSize: '0.75rem',
            padding: '0.25rem 0.5rem',
            borderRadius: '9999px',
            backgroundColor: badgeColor,
            color: '#ffffff',
            fontWeight: 700
          }}
        >
          {badgeLabel}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
        <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px', fontSize: '0.85rem' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem' }}>Screen Lock</span>
          <strong style={{ color: posture.screenLockConfigured ? '#34d399' : '#f87171' }}>
            {posture.screenLockConfigured ? '✓ Configured' : '✗ Not Set'}
          </strong>
        </div>

        <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px', fontSize: '0.85rem' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem' }}>USB Debugging (ADB)</span>
          <strong style={{ color: posture.adbDebuggingEnabled ? '#f87171' : '#34d399' }}>
            {posture.adbDebuggingEnabled ? '⚠️ Enabled' : '✓ Disabled'}
          </strong>
        </div>

        <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px', fontSize: '0.85rem' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem' }}>Developer Options</span>
          <strong style={{ color: posture.developerOptionsEnabled ? '#fcd34d' : '#34d399' }}>
            {posture.developerOptionsEnabled ? 'Active' : 'Disabled'}
          </strong>
        </div>

        <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px', fontSize: '0.85rem' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem' }}>Unknown Sources</span>
          <strong style={{ color: posture.unknownSourcesEnabled ? '#f87171' : '#34d399' }}>
            {posture.unknownSourcesEnabled ? 'Allowed' : '✓ Blocked'}
          </strong>
        </div>
      </div>

      {posture.recommendations.length > 0 && (
        <div style={{ borderTop: '1px solid #334155', paddingTop: '0.75rem' }}>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600 }}>Actionable Guidance:</span>
          <ul style={{ margin: '0.35rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
            {posture.recommendations.map((rec, i) => (
              <li key={i} style={{ marginBottom: '0.25rem' }}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
