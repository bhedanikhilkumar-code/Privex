import React from 'react';
import { SecurityBadge } from '../components/SecurityBadge';
import { DesktopNavTab } from '../components/Sidebar';

interface HomeScreenProps {
  onNavigate: (tab: DesktopNavTab) => void;
  threatsCount: number;
  quarantineCount: number;
  filesScannedTotal: number;
}

export const HomeScreen: React.FC<HomeScreenProps> = ({
  onNavigate,
  threatsCount,
  quarantineCount,
  filesScannedTotal
}) => {
  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '22px', color: '#0f172a' }}>System Protection Overview</h2>
          <p style={{ margin: '4px 0 0 0', color: '#64748b', fontSize: '14px' }}>
            Local-first on-device threat defense running on Windows
          </p>
        </div>
        <SecurityBadge severity={threatsCount > 0 ? 'critical' : 'safe'} size="lg" />
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>FILES ANALYZED</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#0f172a', marginTop: '4px' }}>
            {filesScannedTotal.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: '#16a34a', marginTop: '4px' }}>100% on-device processing</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>ACTIVE THREATS</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold', color: threatsCount > 0 ? '#dc2626' : '#16a34a', marginTop: '4px' }}>
            {threatsCount}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
            {threatsCount > 0 ? 'Requires remediation' : 'No active threats detected'}
          </div>
        </div>

        <div style={{ backgroundColor: '#ffffff', padding: '16px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>QUARANTINED BLOBS</div>
          <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f59e0b', marginTop: '4px' }}>
            {quarantineCount}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Isolated in encrypted vault</div>
        </div>
      </div>

      {/* Quick Action Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div
          onClick={() => onNavigate('quick-scan')}
          style={{
            backgroundColor: '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            cursor: 'pointer',
            transition: 'border-color 0.2s',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
          }}
        >
          <div style={{ fontSize: '20px', marginBottom: '8px' }}>⚡</div>
          <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', color: '#0f172a' }}>Quick Scan</h4>
          <p style={{ margin: 0, fontSize: '13px', color: '#64748b', lineHeight: 1.4 }}>
            Targets high-risk ingress points: Downloads, Temp folders, and Windows Startup.
          </p>
        </div>

        <div
          onClick={() => onNavigate('full-scan')}
          style={{
            backgroundColor: '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            cursor: 'pointer',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
          }}
        >
          <div style={{ fontSize: '20px', marginBottom: '8px' }}>🔍</div>
          <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', color: '#0f172a' }}>Full PC Scan</h4>
          <p style={{ margin: 0, fontSize: '13px', color: '#64748b', lineHeight: 1.4 }}>
            Recursive traversal of the complete filesystem with symlink loop protection.
          </p>
        </div>

        <div
          onClick={() => onNavigate('custom-scan')}
          style={{
            backgroundColor: '#ffffff',
            padding: '20px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            cursor: 'pointer',
            boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
          }}
        >
          <div style={{ fontSize: '20px', marginBottom: '8px' }}>📁</div>
          <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', color: '#0f172a' }}>Custom Scan</h4>
          <p style={{ margin: 0, fontSize: '13px', color: '#64748b', lineHeight: 1.4 }}>
            Select a specific directory, file, or connected drive to analyze.
          </p>
        </div>
      </div>

      {/* Security Posture Box */}
      <div style={{ backgroundColor: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px', padding: '16px' }}>
        <h4 style={{ margin: '0 0 6px 0', color: '#166534', fontSize: '14px' }}>🛡️ Privacy & Operational Guarantee</h4>
        <p style={{ margin: 0, color: '#15803d', fontSize: '13px', lineHeight: 1.5 }}>
          Private Protection never uploads your documents, code, or personal files to any cloud server. All file header inspection, byte entropy calculations, and AI assistant explanations are generated locally in volatile RAM on this PC.
        </p>
      </div>
    </div>
  );
};
