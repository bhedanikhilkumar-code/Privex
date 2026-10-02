import React from 'react';
import { DetectedThreat } from '../../types/desktop.types';
import { SecurityBadge } from '../components/SecurityBadge';

interface ScanResultsScreenProps {
  threats: DetectedThreat[];
  onIsolateThreat: (threat: DetectedThreat) => void;
  onExplainThreat: (threat: DetectedThreat) => void;
}

export const ScanResultsScreen: React.FC<ScanResultsScreenProps> = ({
  threats,
  onIsolateThreat,
  onExplainThreat
}) => {
  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '22px', color: '#0f172a' }}>📊 Scan Results & Detections</h2>
          <p style={{ margin: '4px 0 0 0', color: '#64748b', fontSize: '14px' }}>
            Itemized technical evidence and quarantine remediation actions
          </p>
        </div>
        <SecurityBadge severity={threats.length > 0 ? 'critical' : 'safe'} size="md" />
      </div>

      {threats.length === 0 ? (
        <div style={{ backgroundColor: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px', padding: '32px', textAlign: 'center' }}>
          <div style={{ fontSize: '36px', marginBottom: '12px' }}>✅</div>
          <h3 style={{ margin: '0 0 6px 0', color: '#166534', fontSize: '18px' }}>Clean System Status</h3>
          <p style={{ margin: 0, color: '#15803d', fontSize: '14px' }}>
            No malicious executables, double extensions, or high-entropy anomalies detected.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {threats.map((threat) => (
            <div
              key={threat.id}
              style={{
                backgroundColor: '#ffffff',
                border: '1px solid #e2e8f0',
                borderRadius: '8px',
                padding: '16px',
                boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 'bold', color: '#0f172a' }}>{threat.fileName}</div>
                  <div style={{ fontSize: '12px', color: '#64748b', fontFamily: 'monospace', marginTop: '2px' }}>
                    {threat.filePath}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Score: {threat.riskScore}/100</span>
                  <SecurityBadge severity={threat.severity} size="sm" />
                </div>
              </div>

              {/* Technical Indicators */}
              <div style={{ backgroundColor: '#f8fafc', padding: '10px 12px', borderRadius: '6px', marginBottom: '12px', fontSize: '12px' }}>
                <div style={{ fontWeight: 600, color: '#334155', marginBottom: '4px' }}>Detected Factors:</div>
                <ul style={{ margin: 0, paddingLeft: '16px', color: '#475569' }}>
                  {threat.evidenceFactors.map((factor, i) => (
                    <li key={i}>{factor}</li>
                  ))}
                </ul>
                <div style={{ marginTop: '6px', fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace' }}>
                  SHA-256: {threat.sha256}
                </div>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => onIsolateThreat(threat)}
                  disabled={threat.quarantined}
                  style={{
                    backgroundColor: threat.quarantined ? '#9ca3af' : '#dc2626',
                    color: '#ffffff',
                    padding: '8px 14px',
                    borderRadius: '6px',
                    border: 'none',
                    fontSize: '13px',
                    fontWeight: 600,
                    cursor: threat.quarantined ? 'not-allowed' : 'pointer'
                  }}
                >
                  {threat.quarantined ? 'Quarantined in Vault' : '🔒 Move to Quarantine'}
                </button>
                <button
                  type="button"
                  onClick={() => onExplainThreat(threat)}
                  style={{
                    backgroundColor: '#f1f5f9',
                    color: '#0f172a',
                    padding: '8px 14px',
                    borderRadius: '6px',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    fontWeight: 500,
                    cursor: 'pointer'
                  }}
                >
                  🤖 Explain with AI Assistant
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
