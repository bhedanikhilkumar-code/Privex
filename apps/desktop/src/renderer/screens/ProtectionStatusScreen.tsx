import React, { useState } from 'react';
import { DesktopProtectionStatus, ProcessInfo, PersistenceItem } from '../../types/desktop.types';

interface ProtectionStatusScreenProps {
  status: DesktopProtectionStatus;
  onAuditProcesses: () => Promise<ProcessInfo[]>;
  onAuditPersistence: () => Promise<PersistenceItem[]>;
}

export const ProtectionStatusScreen: React.FC<ProtectionStatusScreenProps> = ({
  status,
  onAuditProcesses,
  onAuditPersistence
}) => {
  const [processes, setProcesses] = useState<ProcessInfo[] | null>(null);
  const [persistence, setPersistence] = useState<PersistenceItem[] | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleAudit = async () => {
    setIsLoading(true);
    try {
      const procs = await onAuditProcesses();
      const persists = await onAuditPersistence();
      setProcesses(procs);
      setPersistence(persists);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>🛡️ Protection Status & Architecture</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Live telemetry and integrity metrics for on-device security engines
      </p>

      {/* Engine Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>REAL-TIME SHIELD</div>
          <div style={{ fontSize: '18px', fontWeight: 'bold', color: status.realtimeShieldActive ? '#16a34a' : '#dc2626', marginTop: '4px' }}>
            {status.realtimeShieldActive ? 'ACTIVE & MONITORING' : 'PAUSED'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Ingress download watcher</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>THREAT DATABASE</div>
          <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a', marginTop: '4px' }}>
            {status.threatDatabaseVersion}
          </div>
          <div style={{ fontSize: '11px', color: '#16a34a', marginTop: '4px' }}>Air-gapped Bloom filter cache</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px' }}>
          <div style={{ fontSize: '12px', color: '#64748b', fontWeight: 600 }}>MEMORY CONSUMPTION</div>
          <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a', marginTop: '4px' }}>
            {Math.round(status.memoryRssBytes / 1024 / 1024)} MB RSS
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Heap used: {Math.round(status.heapUsedBytes / 1024 / 1024)} MB</div>
        </div>
      </div>

      {/* Monitored Locations */}
      <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px', marginBottom: '24px' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#1e293b' }}>Ingress Monitored Paths:</h4>
        {status.monitoredPaths.length > 0 ? (
          <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '13px', color: '#475569' }}>
            {status.monitoredPaths.map((p, idx) => (
              <li key={idx} style={{ fontFamily: 'monospace' }}>{p}</li>
            ))}
          </ul>
        ) : (
          <div style={{ fontSize: '13px', color: '#64748b' }}>Standard user Downloads directory monitored automatically.</div>
        )}
      </div>

      {/* Non-invasive Posture Audit Trigger */}
      <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div>
            <h4 style={{ margin: 0, fontSize: '14px', color: '#0f172a' }}>Process & Startup Persistence Audit</h4>
            <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: '#64748b' }}>
              Read-only inspection of active tasks and Windows startup registry entries.
            </p>
          </div>
          <button
            type="button"
            onClick={handleAudit}
            disabled={isLoading}
            style={{
              padding: '8px 16px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: isLoading ? 'not-allowed' : 'pointer'
            }}
          >
            {isLoading ? 'Auditing...' : 'Run Read-Only Audit'}
          </button>
        </div>

        {processes && (
          <div style={{ marginTop: '16px', borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
            <div style={{ fontWeight: 600, fontSize: '13px', color: '#1e293b', marginBottom: '6px' }}>
              Active Processes ({processes.length} inspected):
            </div>
            <div style={{ fontSize: '12px', color: '#475569' }}>
              {processes.filter((p) => p.isSuspicious).length === 0
                ? '✅ Zero suspicious processes detected in memory.'
                : `⚠️ ${processes.filter((p) => p.isSuspicious).length} suspicious processes flagged for review.`}
            </div>
          </div>
        )}

        {persistence && (
          <div style={{ marginTop: '12px', borderTop: '1px solid #f1f5f9', paddingTop: '12px' }}>
            <div style={{ fontWeight: 600, fontSize: '13px', color: '#1e293b', marginBottom: '6px' }}>
              Startup Persistence Entries ({persistence.length} items):
            </div>
            <div style={{ fontSize: '12px', color: '#475569' }}>
              {persistence.filter((p) => p.isSuspicious).length === 0
                ? '✅ Zero suspicious startup persistence entries identified.'
                : `⚠️ ${persistence.filter((p) => p.isSuspicious).length} unusual startup persistence entries.`}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
