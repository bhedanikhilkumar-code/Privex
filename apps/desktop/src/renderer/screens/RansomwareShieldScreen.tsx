import React, { useState, useEffect } from 'react';
import {
  RansomwareShieldStatus,
  RansomwareIncident,
  IncidentRollbackResult
} from '../../types/desktop.types';

interface RansomwareShieldScreenProps {
  onRequestFrictionGate: (action: string, onConfirm: () => void) => void;
  onNavigateToTrustedApps?: () => void;
}

export const RansomwareShieldScreen: React.FC<RansomwareShieldScreenProps> = ({
  onRequestFrictionGate,
  onNavigateToTrustedApps
}) => {
  const [status, setStatus] = useState<RansomwareShieldStatus | null>(null);
  const [incidents, setIncidents] = useState<RansomwareIncident[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [newFolder, setNewFolder] = useState<string>('');
  const [notice, setNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [rollingBackId, setRollingBackId] = useState<string | null>(null);

  useEffect(() => {
    loadRansomwareState();
  }, []);

  const loadRansomwareState = async () => {
    setLoading(true);
    try {
      if (window.desktopSecurity?.getRansomwareStatus) {
        const s = await window.desktopSecurity.getRansomwareStatus();
        setStatus(s);
      }
      if (window.desktopSecurity?.getRansomwareIncidents) {
        const inc = await window.desktopSecurity.getRansomwareIncidents();
        setIncidents(inc);
      }
    } catch (err: any) {
      setErrorMsg(`Failed to load ransomware status: ${err?.message || 'IPC error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAddFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFolder.trim()) return;

    try {
      if (window.desktopSecurity?.addProtectedFolder) {
        const folders = await window.desktopSecurity.addProtectedFolder(newFolder.trim());
        setNotice(`Added protected folder: ${newFolder.trim()}`);
        setNewFolder('');
        if (status) {
          setStatus({ ...status, protectedFolders: folders });
        }
      }
    } catch (err: any) {
      setErrorMsg(`Failed to protect folder: ${err?.message || 'Permission denied'}`);
    }
  };

  const handleRemoveFolder = (folderPath: string) => {
    onRequestFrictionGate(`Remove protection from folder '${folderPath}'`, async () => {
      try {
        if (window.desktopSecurity?.removeProtectedFolder) {
          const folders = await window.desktopSecurity.removeProtectedFolder(folderPath);
          setNotice(`Removed protected folder: ${folderPath}`);
          if (status) {
            setStatus({ ...status, protectedFolders: folders });
          }
        }
      } catch (err: any) {
        setErrorMsg(`Failed to remove protected folder: ${err?.message || 'Error'}`);
      }
    });
  };

  const handleResetCanaries = async () => {
    try {
      if (window.desktopSecurity?.resetCanaryTraps) {
        const canaries = await window.desktopSecurity.resetCanaryTraps();
        setNotice(`Re-deployed ${canaries.length} hidden decoy canary trap files across protected folders.`);
        await loadRansomwareState();
      }
    } catch (err: any) {
      setErrorMsg(`Failed to deploy canaries: ${err?.message || 'Error'}`);
    }
  };

  const handleRollback = async (incidentId: string) => {
    setRollingBackId(incidentId);
    setErrorMsg(null);
    try {
      if (window.desktopSecurity?.rollbackRansomwareIncident) {
        const res: IncidentRollbackResult = await window.desktopSecurity.rollbackRansomwareIncident(incidentId);
        if (res.success) {
          setNotice(`Rollback complete: ${res.restoredCount} / ${res.totalFiles} modified files restored to pre-attack SHA-256 state.`);
          await loadRansomwareState();
        } else {
          setErrorMsg(`Rollback failed: ${res.failedFiles?.map((f) => f.reason).join(', ') || 'Unknown error'}`);
        }
      }
    } catch (err: any) {
      setErrorMsg(`Emergency rollback failed: ${err?.message || 'Vault error'}`);
    } finally {
      setRollingBackId(null);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', color: '#64748b' }}>
        Loading Ransomware Shield state...
      </div>
    );
  }

  return (
    <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🔒 Ransomware Shield & Shadow Vault</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Decoy canary traps, sliding-window write velocity detection, and pre-attack Shadow Vault rollback.
          </p>
        </div>

        <span
          style={{
            padding: '4px 10px',
            borderRadius: '9999px',
            fontSize: '11px',
            fontWeight: 700,
            backgroundColor: status?.active ? '#dcfce7' : '#f1f5f9',
            color: status?.active ? '#166534' : '#64748b',
            border: `1px solid ${status?.active ? '#86efac' : '#cbd5e1'}`
          }}
        >
          {status?.active ? 'RANSOMWARE SHIELD ARMED' : 'SHIELD STANDBY'}
        </span>
      </div>

      {notice && (
        <div
          role="status"
          style={{
            padding: '12px',
            backgroundColor: '#f0fdf4',
            border: '1px solid #86efac',
            borderRadius: '8px',
            color: '#166534',
            fontSize: '13px'
          }}
        >
          ✅ {notice}
        </div>
      )}

      {errorMsg && (
        <div
          role="alert"
          style={{
            padding: '12px',
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '8px',
            color: '#991b1b',
            fontSize: '13px'
          }}
        >
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Telemetry Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px' }}>
        <div style={{ backgroundColor: '#ffffff', padding: '14px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700 }}>CANARY TRAPS</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#0f172a', marginTop: '4px' }}>
            {status?.activeCanariesCount ?? 3} Active
          </div>
          <div style={{ fontSize: '11px', color: '#16a34a', marginTop: '4px' }}>Hidden .docx / .xlsx</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', padding: '14px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700 }}>PROTECTED FOLDERS</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#0f172a', marginTop: '4px' }}>
            {status?.protectedFolders?.length ?? 3}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>Write-intercepted</div>
        </div>

        <div style={{ backgroundColor: '#ffffff', padding: '14px', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700 }}>SHADOW VAULT QUOTA</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#0284c7', marginTop: '4px' }}>
            {Math.round((status?.vaultTotalSizeBytes || 0) / (1024 * 1024))} MB
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>AES-256-GCM Blobs</div>
        </div>

        <div
          onClick={onNavigateToTrustedApps}
          style={{
            backgroundColor: '#ffffff',
            padding: '14px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            cursor: onNavigateToTrustedApps ? 'pointer' : 'default'
          }}
        >
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700 }}>TRUSTED APPS</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#0f172a', marginTop: '4px' }}>
            {status?.trustedAppsCount ?? 0}
          </div>
          <div style={{ fontSize: '11px', color: onNavigateToTrustedApps ? '#2563eb' : '#64748b', marginTop: '4px' }}>
            {onNavigateToTrustedApps ? 'Manage Allowlist →' : 'SHA-256 Pinned'}
          </div>
        </div>
      </div>

      {/* Contained Incidents & Emergency Rollback */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px'
        }}
      >
        <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a', marginBottom: '8px' }}>
          Contained Ransomware Attacks & Emergency Rollback
        </div>
        {incidents.length === 0 ? (
          <div style={{ fontSize: '13px', color: '#64748b' }}>
            🛡️ Zero active ransomware incidents. No modified files requiring Shadow Vault rollback.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {incidents.map((inc) => (
              <div
                key={inc.incidentId}
                style={{
                  padding: '14px',
                  backgroundColor: '#fef2f2',
                  border: '1px solid #fecaca',
                  borderRadius: '8px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontWeight: 700, color: '#991b1b', fontSize: '14px' }}>
                    🚨 Incident: {inc.threatType} (PID {inc.responsiblePid ?? 'Unknown'})
                  </div>
                  <div style={{ fontSize: '12px', color: '#b91c1c', marginTop: '2px' }}>
                    {inc.reason} • {inc.affectedFiles.length} file(s) modified
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
                    Detected: {new Date(inc.detectedAt).toLocaleString()} • Rollback Status: {inc.rollbackStatus}
                  </div>
                </div>

                {inc.rollbackStatus === 'PENDING' && (
                  <button
                    type="button"
                    onClick={() => handleRollback(inc.incidentId)}
                    disabled={rollingBackId === inc.incidentId}
                    style={{
                      backgroundColor: '#dc2626',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '6px',
                      padding: '8px 16px',
                      fontSize: '13px',
                      fontWeight: 700,
                      cursor: rollingBackId === inc.incidentId ? 'wait' : 'pointer'
                    }}
                  >
                    {rollingBackId === inc.incidentId ? 'Restoring...' : '🔄 Rollback Clean Files'}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Protected Folders Management */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>Protected Folders</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>
              Only trusted, signed applications may perform bulk writes inside these folders.
            </div>
          </div>
          <button
            type="button"
            onClick={handleResetCanaries}
            style={{
              padding: '6px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#f8fafc',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              color: '#334155'
            }}
          >
            Deploy / Verify Canaries
          </button>
        </div>

        {/* Add Folder Form */}
        <form onSubmit={handleAddFolder} style={{ display: 'flex', gap: '8px' }}>
          <input
            type="text"
            placeholder="Enter full directory path to protect (e.g. C:\Projects)..."
            value={newFolder}
            onChange={(e) => setNewFolder(e.target.value)}
            style={{
              flex: 1,
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '13px'
            }}
          />
          <button
            type="submit"
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            + Protect Folder
          </button>
        </form>

        {/* List of Folders */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {(status?.protectedFolders || []).map((folder) => (
            <div
              key={folder}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '8px 12px',
                backgroundColor: '#f8fafc',
                border: '1px solid #e2e8f0',
                borderRadius: '6px',
                fontSize: '13px'
              }}
            >
              <span style={{ fontFamily: 'monospace', color: '#0f172a' }}>📁 {folder}</span>
              <button
                type="button"
                onClick={() => handleRemoveFolder(folder)}
                style={{
                  padding: '4px 8px',
                  borderRadius: '4px',
                  border: '1px solid #fecaca',
                  backgroundColor: '#fff1f2',
                  color: '#dc2626',
                  fontSize: '11px',
                  cursor: 'pointer'
                }}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
