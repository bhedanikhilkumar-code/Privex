import React, { useState, useEffect } from 'react';
import {
  RemovableDrive,
  RemovableDriveScanResult,
  RansomwareIncident
} from '../../types/desktop.types';

interface RecoveryScreenProps {
  onRequestFrictionGate: (action: string, onConfirm: () => void) => void;
}

export const RecoveryScreen: React.FC<RecoveryScreenProps> = ({ onRequestFrictionGate }) => {
  const [drives, setDrives] = useState<RemovableDrive[]>([]);
  const [incidents, setIncidents] = useState<RansomwareIncident[]>([]);
  const [scanningDrive, setScanningDrive] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<RemovableDriveScanResult | null>(null);
  const [shredding, setShredding] = useState<boolean>(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadDrivesAndIncidents();
  }, []);

  const loadDrivesAndIncidents = async () => {
    try {
      if (window.desktopSecurity?.getRemovableMedia) {
        const d = await window.desktopSecurity.getRemovableMedia();
        setDrives(d || []);
      }
      if (window.desktopSecurity?.getRansomwareIncidents) {
        const inc = await window.desktopSecurity.getRansomwareIncidents();
        setIncidents(inc || []);
      }
    } catch (err: any) {
      console.warn('[RECOVERY_LOAD_ERROR]', err);
    }
  };

  const handleScanUsb = async (mountPoint: string) => {
    setScanningDrive(mountPoint);
    setErrorMsg(null);
    setScanResult(null);
    try {
      if (window.desktopSecurity?.scanRemovableMedia) {
        const res = await window.desktopSecurity.scanRemovableMedia(mountPoint);
        setScanResult(res);
        setNotice(`USB scan completed for ${mountPoint}: ${res.threatsFound} threat(s) detected.`);
      }
    } catch (err: any) {
      setErrorMsg(`USB scan error: ${err?.message || 'Read error'}`);
    } finally {
      setScanningDrive(null);
    }
  };

  const handleExecuteShred = () => {
    onRequestFrictionGate(
      'PERMANENT ZERO-KNOWLEDGE CRYPTO-SHRED (Destroys all scan history, vault blobs, and keys)',
      async () => {
        setShredding(true);
        setErrorMsg(null);
        try {
          if (window.desktopSecurity?.privacyShred) {
            await window.desktopSecurity.privacyShred();
            setNotice('✅ 3-Pass DoD 5220.22-M cryptographic shredding complete. All local logs and blobs zeroed.');
          }
        } catch (err: any) {
          setErrorMsg(`Shredding failed: ${err?.message}`);
        } finally {
          setShredding(false);
        }
      }
    );
  };

  return (
    <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div>
        <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🔄 Recovery, USB Rescue & Crypto-Shredder</h2>
        <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
          Emergency file restoration from Shadow Vault, removable media worm triage, and DoD cryptographic data erasure.
        </p>
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
          {notice}
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

      {/* USB Removable Media Rescue */}
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
        <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
          USB & Removable Media Worm Triage
        </div>
        <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>
          Inspects attached flash drives for autorun.inf deception, hidden folder LNK shortcut worms, and double extensions.
        </p>

        {drives.length === 0 ? (
          <div style={{ fontSize: '12px', color: '#94a3b8', fontStyle: 'italic' }}>
            No removable USB storage drives currently mounted on Windows.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {drives.map((d) => (
              <div
                key={d.mountPoint}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 14px',
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px'
                }}
              >
                <div>
                  <strong>💾 Drive {d.mountPoint}</strong> ({d.fileSystem || 'FAT32'})
                  <div style={{ fontSize: '11px', color: '#64748b' }}>
                    Capacity: {Math.round(d.totalBytes / (1024 * 1024 * 1024))} GB • Volume: {d.label || 'Removable'}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleScanUsb(d.mountPoint)}
                  disabled={scanningDrive === d.mountPoint}
                  style={{
                    backgroundColor: '#2563eb',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '8px 14px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: scanningDrive === d.mountPoint ? 'wait' : 'pointer'
                  }}
                >
                  {scanningDrive === d.mountPoint ? 'Scanning USB...' : '🔍 Scan USB Drive'}
                </button>
              </div>
            ))}
          </div>
        )}

        {scanResult && (
          <div
            style={{
              padding: '12px',
              backgroundColor: scanResult.threatsFound > 0 ? '#fef2f2' : '#f0fdf4',
              border: `1px solid ${scanResult.threatsFound > 0 ? '#f87171' : '#86efac'}`,
              borderRadius: '6px',
              fontSize: '12px',
              marginTop: '4px'
            }}
          >
            <strong>Scan Result for {scanResult.mountPoint}: </strong>
            <span>
              {scanResult.totalRootItemsScanned} items scanned, {scanResult.threatsFound} threats found ({scanResult.durationMs}ms).
            </span>
          </div>
        )}
      </div>

      {/* Shadow Vault Rollback Card */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px'
        }}
      >
        <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
          Shadow Vault Rollback Snapshots
        </div>
        <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>
          Pre-attack AES-256-GCM snapshots created immediately before untrusted process writes occurred.
        </p>
        <div style={{ fontSize: '12px', color: '#475569' }}>
          Active Incidents: <strong>{incidents.length}</strong> • Quota Status: <strong>Encrypted & Isolated</strong>
        </div>
      </div>

      {/* Cryptographic Privacy Shredder */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #fecaca',
          padding: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <div style={{ maxWidth: '580px' }}>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#991b1b' }}>
            Permanent Zero-Knowledge Crypto-Shredder
          </div>
          <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: '#7f1d1d', lineHeight: 1.4 }}>
            Overwrites all local scan history, quarantine blobs, and cryptographic master keys using a 3-pass
            DoD 5220.22-M algorithm (0x00, 0xFF, CSPRNG bytes) followed by unlinking. Irreversible.
          </p>
        </div>

        <button
          type="button"
          onClick={handleExecuteShred}
          disabled={shredding}
          style={{
            backgroundColor: '#dc2626',
            color: '#ffffff',
            border: 'none',
            borderRadius: '6px',
            padding: '10px 18px',
            fontSize: '13px',
            fontWeight: 700,
            cursor: shredding ? 'wait' : 'pointer',
            whiteSpace: 'nowrap'
          }}
        >
          {shredding ? 'Shredding...' : '🔥 Execute Crypto-Shred'}
        </button>
      </div>
    </div>
  );
};
