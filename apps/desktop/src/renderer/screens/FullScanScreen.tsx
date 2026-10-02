import React, { useState, useEffect } from 'react';
import { ScanProgress, ScanResult, DetectedThreat } from '../../types/desktop.types';
import { ScanProgressBar } from '../components/ScanProgressBar';
import { SecurityBadge } from '../components/SecurityBadge';

interface FullScanScreenProps {
  onScanComplete: (result: ScanResult) => void;
  onSelectThreat: (threat: DetectedThreat) => void;
}

export const FullScanScreen: React.FC<FullScanScreenProps> = ({
  onScanComplete,
  onSelectThreat
}) => {
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [lastResult, setLastResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!window.desktopSecurity?.onScanProgress) return;
    const unsubscribe = window.desktopSecurity.onScanProgress((liveProgress) => {
      setProgress(liveProgress);
    });
    return () => {
      if (typeof unsubscribe === 'function') unsubscribe();
    };
  }, []);

  const handleStartScan = async () => {
    setIsScanning(true);
    setErrorMsg(null);
    setLastResult(null);

    const initialProgress: ScanProgress = {
      scanId: 'full-init',
      scanType: 'full',
      status: 'running',
      filesScanned: 0,
      threatsFound: 0,
      currentPath: 'Traversing filesystem tree...',
      bytesScanned: 0,
      skippedCount: 0,
      errorCount: 0,
      startTime: Date.now(),
      elapsedMs: 0,
      scanSpeedFilesPerSec: 0
    };
    setProgress(initialProgress);

    try {
      if (window.desktopSecurity?.startFullScan) {
        const result = await window.desktopSecurity.startFullScan();
        setLastResult(result);
        onScanComplete(result);
      } else {
        throw new Error('DESKTOP_BRIDGE_UNAVAILABLE: Native desktop security service is disconnected or running in unprivileged web preview mode. Actual filesystem scanning requires the native desktop runtime.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Full PC scan failed.');
    } finally {
      setIsScanning(false);
      setProgress(null);
    }
  };

  const handlePause = () => {
    window.desktopSecurity?.pauseScan?.();
    if (progress) setProgress({ ...progress, status: 'paused' });
  };

  const handleResume = () => {
    window.desktopSecurity?.resumeScan?.();
    if (progress) setProgress({ ...progress, status: 'running' });
  };

  const handleCancel = () => {
    window.desktopSecurity?.cancelScan?.();
    setIsScanning(false);
    setProgress(null);
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>🔍 Full PC Filesystem Scan</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Exhaustive recursive inspection across user storage directories with symlink loop protection and locked-file tolerance.
      </p>

      {!isScanning && (
        <button
          type="button"
          onClick={handleStartScan}
          style={{
            backgroundColor: '#2563eb',
            color: '#ffffff',
            padding: '12px 24px',
            borderRadius: '6px',
            border: 'none',
            fontSize: '15px',
            fontWeight: 600,
            cursor: 'pointer',
            boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
          }}
        >
          Start Full PC Scan
        </button>
      )}

      {isScanning && progress && (
        <ScanProgressBar
          progress={progress}
          onPause={handlePause}
          onResume={handleResume}
          onCancel={handleCancel}
        />
      )}

      {errorMsg && (
        <div style={{ marginTop: '16px', padding: '12px', backgroundColor: '#fef2f2', border: '1px solid #f87171', borderRadius: '6px', color: '#b91c1c', fontSize: '13px' }}>
          {errorMsg}
        </div>
      )}

      {lastResult && (
        <div style={{ marginTop: '24px', backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>Full Scan Report</h3>
            <SecurityBadge severity={lastResult.threats.length > 0 ? 'critical' : 'safe'} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '16px' }}>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>FILES ANALYZED</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>{lastResult.totalFilesScanned.toLocaleString()}</div>
            </div>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>THREATS DETECTED</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: lastResult.threats.length > 0 ? '#dc2626' : '#16a34a' }}>
                {lastResult.threats.length}
              </div>
            </div>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>DURATION</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>{lastResult.durationMs} ms</div>
            </div>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>SKIPPED LOCKED FILES</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>{lastResult.skippedFiles.length}</div>
            </div>
          </div>

          {lastResult.threats.length > 0 && (
            <div>
              <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#dc2626' }}>Detected Threats:</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {lastResult.threats.map((threat) => (
                  <div
                    key={threat.id}
                    onClick={() => onSelectThreat(threat)}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '10px 12px',
                      backgroundColor: '#fef2f2',
                      border: '1px solid #fecaca',
                      borderRadius: '6px',
                      cursor: 'pointer'
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, color: '#991b1b', fontSize: '13px' }}>{threat.fileName}</div>
                      <div style={{ fontSize: '11px', color: '#64748b' }}>{threat.filePath}</div>
                    </div>
                    <span style={{ fontSize: '12px', color: '#dc2626', fontWeight: 500 }}>Review →</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
