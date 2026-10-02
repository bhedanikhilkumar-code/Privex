import React, { useState } from 'react';
import { ScanProgress, ScanResult, DetectedThreat } from '../../types/desktop.types';
import { ScanProgressBar } from '../components/ScanProgressBar';
import { SecurityBadge } from '../components/SecurityBadge';

interface QuickScanScreenProps {
  onScanComplete: (result: ScanResult) => void;
  onSelectThreat: (threat: DetectedThreat) => void;
}

export const QuickScanScreen: React.FC<QuickScanScreenProps> = ({
  onScanComplete,
  onSelectThreat
}) => {
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [lastResult, setLastResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleStartScan = async () => {
    setIsScanning(true);
    setErrorMsg(null);
    setLastResult(null);

    const initialProgress: ScanProgress = {
      scanId: 'quick-init',
      scanType: 'quick',
      status: 'running',
      filesScanned: 0,
      threatsFound: 0,
      currentPath: 'Preparing ingress scan targets...',
      bytesScanned: 0,
      skippedCount: 0,
      errorCount: 0,
      startTime: Date.now(),
      elapsedMs: 0,
      scanSpeedFilesPerSec: 0
    };
    setProgress(initialProgress);

    try {
      if (window.desktopSecurity?.startQuickScan) {
        const result = await window.desktopSecurity.startQuickScan();
        setLastResult(result);
        onScanComplete(result);
      } else {
        throw new Error('DESKTOP_BRIDGE_UNAVAILABLE: Native desktop security service is disconnected or running in unprivileged web preview mode. Actual filesystem scanning requires the native desktop runtime.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Quick scan failed to complete.');
    } finally {
      setIsScanning(false);
      setProgress(null);
    }
  };

  const handleCancel = () => {
    window.desktopSecurity?.cancelScan?.();
    setIsScanning(false);
    setProgress(null);
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>⚡ Quick Ingress Scan</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Scans common high-risk entry points on this PC: Downloads, Temp directory, Desktop, and Windows Startup.
      </p>

      {/* Target Description Card */}
      <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', color: '#1e293b' }}>Scan Scope Details:</h4>
        <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '13px', color: '#475569', lineHeight: 1.6 }}>
          <li><strong>Downloads:</strong> Inspects newly acquired executable files and double-extension archives.</li>
          <li><strong>Temporary Files:</strong> Scans `%TEMP%` for staging executables dropped by scripts.</li>
          <li><strong>Startup Folder:</strong> Audits persistence items configured to launch on Windows login.</li>
        </ul>
      </div>

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
          Start Quick Scan
        </button>
      )}

      {isScanning && progress && (
        <ScanProgressBar progress={progress} onCancel={handleCancel} />
      )}

      {errorMsg && (
        <div style={{ marginTop: '16px', padding: '12px', backgroundColor: '#fef2f2', border: '1px solid #f87171', borderRadius: '6px', color: '#b91c1c', fontSize: '13px' }}>
          {errorMsg}
        </div>
      )}

      {/* Scan Summary Report */}
      {lastResult && (
        <div style={{ marginTop: '24px', backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>Scan Completed</h3>
            <SecurityBadge severity={lastResult.threats.length > 0 ? 'critical' : 'safe'} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '16px' }}>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>FILES SCANNED</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>{lastResult.totalFilesScanned}</div>
            </div>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>THREATS FOUND</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: lastResult.threats.length > 0 ? '#dc2626' : '#16a34a' }}>
                {lastResult.threats.length}
              </div>
            </div>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>DURATION</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>{lastResult.durationMs} ms</div>
            </div>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>SKIPPED / ERRORS</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>
                {lastResult.skippedFiles.length} / {lastResult.errors.length}
              </div>
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
                      <div style={{ fontSize: '11px', color: '#64748b' }}>{threat.threatName} (Score: {threat.riskScore})</div>
                    </div>
                    <span style={{ fontSize: '12px', color: '#dc2626', fontWeight: 500 }}>Inspect & Quarantined →</span>
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
