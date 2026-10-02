import React, { useState } from 'react';
import { ScanProgress, ScanResult, DetectedThreat } from '../../types/desktop.types';
import { ScanProgressBar } from '../components/ScanProgressBar';
import { SecurityBadge } from '../components/SecurityBadge';

interface CustomScanScreenProps {
  onScanComplete: (result: ScanResult) => void;
  onSelectThreat: (threat: DetectedThreat) => void;
}

export const CustomScanScreen: React.FC<CustomScanScreenProps> = ({
  onScanComplete,
  onSelectThreat
}) => {
  const [targetPath, setTargetPath] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [lastResult, setLastResult] = useState<ScanResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleStartScan = async () => {
    if (!targetPath.trim()) {
      setErrorMsg('Please specify a valid folder, file, or drive path.');
      return;
    }

    setIsScanning(true);
    setErrorMsg(null);
    setLastResult(null);

    const initialProgress: ScanProgress = {
      scanId: 'custom-init',
      scanType: 'custom',
      status: 'running',
      filesScanned: 0,
      threatsFound: 0,
      currentPath: targetPath,
      bytesScanned: 0,
      skippedCount: 0,
      errorCount: 0,
      startTime: Date.now(),
      elapsedMs: 0,
      scanSpeedFilesPerSec: 0
    };
    setProgress(initialProgress);

    try {
      if (window.desktopSecurity?.startCustomScan) {
        const result = await window.desktopSecurity.startCustomScan([targetPath.trim()]);
        setLastResult(result);
        onScanComplete(result);
      } else {
        throw new Error('DESKTOP_BRIDGE_UNAVAILABLE: Native desktop security service is disconnected or running in unprivileged web preview mode. Actual filesystem scanning requires the native desktop runtime.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Custom scan failed.');
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
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>📁 Custom Location Scan</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Scan a specific folder, document, executable, or connected external drive.
      </p>

      {/* Path Input Box */}
      <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
        <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
          Target Directory or File Path:
        </label>
        <div style={{ display: 'flex', gap: '8px' }}>
          <input
            type="text"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            placeholder="e.g. C:\Users\Username\Documents or D:\"
            disabled={isScanning}
            style={{
              flex: 1,
              padding: '10px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              fontSize: '14px'
            }}
          />
          <button
            type="button"
            onClick={handleStartScan}
            disabled={isScanning}
            style={{
              backgroundColor: '#2563eb',
              color: '#ffffff',
              padding: '10px 20px',
              borderRadius: '6px',
              border: 'none',
              fontWeight: 600,
              cursor: isScanning ? 'not-allowed' : 'pointer'
            }}
          >
            Scan Location
          </button>
        </div>

        {/* Quick Sample Presets */}
        <div style={{ display: 'flex', gap: '8px', marginTop: '12px', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: '#64748b' }}>Quick Presets:</span>
          <button
            type="button"
            onClick={() => setTargetPath('C:\\Users\\Default\\Downloads')}
            style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '4px', border: '1px solid #cbd5e1', backgroundColor: '#f8fafc', cursor: 'pointer' }}
          >
            Downloads
          </button>
          <button
            type="button"
            onClick={() => setTargetPath('C:\\Users\\Default\\Desktop')}
            style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '4px', border: '1px solid #cbd5e1', backgroundColor: '#f8fafc', cursor: 'pointer' }}
          >
            Desktop
          </button>
          <button
            type="button"
            onClick={() => setTargetPath('D:\\')}
            style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '4px', border: '1px solid #cbd5e1', backgroundColor: '#f8fafc', cursor: 'pointer' }}
          >
            USB Drive (D:)
          </button>
        </div>
      </div>

      {isScanning && progress && (
        <ScanProgressBar progress={progress} onCancel={handleCancel} />
      )}

      {errorMsg && (
        <div style={{ marginTop: '16px', padding: '12px', backgroundColor: '#fef2f2', border: '1px solid #f87171', borderRadius: '6px', color: '#b91c1c', fontSize: '13px' }}>
          {errorMsg}
        </div>
      )}

      {lastResult && (
        <div style={{ marginTop: '24px', backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ margin: 0, fontSize: '16px', color: '#0f172a' }}>Custom Scan Complete</h3>
            <SecurityBadge severity={lastResult.threats.length > 0 ? 'critical' : 'safe'} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
            <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
              <div style={{ fontSize: '11px', color: '#64748b' }}>FILES INSPECTED</div>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#0f172a' }}>{lastResult.totalFilesScanned}</div>
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
