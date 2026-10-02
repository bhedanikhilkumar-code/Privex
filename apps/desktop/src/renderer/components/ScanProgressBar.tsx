import React from 'react';
import { ScanProgress } from '../../types/desktop.types';

interface ScanProgressBarProps {
  progress: ScanProgress;
  onPause?: () => void;
  onResume?: () => void;
  onCancel?: () => void;
}

export const ScanProgressBar: React.FC<ScanProgressBarProps> = ({
  progress,
  onPause,
  onResume,
  onCancel
}) => {
  return (
    <div
      style={{
        backgroundColor: '#f8fafc',
        border: '1px solid #e2e8f0',
        borderRadius: '8px',
        padding: '16px',
        marginTop: '16px'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
        <span style={{ fontWeight: 600, color: '#1e293b' }}>
          {progress.status === 'paused' ? 'Scan Paused' : 'Scanning Filesystem...'}
        </span>
        <span style={{ color: '#64748b', fontSize: '13px' }}>
          Files: {progress.filesScanned} | Threats: {progress.threatsFound}
        </span>
      </div>

      {/* Progress Track */}
      <div
        style={{
          width: '100%',
          height: '8px',
          backgroundColor: '#e2e8f0',
          borderRadius: '4px',
          overflow: 'hidden',
          marginBottom: '8px'
        }}
      >
        <div
          style={{
            width: '100%',
            height: '100%',
            backgroundColor: progress.status === 'paused' ? '#f59e0b' : '#3b82f6',
            animation: progress.status === 'running' ? 'pulse 1.5s infinite' : 'none'
          }}
        />
      </div>

      <div style={{ fontSize: '12px', color: '#64748b', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
        Current: {progress.currentPath || 'Analyzing index...'}
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
        {progress.status === 'running' && onPause && (
          <button
            type="button"
            onClick={onPause}
            style={{
              padding: '4px 12px',
              borderRadius: '4px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              cursor: 'pointer',
              fontSize: '12px'
            }}
          >
            Pause
          </button>
        )}
        {progress.status === 'paused' && onResume && (
          <button
            type="button"
            onClick={onResume}
            style={{
              padding: '4px 12px',
              borderRadius: '4px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#3b82f6',
              color: '#ffffff',
              cursor: 'pointer',
              fontSize: '12px'
            }}
          >
            Resume
          </button>
        )}
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            style={{
              padding: '4px 12px',
              borderRadius: '4px',
              border: '1px solid #fca5a5',
              backgroundColor: '#fef2f2',
              color: '#b91c1c',
              cursor: 'pointer',
              fontSize: '12px'
            }}
          >
            Cancel Scan
          </button>
        )}
      </div>
    </div>
  );
};
