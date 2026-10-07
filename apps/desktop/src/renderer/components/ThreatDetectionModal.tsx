import React, { useEffect, useRef } from 'react';
import { RealtimeThreatEvent, DetectedThreat } from '../../types/desktop.types';

interface ThreatDetectionModalProps {
  alert: RealtimeThreatEvent;
  onAcknowledge: () => void;
  onInspectEvidence: (threat: DetectedThreat) => void;
  onRequestRestore?: (threat: DetectedThreat) => void;
}

/**
 * Sanitizes RTLO (Right-to-Left Override) and dangerous Unicode bidirectional control characters
 * (\u202A-\u202E, \u2066-\u2069) to defeat filename spoofing attacks.
 */
export function sanitizeUnicodeDisplay(str: string): string {
  if (!str) return '';
  return str.replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '');
}

export const ThreatDetectionModal: React.FC<ThreatDetectionModalProps> = ({
  alert,
  onAcknowledge,
  onInspectEvidence,
  onRequestRestore
}) => {
  const safeButtonRef = useRef<HTMLButtonElement>(null);
  const anyAlert = alert as any;
  const threat: DetectedThreat = anyAlert.threat || {
    threatId: anyAlert.analysis?.sha256 || 'threat-1',
    fileName: anyAlert.analysis?.filePath
      ? anyAlert.analysis.filePath.split('\\').pop()
      : anyAlert.event?.filePath
      ? anyAlert.event.filePath.split('\\').pop()
      : 'Suspicious File',
    filePath: anyAlert.analysis?.filePath || anyAlert.event?.filePath || '',
    threatName: anyAlert.analysis?.threatIndicators?.[0] || 'Malicious Threat',
    severity: anyAlert.analysis?.severity || 'critical',
    riskScore: anyAlert.analysis?.riskScore || 90,
    evidenceFactors: anyAlert.analysis?.evidenceFactors || [],
    detectedAt: anyAlert.timestamp || Date.now(),
    quarantined: anyAlert.quarantined ?? true
  };
  const actionTaken = anyAlert.actionTaken || (anyAlert.quarantined ? 'AUTO_QUARANTINED' : 'ALERT_ONLY');

  // Auto-focus the safe CTA on mount (WCAG alertdialog requirement)
  useEffect(() => {
    safeButtonRef.current?.focus();
  }, []);

  const sanitizedFileName = sanitizeUnicodeDisplay(threat.fileName);
  const sanitizedFilePath = sanitizeUnicodeDisplay(threat.filePath);

  const isQuarantined = actionTaken === 'AUTO_QUARANTINED' || threat.quarantined;

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="threat-dialog-title"
      aria-describedby="threat-dialog-desc"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.75)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '20px'
      }}
    >
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '12px',
          maxWidth: '580px',
          width: '100%',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
          border: '2px solid #ef4444',
          overflow: 'hidden'
        }}
      >
        {/* Header Banner */}
        <div
          style={{
            backgroundColor: '#fee2e2',
            borderBottom: '1px solid #fecaca',
            padding: '16px 20px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}
        >
          <span style={{ fontSize: '24px' }}>🚨</span>
          <div>
            <h2
              id="threat-dialog-title"
              style={{
                margin: 0,
                fontSize: '18px',
                fontWeight: 700,
                color: '#991b1b'
              }}
            >
              Malicious Threat Intercepted
            </h2>
            <div style={{ fontSize: '12px', color: '#b91c1c', marginTop: '2px' }}>
              Severity: <strong>{threat.severity.toUpperCase()}</strong> • Risk Score: {threat.riskScore}/100
            </div>
          </div>
        </div>

        {/* Content Body with 4-Pillar Plain Language */}
        <div id="threat-dialog-desc" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Target File Info */}
          <div
            style={{
              backgroundColor: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '12px',
              fontSize: '13px'
            }}
          >
            <div style={{ fontWeight: 600, color: '#334155' }}>Detected Item:</div>
            <div
              style={{
                fontFamily: 'Consolas, monospace',
                color: '#0f172a',
                fontSize: '12px',
                wordBreak: 'break-all',
                marginTop: '4px',
                padding: '6px 8px',
                backgroundColor: '#ffffff',
                borderRadius: '4px',
                border: '1px solid #cbd5e1'
              }}
            >
              {sanitizedFileName}
            </div>
            <div
              style={{
                color: '#64748b',
                fontSize: '11px',
                marginTop: '4px',
                wordBreak: 'break-all'
              }}
            >
              Path: {sanitizedFilePath}
            </div>
          </div>

          {/* 4 Pillars */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div
              style={{
                backgroundColor: '#f1f5f9',
                borderRadius: '6px',
                padding: '10px',
                fontSize: '12px'
              }}
            >
              <div style={{ fontWeight: 700, color: '#475569', marginBottom: '4px' }}>1. WHAT HAPPENED</div>
              <div style={{ color: '#1e293b' }}>
                {threat.threatName || 'A suspicious file with dangerous properties was accessed.'}
              </div>
            </div>

            <div
              style={{
                backgroundColor: '#f1f5f9',
                borderRadius: '6px',
                padding: '10px',
                fontSize: '12px'
              }}
            >
              <div style={{ fontWeight: 700, color: '#475569', marginBottom: '4px' }}>2. WHY IT MATTERS</div>
              <div style={{ color: '#1e293b' }}>
                Could attempt to steal passwords, encrypt documents, or compromise Windows security.
              </div>
            </div>

            <div
              style={{
                backgroundColor: '#ecfdf5',
                border: '1px solid #a7f3d0',
                borderRadius: '6px',
                padding: '10px',
                fontSize: '12px'
              }}
            >
              <div style={{ fontWeight: 700, color: '#065f46', marginBottom: '4px' }}>3. WHAT WE DID</div>
              <div style={{ color: '#047857' }}>
                {isQuarantined
                  ? 'Safely isolated inside the encrypted Quarantine Vault (PPVAULT2).'
                  : 'Blocked from execution and alerted user.'}
              </div>
            </div>

            <div
              style={{
                backgroundColor: '#eff6ff',
                border: '1px solid #bfdbfe',
                borderRadius: '6px',
                padding: '10px',
                fontSize: '12px'
              }}
            >
              <div style={{ fontWeight: 700, color: '#1e40af', marginBottom: '4px' }}>4. NEXT STEP</div>
              <div style={{ color: '#1d4ed8' }}>
                Keep file quarantined. No further action needed to remain safe.
              </div>
            </div>
          </div>
        </div>

        {/* Modal Actions */}
        <div
          style={{
            backgroundColor: '#f8fafc',
            borderTop: '1px solid #e2e8f0',
            padding: '14px 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '10px'
          }}
        >
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              onClick={() => onInspectEvidence(threat)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                backgroundColor: '#ffffff',
                color: '#334155',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              🔍 Inspect Evidence & AI
            </button>

            {onRequestRestore && (
              <button
                type="button"
                onClick={() => onRequestRestore(threat)}
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid #fecaca',
                  backgroundColor: '#fff1f2',
                  color: '#be123c',
                  fontSize: '12px',
                  cursor: 'pointer'
                }}
              >
                Restore...
              </button>
            )}
          </div>

          <button
            ref={safeButtonRef}
            type="button"
            onClick={onAcknowledge}
            style={{
              padding: '9px 18px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#16a34a',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            🛡️ Keep in Quarantine (Recommended)
          </button>
        </div>
      </div>
    </div>
  );
};
