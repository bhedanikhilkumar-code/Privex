import React, { useState, useEffect } from 'react';
import {
  PreThreatWarningPayload,
  PreThreatActionType,
  WarningConfidenceLevel
} from '../types/mobile.types';

interface PreThreatWarningModalProps {
  warning: PreThreatWarningPayload | null;
  onActionSelected: (action: PreThreatActionType, bypassedWithFrictionGate: boolean) => void;
  onDismiss?: () => void;
}

export const PreThreatWarningModal: React.FC<PreThreatWarningModalProps> = ({
  warning,
  onActionSelected,
  onDismiss
}) => {
  const [showEvidence, setShowEvidence] = useState<boolean>(false);
  const [showFrictionGate, setShowFrictionGate] = useState<boolean>(false);
  const [countdown, setCountdown] = useState<number>(5);

  useEffect(() => {
    if (!warning) {
      setShowFrictionGate(false);
      setShowEvidence(false);
      return;
    }
    setCountdown(warning.frictionGateSeconds || 5);
  }, [warning]);

  useEffect(() => {
    if (!showFrictionGate) return;
    if (countdown <= 0) return;

    const timer = setInterval(() => {
      setCountdown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);

    return () => clearInterval(timer);
  }, [showFrictionGate, countdown]);

  if (!warning) {
    return null;
  }

  const isDangerous = warning.verdict === 'DANGEROUS';
  const isSuspicious = warning.verdict === 'SUSPICIOUS';

  const borderColor = isDangerous ? '#ef4444' : isSuspicious ? '#f59e0b' : '#38bdf8';
  const badgeColor = isDangerous ? '#dc2626' : isSuspicious ? '#d97706' : '#0284c7';

  const formatConfidenceLabel = (conf: WarningConfidenceLevel): string => {
    switch (conf) {
      case 'CONFIRMED_MALWARE':
        return 'Confirmed Malware';
      case 'STRONG_SUSPICION':
        return 'Strong Suspicion';
      case 'HEURISTIC_ANOMALY':
        return 'Heuristic Anomaly';
      default:
        return conf;
    }
  };

  const formatSafeActionLabel = (action: PreThreatActionType): string => {
    switch (action) {
      case 'GO_BACK':
        return '← Go Back to Safety (Recommended)';
      case 'CANCEL_INSTALL':
        return '✕ Cancel Installation (Recommended)';
      case 'DELETE_DOWNLOAD':
        return '🗑 Delete Download (Recommended)';
      case 'QUARANTINE':
        return '🔒 Quarantine File (Recommended)';
      case 'RESCAN':
        return '🔄 Rescan Target';
      default:
        return 'Safe Action';
    }
  };

  const handlePrimarySafeAction = () => {
    onActionSelected(warning.recommendedAction, false);
  };

  const handleInitiateBypass = () => {
    if (warning.requiresFrictionGate) {
      setShowFrictionGate(true);
      setCountdown(warning.frictionGateSeconds || 5);
    } else {
      onActionSelected('CONTINUE_AT_OWN_RISK', false);
    }
  };

  const handleConfirmFrictionBypass = () => {
    onActionSelected('CONTINUE_AT_OWN_RISK', true);
  };

  const handleCancelFrictionBypass = () => {
    setShowFrictionGate(false);
  };

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="pre-threat-title"
      aria-describedby="pre-threat-desc"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(2, 6, 23, 0.92)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
        zIndex: 10000
      }}
    >
      <div
        style={{
          backgroundColor: '#0f172a',
          borderRadius: '20px',
          border: `2px solid ${borderColor}`,
          padding: '1.5rem',
          maxWidth: '460px',
          width: '100%',
          color: '#f8fafc',
          boxShadow: `0 25px 50px -12px ${isDangerous ? 'rgba(239, 68, 68, 0.35)' : 'rgba(0, 0, 0, 0.6)'}`,
          maxHeight: '90vh',
          overflowY: 'auto'
        }}
      >
        {/* Warning Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <span style={{ fontSize: '1.25rem' }}>{isDangerous ? '🛑' : isSuspicious ? '⚠️' : 'ℹ️'}</span>
              <span
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  color: borderColor
                }}
              >
                Pre-Threat Defense Warning
              </span>
            </div>
            <h2 id="pre-threat-title" style={{ margin: 0, fontSize: '1.35rem', color: '#f8fafc', fontWeight: 700 }}>
              {isDangerous ? 'High-Risk Threat Blocked' : 'Security Caution Advised'}
            </h2>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                backgroundColor: badgeColor,
                color: '#ffffff',
                padding: '0.25rem 0.6rem',
                borderRadius: '9999px',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}
            >
              {formatConfidenceLabel(warning.confidenceLevel)}
            </span>
            {onDismiss && (
              <button
                type="button"
                onClick={onDismiss}
                aria-label="Close warning"
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  fontSize: '1.25rem',
                  cursor: 'pointer',
                  padding: '0 0.25rem'
                }}
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Target Card */}
        <div
          style={{
            backgroundColor: '#1e293b',
            borderRadius: '12px',
            padding: '0.85rem',
            marginBottom: '1rem',
            border: '1px solid #334155'
          }}
        >
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>
            Target [{warning.targetType}]
          </div>
          <div
            style={{
              fontSize: '0.875rem',
              color: '#38bdf8',
              fontFamily: 'monospace',
              wordBreak: 'break-all',
              marginTop: '0.25rem'
            }}
          >
            {warning.targetIdentifier}
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem', fontSize: '0.75rem', color: '#cbd5e1' }}>
            <span>Risk Score: <strong>{warning.riskScore}/100</strong></span>
            <span>Verdict: <strong>{warning.verdict}</strong></span>
          </div>
        </div>

        {/* What Was Detected */}
        <div style={{ marginBottom: '1rem' }}>
          <h4 style={{ margin: '0 0 0.25rem 0', fontSize: '0.85rem', color: '#f87171', textTransform: 'uppercase' }}>
            What was detected:
          </h4>
          <p id="pre-threat-desc" style={{ margin: 0, fontSize: '0.9rem', color: '#e2e8f0', lineHeight: 1.5 }}>
            {warning.whatDetected}
          </p>
        </div>

        {/* Potential Consequences */}
        <div style={{ marginBottom: '1.25rem' }}>
          <h4 style={{ margin: '0 0 0.25rem 0', fontSize: '0.85rem', color: '#fbbf24', textTransform: 'uppercase' }}>
            Potential consequences:
          </h4>
          <p style={{ margin: 0, fontSize: '0.9rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {warning.potentialConsequences}
          </p>
        </div>

        {/* Technical Evidence Collapsible */}
        {warning.evidenceDetails && warning.evidenceDetails.length > 0 && (
          <div style={{ marginBottom: '1.25rem' }}>
            <button
              type="button"
              onClick={() => setShowEvidence(!showEvidence)}
              style={{
                background: 'none',
                border: 'none',
                color: '#94a3b8',
                fontSize: '0.8rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                padding: 0
              }}
            >
              <span>{showEvidence ? '▼' : '▶'}</span>
              <span>Technical Evidence Details ({warning.evidenceDetails.length} items)</span>
            </button>

            {showEvidence && (
              <div
                style={{
                  marginTop: '0.5rem',
                  backgroundColor: '#020617',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '0.75rem',
                  maxHeight: '120px',
                  overflowY: 'auto'
                }}
              >
                {warning.evidenceDetails.map((ev, idx) => (
                  <div
                    key={idx}
                    style={{
                      fontSize: '0.75rem',
                      marginBottom: idx < warning.evidenceDetails.length - 1 ? '0.5rem' : 0,
                      borderBottom: idx < warning.evidenceDetails.length - 1 ? '1px solid #1e293b' : 'none',
                      paddingBottom: idx < warning.evidenceDetails.length - 1 ? '0.5rem' : 0
                    }}
                  >
                    <div style={{ color: '#f87171', fontWeight: 600 }}>{ev.code} [{ev.severity}]</div>
                    <div style={{ color: '#cbd5e1', marginTop: '0.15rem' }}>{ev.description}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Friction Gate Confirmation State */}
        {showFrictionGate ? (
          <div
            style={{
              backgroundColor: '#450a0a',
              border: '2px solid #ef4444',
              borderRadius: '12px',
              padding: '1rem',
              marginTop: '0.5rem'
            }}
          >
            <div style={{ fontSize: '0.9rem', fontWeight: 700, color: '#fca5a5', marginBottom: '0.5rem' }}>
              ⚠️ Severe Risk Acknowledgment
            </div>
            <p style={{ fontSize: '0.85rem', color: '#fecaca', margin: '0 0 1rem 0', lineHeight: 1.4 }}>
              You are choosing to proceed against our defensive recommendation. This action may expose your device or credentials to attack.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <button
                type="button"
                onClick={handleCancelFrictionBypass}
                style={{
                  padding: '0.75rem',
                  backgroundColor: '#3b82f6',
                  color: '#ffffff',
                  fontWeight: 600,
                  borderRadius: '8px',
                  border: 'none',
                  cursor: 'pointer'
                }}
              >
                ← Return to Safety (Recommended)
              </button>

              <button
                type="button"
                onClick={handleConfirmFrictionBypass}
                disabled={countdown > 0}
                style={{
                  padding: '0.75rem',
                  backgroundColor: countdown > 0 ? '#64748b' : '#ef4444',
                  color: '#ffffff',
                  fontWeight: 600,
                  borderRadius: '8px',
                  border: 'none',
                  cursor: countdown > 0 ? 'not-allowed' : 'pointer'
                }}
              >
                {countdown > 0
                  ? `Wait ${countdown}s before continuing...`
                  : 'I Understand the Risks, Continue'}
              </button>
            </div>
          </div>
        ) : (
          /* Normal Action Buttons */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
            <button
              type="button"
              onClick={handlePrimarySafeAction}
              style={{
                padding: '0.85rem 1rem',
                backgroundColor: '#2563eb',
                color: '#ffffff',
                fontWeight: 700,
                fontSize: '0.95rem',
                borderRadius: '12px',
                border: 'none',
                cursor: 'pointer',
                boxShadow: '0 4px 6px -1px rgba(37, 99, 235, 0.4)'
              }}
            >
              {formatSafeActionLabel(warning.recommendedAction)}
            </button>

            {warning.supportedChoices.includes('QUARANTINE') && warning.recommendedAction !== 'QUARANTINE' && (
              <button
                type="button"
                onClick={() => onActionSelected('QUARANTINE', false)}
                style={{
                  padding: '0.65rem 1rem',
                  backgroundColor: '#334155',
                  color: '#e2e8f0',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  borderRadius: '10px',
                  border: 'none',
                  cursor: 'pointer'
                }}
              >
                🔒 Move to Quarantine
              </button>
            )}

            {warning.supportedChoices.includes('CONTINUE_AT_OWN_RISK') && (
              <button
                type="button"
                onClick={handleInitiateBypass}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  fontSize: '0.8rem',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                  padding: '0.25rem'
                }}
              >
                Continue at your own risk...
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
