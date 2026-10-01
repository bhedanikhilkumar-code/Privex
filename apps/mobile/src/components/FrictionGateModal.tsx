import React, { useState, useEffect } from 'react';

interface FrictionGateModalProps {
  isOpen: boolean;
  threatCategory: string;
  durationSec?: number;
  onConfirmBypass: () => void;
  onCancel: () => void;
}

export const FrictionGateModal: React.FC<FrictionGateModalProps> = ({
  isOpen,
  threatCategory,
  durationSec = 5,
  onConfirmBypass,
  onCancel
}) => {
  const [secondsRemaining, setSecondsRemaining] = useState<number>(durationSec);

  useEffect(() => {
    if (!isOpen) {
      setSecondsRemaining(durationSec);
      return;
    }

    if (secondsRemaining <= 0) return;

    const timer = setInterval(() => {
      setSecondsRemaining((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);

    return () => clearInterval(timer);
  }, [isOpen, secondsRemaining, durationSec]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="friction-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.85)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
        zIndex: 9999
      }}
    >
      <div
        style={{
          backgroundColor: '#1e293b',
          borderRadius: '16px',
          border: '2px solid #ef4444',
          padding: '1.5rem',
          maxWidth: '420px',
          width: '100%',
          color: '#f8fafc',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
        }}
      >
        <h3
          id="friction-title"
          style={{
            margin: '0 0 0.5rem 0',
            fontSize: '1.25rem',
            color: '#f87171',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}
        >
          <span>🛑</span> Severe Threat Warning
        </h3>
        <p style={{ margin: '0 0 1rem 0', fontSize: '0.9rem', color: '#cbd5e1', lineHeight: 1.5 }}>
          This target has been flagged as high-risk <strong>{threatCategory}</strong>. Opening this content may compromise your accounts or device.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1.25rem' }}>
          <button
            type="button"
            onClick={onCancel}
            style={{
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              backgroundColor: '#3b82f6',
              color: '#ffffff',
              fontWeight: 600,
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.95rem'
            }}
          >
            ← Back to Safety (Recommended)
          </button>

          <button
            type="button"
            disabled={secondsRemaining > 0}
            onClick={onConfirmBypass}
            style={{
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              backgroundColor: secondsRemaining > 0 ? '#334155' : '#ef4444',
              color: secondsRemaining > 0 ? '#94a3b8' : '#ffffff',
              fontWeight: 600,
              border: 'none',
              cursor: secondsRemaining > 0 ? 'not-allowed' : 'pointer',
              fontSize: '0.9rem'
            }}
          >
            {secondsRemaining > 0
              ? `Proceed Anyway (${secondsRemaining}s)...`
              : 'Proceed Anyway (Unsafe)'}
          </button>
        </div>
      </div>
    </div>
  );
};
