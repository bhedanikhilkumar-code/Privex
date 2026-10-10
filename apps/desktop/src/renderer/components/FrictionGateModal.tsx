import React, { useState, useEffect } from 'react';

interface FrictionGateModalProps {
  isOpen: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  countdownSeconds?: number;
  onConfirm: () => void;
  onCancel: () => void;
}

export const FrictionGateModal: React.FC<FrictionGateModalProps> = ({
  isOpen,
  title,
  description,
  confirmLabel,
  countdownSeconds = 3,
  onConfirm,
  onCancel
}) => {
  const [remaining, setRemaining] = useState(countdownSeconds);

  useEffect(() => {
    if (!isOpen) {
      setRemaining(countdownSeconds);
      return;
    }

    if (remaining <= 0) return;

    const timer = setInterval(() => {
      setRemaining((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);

    return () => clearInterval(timer);
  }, [isOpen, remaining, countdownSeconds]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="friction-gate-title"
      className="motion-modal-backdrop"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999
      }}
    >
      <div
        className="motion-modal-panel"
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '8px',
          padding: '24px',
          maxWidth: '500px',
          width: '90%',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3)'
        }}
      >
        <h3 id="friction-gate-title" style={{ color: '#b91c1c', marginTop: 0 }}>
          {title}
        </h3>
        <p style={{ color: '#374151', fontSize: '14px', lineHeight: 1.5 }}>
          {description}
        </p>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '24px' }}>
          <button
            type="button"
            onClick={onCancel}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: '1px solid #d1d5db',
              backgroundColor: '#f3f4f6',
              cursor: 'pointer',
              fontWeight: 500
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={remaining > 0}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: remaining > 0 ? '#9ca3af' : '#dc2626',
              color: '#ffffff',
              cursor: remaining > 0 ? 'not-allowed' : 'pointer',
              fontWeight: 'bold'
            }}
          >
            {remaining > 0 ? `${confirmLabel} (${remaining}s)` : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};
