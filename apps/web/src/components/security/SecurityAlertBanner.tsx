import React from 'react';
import { SecurityEvent } from '../../lib/security/security-events';

interface SecurityAlertBannerProps {
  alerts: SecurityEvent[];
  onDismiss: (id: string) => void;
  onReviewActivity: () => void;
  onChangePasswordClick: () => void;
}

export const SecurityAlertBanner: React.FC<SecurityAlertBannerProps> = ({
  alerts,
  onDismiss,
  onReviewActivity,
  onChangePasswordClick
}) => {
  if (alerts.length === 0) return null;

  const currentAlert = alerts[0];

  const isCritical = currentAlert.severity === 'critical' || currentAlert.severity === 'high';
  const bgColor = isCritical ? 'var(--color-danger-bg)' : 'var(--color-caution-bg)';
  const borderColor = isCritical ? 'var(--color-danger)' : 'var(--color-caution)';

  return (
    <aside
      role="alert"
      aria-live="polite"
      className="motion-fade-down"
      style={{
        backgroundColor: bgColor,
        border: `2px solid ${borderColor}`,
        boxShadow: 'var(--shadow-brutal)',
        padding: '1rem 1.5rem',
        margin: '0 auto 1.5rem auto',
        maxWidth: '1200px',
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.85rem', flex: '1 1 450px' }}>
        <span className="motion-shield-beacon" style={{ fontSize: '1.5rem', display: 'inline-block' }}>🔐</span>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', textTransform: 'uppercase', color: '#111111' }}>
              Security Alert ({currentAlert.severity.toUpperCase()})
            </strong>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.7rem',
                padding: '0.1rem 0.4rem',
                backgroundColor: '#111111',
                color: '#FFFFFF'
              }}
            >
              {currentAlert.type}
            </span>
          </div>

          <p style={{ margin: 0, fontSize: '0.875rem', color: '#222222', lineHeight: 1.45 }}>
            {currentAlert.message}
          </p>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem', fontFamily: 'var(--font-mono)' }}>
            For your safety, consider reviewing recent activity or updating your account password.
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={onChangePasswordClick}
          style={{
            padding: '0.5rem 0.9rem',
            backgroundColor: 'var(--color-brand)',
            color: '#FFFFFF',
            border: '2px solid var(--border-dark)',
            boxShadow: '2px 2px 0px #111111',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            fontWeight: 800,
            textTransform: 'uppercase',
            cursor: 'pointer'
          }}
        >
          Change Password
        </button>

        <button
          type="button"
          onClick={onReviewActivity}
          style={{
            padding: '0.5rem 0.9rem',
            backgroundColor: '#FFFFFF',
            color: '#111111',
            border: '2px solid var(--border-dark)',
            boxShadow: '2px 2px 0px #111111',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            fontWeight: 800,
            textTransform: 'uppercase',
            cursor: 'pointer'
          }}
        >
          Review Activity
        </button>

        <button
          type="button"
          onClick={() => onDismiss(currentAlert.id)}
          aria-label="Dismiss security alert"
          style={{
            padding: '0.5rem 0.75rem',
            backgroundColor: 'transparent',
            border: '1px solid var(--border-dark)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            cursor: 'pointer'
          }}
        >
          ✕ Dismiss
        </button>
      </div>
    </aside>
  );
};
