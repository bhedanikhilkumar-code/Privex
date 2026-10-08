import React from 'react';

interface HeaderProps {
  threatsCount?: number;
  engineActive: boolean;
  offline: boolean;
  unreadNotificationsCount?: number;
  postureStatus?: 'PROTECTED' | 'ATTENTION' | 'ACTION_REQUIRED';
  onOpenNotifications?: () => void;
  onOpenStatus?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  threatsCount = 0,
  engineActive,
  offline,
  unreadNotificationsCount = 0,
  postureStatus = 'PROTECTED',
  onOpenNotifications,
  onOpenStatus
}) => {
  const postureConfig = {
    PROTECTED: {
      label: '🟢 PROTECTED',
      bg: '#dcfce7',
      color: '#166534',
      border: '#86efac'
    },
    ATTENTION: {
      label: '🟡 ATTENTION REQUIRED',
      bg: '#fef3c7',
      color: '#92400e',
      border: '#fcd34d'
    },
    ACTION_REQUIRED: {
      label: '🔴 ACTION REQUIRED',
      bg: '#fee2e2',
      color: '#991b1b',
      border: '#f87171'
    }
  }[postureStatus];

  return (
    <header
      role="banner"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 24px',
        backgroundColor: '#ffffff',
        borderBottom: '1px solid #e2e8f0',
        height: '60px',
        boxSizing: 'border-box'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <h1 style={{ fontSize: '16px', fontWeight: 'bold', margin: 0, color: '#0f172a' }}>
          PRIVEX
        </h1>
        <span
          style={{
            fontSize: '11px',
            color: '#475569',
            backgroundColor: '#f1f5f9',
            padding: '2px 8px',
            borderRadius: '4px',
            fontWeight: 600
          }}
        >
          WINDOWS ANTIVIRUS v1.0
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {/* Posture Pill */}
        <button
          type="button"
          onClick={onOpenStatus}
          aria-label={`Current security posture: ${postureConfig.label}. Click to inspect health.`}
          style={{
            display: 'flex',
            alignItems: 'center',
            backgroundColor: postureConfig.bg,
            color: postureConfig.color,
            border: `1px solid ${postureConfig.border}`,
            padding: '4px 10px',
            borderRadius: '9999px',
            fontSize: '11px',
            fontWeight: 700,
            cursor: onOpenStatus ? 'pointer' : 'default',
            outline: 'none'
          }}
        >
          {postureConfig.label}
        </button>

        {/* Shield Status */}
        <span
          style={{
            fontSize: '12px',
            fontWeight: 500,
            color: engineActive ? '#16a34a' : '#dc2626',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}
        >
          <span>{engineActive ? '●' : '○'}</span>
          <span>{engineActive ? 'Real-Time Active' : 'Shield Offline'}</span>
        </span>

        {/* Offline Air-Gapped Indicator */}
        <span
          style={{
            fontSize: '12px',
            color: offline ? '#0284c7' : '#64748b',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}
        >
          <span>{offline ? '🛡️ Air-Gapped' : '🌐 Connected'}</span>
        </span>

        {/* Threats Counter Badge */}
        {threatsCount > 0 && (
          <span
            aria-label={`${threatsCount} active threats`}
            style={{
              backgroundColor: '#fee2e2',
              color: '#991b1b',
              border: '1px solid #fecaca',
              padding: '4px 8px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700
            }}
          >
            ⚠️ {threatsCount} Threat{threatsCount > 1 ? 's' : ''}
          </span>
        )}

        {/* Notifications Icon Button */}
        {onOpenNotifications && (
          <button
            type="button"
            onClick={onOpenNotifications}
            aria-label={`Notifications: ${unreadNotificationsCount} unread`}
            style={{
              position: 'relative',
              background: 'transparent',
              border: '1px solid #e2e8f0',
              borderRadius: '6px',
              padding: '6px 10px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '13px'
            }}
          >
            <span>🔔</span>
            {unreadNotificationsCount > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: '-4px',
                  right: '-4px',
                  backgroundColor: '#ef4444',
                  color: '#ffffff',
                  borderRadius: '10px',
                  padding: '1px 5px',
                  fontSize: '9px',
                  fontWeight: 'bold',
                  lineHeight: '1.2'
                }}
              >
                {unreadNotificationsCount}
              </span>
            )}
          </button>
        )}
      </div>
    </header>
  );
};
