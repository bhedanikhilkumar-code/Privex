import React, { useState, useEffect } from 'react';
import {
  DesktopNotification,
  NotificationInboxState
} from '../../types/desktop.types';

export const NotificationsScreen: React.FC = () => {
  const [notifications, setNotifications] = useState<DesktopNotification[]>([]);
  const [inboxState, setInboxState] = useState<NotificationInboxState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [filter, setFilter] = useState<'ALL' | 'UNREAD' | 'CRITICAL'>('ALL');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadNotifications();
  }, []);

  const loadNotifications = async () => {
    setLoading(true);
    try {
      if (window.desktopSecurity?.getNotifications) {
        const notifs = await window.desktopSecurity.getNotifications(100);
        setNotifications(notifs || []);
      }
      if (window.desktopSecurity?.getNotificationInboxState) {
        const state = await window.desktopSecurity.getNotificationInboxState();
        setInboxState(state);
      }
    } catch (err: any) {
      setErrorMsg(`Failed to load notifications: ${err?.message || 'IPC error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleMarkRead = async (id: string) => {
    try {
      if (window.desktopSecurity?.markNotificationRead) {
        await window.desktopSecurity.markNotificationRead(id);
        setNotifications((prev) =>
          prev.map((n) => (n.id === id ? { ...n, isRead: true } : n))
        );
        if (inboxState) {
          setInboxState({
            ...inboxState,
            unreadCount: Math.max(0, inboxState.unreadCount - 1)
          });
        }
      }
    } catch (err: any) {
      setErrorMsg(`Error updating notification: ${err?.message}`);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      if (window.desktopSecurity?.markAllNotificationsRead) {
        await window.desktopSecurity.markAllNotificationsRead();
        setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
        if (inboxState) {
          setInboxState({ ...inboxState, unreadCount: 0 });
        }
      }
    } catch (err: any) {
      setErrorMsg(`Error updating notifications: ${err?.message}`);
    }
  };

  const handleClearAll = async () => {
    try {
      if (window.desktopSecurity?.clearAllNotifications) {
        await window.desktopSecurity.clearAllNotifications();
        setNotifications([]);
        if (inboxState) {
          setInboxState({ ...inboxState, unreadCount: 0, totalCount: 0 });
        }
      }
    } catch (err: any) {
      setErrorMsg(`Error clearing notifications: ${err?.message}`);
    }
  };

  const filteredNotifs = notifications.filter((n) => {
    if (filter === 'UNREAD') return !n.isRead;
    if (filter === 'CRITICAL') return n.severity === 'critical';
    return true;
  });

  return (
    <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🔔 Notifications & Alert Inbox</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            In-app security alerts and Windows Native Toast rate-limiting (RULE-15).
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            onClick={handleMarkAllRead}
            disabled={notifications.length === 0}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              color: '#334155',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Mark All Read
          </button>
          <button
            type="button"
            onClick={handleClearAll}
            disabled={notifications.length === 0}
            style={{
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              color: '#64748b',
              fontSize: '12px',
              cursor: 'pointer'
            }}
          >
            Clear Inbox
          </button>
        </div>
      </div>

      {errorMsg && (
        <div
          role="alert"
          style={{
            padding: '12px',
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '8px',
            color: '#991b1b',
            fontSize: '13px'
          }}
        >
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Storm Rate Limiter Telemetry Banner */}
      <div
        style={{
          backgroundColor: '#eff6ff',
          border: '1px solid #bfdbfe',
          borderRadius: '8px',
          padding: '14px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '12px'
        }}
      >
        <div>
          <strong style={{ color: '#1e40af' }}>⚡ Storm Rate-Limiter (RULE-15): </strong>
          <span style={{ color: '#1d4ed8' }}>
            Active (Max 3 OS Toasts per 10s • Burst Coalescing Armed to prevent alert fatigue)
          </span>
        </div>
        <span style={{ color: '#60a5fa', fontWeight: 600 }}>
          Unread: {inboxState?.unreadCount ?? 0}
        </span>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '8px' }}>
        <button
          type="button"
          onClick={() => setFilter('ALL')}
          style={{
            padding: '6px 14px',
            borderRadius: '6px',
            border: 'none',
            backgroundColor: filter === 'ALL' ? '#0f172a' : '#e2e8f0',
            color: filter === 'ALL' ? '#ffffff' : '#334155',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          All ({notifications.length})
        </button>
        <button
          type="button"
          onClick={() => setFilter('UNREAD')}
          style={{
            padding: '6px 14px',
            borderRadius: '6px',
            border: 'none',
            backgroundColor: filter === 'UNREAD' ? '#0f172a' : '#e2e8f0',
            color: filter === 'UNREAD' ? '#ffffff' : '#334155',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Unread ({inboxState?.unreadCount ?? 0})
        </button>
        <button
          type="button"
          onClick={() => setFilter('CRITICAL')}
          style={{
            padding: '6px 14px',
            borderRadius: '6px',
            border: 'none',
            backgroundColor: filter === 'CRITICAL' ? '#0f172a' : '#e2e8f0',
            color: filter === 'CRITICAL' ? '#ffffff' : '#334155',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Critical Only
        </button>
      </div>

      {/* Notifications List */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          overflow: 'hidden'
        }}
      >
        {loading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '13px' }}>
            Loading alerts...
          </div>
        ) : filteredNotifs.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
            🔔 Notification Inbox is clear. Zero alerts found.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {filteredNotifs.map((n) => {
              const isCrit = n.severity === 'critical';
              const isWarn = n.severity === 'high' || n.severity === 'medium';
              const sevColor = isCrit ? '#dc2626' : isWarn ? '#d97706' : '#2563eb';

              return (
                <div
                  key={n.id}
                  style={{
                    padding: '14px 18px',
                    borderBottom: '1px solid #f1f5f9',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    backgroundColor: n.isRead ? '#ffffff' : '#f8fafc'
                  }}
                >
                  <div style={{ maxWidth: '640px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          color: sevColor,
                          backgroundColor: `${sevColor}15`,
                          padding: '2px 6px',
                          borderRadius: '4px'
                        }}
                      >
                        {n.severity.toUpperCase()}
                      </span>
                      <strong style={{ fontSize: '14px', color: '#0f172a' }}>{n.title}</strong>
                      {!n.isRead && (
                        <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#2563eb' }} />
                      )}
                    </div>
                    <div style={{ fontSize: '12px', color: '#475569', marginTop: '4px' }}>
                      {n.message}
                    </div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>
                      {new Date(n.timestamp).toLocaleString()} • {n.category}
                    </div>
                  </div>

                  {!n.isRead && (
                    <button
                      type="button"
                      onClick={() => handleMarkRead(n.id)}
                      style={{
                        padding: '4px 10px',
                        borderRadius: '4px',
                        border: '1px solid #cbd5e1',
                        backgroundColor: '#ffffff',
                        color: '#475569',
                        fontSize: '11px',
                        cursor: 'pointer'
                      }}
                    >
                      Dismiss
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
