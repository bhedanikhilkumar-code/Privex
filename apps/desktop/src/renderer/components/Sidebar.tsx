import React from 'react';

export type DesktopNavTab =
  | 'home'
  | 'quick-scan'
  | 'full-scan'
  | 'custom-scan'
  | 'scheduled-scan'
  | 'realtime'
  | 'results'
  | 'assistant'
  | 'quarantine'
  | 'history'
  | 'ransomware'
  | 'web-protection'
  | 'notifications'
  | 'status'
  | 'updates'
  | 'settings'
  | 'exclusions'
  | 'trusted-apps'
  | 'recovery'
  | 'about';

interface NavGroup {
  readonly title: string;
  readonly items: Array<{
    readonly id: DesktopNavTab;
    readonly label: string;
    readonly badge?: number;
    readonly badgeColor?: string;
  }>;
}

interface SidebarProps {
  activeTab: DesktopNavTab;
  onSelectTab: (tab: DesktopNavTab) => void;
  quarantineCount: number;
  threatsCount: number;
  unreadNotificationsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  quarantineCount,
  threatsCount,
  unreadNotificationsCount = 0
}) => {
  const navGroups: NavGroup[] = [
    {
      title: 'OVERVIEW',
      items: [
        { id: 'home', label: '🏠 Dashboard' },
        { id: 'about', label: 'ℹ️ About & Security' }
      ]
    },
    {
      title: 'SCANNING',
      items: [
        { id: 'quick-scan', label: '⚡ Quick Scan' },
        { id: 'full-scan', label: '🔍 Full PC Scan' },
        { id: 'custom-scan', label: '📁 Custom Scan' },
        { id: 'scheduled-scan', label: '📅 Scheduled Scan' }
      ]
    },
    {
      title: 'ACTIVE SHIELDS',
      items: [
        { id: 'realtime', label: '🛡️ Real-Time Shield' },
        { id: 'ransomware', label: '🔒 Ransomware Shield' },
        { id: 'web-protection', label: '🌐 Web Protection' }
      ]
    },
    {
      title: 'FORENSICS & RECOVERY',
      items: [
        { id: 'results', label: '📊 Threat Details', badge: threatsCount, badgeColor: '#ef4444' },
        { id: 'assistant', label: '🤖 AI Assistant' },
        { id: 'quarantine', label: '☣️ Quarantine Vault', badge: quarantineCount, badgeColor: '#f59e0b' },
        { id: 'history', label: '📜 Forensic Audit Log' },
        { id: 'recovery', label: '🔄 Recovery & Shred' }
      ]
    },
    {
      title: 'SYSTEM & SETTINGS',
      items: [
        { id: 'status', label: '🩺 Health & Watchdog' },
        { id: 'updates', label: '🔄 Definitions & Updates' },
        { id: 'exclusions', label: '🚫 Exclusions Manager' },
        { id: 'trusted-apps', label: '🤝 Trusted Apps' },
        { id: 'notifications', label: '🔔 Notifications', badge: unreadNotificationsCount, badgeColor: '#3b82f6' },
        { id: 'settings', label: '⚙️ Settings' }
      ]
    }
  ];

  return (
    <aside
      aria-label="Antivirus Navigation"
      style={{
        width: '240px',
        backgroundColor: '#0f172a',
        color: '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
        padding: '16px 8px',
        flexShrink: 0,
        overflowY: 'auto',
        height: '100vh',
        boxSizing: 'border-box'
      }}
    >
      <div style={{ padding: '0 12px 14px 12px', borderBottom: '1px solid #1e293b', marginBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <img
            src="./icon.png"
            alt="PRIVEX logo"
            style={{ width: '24px', height: '24px', objectFit: 'contain' }}
          />
          <div style={{ fontSize: '15px', fontWeight: 'bold', color: '#38bdf8', letterSpacing: '0.05em' }}>
            PRIVEX
          </div>
        </div>
        <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px' }}>
          Endpoint Security • 100% Offline
        </div>
      </div>

      <nav
        style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1 }}
        role="navigation"
        aria-label="Main menu"
      >
        {navGroups.map((group) => (
          <div key={group.title}>
            <div
              style={{
                fontSize: '10px',
                fontWeight: 700,
                color: '#64748b',
                padding: '0 12px 4px 12px',
                letterSpacing: '0.08em'
              }}
            >
              {group.title}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
              {group.items.map((item) => {
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onSelectTab(item.id)}
                    aria-current={isActive ? 'page' : undefined}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      border: 'none',
                      backgroundColor: isActive ? '#1e293b' : 'transparent',
                      color: isActive ? '#38bdf8' : '#cbd5e1',
                      fontSize: '12px',
                      fontWeight: isActive ? 600 : 400,
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'background-color 0.12s ease',
                      outline: 'none'
                    }}
                  >
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.label}
                    </span>
                    {typeof item.badge === 'number' && item.badge > 0 && (
                      <span
                        aria-label={`${item.badge} items`}
                        style={{
                          backgroundColor: item.badgeColor || '#ef4444',
                          color: '#ffffff',
                          borderRadius: '10px',
                          padding: '1px 6px',
                          fontSize: '10px',
                          fontWeight: 'bold',
                          marginLeft: '6px'
                        }}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div style={{ padding: '12px', borderTop: '1px solid #1e293b', fontSize: '11px', color: '#64748b' }}>
        <span>Engine: v1.0.0-verified</span>
      </div>
    </aside>
  );
};
