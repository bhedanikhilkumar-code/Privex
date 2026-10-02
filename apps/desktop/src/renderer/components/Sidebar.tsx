import React from 'react';

export type DesktopNavTab =
  | 'home'
  | 'quick-scan'
  | 'full-scan'
  | 'custom-scan'
  | 'results'
  | 'quarantine'
  | 'status'
  | 'assistant'
  | 'privacy'
  | 'settings'
  | 'updates';

interface SidebarProps {
  activeTab: DesktopNavTab;
  onSelectTab: (tab: DesktopNavTab) => void;
  quarantineCount: number;
  threatsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  quarantineCount,
  threatsCount
}) => {
  const navItems: Array<{ id: DesktopNavTab; label: string; badge?: number }> = [
    { id: 'home', label: '🏠 Dashboard' },
    { id: 'quick-scan', label: '⚡ Quick Scan' },
    { id: 'full-scan', label: '🔍 Full PC Scan' },
    { id: 'custom-scan', label: '📁 Custom Scan' },
    { id: 'results', label: '📊 Scan Results', badge: threatsCount },
    { id: 'quarantine', label: '🔒 Quarantine Vault', badge: quarantineCount },
    { id: 'status', label: '🛡️ Protection Status' },
    { id: 'assistant', label: '🤖 AI Assistant' },
    { id: 'privacy', label: '👁️ Privacy & Shred' },
    { id: 'settings', label: '⚙️ Settings' },
    { id: 'updates', label: '🔄 Update Status' }
  ];

  return (
    <aside
      style={{
        width: '240px',
        backgroundColor: '#0f172a',
        color: '#f8fafc',
        display: 'flex',
        flexDirection: 'column',
        padding: '16px 8px',
        flexShrink: 0
      }}
    >
      <div style={{ padding: '0 12px 16px 12px', borderBottom: '1px solid #1e293b', marginBottom: '12px' }}>
        <div style={{ fontSize: '14px', fontWeight: 'bold', color: '#38bdf8' }}>PRIVATE PROTECTION</div>
        <div style={{ fontSize: '11px', color: '#94a3b8' }}>Endpoint Security Client</div>
      </div>

      <nav style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 12px',
                borderRadius: '6px',
                border: 'none',
                backgroundColor: isActive ? '#1e293b' : 'transparent',
                color: isActive ? '#38bdf8' : '#cbd5e1',
                fontSize: '13px',
                fontWeight: isActive ? 600 : 400,
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background-color 0.15s ease'
              }}
            >
              <span>{item.label}</span>
              {typeof item.badge === 'number' && item.badge > 0 && (
                <span
                  style={{
                    backgroundColor: item.id === 'quarantine' ? '#f59e0b' : '#ef4444',
                    color: '#ffffff',
                    borderRadius: '10px',
                    padding: '1px 6px',
                    fontSize: '11px',
                    fontWeight: 'bold'
                  }}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div style={{ padding: '12px', borderTop: '1px solid #1e293b', fontSize: '11px', color: '#64748b' }}>
        100% On-Device Protection
      </div>
    </aside>
  );
};
