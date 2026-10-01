import React from 'react';

export type MobileTab = 'HOME' | 'URL_SCAN' | 'TEXT_SCAN' | 'FILE_SCAN' | 'ASSISTANT' | 'STATUS' | 'PRIVACY' | 'SETTINGS';

interface TabBarProps {
  currentTab: MobileTab;
  onSelectTab: (tab: MobileTab) => void;
}

export const TabBar: React.FC<TabBarProps> = ({ currentTab, onSelectTab }) => {
  const tabs: { id: MobileTab; label: string; icon: string }[] = [
    { id: 'HOME', label: 'Home', icon: '🛡️' },
    { id: 'URL_SCAN', label: 'URL', icon: '🔗' },
    { id: 'TEXT_SCAN', label: 'Message', icon: '💬' },
    { id: 'FILE_SCAN', label: 'File', icon: '📁' },
    { id: 'ASSISTANT', label: 'Assistant', icon: '🤖' },
    { id: 'STATUS', label: 'Engine', icon: '⚙️' },
    { id: 'PRIVACY', label: 'Privacy', icon: '🔒' },
    { id: 'SETTINGS', label: 'Settings', icon: '⚡' }
  ];

  return (
    <nav
      aria-label="Mobile Navigation"
      style={{
        display: 'flex',
        justifyContent: 'space-around',
        backgroundColor: '#0f172a',
        borderTop: '1px solid #1e293b',
        padding: '0.5rem 0.25rem',
        position: 'sticky',
        bottom: 0,
        zIndex: 100,
        overflowX: 'auto'
      }}
    >
      {tabs.map((tab) => {
        const isActive = currentTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onSelectTab(tab.id)}
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              backgroundColor: 'transparent',
              border: 'none',
              cursor: 'pointer',
              padding: '0.35rem 0.5rem',
              color: isActive ? '#38bdf8' : '#64748b',
              minWidth: '50px'
            }}
          >
            <span style={{ fontSize: '1.1rem' }}>{tab.icon}</span>
            <span style={{ fontSize: '0.65rem', marginTop: '0.2rem', fontWeight: isActive ? 700 : 500 }}>
              {tab.label}
            </span>
          </button>
        );
      })}
    </nav>
  );
};
