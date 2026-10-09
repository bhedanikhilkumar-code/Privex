import React, { useState } from 'react';

export type MobileTab =
  | 'HOME'
  | 'URL_SCAN'
  | 'TEXT_SCAN'
  | 'FILE_SCAN'
  | 'QR_SCAN'
  | 'PASSWORD'
  | 'ASSISTANT'
  | 'STATUS'
  | 'PRIVACY'
  | 'SETTINGS';

interface TabBarProps {
  currentTab: MobileTab;
  onSelectTab: (tab: MobileTab) => void;
}

export const TabBar: React.FC<TabBarProps> = ({ currentTab, onSelectTab }) => {
  const [isMoreOpen, setIsMoreOpen] = useState(false);

  const isScannerTab = ['URL_SCAN', 'TEXT_SCAN', 'FILE_SCAN', 'QR_SCAN'].includes(currentTab);
  const isMoreActive = ['SETTINGS', 'PRIVACY', 'PASSWORD'].includes(currentTab);

  const primaryTabs: {
    id: MobileTab | 'MORE';
    label: string;
    icon: string;
    isActive: boolean;
    onClick: () => void;
  }[] = [
    {
      id: 'HOME',
      label: 'Home',
      icon: '🛡️',
      isActive: currentTab === 'HOME',
      onClick: () => {
        setIsMoreOpen(false);
        onSelectTab('HOME');
      }
    },
    {
      id: 'URL_SCAN',
      label: 'Scans',
      icon: '🔍',
      isActive: isScannerTab,
      onClick: () => {
        setIsMoreOpen(false);
        if (!isScannerTab) {
          onSelectTab('URL_SCAN');
        } else {
          // If already in a scanner, toggle the more menu to easily switch scanners
          setIsMoreOpen(true);
        }
      }
    },
    {
      id: 'ASSISTANT',
      label: 'Assistant',
      icon: '🤖',
      isActive: currentTab === 'ASSISTANT',
      onClick: () => {
        setIsMoreOpen(false);
        onSelectTab('ASSISTANT');
      }
    },
    {
      id: 'STATUS',
      label: 'Engine',
      icon: '⚙️',
      isActive: currentTab === 'STATUS',
      onClick: () => {
        setIsMoreOpen(false);
        onSelectTab('STATUS');
      }
    },
    {
      id: 'MORE',
      label: 'More',
      icon: '☰',
      isActive: isMoreActive || isMoreOpen,
      onClick: () => {
        setIsMoreOpen((prev) => !prev);
      }
    }
  ];

  const drawerItems: { id: MobileTab; label: string; icon: string; description: string }[] = [
    { id: 'SETTINGS', label: 'Protection Settings', icon: '⚡', description: 'Configure active shields & thresholds' },
    { id: 'PRIVACY', label: 'Privacy Center', icon: '🔒', description: 'Zero-knowledge guarantees & crypto-shredder' },
    { id: 'PASSWORD', label: 'Password Generator', icon: '🔐', description: 'CSPRNG cryptographic entropy passwords' },
    { id: 'QR_SCAN', label: 'QR Code Scanner', icon: '📷', description: 'Volatile RAM frame inspection' },
    { id: 'FILE_SCAN', label: 'File Inspection', icon: '📁', description: 'PE/ELF/APK magic bytes & double extensions' },
    { id: 'TEXT_SCAN', label: 'Message Scanner', icon: '💬', description: 'Heuristic scam & extortion detection' },
    { id: 'URL_SCAN', label: 'URL Scanner', icon: '🔗', description: 'Punycode, entropy & offline Bloom check' }
  ];

  return (
    <>
      {/* More Tools Modal / Drawer Overlay */}
      {isMoreOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="More Navigation Options"
          style={{
            position: 'fixed',
            bottom: '60px',
            left: 0,
            right: 0,
            backgroundColor: '#0f172a',
            borderTop: '2px solid #38bdf8',
            boxShadow: '0 -10px 25px -5px rgba(0, 0, 0, 0.7)',
            zIndex: 150,
            padding: '1rem',
            maxHeight: '75vh',
            overflowY: 'auto'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
              Security Tools & Preferences
            </h3>
            <button
              type="button"
              onClick={() => setIsMoreOpen(false)}
              aria-label="Close menu"
              style={{
                background: '#1e293b',
                border: '1px solid #334155',
                color: '#94a3b8',
                borderRadius: '8px',
                padding: '0.4rem 0.75rem',
                cursor: 'pointer',
                fontSize: '0.85rem'
              }}
            >
              ✕ Close
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {drawerItems.map((item) => {
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setIsMoreOpen(false);
                    onSelectTab(item.id);
                  }}
                  aria-label={`${item.label}: ${item.description}`}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    padding: '0.75rem 1rem',
                    minHeight: '48px',
                    borderRadius: '10px',
                    backgroundColor: isActive ? '#1e293b' : '#090d16',
                    border: isActive ? '1px solid #38bdf8' : '1px solid #1e293b',
                    color: isActive ? '#38bdf8' : '#f8fafc',
                    cursor: 'pointer',
                    textAlign: 'left'
                  }}
                >
                  <span style={{ fontSize: '1.3rem' }}>{item.icon}</span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{item.label}</div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{item.description}</div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Primary Accessible Bottom Navigation Bar */}
      <nav
        role="tablist"
        aria-label="Application Navigation"
        style={{
          display: 'flex',
          justifyContent: 'space-around',
          alignItems: 'center',
          backgroundColor: '#0f172a',
          borderTop: '1px solid #1e293b',
          position: 'sticky',
          bottom: 0,
          zIndex: 100,
          width: '100%',
          boxSizing: 'border-box'
        }}
      >
        {primaryTabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={tab.isActive}
            aria-label={tab.label}
            onClick={tab.onClick}
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              backgroundColor: 'transparent',
              border: 'none',
              cursor: 'pointer',
              minHeight: '52px',
              minWidth: '56px',
              padding: '0.4rem 0.2rem',
              color: tab.isActive ? '#38bdf8' : '#64748b',
              transition: 'color 0.15s ease'
            }}
          >
            <span style={{ fontSize: '1.2rem', lineHeight: 1 }}>{tab.icon}</span>
            <span
              style={{
                fontSize: '0.7rem',
                marginTop: '0.25rem',
                fontWeight: tab.isActive ? 700 : 500,
                letterSpacing: '0.01em'
              }}
            >
              {tab.label}
            </span>
          </button>
        ))}
      </nav>
    </>
  );
};
