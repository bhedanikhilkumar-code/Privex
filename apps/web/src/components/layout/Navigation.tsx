import React, { useRef } from 'react';
import { ActiveTab } from '../../scanner/types';

interface NavigationProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
}

interface NavItem {
  key: ActiveTab;
  label: string;
  icon: string;
}

const NAV_ITEMS: NavItem[] = [
  { key: 'HOME', label: 'Overview', icon: '🏠' },
  { key: 'URL_SCAN', label: 'URL Scanner', icon: '🔗' },
  { key: 'TEXT_SCAN', label: 'Message Scanner', icon: '💬' },
  { key: 'ASSISTANT', label: 'AI Security Assistant', icon: '🤖' },
  { key: 'SECURITY_MONITOR', label: 'Password & Network', icon: '🛡️' },
  { key: 'PRIVACY', label: 'Privacy & Architecture', icon: '🔒' },
  { key: 'SETTINGS', label: 'Settings', icon: '⚙️' }
];

export const Navigation: React.FC<NavigationProps> = ({ activeTab, onTabChange }) => {
  const tabListRef = useRef<HTMLDivElement>(null);

  const handleKeyDown = (event: React.KeyboardEvent, index: number) => {
    if (event.key === 'ArrowRight') {
      event.preventDefault();
      const nextIndex = (index + 1) % NAV_ITEMS.length;
      onTabChange(NAV_ITEMS[nextIndex].key);
      const nextTab = tabListRef.current?.children[nextIndex] as HTMLElement;
      nextTab?.focus();
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault();
      const prevIndex = (index - 1 + NAV_ITEMS.length) % NAV_ITEMS.length;
      onTabChange(NAV_ITEMS[prevIndex].key);
      const prevTab = tabListRef.current?.children[prevIndex] as HTMLElement;
      prevTab?.focus();
    }
  };

  return (
    <nav
      aria-label="Dashboard navigation tabs"
      style={{
        backgroundColor: 'var(--surface-container-low, var(--bg-secondary))',
        borderBottom: '2px solid var(--border-dark)',
        padding: '0.45rem 2rem',
        overflowX: 'auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem'
      }}
    >
      <div
        ref={tabListRef}
        role="tablist"
        style={{
          display: 'flex',
          gap: '0.5rem',
          minWidth: 'max-content'
        }}
      >
        {NAV_ITEMS.map((item, index) => {
          const isActive = activeTab === item.key;
          return (
            <button
              key={item.key}
              role="tab"
              id={`tab-${item.key.toLowerCase()}`}
              aria-selected={isActive}
              aria-controls={`panel-${item.key.toLowerCase()}`}
              tabIndex={isActive ? 0 : -1}
              onClick={() => onTabChange(item.key)}
              onKeyDown={(e) => handleKeyDown(e, index)}
              className="motion-pressable"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.55rem 1rem',
                backgroundColor: isActive ? 'var(--color-brand)' : 'var(--bg-card)',
                color: isActive ? '#FFFFFF' : 'var(--text-primary)',
                border: '2px solid var(--border-dark)',
                borderBottom: isActive ? '3px solid var(--color-accent)' : '2px solid var(--border-dark)',
                boxShadow: isActive ? '3px 3px 0px var(--border-dark)' : '1px 1px 0px var(--border-dark)',
                fontSize: '0.8rem',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
                cursor: 'pointer',
                transition: 'all 0.14s cubic-bezier(0.16, 1, 0.3, 1)',
                outlineOffset: '2px',
                transform: isActive ? 'translateY(-1px)' : 'none'
              }}
            >
              <span aria-hidden="true">{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 'max-content' }}>
        <a
          href="./stitch_privex_security_web_ui/privex_overview_dashboard_terra/code.html"
          title="Switch to Terra Organic Theme Prototype"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: 'var(--color-safe)',
            padding: '0.35rem 0.65rem',
            border: '1px solid var(--border-dark)',
            backgroundColor: 'var(--bg-card)',
            textDecoration: 'none'
          }}
        >
          [TERRA_THEME]
        </a>
      </div>
    </nav>
  );
};
