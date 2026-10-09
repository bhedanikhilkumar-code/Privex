import React, { useState, useEffect } from 'react';
import { AppTheme } from '../../scanner/types';
import { PreferenceStorage } from '../../lib/storage';

export interface ThemeToggleProps {
  theme?: AppTheme;
  onThemeChange?: (newTheme: AppTheme) => void;
}

interface ThemeOption {
  id: AppTheme;
  label: string;
  icon: string;
  metaColor: string;
}

const THEME_OPTIONS: ThemeOption[] = [
  { id: 'light', label: 'Light', icon: '☀️', metaColor: '#F7F3EB' },
  { id: 'dark', label: 'Dark', icon: '🌙', metaColor: '#0b1120' },
  { id: 'night', label: 'Night', icon: '🌑', metaColor: '#000000' }
];

export const ThemeToggle: React.FC<ThemeToggleProps> = ({
  theme: controlledTheme,
  onThemeChange
}) => {
  const [themeState, setThemeState] = useState<AppTheme>(() => {
    return controlledTheme || PreferenceStorage.loadTheme();
  });

  const applyThemeToDocument = (t: AppTheme) => {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', t);
      const metaThemeColor = document.querySelector('meta[name="theme-color"]');
      const opt = THEME_OPTIONS.find((o) => o.id === t);
      if (metaThemeColor && opt) {
        metaThemeColor.setAttribute('content', opt.metaColor);
      }
    }
  };

  useEffect(() => {
    if (controlledTheme) {
      setThemeState(controlledTheme);
      applyThemeToDocument(controlledTheme);
    }
  }, [controlledTheme]);

  useEffect(() => {
    applyThemeToDocument(themeState);
  }, []);

  const handleSelectTheme = (newTheme: AppTheme) => {
    setThemeState(newTheme);
    PreferenceStorage.saveTheme(newTheme);
    applyThemeToDocument(newTheme);
    if (onThemeChange) {
      onThemeChange(newTheme);
    }
  };

  const activeTheme = themeState;


  return (
    <div
      role="radiogroup"
      aria-label="Color theme selection"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '2px',
        padding: '3px',
        backgroundColor: 'var(--bg-secondary)',
        border: '2px solid var(--border-dark)',
        boxShadow: 'var(--shadow-brutal-sm)',
        userSelect: 'none'
      }}
    >
      {THEME_OPTIONS.map((opt) => {
        const isSelected = activeTheme === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            role="radio"
            aria-checked={isSelected}
            aria-label={`${opt.label} mode`}
            title={`Switch to ${opt.label} mode`}
            onClick={() => handleSelectTheme(opt.id)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              padding: '0.3rem 0.65rem',
              backgroundColor: isSelected ? 'var(--color-brand)' : 'transparent',
              color: isSelected ? '#FFFFFF' : 'var(--text-primary)',
              border: isSelected ? '1px solid var(--border-dark)' : '1px solid transparent',
              boxShadow: isSelected ? '1px 1px 0px var(--border-dark)' : 'none',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.725rem',
              fontWeight: isSelected ? 800 : 600,
              cursor: 'pointer',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              transition: 'all 0.12s ease',
              outline: 'none',
              whiteSpace: 'nowrap'
            }}
          >
            <span aria-hidden="true" style={{ fontSize: '0.85rem', lineHeight: 1 }}>
              {opt.icon}
            </span>
            <span>{opt.label}</span>
          </button>
        );
      })}
    </div>
  );
};
