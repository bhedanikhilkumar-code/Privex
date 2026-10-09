import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeToggle } from '../../components/layout/ThemeToggle';
import { Header } from '../../components/layout/Header';
import { SettingsView } from '../../components/settings/SettingsView';
import { PreferenceStorage } from '../../lib/storage';
import { UserPreferences } from '../../scanner/types';

describe('Theme Toggle & Multi-Mode Theme System', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('renders all three theme buttons (Light, Dark, Night) in ThemeToggle', () => {
    render(<ThemeToggle />);
    expect(screen.getByRole('radio', { name: /light mode/i })).toBeDefined();
    expect(screen.getByRole('radio', { name: /dark mode/i })).toBeDefined();
    expect(screen.getByRole('radio', { name: /night mode/i })).toBeDefined();
  });

  it('defaults to light theme if no preference is stored', () => {
    render(<ThemeToggle />);
    const lightBtn = screen.getByRole('radio', { name: /light mode/i });
    expect(lightBtn.getAttribute('aria-checked')).toBe('true');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('toggles to Dark mode when Dark button is clicked', () => {
    const onThemeChange = vi.fn();
    render(<ThemeToggle onThemeChange={onThemeChange} />);

    const darkBtn = screen.getByRole('radio', { name: /dark mode/i });
    fireEvent.click(darkBtn);

    expect(darkBtn.getAttribute('aria-checked')).toBe('true');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(onThemeChange).toHaveBeenCalledWith('dark');
    expect(localStorage.getItem('privex_theme')).toBe('dark');
  });

  it('toggles to Night mode when Night button is clicked', () => {
    const onThemeChange = vi.fn();
    render(<ThemeToggle onThemeChange={onThemeChange} />);

    const nightBtn = screen.getByRole('radio', { name: /night mode/i });
    fireEvent.click(nightBtn);

    expect(nightBtn.getAttribute('aria-checked')).toBe('true');
    expect(document.documentElement.getAttribute('data-theme')).toBe('night');
    expect(onThemeChange).toHaveBeenCalledWith('night');
    expect(localStorage.getItem('privex_theme')).toBe('night');
  });

  it('toggles back to Light mode when Light button is clicked', () => {
    const onThemeChange = vi.fn();
    render(<ThemeToggle theme="dark" onThemeChange={onThemeChange} />);

    const lightBtn = screen.getByRole('radio', { name: /light mode/i });
    fireEvent.click(lightBtn);

    expect(lightBtn.getAttribute('aria-checked')).toBe('true');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(onThemeChange).toHaveBeenCalledWith('light');
    expect(localStorage.getItem('privex_theme')).toBe('light');
  });

  it('Header component renders ThemeToggle and DOES NOT render the removed engine status box', () => {
    render(<Header />);

    // Verify ThemeToggle is rendered in Header
    expect(screen.getByRole('radiogroup', { name: /color theme selection/i })).toBeDefined();
    expect(screen.getByRole('radio', { name: /light mode/i })).toBeDefined();
    expect(screen.getByRole('radio', { name: /dark mode/i })).toBeDefined();
    expect(screen.getByRole('radio', { name: /night mode/i })).toBeDefined();

    // Verify the removed box is completely absent
    expect(screen.queryByText(/ENGINE: v0.1.1/i)).toBeNull();
    expect(screen.queryByText(/RAM: 42MB/i)).toBeNull();
    expect(screen.queryByText(/LATENCY: <1ms/i)).toBeNull();
  });

  it('SettingsView provides theme toggle options and updates preferences', () => {
    const mockPrefs: UserPreferences = {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: true,
      allowlistDomains: [],
      theme: 'light'
    };
    const onPreferencesChange = vi.fn();

    render(<SettingsView preferences={mockPrefs} onPreferencesChange={onPreferencesChange} />);

    expect(screen.getByText(/APPEARANCE & THEME/i)).toBeDefined();
    expect(screen.getByText(/Interface Color Mode/i)).toBeDefined();

    const darkButton = screen.getByRole('radio', { name: /dark mode/i });
    fireEvent.click(darkButton);

    expect(onPreferencesChange).toHaveBeenCalledWith(
      expect.objectContaining({ theme: 'dark' })
    );
  });

  it('PreferenceStorage loads and saves theme properly', () => {
    PreferenceStorage.saveTheme('night');
    expect(PreferenceStorage.loadTheme()).toBe('night');

    const prefs = PreferenceStorage.loadPreferences();
    expect(prefs.theme).toBe('night');

    PreferenceStorage.clearAllData();
    expect(PreferenceStorage.loadTheme()).toBe('light');
  });
});
