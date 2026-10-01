import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SettingsView } from '../../components/settings/SettingsView';
import { UserPreferences } from '../../scanner/types';

describe('SettingsView Detailed Interactions', () => {
  it('handles adding and removing custom allowlist domains', () => {
    const onPrefsChange = vi.fn();
    const prefsWithDomains: UserPreferences = {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: true,
      allowlistDomains: ['trusted-corp.internal']
    };

    render(
      <SettingsView preferences={prefsWithDomains} onPreferencesChange={onPrefsChange} />
    );

    expect(screen.getByText('trusted-corp.internal')).toBeDefined();

    // Remove domain
    const removeBtn = screen.getByRole('button', { name: /Remove/i });
    fireEvent.click(removeBtn);
    expect(onPrefsChange).toHaveBeenCalledWith({
      ...prefsWithDomains,
      allowlistDomains: []
    });

    // Add new domain
    const input = screen.getByPlaceholderText(/e\.g\. internal\.corp\.local/i);
    fireEvent.change(input, { target: { value: 'intranet.portal.local' } });

    const addBtn = screen.getByRole('button', { name: /Add Domain/i });
    fireEvent.click(addBtn);

    expect(onPrefsChange).toHaveBeenCalledWith({
      ...prefsWithDomains,
      allowlistDomains: ['trusted-corp.internal', 'intranet.portal.local']
    });
  });

  it('handles changing cognitive reading grade level', () => {
    const onPrefsChange = vi.fn();
    const prefs: UserPreferences = {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: true,
      allowlistDomains: []
    };

    render(<SettingsView preferences={prefs} onPreferencesChange={onPrefsChange} />);

    const grade8Btn = screen.getByRole('button', { name: /Grade 8/i });
    fireEvent.click(grade8Btn);

    expect(onPrefsChange).toHaveBeenCalledWith({
      ...prefs,
      cognitiveReadingGrade: 8
    });
  });

  it('handles toggling Web Worker background offloading', () => {
    const onPrefsChange = vi.fn();
    const prefs: UserPreferences = {
      cognitiveReadingGrade: 6,
      enableWorkerOffloading: true,
      allowlistDomains: []
    };

    render(<SettingsView preferences={prefs} onPreferencesChange={onPrefsChange} />);

    const toggleBtn = screen.getByRole('button', { name: /Enabled/i });
    fireEvent.click(toggleBtn);

    expect(onPrefsChange).toHaveBeenCalledWith({
      ...prefs,
      enableWorkerOffloading: false
    });
  });
});
