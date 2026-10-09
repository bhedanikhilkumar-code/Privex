import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TabBar } from '../../components/TabBar';

describe('Phase 6: TabBar Navigation & Accessibility Verification (IMP-001)', () => {
  it('renders primary navigation bar with 5 accessible tabs and ARIA semantics', () => {
    const onSelectSpy = vi.fn();
    render(<TabBar currentTab="HOME" onSelectTab={onSelectSpy} />);

    const nav = screen.getByRole('tablist', { name: /Application Navigation/i });
    expect(nav).toBeDefined();

    const tabs = screen.getAllByRole('tab');
    expect(tabs.length).toBe(5);

    const homeTab = screen.getByRole('tab', { name: 'Home' });
    expect(homeTab.getAttribute('aria-selected')).toBe('true');

    const scansTab = screen.getByRole('tab', { name: 'Scans' });
    expect(scansTab.getAttribute('aria-selected')).toBe('false');

    const assistantTab = screen.getByRole('tab', { name: 'Assistant' });
    expect(assistantTab.getAttribute('aria-selected')).toBe('false');

    const engineTab = screen.getByRole('tab', { name: 'Engine' });
    expect(engineTab.getAttribute('aria-selected')).toBe('false');

    const moreTab = screen.getByRole('tab', { name: 'More' });
    expect(moreTab.getAttribute('aria-selected')).toBe('false');
  });

  it('navigates directly on primary tab click', () => {
    const onSelectSpy = vi.fn();
    render(<TabBar currentTab="HOME" onSelectTab={onSelectSpy} />);

    fireEvent.click(screen.getByRole('tab', { name: 'Assistant' }));
    expect(onSelectSpy).toHaveBeenCalledWith('ASSISTANT');

    fireEvent.click(screen.getByRole('tab', { name: 'Engine' }));
    expect(onSelectSpy).toHaveBeenCalledWith('STATUS');

    fireEvent.click(screen.getByRole('tab', { name: 'Scans' }));
    expect(onSelectSpy).toHaveBeenCalledWith('URL_SCAN');
  });

  it('marks Scans tab active when currentTab is a scanner sub-tab', () => {
    const onSelectSpy = vi.fn();
    const { rerender } = render(<TabBar currentTab="TEXT_SCAN" onSelectTab={onSelectSpy} />);

    expect(screen.getByRole('tab', { name: 'Scans' }).getAttribute('aria-selected')).toBe('true');

    rerender(<TabBar currentTab="FILE_SCAN" onSelectTab={onSelectSpy} />);
    expect(screen.getByRole('tab', { name: 'Scans' }).getAttribute('aria-selected')).toBe('true');

    rerender(<TabBar currentTab="QR_SCAN" onSelectTab={onSelectSpy} />);
    expect(screen.getByRole('tab', { name: 'Scans' }).getAttribute('aria-selected')).toBe('true');
  });

  it('toggles More drawer with dialog role and accessible security tools', () => {
    const onSelectSpy = vi.fn();
    render(<TabBar currentTab="HOME" onSelectTab={onSelectSpy} />);

    // Click More tab
    const moreTab = screen.getByRole('tab', { name: 'More' });
    fireEvent.click(moreTab);

    // Verify dialog overlay is opened
    const dialog = screen.getByRole('dialog', { name: /More Navigation Options/i });
    expect(dialog).toBeDefined();

    // Verify presence of accessible tools in drawer
    expect(screen.getByRole('button', { name: /Protection Settings/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /Privacy Center/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /Password Generator/i })).toBeDefined();

    // Click Privacy Center in drawer
    fireEvent.click(screen.getByRole('button', { name: /Privacy Center/i }));
    expect(onSelectSpy).toHaveBeenCalledWith('PRIVACY');

    // Dialog should be closed after selection
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('closes More drawer when close button is clicked', () => {
    const onSelectSpy = vi.fn();
    render(<TabBar currentTab="HOME" onSelectTab={onSelectSpy} />);

    fireEvent.click(screen.getByRole('tab', { name: 'More' }));
    expect(screen.getByRole('dialog')).toBeDefined();

    const closeBtn = screen.getByRole('button', { name: /Close menu/i });
    fireEvent.click(closeBtn);

    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
