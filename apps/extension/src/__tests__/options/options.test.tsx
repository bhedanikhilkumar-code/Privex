import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { OptionsApp } from '../../options/options';
import { ExtensionStorage } from '../../shared/storage';

describe('Options / Settings UI Component', () => {
  beforeEach(async () => {
    await ExtensionStorage.clearAllStorage();
    (globalThis as any).chrome = {
      runtime: {
        sendMessage: vi.fn()
      }
    };
  });

  it('renders settings headings and toggles', async () => {
    render(<OptionsApp />);

    await waitFor(() => {
      expect(screen.getByText(/Private Protection Settings/i)).toBeDefined();
      expect(screen.getByText(/Real-Time Navigation Defense/i)).toBeDefined();
      expect(screen.getByText(/AI Security Assistant Reading Complexity/i)).toBeDefined();
    });
  });

  it('adds and removes trusted allowlist domains', async () => {
    render(<OptionsApp />);

    await waitFor(() => {
      expect(screen.getByText(/Private Protection Settings/i)).toBeDefined();
    });

    const input = screen.getByPlaceholderText(/e\.g\. internal\.corp\.local/i);
    fireEvent.change(input, { target: { value: 'intranet.portal.corp' } });

    const form = input.closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByText('intranet.portal.corp')).toBeDefined();
    });

    const removeBtn = screen.getByRole('button', { name: /Remove intranet\.portal\.corp/i });
    fireEvent.click(removeBtn);

    await waitFor(() => {
      expect(screen.queryByText('intranet.portal.corp')).toBeNull();
    });
  });

  it('allows changing reading grade level', async () => {
    render(<OptionsApp />);

    const grade8Btn = screen.getByRole('button', { name: /Grade 8/i });
    fireEvent.click(grade8Btn);

    await waitFor(() => {
      expect(grade8Btn.style.fontWeight).toBe('700');
    });
  });
});
