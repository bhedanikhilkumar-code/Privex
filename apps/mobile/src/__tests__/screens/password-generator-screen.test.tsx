import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PasswordGeneratorScreen } from '../../screens/PasswordGeneratorScreen';
import { PasswordGeneratorService } from '../../services/password-generator.service';

describe('Phase T8: PasswordGeneratorScreen UI Component', () => {
  it('renders password generator screen with default 20-character password', () => {
    render(<PasswordGeneratorScreen />);

    expect(screen.getByText('🔐 Secure Password Generator')).toBeDefined();
    expect(screen.getByText('100% On-Device CSPRNG')).toBeDefined();
    expect(screen.getByRole('button', { name: /Password \(Chars\)/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /Passphrase \(Words\)/i })).toBeDefined();

    // Check regenerate and copy buttons
    expect(screen.getByRole('button', { name: /🔄 Regenerate/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /📋 Copy Secret/i })).toBeDefined();
  });

  it('allows switching to Passphrase mode and renders word configuration', async () => {
    render(<PasswordGeneratorScreen />);

    const passphraseTab = screen.getByRole('button', { name: /Passphrase \(Words\)/i });
    fireEvent.click(passphraseTab);

    expect(screen.getByText('Passphrase Configuration')).toBeDefined();
    expect(screen.getByLabelText(/Word Separator:/i)).toBeDefined();
    expect(screen.getByLabelText(/Capitalize Each Word/i)).toBeDefined();
  });

  it('updates options when preset buttons are clicked', () => {
    render(<PasswordGeneratorScreen />);

    const strongBtn = screen.getByRole('button', { name: /Strong \(32\)/i });
    fireEvent.click(strongBtn);

    expect(screen.getByText(/Length: 32 chars/i)).toBeDefined();
  });

  it('triggers copy action and displays transient feedback', async () => {
    const copySpy = vi.spyOn(PasswordGeneratorService.getInstance(), 'copyToClipboard')
      .mockResolvedValue(true);

    render(<PasswordGeneratorScreen />);

    const copyBtn = screen.getByRole('button', { name: /📋 Copy Secret/i });
    fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(screen.getByText(/✓ Copied \(Auto-clear in 60s\)/i)).toBeDefined();
    });

    expect(copySpy).toHaveBeenCalled();
  });

  it('displays back button when onBack prop is supplied', () => {
    const handleBack = vi.fn();
    render(<PasswordGeneratorScreen onBack={handleBack} />);

    const backBtn = screen.getByRole('button', { name: '←' });
    expect(backBtn).toBeDefined();
    fireEvent.click(backBtn);
    expect(handleBack).toHaveBeenCalledTimes(1);
  });
});
