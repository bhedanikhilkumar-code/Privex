import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { App } from '../../renderer/App';
import { SecurityBadge } from '../../renderer/components/SecurityBadge';
import { SettingsScreen } from '../../renderer/screens/SettingsScreen';
import { PrivacyScreen } from '../../renderer/screens/PrivacyScreen';

describe('Desktop UI & Dashboard Presentation Layer', () => {
  it('renders App shell with header, sidebar, and initial HomeScreen', () => {
    render(<App />);
    expect(screen.getAllByText('PRIVATE PROTECTION').length).toBeGreaterThan(0);
    expect(screen.getByText('System Protection Overview')).toBeDefined();
    expect(screen.getByText('⚡ Quick Scan')).toBeDefined();
    expect(screen.getByText('🔍 Full PC Scan')).toBeDefined();
    expect(screen.getByText('🔒 Quarantine Vault')).toBeDefined();
  });

  it('navigates to different desktop screens via sidebar tabs', () => {
    render(<App />);

    // Click on Quick Scan tab
    fireEvent.click(screen.getByText('⚡ Quick Scan'));
    expect(screen.getByText('⚡ Quick Ingress Scan')).toBeDefined();

    // Click on Full PC Scan tab
    fireEvent.click(screen.getByText('🔍 Full PC Scan'));
    expect(screen.getByText('🔍 Full PC Filesystem Scan')).toBeDefined();

    // Click on Privacy tab
    fireEvent.click(screen.getByText('👁️ Privacy & Shred'));
    expect(screen.getByText('👁️ Privacy Guarantees & Cryptographic Erasure')).toBeDefined();

    // Click on Settings tab
    fireEvent.click(screen.getByText('⚙️ Settings'));
    expect(screen.getByText('⚙️ Protection Settings')).toBeDefined();
  });

  it('renders SecurityBadge with correct severity labels and colors', () => {
    const { rerender } = render(<SecurityBadge severity="safe" />);
    expect(screen.getByText('SECURE')).toBeDefined();

    rerender(<SecurityBadge severity="critical" />);
    expect(screen.getByText('CRITICAL THREAT')).toBeDefined();

    rerender(<SecurityBadge severity="suspicious" />);
    expect(screen.getByText('SUSPICIOUS')).toBeDefined();
  });

  it('allows configuring protection settings in SettingsScreen', async () => {
    const initialSettings = {
      realtimeShieldEnabled: true,
      monitorDownloads: true,
      monitorTemp: true,
      scanLargeFilesLimitMb: 50,
      entropyDetectionEnabled: true,
      autoQuarantineCritical: false,
      frictionGateEnabled: true,
      cognitiveLevel: 'grade6' as const,
      excludedPaths: []
    };

    let saved = false;
    render(
      <SettingsScreen
        initialSettings={initialSettings}
        onSaveSettings={async () => {
          saved = true;
        }}
      />
    );

    expect(screen.getByText('Real-Time Ingress Protection')).toBeDefined();
    fireEvent.click(screen.getByText('Save Settings'));
    expect(saved).toBe(true);
  });

  it('renders PrivacyScreen and opens friction gate modal when crypto-shred is clicked', () => {
    render(<PrivacyScreen onCryptoShred={async () => {}} />);
    expect(screen.getByText('0 Bytes')).toBeDefined();
    expect(screen.getByText('100% Offline')).toBeDefined();

    fireEvent.click(screen.getByText('Purge All Data (Crypto-Shred)'));
    expect(screen.getByText('Execute Complete Cryptographic Erasure?')).toBeDefined();
  });
});
