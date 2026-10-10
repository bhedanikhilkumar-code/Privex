import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { PortScannerScreen } from '../../screens/PortScannerScreen';

describe('PortScannerScreen (Dedicated On-Device Port Auditor UI)', () => {
  const mockNavigateHome = vi.fn();
  const mockNavigateVulnerabilityAudit = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders initial state with heading, badges and air-gapped guarantees', () => {
    render(
      <PortScannerScreen
        onNavigateHome={mockNavigateHome}
        onNavigateVulnerabilityAudit={mockNavigateVulnerabilityAudit}
      />
    );

    expect(screen.getByText('⚡ On-Device Port Scanner')).toBeDefined();
    expect(screen.getAllByText(/AIR-GAPPED/i).length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText(/e\.g\. 192\.168\.1\.1, company\.com, or host:3306/i)).toBeDefined();
    expect(screen.getByRole('button', { name: /⚡ Scan/i })).toBeDefined();
  });

  it('validates empty host input and displays friendly warning', () => {
    render(
      <PortScannerScreen
        onNavigateHome={mockNavigateHome}
      />
    );

    const scanBtn = screen.getByRole('button', { name: /⚡ Scan/i });
    fireEvent.click(scanBtn);

    expect(screen.getByText(/Please enter a host, IP address, or domain name to scan\./i)).toBeDefined();
  });

  it('audits target host ports and displays exposed services, filters, and remediation', async () => {
    render(
      <PortScannerScreen
        onNavigateHome={mockNavigateHome}
      />
    );

    const input = screen.getByPlaceholderText(/e\.g\. 192\.168\.1\.1, company\.com, or host:3306/i);
    fireEvent.change(input, { target: { value: '192.168.1.105:3306' } });

    const scanBtn = screen.getByRole('button', { name: /⚡ Scan/i });
    fireEvent.click(scanBtn);

    await waitFor(() => {
      expect(screen.getByText('192.168.1.105:3306')).toBeDefined();
    }, { timeout: 3000 });

    expect(screen.getByText('14 Core')).toBeDefined();

    // Switch filter to Databases (4)
    const dbFilter = screen.getByRole('button', { name: /Databases \(4\)/i });
    fireEvent.click(dbFilter);

    const mysqlMatches = screen.getAllByText(/MySQL/i);
    expect(mysqlMatches.length).toBeGreaterThan(0);
  });

  it('probes custom arbitrary port numbers accurately', async () => {
    render(
      <PortScannerScreen
        onNavigateHome={mockNavigateHome}
      />
    );

    // Scan a host first so custom port probe card is displayed
    const input = screen.getByPlaceholderText(/e\.g\. 192\.168\.1\.1, company\.com, or host:3306/i);
    fireEvent.change(input, { target: { value: 'privex.io' } });
    fireEvent.click(screen.getByRole('button', { name: /⚡ Scan/i }));

    await waitFor(() => {
      expect(screen.getByText('privex.io')).toBeDefined();
    }, { timeout: 3000 });

    const customInput = screen.getByPlaceholderText(/e\.g\. 8080, 22, 3306/i);
    fireEvent.change(customInput, { target: { value: '6379' } });

    const probeBtn = screen.getByRole('button', { name: /Probe/i });
    fireEvent.click(probeBtn);

    expect(screen.getByText(/Port :6379/i)).toBeDefined();
  });

  it('copies audit report to clipboard on button click', async () => {
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock
      }
    });

    render(
      <PortScannerScreen
        onNavigateHome={mockNavigateHome}
      />
    );

    const input = screen.getByPlaceholderText(/e\.g\. 192\.168\.1\.1, company\.com, or host:3306/i);
    fireEvent.change(input, { target: { value: 'privex.io' } });

    const scanBtn = screen.getByRole('button', { name: /⚡ Scan/i });
    fireEvent.click(scanBtn);

    await waitFor(() => {
      expect(screen.getByText('privex.io')).toBeDefined();
    }, { timeout: 3000 });

    const copyBtn = screen.getByText(/Copy Full/i);
    fireEvent.click(copyBtn);

    expect(writeTextMock).toHaveBeenCalled();
  });

  it('handles navigation back to home screen cleanly', () => {
    render(
      <PortScannerScreen
        onNavigateHome={mockNavigateHome}
      />
    );

    const backBtn = screen.getByRole('button', { name: /Back to Dashboard/i });
    fireEvent.click(backBtn);

    expect(mockNavigateHome).toHaveBeenCalledTimes(1);
  });
});
