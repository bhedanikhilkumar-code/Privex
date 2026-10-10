import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { HomeScreen } from '../../screens/HomeScreen';
import { UrlScannerScreen } from '../../screens/UrlScannerScreen';
import { TextScannerScreen } from '../../screens/TextScannerScreen';
import { FileScannerScreen } from '../../screens/FileScannerScreen';
import { QrScannerScreen } from '../../screens/QrScannerScreen';
import { CameraScannerService } from '../../services/camera-scanner.service';
import { PrivacyScreen } from '../../screens/PrivacyScreen';
import { SettingsScreen } from '../../screens/SettingsScreen';
import { FrictionGateModal } from '../../components/FrictionGateModal';
import { MobileSecurityAdapter } from '../../adapters/mobile-security-adapter';
import { UrlScannerService } from '../../services/url-scanner.service';
import { TextScannerService } from '../../services/text-scanner.service';
import { FileScannerService } from '../../services/file-scanner.service';

describe('Mobile Screen Components & Presentation Layer', () => {
  const adapter = new MobileSecurityAdapter();
  const urlService = new UrlScannerService(adapter);
  const textService = new TextScannerService(adapter);
  const fileService = new FileScannerService();

  it('renders HomeScreen with title, quick actions, and posture card', async () => {
    const navSpy = vi.fn();
    const selectSpy = vi.fn();
    render(<HomeScreen onNavigate={navSpy} onSelectResult={selectSpy} />);

    expect(screen.getAllByText(/PRIVEX/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Scan URL/i)).toBeDefined();
    expect(screen.getByText(/Scan Message/i)).toBeDefined();
    expect(screen.getByText(/Inspect File/i)).toBeDefined();
    expect(screen.getByText(/Privacy Center/i)).toBeDefined();
    expect(screen.getByText(/Protection Settings/i)).toBeDefined();

    // Verify quick action navigation
    fireEvent.click(screen.getByText(/Privacy Center/i));
    expect(navSpy).toHaveBeenCalledWith('PRIVACY');

    fireEvent.click(screen.getByText(/Protection Settings/i));
    expect(navSpy).toHaveBeenCalledWith('SETTINGS');
  });

  it('renders UrlScannerScreen and executes scan on sample click', async () => {
    render(<UrlScannerScreen scannerService={urlService} onNavigateHome={() => {}} />);

    expect(screen.getByText(/On-Device URL Scanner/i)).toBeDefined();
    const safeSampleBtn = screen.getByText(/Safe Baseline: https:\/\/google.com/i);
    fireEvent.click(safeSampleBtn);

    await waitFor(() => {
      expect(screen.getByText(/Analysis Verdict/i)).toBeDefined();
      expect(screen.getByText(/SAFE \/ ALLOWED/i)).toBeDefined();
      expect(screen.getByText(/ON-DEVICE PORT SCANNER/i)).toBeDefined();
      expect(screen.getByText(/Perimeter Port Audit: google.com/i)).toBeDefined();
      expect(screen.getByText(/Re-Probe Target Ports/i)).toBeDefined();
    }, { timeout: 4000 });
  });

  it('renders TextScannerScreen and executes scan on scam sample click', async () => {
    render(<TextScannerScreen scannerService={textService} onNavigateHome={() => {}} />);

    expect(screen.getByText(/On-Device Message & SMS Scanner/i)).toBeDefined();
    const scamSampleBtn = screen.getByText(/Crypto Extortion/i);
    fireEvent.click(scamSampleBtn);

    await waitFor(() => {
      expect(screen.getByText(/Analysis Verdict/i)).toBeDefined();
    }, { timeout: 4000 });
  });

  it('renders FileScannerScreen and handles file inspection', async () => {
    render(<FileScannerScreen scannerService={fileService} onNavigateHome={() => {}} />);

    expect(screen.getByText(/On-Device File Inspection/i)).toBeDefined();
    const fileSampleBtn = screen.getByText(/Test Deceptive Executable/i);
    fireEvent.click(fileSampleBtn);

    await waitFor(() => {
      expect(screen.getByText('invoice_document.pdf.exe')).toBeDefined();
      expect(screen.getByText(/DANGEROUS \/ MALICIOUS/i)).toBeDefined();
    });
  });

  it('inspects user-selected file via SAF file input and records scan history', async () => {
    const { SecureStorageService } = await import('../../services/secure-storage.service');
    const recordSpy = vi.spyOn(SecureStorageService, 'recordScan');

    render(<FileScannerScreen scannerService={fileService} onNavigateHome={() => {}} />);

    const fileInput = screen.getByTestId('saf-file-input') as HTMLInputElement;

    // Create a mock executable file with MZ header
    const mockFile = new File([new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03])], 'downloaded_malware.exe', {
      type: 'application/x-msdownload'
    });

    fireEvent.change(fileInput, { target: { files: [mockFile] } });

    await waitFor(() => {
      expect(screen.getByText('downloaded_malware.exe')).toBeDefined();
      expect(screen.getByText(/DANGEROUS \/ MALICIOUS/i)).toBeDefined();
    });

    expect(recordSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        targetType: 'FILE',
        sanitizedSummary: 'downloaded_malware.exe'
      })
    );
  });

  it('auto-displays inspection when navigated with initialFileName', async () => {
    render(
      <FileScannerScreen
        scannerService={fileService}
        initialFileName="report.pdf"
        onNavigateHome={() => {}}
      />
    );

    await waitFor(() => {
      expect(screen.getByText('report.pdf')).toBeDefined();
      expect(screen.getByText(/SAFE \/ ALLOWED/i)).toBeDefined();
    });
  });

  it('enforces countdown gate inside FrictionGateModal', async () => {
    const bypassSpy = vi.fn();
    const cancelSpy = vi.fn();

    render(
      <FrictionGateModal
        isOpen={true}
        threatCategory="MALWARE_PHISH"
        durationSec={2}
        onConfirmBypass={bypassSpy}
        onCancel={cancelSpy}
      />
    );

    const bypassBtn = screen.getByRole('button', { name: /Proceed Anyway/i });
    expect(bypassBtn.hasAttribute('disabled')).toBe(true);

    const backBtn = screen.getByRole('button', { name: /Back to Safety/i });
    fireEvent.click(backBtn);
    expect(cancelSpy).toHaveBeenCalled();
  });

  it('renders PrivacyScreen and triggers crypto-shredder action', async () => {
    render(<PrivacyScreen />);

    expect(screen.getByText(/Privacy Architecture & Guarantees/i)).toBeDefined();
    const shredBtn = screen.getByRole('button', { name: /Crypto-Shred All Local Data/i });
    fireEvent.click(shredBtn);

    await waitFor(() => {
      expect(screen.getByText(/All local data and memory purged successfully/i)).toBeDefined();
    });
  });

  it('renders SettingsScreen and handles allowlist interaction', async () => {
    render(<SettingsScreen />);

    expect(screen.getByText(/Mobile Protection Settings/i)).toBeDefined();
    expect(screen.getByText(/Trusted Domains Allowlist/i)).toBeDefined();
  });

  it('renders QrScannerScreen and executes scan on synthetic sample click', async () => {
    const cameraService = new CameraScannerService(adapter);
    render(<QrScannerScreen cameraService={cameraService} onNavigateHome={() => {}} />);

    expect(screen.getByText(/On-Device QR Code Scanner/i)).toBeDefined();
    const safeSampleBtn = screen.getByText(/Safe QR Link: https:\/\/google.com/i);
    fireEvent.click(safeSampleBtn);

    await waitFor(() => {
      expect(screen.getByText(/Analysis Verdict/i)).toBeDefined();
      expect(screen.getByText(/SAFE \/ ALLOWED/i)).toBeDefined();
    }, { timeout: 4000 });
  });

  it('handles recent scan history item click in HomeScreen (IMP-002)', async () => {
    const navSpy = vi.fn();
    const selectSpy = vi.fn();

    // Mock SecureStorageService to return a record
    const { SecureStorageService } = await import('../../services/secure-storage.service');
    const getHistorySpy = vi.spyOn(SecureStorageService, 'getScanHistory').mockResolvedValueOnce([
      {
        scanId: 'scan-123',
        targetType: 'URL',
        sanitizedSummary: 'https://suspicious-bank-login.com',
        verdict: 'DANGEROUS',
        score: 95,
        timestamp: Date.now()
      }
    ]);

    render(<HomeScreen onNavigate={navSpy} onSelectResult={selectSpy} />);

    await waitFor(() => {
      expect(screen.getByText(/https:\/\/suspicious-bank-login.com/i)).toBeDefined();
    });

    const historyBtn = screen.getByRole('button', { name: /View URL scan result/i });
    fireEvent.click(historyBtn);

    expect(selectSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        scanId: 'scan-123',
        targetType: 'URL',
        verdict: 'DANGEROUS'
      })
    );

    getHistorySpy.mockRestore();
  });
});
