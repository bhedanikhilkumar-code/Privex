import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Header } from '../../components/layout/Header';
import { Navigation } from '../../components/layout/Navigation';
import { Footer } from '../../components/layout/Footer';
import { ResultCard } from '../../components/scanner/ResultCard';
import { UrlScannerView } from '../../components/scanner/UrlScannerView';
import { TextScannerView } from '../../components/scanner/TextScannerView';
import { PrivacyView } from '../../components/privacy/PrivacyView';
import { SettingsView } from '../../components/settings/SettingsView';
import { ScanResultViewData, UserPreferences } from '../../scanner/types';
import { WorkerBridge } from '../../workers/worker-bridge';
import { Verdict, SeverityLevel, ActionRecommendation, FrictionLevel } from '@private-protection/core';

describe('Web UI Components Testing', () => {
  const mockPrefs: UserPreferences = {
    cognitiveReadingGrade: 6,
    enableWorkerOffloading: false,
    allowlistDomains: []
  };

  const mockSafeResult: ScanResultViewData = {
    id: 'test-safe-1',
    targetPreview: 'https://www.wikipedia.org',
    scanType: 'URL',
    verdict: Verdict.ALLOW,
    overallScore: 5,
    severity: SeverityLevel.LOW,
    confidence: 0.95,
    evidence: [],
    recommendation: {
      action: ActionRecommendation.ALLOW,
      frictionLevel: FrictionLevel.NONE,
      suggestedAction: 'Safe to proceed.',
      bypassPermitted: true
    },
    rawAssessment: {
      overallScore: 5,
      confidence: 0.95,
      severity: SeverityLevel.LOW,
      primaryThreatFactor: 'NONE',
      detectorContributions: {},
    },
    aiExplanation: {
      headline: 'Legitimate Website',
      summaryParagraph: 'This website appears authentic and exhibits standard domain attributes.',
      dangerFactors: [],
      recommendedSteps: ['Safe to browse normally.'],
      uncertaintyNote: 'Evaluated locally.',
      inferenceStatus: 'DETERMINISTIC_FALLBACK',
      executionTimeMs: 1.2
    },
    executionTimeMs: 1.5,
    timestamp: Date.now(),
    isModelBacked: false,
    privacyGuarantee: '100% processed on-device in browser RAM.'
  };

  const mockDangerousResult: ScanResultViewData = {
    id: 'test-danger-1',
    targetPreview: 'http://192.168.1.1/paypal/login.php',
    scanType: 'URL',
    verdict: Verdict.DANGEROUS,
    overallScore: 95,
    severity: SeverityLevel.CRITICAL,
    confidence: 0.98,
    evidence: [
      {
        source: 'DETERMINISTIC_RULES',
        name: 'IP Host Signal',
        indicator: 'url-ip-host',
        type: 'SUSPICIOUS_URL',
        scoreContribution: 90,
        weight: 90,
        confidence: 0.98,
        description: 'URL uses raw IP host rather than registered domain name.'
      }
    ],
    recommendation: {
      action: ActionRecommendation.BLOCK,
      frictionLevel: FrictionLevel.HIGH,
      suggestedAction: 'Do not enter passwords or personal data.',
      bypassPermitted: false
    },
    rawAssessment: {
      overallScore: 95,
      confidence: 0.98,
      severity: SeverityLevel.CRITICAL,
      primaryThreatFactor: 'PHISHING',
      detectorContributions: {},
    },
    aiExplanation: {
      headline: 'Dangerous Phishing Link Detected',
      summaryParagraph: 'This website is pretending to be PayPal to steal your login credentials.',
      dangerFactors: ['Direct IP address host', 'Spoofed login destination'],
      recommendedSteps: ['Do not enter passwords', 'Close this webpage immediately'],
      uncertaintyNote: 'Confidence 98%',
      inferenceStatus: 'DETERMINISTIC_FALLBACK',
      executionTimeMs: 2.1
    },
    executionTimeMs: 2.5,
    timestamp: Date.now(),
    isModelBacked: false,
    privacyGuarantee: '100% processed on-device in browser RAM.'
  };

  describe('Header, Navigation & Footer', () => {
    it('renders Header with brand title and subtitle', () => {
      render(<Header />);
      expect(screen.getByText(/PRIVEX/i)).toBeDefined();
      expect(screen.getByText(/Zero-Install Client-Side Cyber Threat Dashboard/i)).toBeDefined();
    });

    it('renders Navigation with tabs and handles tab changes', () => {
      const onTabChange = vi.fn();
      render(<Navigation activeTab="URL_SCAN" onTabChange={onTabChange} />);

      const textTab = screen.getByRole('tab', { name: /Message Scanner/i });
      fireEvent.click(textTab);
      expect(onTabChange).toHaveBeenCalledWith('TEXT_SCAN');
    });

    it('renders Footer with privacy commitments', () => {
      render(<Footer />);
      expect(screen.getByText(/Zero Cloud Persistence/i)).toBeDefined();
    });
  });

  describe('ResultCard Component', () => {
    it('renders safe result with green indicators and explanation', () => {
      render(<ResultCard result={mockSafeResult} onReset={vi.fn()} />);
      expect(screen.getByText(/Legitimate Website/i)).toBeDefined();
      expect(screen.getByText(/Safe to proceed/i)).toBeDefined();
    });

    it('renders dangerous result with friction gate and danger factors', () => {
      render(<ResultCard result={mockDangerousResult} onReset={vi.fn()} />);
      expect(screen.getByText(/Dangerous Phishing Link Detected/i)).toBeDefined();
      expect(screen.getByText(/Direct IP address host/i)).toBeDefined();
      expect(screen.getAllByText(/Do not enter passwords/i).length).toBeGreaterThan(0);
    });

    it('resets friction gate state when result prop updates across consecutive scans (DEFECT-WEB-02)', () => {
      const { rerender } = render(<ResultCard result={mockSafeResult} onReset={vi.fn()} />);
      expect(screen.queryByText(/Safety Friction Gate:/i)).toBeNull();

      rerender(<ResultCard result={{ ...mockDangerousResult, id: 'test-danger-consecutive' }} onReset={vi.fn()} />);
      expect(screen.getByText(/Safety Friction Gate: Action blocked for 5 seconds/i)).toBeDefined();
    });
  });

  describe('UrlScannerView Component', () => {
    it('renders URL input form and allows scanning sample URLs', async () => {
      const bridge = new WorkerBridge();
      const scanSpy = vi.spyOn(bridge, 'scanUrl').mockResolvedValue(mockDangerousResult);

      render(<UrlScannerView scannerBridge={bridge} preferences={mockPrefs} />);

      const input = screen.getByPlaceholderText(/Enter or paste web address/i);
      fireEvent.change(input, { target: { value: 'http://192.168.1.100/account/login' } });

      const submitBtn = screen.getByRole('button', { name: /Scan URL/i });
      fireEvent.click(submitBtn);

      expect(scanSpy).toHaveBeenCalledWith('http://192.168.1.100/account/login', mockPrefs);
    });
  });

  describe('TextScannerView Component', () => {
    it('renders message input area and sample scam chips', () => {
      const bridge = new WorkerBridge();
      const scanSpy = vi.spyOn(bridge, 'scanText').mockResolvedValue(mockDangerousResult);

      render(<TextScannerView scannerBridge={bridge} preferences={mockPrefs} />);

      const textarea = screen.getByPlaceholderText(/Paste suspicious text message/i);
      fireEvent.change(textarea, { target: { value: 'URGENT: Your account is suspended!' } });

      const submitBtn = screen.getByRole('button', { name: /Analyze Message/i });
      fireEvent.click(submitBtn);

      expect(scanSpy).toHaveBeenCalledWith('URGENT: Your account is suspended!', mockPrefs);
    });
  });

  describe('PrivacyView Component', () => {
    it('renders privacy guarantee and architectural tier breakdown', () => {
      render(<PrivacyView />);
      expect(screen.getByText(/Your scan is processed locally in your browser/i)).toBeDefined();
      expect(screen.getByText(/Tier 1: Scanned Content/i)).toBeDefined();
      expect(screen.getByText(/Volatile RAM/i)).toBeDefined();
    });
  });

  describe('SettingsView Component', () => {
    it('renders reading grade selection and privacy controls', () => {
      const onPrefsChange = vi.fn();
      render(
        <SettingsView
          preferences={mockPrefs}
          onPreferencesChange={onPrefsChange}
        />
      );

      expect(screen.getByText(/Explanation Reading Level/i)).toBeDefined();
      expect(screen.getByText(/Web Worker Background Processing/i)).toBeDefined();

      // Trigger clear data
      const clearBtn = screen.getByRole('button', { name: /Clear All Local Data/i });
      fireEvent.click(clearBtn);
      expect(onPrefsChange).toHaveBeenCalled();
    });
  });

  describe('App Component Root Integration', () => {
    it('renders home page by default and navigates via tabs', async () => {
      const { App } = await import('../../app/App');
      render(<App />);

      expect(screen.getByText(/On-Device Threat & Scam Protection/i)).toBeDefined();

      // Click URL Scanner tab
      const urlTab = screen.getByRole('tab', { name: /URL Scanner/i });
      fireEvent.click(urlTab);

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /On-Device URL Security Scanner/i })).toBeDefined();
      });
    });

    it('navigates to message scanner tab from navigation', async () => {
      const { App } = await import('../../app/App');
      render(<App />);

      // Click Message Scanner tab
      const msgTab = screen.getByRole('tab', { name: /Message Scanner/i });
      fireEvent.click(msgTab);

      await waitFor(() => {
        expect(screen.getByRole('heading', { name: /On-Device Message & Text Scam Analyzer/i })).toBeDefined();
      });
    });
  });
});
