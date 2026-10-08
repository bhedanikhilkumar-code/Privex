import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { App } from '../../app/App';
import { Navigation } from '../../components/layout/Navigation';
import { ResultCard } from '../../components/scanner/ResultCard';
import { ScanResultViewData } from '../../scanner/types';
import { Verdict, SeverityLevel, ActionRecommendation, FrictionLevel } from '@private-protection/core';

describe('Web Application Accessibility (WCAG 2.1 AA Compliance)', () => {
  it('renders standard ARIA Landmark roles (banner, main, contentinfo, navigation)', () => {
    render(<App />);

    expect(screen.getByRole('banner')).toBeDefined();
    expect(screen.getByRole('main')).toBeDefined();
    expect(screen.getByRole('contentinfo')).toBeDefined();
    expect(screen.getByRole('tablist')).toBeDefined();
  });

  it('implements complete ARIA tablist pattern with active selection states', () => {
    const onTabChange = vi.fn();
    render(<Navigation activeTab="URL_SCAN" onTabChange={onTabChange} />);

    const tabs = screen.getAllByRole('tab');
    expect(tabs.length).toBe(7);

    const activeTab = tabs.find((t) => t.getAttribute('aria-selected') === 'true');
    expect(activeTab).toBeDefined();
    expect(activeTab?.textContent).toContain('URL Scanner');
  });

  it('supports keyboard arrow navigation across tabs', () => {
    const onTabChange = vi.fn();
    render(<Navigation activeTab="HOME" onTabChange={onTabChange} />);

    const firstTab = screen.getByRole('tab', { name: /Overview/i });
    fireEvent.keyDown(firstTab, { key: 'ArrowRight' });
    expect(onTabChange).toHaveBeenCalledWith('URL_SCAN');

    fireEvent.keyDown(firstTab, { key: 'ArrowLeft' });
    expect(onTabChange).toHaveBeenCalledWith('SETTINGS');
  });

  it('provides accessible labels for all form inputs', () => {
    render(<App />);

    // Switch to URL Scanner
    const urlTab = screen.getByRole('tab', { name: /URL Scanner/i });
    fireEvent.click(urlTab);

    const urlInput = screen.getByLabelText(/URL to scan for cyber threats/i);
    expect(urlInput).toBeDefined();
    expect(urlInput.getAttribute('type')).toBe('text');
  });

  it('renders progressbar with full ARIA value attributes on result card', () => {
    const sampleResult: ScanResultViewData = {
      id: 'a11y-result-1',
      targetPreview: 'https://test-check.com',
      scanType: 'URL',
      verdict: Verdict.SUSPICIOUS,
      overallScore: 65,
      severity: SeverityLevel.MEDIUM,
      confidence: 0.9,
      evidence: [],
      recommendation: {
        action: ActionRecommendation.WARN,
        frictionLevel: FrictionLevel.MEDIUM,
        suggestedAction: 'Exercise caution.',
        bypassPermitted: true
      },
      rawAssessment: {
        overallScore: 65,
        confidence: 0.9,
        severity: SeverityLevel.MEDIUM,
        primaryThreatFactor: 'CAUTION',
        detectorContributions: {},
      },
      aiExplanation: {
        headline: 'Suspicious Target',
        summaryParagraph: 'This target exhibits multiple anomalous flags.',
        dangerFactors: ['Unknown reputation'],
        recommendedSteps: ['Inspect before proceeding'],
        uncertaintyNote: 'Confidence 90%',
        inferenceStatus: 'DETERMINISTIC_FALLBACK',
        executionTimeMs: 1.0
      },
      executionTimeMs: 1.5,
      timestamp: Date.now(),
      isModelBacked: false,
      privacyGuarantee: '100% processed on-device.'
    };

    render(<ResultCard result={sampleResult} onReset={vi.fn()} />);

    const progressBar = screen.getByRole('progressbar');
    expect(progressBar).toBeDefined();
    expect(progressBar.getAttribute('aria-valuenow')).toBe('65');
    expect(progressBar.getAttribute('aria-valuemin')).toBe('0');
    expect(progressBar.getAttribute('aria-valuemax')).toBe('100');
  });
});
