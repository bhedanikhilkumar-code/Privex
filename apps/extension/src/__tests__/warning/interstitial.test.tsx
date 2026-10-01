import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { InterstitialApp } from '../../warning/interstitial';

describe('Interstitial Warning View (Friction Gate & User Override)', () => {
  beforeEach(() => {
    window.history.pushState({}, '', '?tabId=44&target=http%3A%2F%2F192.168.1.100%2Flogin');

    (globalThis as any).chrome = {
      runtime: {
        sendMessage: vi.fn((message, callback) => {
          if (message.type === 'GET_TAB_STATUS') {
            callback({
              success: true,
              state: {
                tabId: 44,
                url: 'http://192.168.1.100/login',
                domain: '192.168.1.100',
                verdict: 'DANGEROUS',
                overallScore: 95,
                severity: 'CRITICAL',
                confidence: 0.98,
                threatCategory: 'MALICIOUS_IP_PHISH',
                evidence: [
                  { name: 'Raw IP Host Signal', description: 'URL uses numerical IP host instead of domain.' }
                ],
                aiExplanation: {
                  headline: 'Dangerous Login Theft Site',
                  summaryParagraph: 'This website is pretending to be a legitimate login page to steal credentials.',
                  dangerFactors: ['Direct IP host without SSL'],
                  recommendedSteps: ['Do not enter passwords']
                },
                timestamp: Date.now(),
                overridden: false
              }
            });
          } else if (message.type === 'REQUEST_OVERRIDE') {
            callback({ success: true, proceedUrl: 'http://192.168.1.100/login' });
          }
        })
      }
    };
  });

  it('renders dangerous blocked warning with threat summary and AI briefing', async () => {
    render(<InterstitialApp />);

    await waitFor(() => {
      expect(screen.getByText(/Dangerous Website Blocked/i)).toBeDefined();
      expect(screen.getByText(/MALICIOUS_IP_PHISH/i)).toBeDefined();
      expect(screen.getByText(/95 \/ 100/i)).toBeDefined();
      expect(screen.getByText(/Why This Website Is Dangerous/i)).toBeDefined();
    });
  });

  it('provides safe return navigation via Back to Safety button', async () => {
    const backSpy = vi.spyOn(window.history, 'back').mockImplementation(() => {});

    render(<InterstitialApp />);

    const backBtn = screen.getByRole('button', { name: /Back to Safety/i });
    fireEvent.click(backBtn);

    expect(backSpy).toHaveBeenCalled();
  });

  it('enforces safety gate before allowing user override', async () => {
    render(<InterstitialApp />);

    // Click Advanced / Override
    const advancedBtn = screen.getByRole('button', { name: /Advanced \/ Override Options/i });
    fireEvent.click(advancedBtn);

    // Button should be disabled during countdown
    const overrideBtn = screen.getByRole('button', { name: /Safety Gate/i });
    expect(overrideBtn).toBeDefined();
    expect((overrideBtn as HTMLButtonElement).disabled).toBe(true);
  });
});
