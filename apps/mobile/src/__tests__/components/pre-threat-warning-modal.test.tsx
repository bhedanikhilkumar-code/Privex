import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { PreThreatWarningModal } from '../../components/PreThreatWarningModal';
import { PreThreatWarningPayload } from '../../types/mobile.types';

describe('PreThreatWarningModal Component (Phase T7)', () => {
  const mockDangerousWarning: PreThreatWarningPayload = {
    warningId: 'warn-test-1',
    targetType: 'URL',
    targetIdentifier: 'https://xn--pypal-4ve.com/signin',
    riskScore: 88,
    verdict: 'DANGEROUS',
    confidenceLevel: 'STRONG_SUSPICION',
    whatDetected: 'Deceptive lookalike domain using internationalized characters to mimic paypal.com.',
    potentialConsequences: 'Visiting this site may allow attackers to steal your account credentials.',
    recommendedAction: 'GO_BACK',
    supportedChoices: ['GO_BACK', 'INSPECT_DETAILS', 'CONTINUE_AT_OWN_RISK'],
    evidenceDetails: [
      { code: 'HOMOGLYPH_ATTACK', severity: 'CRITICAL', description: 'Cyrillic lookalike homoglyph' },
      { code: 'BRAND_SPOOF', severity: 'HIGH', description: 'Spoofs financial brand paypal' }
    ],
    requiresFrictionGate: true,
    frictionGateSeconds: 5,
    timestamp: Date.now()
  };

  beforeEach(() => {
    vi.useRealTimers();
  });

  it('renders nothing when warning is null', () => {
    const { container } = render(
      <PreThreatWarningModal warning={null} onActionSelected={() => {}} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders accessible alertdialog with correct ARIA attributes and content', () => {
    render(
      <PreThreatWarningModal warning={mockDangerousWarning} onActionSelected={() => {}} />
    );

    const dialog = screen.getByRole('alertdialog');
    expect(dialog).toBeDefined();
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(dialog.getAttribute('aria-labelledby')).toBe('pre-threat-title');

    expect(screen.getByText(/High-Risk Threat Blocked/i)).toBeDefined();
    expect(screen.getByText(/Strong Suspicion/i)).toBeDefined();
    expect(screen.getByText(/https:\/\/xn--pypal-4ve.com\/signin/i)).toBeDefined();
    expect(screen.getByText(/Risk Score:/i)).toBeDefined();
    expect(screen.getByText(/88\/100/i)).toBeDefined();
    expect(screen.getByText(/Deceptive lookalike domain/i)).toBeDefined();
    expect(screen.getByText(/steal your account credentials/i)).toBeDefined();
  });

  it('triggers onActionSelected when primary safe recommendation CTA is clicked', () => {
    const actionSpy = vi.fn();
    render(
      <PreThreatWarningModal warning={mockDangerousWarning} onActionSelected={actionSpy} />
    );

    const safeButton = screen.getByText(/← Go Back to Safety \(Recommended\)/i);
    fireEvent.click(safeButton);

    expect(actionSpy).toHaveBeenCalledWith('GO_BACK', false);
  });

  it('toggles technical evidence details when clicked', () => {
    render(
      <PreThreatWarningModal warning={mockDangerousWarning} onActionSelected={() => {}} />
    );

    expect(screen.queryByText(/Cyrillic lookalike homoglyph/i)).toBeNull();

    const toggleBtn = screen.getByText(/Technical Evidence Details/i);
    fireEvent.click(toggleBtn);

    expect(screen.getByText(/Cyrillic lookalike homoglyph/i)).toBeDefined();
    expect(screen.getByText(/Spoofs financial brand paypal/i)).toBeDefined();
  });

  it('initiates friction gate when Continue at own risk is clicked', () => {
    vi.useFakeTimers();
    const actionSpy = vi.fn();
    render(
      <PreThreatWarningModal warning={mockDangerousWarning} onActionSelected={actionSpy} />
    );

    const bypassLink = screen.getByText(/Continue at your own risk.../i);
    fireEvent.click(bypassLink);

    expect(screen.getByText(/Severe Risk Acknowledgment/i)).toBeDefined();
    const continueBtn = screen.getByText(/Wait 5s before continuing.../i);
    expect(continueBtn).toBeDefined();
    expect(continueBtn.hasAttribute('disabled')).toBe(true);

    // Fast-forward 5 seconds
    act(() => {
      vi.advanceTimersByTime(5000);
    });

    const activeContinueBtn = screen.getByText(/I Understand the Risks, Continue/i);
    expect(activeContinueBtn.hasAttribute('disabled')).toBe(false);

    fireEvent.click(activeContinueBtn);
    expect(actionSpy).toHaveBeenCalledWith('CONTINUE_AT_OWN_RISK', true);

    vi.useRealTimers();
  });

  it('allows canceling friction gate and returns to normal modal view', () => {
    render(
      <PreThreatWarningModal warning={mockDangerousWarning} onActionSelected={() => {}} />
    );

    const bypassLink = screen.getByText(/Continue at your own risk.../i);
    fireEvent.click(bypassLink);

    expect(screen.getByText(/Severe Risk Acknowledgment/i)).toBeDefined();
    const returnBtn = screen.getByText(/← Return to Safety \(Recommended\)/i);
    fireEvent.click(returnBtn);

    expect(screen.queryByText(/Severe Risk Acknowledgment/i)).toBeNull();
    expect(screen.getByText(/← Go Back to Safety \(Recommended\)/i)).toBeDefined();
  });
});
