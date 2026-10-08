import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { PasswordChecker } from '../../components/security/PasswordChecker';
import { PasswordGenerator } from '../../components/security/PasswordGenerator';
import { NetworkMonitor } from '../../components/security/NetworkMonitor';
import { SecurityAlertBanner } from '../../components/security/SecurityAlertBanner';
import { SecurityDashboardView } from '../../components/security/SecurityDashboardView';
import { DEFAULT_MONITOR_CONFIG } from '../../lib/security/request-monitor';
import { securityEventManager } from '../../lib/security/security-events';

describe('Password & Network Security Components', () => {
  beforeEach(() => {
    securityEventManager.clearAllEvents();
  });

  describe('PasswordChecker', () => {
    it('renders input and responds to user typing', () => {
      render(<PasswordChecker />);
      expect(screen.getByText('Password Security Checker')).toBeDefined();

      const input = screen.getByLabelText(/Enter Password To Analyze/i);
      fireEvent.change(input, { target: { value: 'Password@123' } });

      expect(screen.getByText(/Password Strength:/i)).toBeDefined();
      expect(screen.getByText(/Uppercase letters/i)).toBeDefined();
    });

    it('clears password input when Clear button is clicked', () => {
      render(<PasswordChecker />);
      const input = screen.getByLabelText(/Enter Password To Analyze/i);
      fireEvent.change(input, { target: { value: 'MySecretPassword123' } });

      const clearBtn = screen.getByRole('button', { name: /Clear/i });
      fireEvent.click(clearBtn);

      expect((input as HTMLInputElement).value).toBe('');
    });
  });

  describe('PasswordGenerator', () => {
    it('renders generator controls and generates strong passwords', () => {
      render(<PasswordGenerator />);
      expect(screen.getByText('Strong Password Generator')).toBeDefined();
      expect(screen.getByRole('button', { name: /Regenerate/i })).toBeDefined();
      expect(screen.getByRole('button', { name: /Copy Password/i })).toBeDefined();
    });

    it('updates password when length preset is clicked', () => {
      render(<PasswordGenerator />);
      const preset24 = screen.getByRole('button', { name: '24' });
      fireEvent.click(preset24);
      expect(screen.getByText(/Password Length: 24 Characters/i)).toBeDefined();
    });
  });

  describe('NetworkMonitor', () => {
    it('renders traffic log and triggers traffic simulation', () => {
      const mockClear = vi.fn();
      const mockSimulate = vi.fn();
      const mockBurst = vi.fn();
      const mockUpdate = vi.fn();

      render(
        <NetworkMonitor
          requests={[
            {
              id: 'req1',
              url: 'https://api.test.com/v1',
              domain: 'api.test.com',
              method: 'GET',
              timestamp: Date.now(),
              destinationType: 'FIRST_PARTY',
              riskLevel: 'SAFE',
              status: 200
            }
          ]}
          config={DEFAULT_MONITOR_CONFIG}
          onClear={mockClear}
          onSimulateRequest={mockSimulate}
          onSimulateBurst={mockBurst}
          onUpdateConfig={mockUpdate}
        />
      );

      expect(screen.getByText('URL & Network Request Monitor')).toBeDefined();
      expect(screen.getByText('api.test.com')).toBeDefined();

      const simBtn = screen.getByRole('button', { name: /\+ 1st Party Request/i });
      fireEvent.click(simBtn);
      expect(mockSimulate).toHaveBeenCalled();
    });
  });

  describe('SecurityAlertBanner', () => {
    it('renders active security alerts and handles actions', () => {
      const mockDismiss = vi.fn();
      const mockReview = vi.fn();
      const mockChange = vi.fn();

      render(
        <SecurityAlertBanner
          alerts={[
            {
              id: 'alt1',
              type: 'HIGH_REQUEST_ACTIVITY',
              severity: 'medium',
              timestamp: new Date().toISOString(),
              message: 'High request frequency detected on api.tracker.com'
            }
          ]}
          onDismiss={mockDismiss}
          onReviewActivity={mockReview}
          onChangePasswordClick={mockChange}
        />
      );

      expect(screen.getByText(/Security Alert/i)).toBeDefined();
      expect(screen.getByText(/High request frequency detected on api.tracker.com/i)).toBeDefined();

      const changeBtn = screen.getByRole('button', { name: /Change Password/i });
      fireEvent.click(changeBtn);
      expect(mockChange).toHaveBeenCalled();

      const dismissBtn = screen.getByRole('button', { name: /Dismiss/i });
      fireEvent.click(dismissBtn);
      expect(mockDismiss).toHaveBeenCalledWith('alt1');
    });
  });

  describe('SecurityDashboardView', () => {
    it('renders dashboard with metrics and allows switching sub-sections', () => {
      render(<SecurityDashboardView />);
      expect(screen.getByText('Password Security & Network Protection')).toBeDefined();
      expect(screen.getByText(/System Status/i)).toBeDefined();
      expect(screen.getByText(/Network Activity/i)).toBeDefined();

      const networkTab = screen.getByRole('button', { name: /Network & Request Monitor/i });
      fireEvent.click(networkTab);
      expect(screen.getByText('URL & Network Request Monitor')).toBeDefined();

      const eventsTab = screen.getByRole('button', { name: /Security Events & Alerts/i });
      fireEvent.click(eventsTab);
      expect(screen.getByText('Recent Security Events')).toBeDefined();
    });
  });
});
