import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { PopupApp } from '../../popup/popup';

describe('Popup UI Component', () => {
  beforeEach(() => {
    (globalThis as any).chrome = {
      tabs: {
        query: vi.fn((_query, callback) => {
          callback([{ id: 1, url: 'https://example.com/test' }]);
        })
      },
      runtime: {
        sendMessage: vi.fn((message, callback) => {
          if (message.type === 'GET_TAB_STATUS') {
            callback({
              success: true,
              state: {
                tabId: 1,
                url: 'https://example.com/test',
                domain: 'example.com',
                verdict: 'ALLOW',
                overallScore: 5,
                severity: 'NONE',
                confidence: 0.99,
                threatCategory: 'NONE',
                evidence: [],
                recommendation: {
                  action: 'ALLOW',
                  frictionLevel: 'NONE',
                  suggestedAction: 'Safe to proceed',
                  bypassPermitted: true
                },
                timestamp: Date.now(),
                overridden: false
              }
            });
          } else if (message.type === 'GET_SETTINGS') {
            callback({
              success: true,
              settings: {
                enabled: true,
                readingGrade: 6,
                allowlistDomains: [],
                showShadowDomBanners: true,
                frictionGateDurationSec: 5
              }
            });
          }
        }),
        openOptionsPage: vi.fn()
      }
    };
  });

  it('renders extension title and site safety status', async () => {
    render(<PopupApp />);

    await waitFor(() => {
      expect(screen.getByText(/PRIVEX/i)).toBeDefined();
      expect(screen.getByText('example.com')).toBeDefined();
      expect(screen.getByText(/SAFE \/ ALLOWED/i)).toBeDefined();
    });
  });

  it('handles restricted internal browser pages gracefully', async () => {
    (globalThis as any).chrome.tabs.query = vi.fn((_query, callback) => {
      callback([{ id: 2, url: 'chrome://extensions' }]);
    });
    (globalThis as any).chrome.runtime.sendMessage = vi.fn((message, callback) => {
      if (message.type === 'GET_TAB_STATUS') {
        callback({
          success: true,
          state: {
            tabId: 2,
            url: 'chrome://extensions',
            domain: 'chrome://extensions',
            verdict: 'ALLOW',
            overallScore: 0,
            severity: 'NONE',
            confidence: 1.0,
            threatCategory: 'INTERNAL_PAGE',
            evidence: [],
            recommendation: { action: 'ALLOW', frictionLevel: 'NONE', suggestedAction: 'None', bypassPermitted: true },
            timestamp: Date.now(),
            overridden: false,
            isRestrictedUrl: true
          }
        });
      }
    });

    render(<PopupApp />);

    await waitFor(() => {
      expect(screen.getByText(/Browser System Page/i)).toBeDefined();
    });
  });
});
