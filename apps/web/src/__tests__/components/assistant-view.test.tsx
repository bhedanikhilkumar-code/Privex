import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AssistantView } from '../../components/assistant/AssistantView';
import { UserPreferences } from '../../scanner/types';

describe('AssistantView Component (Interactive AI Security Assistant)', () => {
  const mockPrefs: UserPreferences = {
    cognitiveReadingGrade: 6,
    enableWorkerOffloading: true,
    allowlistDomains: []
  };

  it('renders Assistant view header and safety boundary indicator', () => {
    render(<AssistantView preferences={mockPrefs} />);

    expect(screen.getByText(/On-Device AI Security Assistant/i)).toBeDefined();
    expect(screen.getByText(/Strict Safety Boundary/i)).toBeDefined();
    expect(screen.getByRole('button', { name: /Credential Phishing/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /Urgent Extortion/i })).toBeDefined();
  });

  it('synthesizes plain-language threat explanations when scenario clicked', async () => {
    render(<AssistantView preferences={mockPrefs} />);

    const extortionBtn = screen.getByRole('button', { name: /Urgent Extortion/i });
    fireEvent.click(extortionBtn);

    await waitFor(() => {
      expect(screen.getByText(/Extortion Scam Detected/i)).toBeDefined();
    });

    expect(screen.getByText(/Key Threat Indicators:/i)).toBeDefined();
    expect(screen.getByText(/Recommended Defensive Actions:/i)).toBeDefined();
  });

  it('allows analyzing custom untrusted text snippets safely', async () => {
    render(<AssistantView preferences={mockPrefs} />);

    const input = screen.getByPlaceholderText(/Enter custom suspicious text snippet/i);
    fireEvent.change(input, { target: { value: 'Your bank account has been locked. Verify immediately.' } });

    const explainBtn = screen.getByRole('button', { name: /Synthesize Explanation/i });
    fireEvent.click(explainBtn);

    await waitFor(() => {
      expect(screen.getByText(/Recommended Defensive Actions:/i)).toBeDefined();
    });
  });
});
