import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { IntroOverlay } from '../../components/intro/IntroOverlay';
import { IntroStorage } from '../../components/intro/IntroStorage';
import { INTRO_CONFIG } from '../../components/intro/introConfig';
import { App } from '../../app/App';

describe('PRIVEX Cinematic Intro Animation Suite', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    localStorage.clear();
  });

  describe('IntroStorage Persistent State Management', () => {
    it('returns false when intro has never been seen on first visit', () => {
      expect(IntroStorage.hasSeenIntro()).toBe(false);
    });

    it('marks intro as seen and persists flag to localStorage', () => {
      IntroStorage.markIntroSeen();
      expect(localStorage.getItem(INTRO_CONFIG.storageKey)).toBe('true');
      expect(IntroStorage.hasSeenIntro()).toBe(true);
    });

    it('resets intro seen flag cleanly when requested', () => {
      IntroStorage.markIntroSeen();
      expect(IntroStorage.hasSeenIntro()).toBe(true);
      IntroStorage.resetIntro();
      expect(localStorage.getItem(INTRO_CONFIG.storageKey)).toBeNull();
      expect(IntroStorage.hasSeenIntro()).toBe(false);
    });

    it('gracefully handles localStorage exceptions in restricted sandboxes', () => {
      const getItemSpy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('SecurityError: LocalStorage denied');
      });
      // Should fail-safe and not throw
      expect(IntroStorage.hasSeenIntro()).toBe(true);
      getItemSpy.mockRestore();

      const setItemSpy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('QuotaExceeded or SecurityError');
      });
      // Should not throw on set
      expect(() => IntroStorage.markIntroSeen()).not.toThrow();
      setItemSpy.mockRestore();
    });
  });

  describe('IntroOverlay Lifecycle & Storyboard Progression', () => {
    it('renders initial Scene 1 with caption and skip button on first mount', () => {
      const onComplete = vi.fn();
      render(<IntroOverlay onComplete={onComplete} />);

      expect(screen.getByRole('dialog', { name: /PRIVEX Cinematic Introduction/i })).toBeDefined();
      expect(screen.getAllByText(INTRO_CONFIG.scenes.scene1.caption).length).toBeGreaterThan(0);
      expect(screen.getByRole('button', { name: /Skip introduction animation/i })).toBeDefined();
    });

    it('progresses smoothly through all 4 scenes within 5 seconds exactly', () => {
      const onComplete = vi.fn();
      render(<IntroOverlay onComplete={onComplete} />);

      // Initial: Scene 1 (0.0s - 1.4s)
      expect(screen.getAllByText(INTRO_CONFIG.scenes.scene1.caption).length).toBeGreaterThan(0);

      // Advance to Scene 2 (at 1.4s: Unusual activity)
      act(() => {
        vi.advanceTimersByTime(1500);
      });
      expect(screen.getByText(INTRO_CONFIG.scenes.scene2.warningLabel)).toBeDefined();
      expect(screen.getByText('UNKNOWN HOST')).toBeDefined();

      // Advance to Scene 3 (at 2.8s: Protection activates)
      act(() => {
        vi.advanceTimersByTime(1400);
      });
      expect(screen.getByText('Sandbox Isolation')).toBeDefined();
      expect(screen.getByText('Cloud Persistence')).toBeDefined();

      // Advance to Scene 4 (at 4.0s: PRIVEX Brand Reveal)
      act(() => {
        vi.advanceTimersByTime(1200);
      });
      expect(screen.getByRole('heading', { level: 1, name: INTRO_CONFIG.brandName })).toBeDefined();
      expect(screen.getAllByText(new RegExp(INTRO_CONFIG.tagline, 'i')).length).toBeGreaterThan(0);

      // Finish intro at 5.0s + 400ms fade duration
      act(() => {
        vi.advanceTimersByTime(1500);
      });
      expect(onComplete).toHaveBeenCalled();
      expect(localStorage.getItem(INTRO_CONFIG.storageKey)).toBe('true');
    });

    it('allows skipping immediately when user clicks the Skip button', () => {
      const onComplete = vi.fn();
      render(<IntroOverlay onComplete={onComplete} />);

      const skipButton = screen.getByRole('button', { name: /Skip introduction animation/i });
      fireEvent.click(skipButton);

      // Fast-forward fade transition
      act(() => {
        vi.advanceTimersByTime(500);
      });

      expect(onComplete).toHaveBeenCalledTimes(1);
      expect(localStorage.getItem(INTRO_CONFIG.storageKey)).toBe('true');
    });

    it('allows skipping with the Escape key', () => {
      const onComplete = vi.fn();
      render(<IntroOverlay onComplete={onComplete} />);

      fireEvent.keyDown(window, { key: 'Escape' });

      act(() => {
        vi.advanceTimersByTime(500);
      });

      expect(onComplete).toHaveBeenCalledTimes(1);
      expect(localStorage.getItem(INTRO_CONFIG.storageKey)).toBe('true');
    });

    it('respects prefers-reduced-motion media query by fast-tracking reveal', () => {
      const onComplete = vi.fn();
      const originalMatchMedia = window.matchMedia;
      window.matchMedia = vi.fn().mockImplementation((query: string) => ({
        matches: query.includes('prefers-reduced-motion'),
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn()
      } as any));

      render(<IntroOverlay onComplete={onComplete} />);

      // Should jump directly to brand reveal and complete in ~1.2s
      expect(screen.getByRole('heading', { level: 1, name: INTRO_CONFIG.brandName })).toBeDefined();

      act(() => {
        vi.advanceTimersByTime(1700);
      });

      expect(onComplete).toHaveBeenCalled();
      window.matchMedia = originalMatchMedia;
    });
  });

  describe('App Root Integration with One-Time Intro Playback', () => {
    it('shows intro on first visit when flag is absent, and permits replay from Settings', async () => {
      // First visit: storage key is null
      render(<App />);

      // Intro overlay is mounted
      expect(screen.getByRole('dialog', { name: /PRIVEX Cinematic Introduction/i })).toBeDefined();

      // Skip intro
      const skipBtn = screen.getByRole('button', { name: /Skip introduction animation/i });
      fireEvent.click(skipBtn);

      act(() => {
        vi.advanceTimersByTime(500);
      });

      // After skip, intro is closed and persistent flag is set
      expect(localStorage.getItem(INTRO_CONFIG.storageKey)).toBe('true');

      // Switch to Settings tab
      const settingsTab = screen.getByRole('tab', { name: /Settings/i });
      fireEvent.click(settingsTab);

      // Verify the replay button in Settings
      const replayBtn = screen.getByRole('button', { name: /Replay intro animation from settings/i });
      expect(replayBtn).toBeDefined();

      // Click Replay Intro
      fireEvent.click(replayBtn);

      // Intro should now be visible again!
      expect(screen.getByRole('dialog', { name: /PRIVEX Cinematic Introduction/i })).toBeDefined();
    });

    it('bypasses intro automatically for returning visitors who have already seen it', async () => {
      // Mark as seen previously
      localStorage.setItem(INTRO_CONFIG.storageKey, 'true');

      render(<App />);

      // Intro overlay should not be rendered
      expect(screen.queryByRole('dialog', { name: /PRIVEX Cinematic Introduction/i })).toBeNull();
      // Main dashboard is directly visible
      expect(screen.getByRole('banner')).toBeDefined();
      expect(screen.getByRole('main')).toBeDefined();
    });
  });
});
