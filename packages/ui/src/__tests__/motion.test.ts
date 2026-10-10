/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  MotionDurations,
  MotionEasings,
  isReducedMotionPreferred,
  getStaggerDelay,
  animateCountUp,
  scrambleText
} from '../motion';

describe('Motion Tokens & Utilities', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('defines correct motion duration and easing tokens', () => {
    expect(MotionDurations.microFast).toBe(120);
    expect(MotionDurations.micro).toBe(160);
    expect(MotionDurations.standardFast).toBe(200);
    expect(MotionDurations.standard).toBe(240);
    expect(MotionDurations.emphasisFast).toBe(300);
    expect(MotionDurations.emphasis).toBe(360);
    expect(MotionEasings.enter).toContain('cubic-bezier');
  });

  it('calculates capped stagger delays for lists', () => {
    expect(getStaggerDelay(0)).toBe(0);
    expect(getStaggerDelay(1)).toBe(50);
    expect(getStaggerDelay(4)).toBe(200);
    // Capped at max 8 items (index 7)
    expect(getStaggerDelay(10)).toBe(350);
  });

  it('animates count-up smoothly to target', () => {
    let currentValue = 0;
    let completed = false;

    // Mock matchMedia returning false for reduced motion
    window.matchMedia = vi.fn().mockImplementation((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn()
    }));

    animateCountUp(0, 100, 300, (v) => { currentValue = v; }, () => { completed = true; });

    expect(currentValue).toBe(0);
  });

  it('jumps directly to target when prefers-reduced-motion is active', () => {
    window.matchMedia = vi.fn().mockImplementation((query) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn()
    }));

    let currentValue = 0;
    let completed = false;

    animateCountUp(0, 85, 300, (v) => { currentValue = v; }, () => { completed = true; });

    // Should immediately resolve to target without animating
    expect(currentValue).toBe(85);
    expect(completed).toBe(true);
  });

  it('scrambles and reveals text, jumping immediately when reduced-motion active', () => {
    window.matchMedia = vi.fn().mockImplementation((query) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn()
    }));

    let textValue = '';
    let completed = false;

    scrambleText('SecretPassword123!', 300, (t) => { textValue = t; }, () => { completed = true; });

    expect(textValue).toBe('SecretPassword123!');
    expect(completed).toBe(true);
  });
});
