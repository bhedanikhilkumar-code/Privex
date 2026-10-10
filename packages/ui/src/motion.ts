/**
 * PRIVEX Canonical Motion Tokens & Principles
 * 
 * Strict constraints:
 * - Brand palette: Deep Void #0B0F19, Alert Red #DC2626, Node White #F8FAFC, Cyber Slate #0284C7
 * - Durations:
 *    - Micro: 120ms - 160ms (buttons, hovers, toggles)
 *    - Standard: 200ms - 260ms (cards, banners, tabs, list items)
 *    - Emphasis: 300ms - 420ms (verdict reveal, modals, interstitials)
 * - Easings:
 *    - Enter: cubic-bezier(0.22, 1, 0.36, 1)
 *    - Exit:  cubic-bezier(0.4, 0, 1, 1)
 *    - Standard: cubic-bezier(0.16, 1, 0.3, 1)
 * - Stagger lists: 40ms - 60ms, max 8 items
 * - Properties animated: transform, opacity, stroke-dashoffset ONLY
 * - prefers-reduced-motion: reduce -> zero transform/shake, instant or pure opacity
 */

export const MotionDurations = {
  microFast: 120,
  micro: 160,
  standardFast: 200,
  standard: 240,
  standardSlow: 260,
  emphasisFast: 300,
  emphasis: 360,
  emphasisSlow: 420,
  staggerStep: 50,
  maxStaggerItems: 8
} as const;

export const MotionEasings = {
  enter: 'cubic-bezier(0.22, 1, 0.36, 1)',
  exit: 'cubic-bezier(0.4, 0, 1, 1)',
  standard: 'cubic-bezier(0.16, 1, 0.3, 1)',
  linear: 'linear'
} as const;

export const MotionColors = {
  deepVoid: '#0B0F19',
  alertRed: '#DC2626',
  nodeWhite: '#F8FAFC',
  cyberSlate: '#0284C7',
  safeGreen: '#16A34A',
  cautionAmber: '#D97706'
} as const;

/**
 * Checks if client environment prefers reduced motion.
 * Returns false on SSR or non-browser environments.
 */
export function isReducedMotionPreferred(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * Generates staggered transition delay up to max 8 items.
 */
export function getStaggerDelay(index: number, stepMs = MotionDurations.staggerStep): number {
  const cappedIndex = Math.min(Math.max(0, index), MotionDurations.maxStaggerItems - 1);
  return cappedIndex * stepMs;
}

/**
 * Lightweight in-memory number count-up animator using RequestAnimationFrame.
 * Automatically respects reduced-motion by jumping immediately to target.
 */
export function animateCountUp(
  from: number,
  to: number,
  durationMs: number,
  onUpdate: (value: number) => void,
  onComplete?: () => void
): () => void {
  if (isReducedMotionPreferred() || durationMs <= 0 || from === to) {
    onUpdate(to);
    onComplete?.();
    return () => {};
  }

  let startTime: number | null = null;
  let rafId: number | null = null;
  let cancelled = false;

  const step = (timestamp: number) => {
    if (cancelled) return;
    if (startTime === null) startTime = timestamp;
    const elapsed = timestamp - startTime;
    const progress = Math.min(elapsed / durationMs, 1);
    
    // Smooth ease-out quad
    const eased = 1 - (1 - progress) * (1 - progress);
    const current = Math.round(from + (to - from) * eased);
    onUpdate(current);

    if (progress < 1) {
      rafId = requestAnimationFrame(step);
    } else {
      onUpdate(to);
      onComplete?.();
    }
  };

  rafId = requestAnimationFrame(step);

  return () => {
    cancelled = true;
    if (rafId !== null) cancelAnimationFrame(rafId);
  };
}

/**
 * Text scramble effect for secure reveals (e.g. password generator).
 * Settles strictly within maxDurationMs (<= 350ms).
 */
export function scrambleText(
  finalText: string,
  durationMs = 300,
  onUpdate: (text: string) => void,
  onComplete?: () => void
): () => void {
  if (isReducedMotionPreferred() || durationMs <= 0 || !finalText) {
    onUpdate(finalText);
    onComplete?.();
    return () => {};
  }

  const chars = '!@#$%^&*()_+~`|}{[]:;?><,./-=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let startTime: number | null = null;
  let rafId: number | null = null;
  let cancelled = false;

  const step = (timestamp: number) => {
    if (cancelled) return;
    if (startTime === null) startTime = timestamp;
    const elapsed = timestamp - startTime;
    const progress = Math.min(elapsed / durationMs, 1);

    const revealedLength = Math.floor(progress * finalText.length);
    let result = '';

    for (let i = 0; i < finalText.length; i++) {
      if (i < revealedLength) {
        result += finalText[i];
      } else {
        result += chars[Math.floor(Math.random() * chars.length)];
      }
    }

    onUpdate(result);

    if (progress < 1) {
      rafId = requestAnimationFrame(step);
    } else {
      onUpdate(finalText);
      onComplete?.();
    }
  };

  rafId = requestAnimationFrame(step);

  return () => {
    cancelled = true;
    if (rafId !== null) cancelAnimationFrame(rafId);
  };
}
