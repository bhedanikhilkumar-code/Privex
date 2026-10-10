import React, { useState, useEffect, useCallback, useRef } from 'react';
import { INTRO_CONFIG } from './introConfig';
import { IntroStorage } from './IntroStorage';
import './intro.css';

export interface IntroOverlayProps {
  onComplete: () => void;
}

export const IntroOverlay: React.FC<IntroOverlayProps> = ({ onComplete }) => {
  const [activeScene, setActiveScene] = useState<1 | 2 | 3 | 4>(1);
  const [isFadingOut, setIsFadingOut] = useState<boolean>(false);
  const hasFinishedRef = useRef<boolean>(false);

  // Complete and close intro
  const handleFinish = useCallback(() => {
    if (hasFinishedRef.current) return;
    hasFinishedRef.current = true;

    // Persist seen status to localStorage
    IntroStorage.markIntroSeen();

    // Fade out overlay smoothly
    setIsFadingOut(true);

    const timer = setTimeout(() => {
      onComplete();
    }, 400);

    return () => clearTimeout(timer);
  }, [onComplete]);

  // Handle Skip button
  const handleSkip = useCallback(() => {
    handleFinish();
  }, [handleFinish]);

  // Keyboard navigation: Escape key to skip intro
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        handleSkip();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleSkip]);

  // Exactly 5.0-second storyboard sequence
  useEffect(() => {
    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReducedMotion) {
      setActiveScene(4);
      const reducedTimer = setTimeout(() => {
        handleFinish();
      }, 1000);
      return () => clearTimeout(reducedTimer);
    }

    const { scenes } = INTRO_CONFIG;
    // 0.0s - 1.4s: Scene 1 (1400ms)
    // 1.4s - 2.8s: Scene 2 (1400ms)
    const tScene2 = scenes.scene1.durationMs; // 1400ms
    // 2.8s - 4.0s: Scene 3 (1200ms)
    const tScene3 = tScene2 + scenes.scene2.durationMs; // 2800ms
    // 4.0s - 5.0s: Scene 4 (1000ms)
    const tScene4 = tScene3 + scenes.scene3.durationMs; // 4000ms
    // Total: 5000ms (5.0 seconds)
    const tFinish = tScene4 + scenes.scene4.durationMs; // 5000ms

    const timer2 = setTimeout(() => setActiveScene(2), tScene2);
    const timer3 = setTimeout(() => setActiveScene(3), tScene3);
    const timer4 = setTimeout(() => setActiveScene(4), tScene4);
    const timerEnd = setTimeout(() => handleFinish(), tFinish);

    // Watchdog fallback
    const watchdog = setTimeout(() => handleFinish(), 5800);

    return () => {
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);
      clearTimeout(timerEnd);
      clearTimeout(watchdog);
    };
  }, [handleFinish]);

  // Get current story caption
  const getCaption = () => {
    switch (activeScene) {
      case 1:
        return INTRO_CONFIG.scenes.scene1.caption;
      case 2:
        return INTRO_CONFIG.scenes.scene2.caption;
      case 3:
        return INTRO_CONFIG.scenes.scene3.caption;
      case 4:
        return `${INTRO_CONFIG.brandName} — ${INTRO_CONFIG.tagline}`;
      default:
        return '';
    }
  };

  return (
    <div
      id="privex-intro"
      className={isFadingOut ? 'hidden' : ''}
      role="dialog"
      aria-modal="true"
      aria-label="PRIVEX Cinematic Introduction"
    >
      <div className="privex-intro-grid" />

      {/* Skip Button */}
      <button
        type="button"
        className="intro-skip-btn"
        id="intro-skip-btn"
        onClick={handleSkip}
        aria-label="Skip introduction animation"
      >
        <span>SKIP</span>
        <span>➔</span>
      </button>

      {/* Scene 1: Person 1 + Everyday Digital Life (0.0s - 1.4s) */}
      <div className={`intro-scene ${activeScene === 1 ? 'active' : ''}`} id="scene-1">
        <img
          src="/assets/intro-scene-1.png"
          className="human-bg"
          alt="Everyday digital life"
          onError={(e) => {
            (e.target as HTMLElement).style.display = 'none';
          }}
        />
        <div className="privex-brutal-card">
          <div className="privex-badge-acid">
            <span>●</span> LOCAL ENCLAVE CONNECTED
          </div>
          <p style={{ margin: 0, fontWeight: 700, fontSize: '0.95rem' }}>
            Your digital space is always active.
          </p>
        </div>
      </div>

      {/* Scene 2: Person 2 + Unusual Network Traffic Intercepted (1.4s - 2.8s) */}
      <div className={`intro-scene ${activeScene === 2 ? 'active' : ''}`} id="scene-2">
        <img
          src="/assets/intro-scene-2.png"
          className="human-bg"
          alt="Unusual network activity"
          onError={(e) => {
            (e.target as HTMLElement).style.display = 'none';
          }}
        />
        <div className="privex-brutal-card">
          <div className="privex-brutal-flow">
            <span className="privex-flow-pill">GET /api</span>
            <span>➔</span>
            <span className="privex-flow-pill">ROUTE</span>
            <span>➔</span>
            <span className="privex-flow-pill danger">UNKNOWN HOST</span>
          </div>
          <div className="privex-badge-alert">
            <span>⚠️</span> {INTRO_CONFIG.scenes.scene2.warningLabel}
          </div>
        </div>
      </div>

      {/* Scene 3: Protection Activates on Device (2.8s - 4.0s) */}
      <div className={`intro-scene ${activeScene === 3 ? 'active' : ''}`} id="scene-activate">
        <img
          src="/assets/intro-scene-3.png"
          className="human-bg"
          alt="Protection activates"
          style={{ opacity: 0.35, filter: 'blur(3px)' }}
          onError={(e) => {
            (e.target as HTMLElement).style.display = 'none';
          }}
        />
        <div className="privex-shield-wrap">
          <div className="privex-shield-ring-out" />
          <div className="privex-shield-ring-in" />
          <div className="privex-shield-wave" />
          <span className="privex-shield-center-icon" role="img" aria-label="Shield">🛡️</span>
        </div>
        <div className="privex-status-row">
          <div className="privex-status-chip">
            <span>Sandbox Isolation</span>
            <span className="chip-tag" style={{ background: '#00E5FF' }}>ACTIVE</span>
          </div>
          <div className="privex-status-chip">
            <span>Cloud Persistence</span>
            <span className="chip-tag" style={{ background: '#D7FF3F' }}>ZERO</span>
          </div>
          <div className="privex-status-chip">
            <span>Verdict</span>
            <span className="chip-tag" style={{ background: '#10B981', color: '#FFF' }}>SHIELDED</span>
          </div>
        </div>
      </div>

      {/* Scene 4: PRIVEX Brand Reveal & Immediate Entry (4.0s - 5.0s) */}
      <div className={`intro-scene ${activeScene === 4 ? 'active' : ''}`} id="scene-reveal">
        <div className="privex-brand-lockup">
          <div className="privex-brand-shield-logo">
            🛡️
          </div>
          <h1 className="privex-brand-heading">{INTRO_CONFIG.brandName}</h1>
          <div className="privex-brand-subtag">{INTRO_CONFIG.tagline}</div>
        </div>
      </div>

      {/* Bottom Story Caption Bar */}
      <div className="privex-caption-bar" aria-live="polite">
        <p className={`privex-caption-text ${activeScene === 2 ? 'alert' : ''}`}>
          {getCaption()}
        </p>
      </div>

      {/* 5-Second Timeline Progress Line */}
      <div className="privex-progress-line" aria-hidden="true">
        <div className="privex-progress-fill" />
      </div>
    </div>
  );
};
