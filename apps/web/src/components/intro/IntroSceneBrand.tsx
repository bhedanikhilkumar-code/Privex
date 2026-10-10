import React from 'react';
import { INTRO_CONFIG } from './introConfig';

export const IntroSceneBrand: React.FC = () => {
  const { brandName, tagline } = INTRO_CONFIG.scenes.scene4;

  return (
    <div className="privex-brand-reveal-stage" role="region" aria-label="Brand Presentation">
      {/* Brand Icon Shield Transform */}
      <div className="privex-brand-logo-container" aria-hidden="true">
        <div className="privex-brand-glow-backdrop" />
        <svg
          className="privex-brand-logo-svg"
          viewBox="0 0 100 115"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="brandShieldGradient" x1="0" y1="0" x2="100" y2="115" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#00E5FF" />
              <stop offset="50%" stopColor="#3B82F6" />
              <stop offset="100%" stopColor="#7C4DFF" />
            </linearGradient>
            <linearGradient id="brandCoreGradient" x1="25" y1="25" x2="75" y2="95" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#FFFFFF" />
              <stop offset="100%" stopColor="#00E5FF" />
            </linearGradient>
          </defs>
          {/* Main Shield Geometry */}
          <path
            d="M50 6 L90 22 L90 65 Q50 108 50 108 Q10 65 10 22 Z"
            fill="url(#brandShieldGradient)"
            stroke="#00E5FF"
            strokeWidth="3"
            strokeLinejoin="round"
          />
          {/* Inner Geometric Star/Core Monogram */}
          <path
            d="M50 24 L68 46 L50 68 L32 46 Z"
            fill="url(#brandCoreGradient)"
            opacity="0.9"
          />
          <circle cx="50" cy="46" r="6" fill="#070B14" />
          <path
            d="M50 72 L62 82 L50 92 L38 82 Z"
            fill="#FFFFFF"
            opacity="0.6"
          />
        </svg>
      </div>

      {/* Brand Title */}
      <h1 className="privex-brand-title">{brandName}</h1>

      {/* Brand Tagline */}
      <p className="privex-brand-tagline">{tagline}</p>
    </div>
  );
};
