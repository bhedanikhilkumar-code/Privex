import React from 'react';
import { INTRO_CONFIG } from './introConfig';

export const IntroSceneShield: React.FC = () => {
  const { statusItems } = INTRO_CONFIG.scenes.scene3;

  return (
    <div className="privex-hud-overlay" role="region" aria-label="Protection Activation">
      {/* Holographic Shield Ring Constructor */}
      <div className="privex-shield-constructor" aria-hidden="true">
        <div className="privex-ring-outer" />
        <div className="privex-ring-inner" />
        <div className="privex-energy-wave" />

        {/* Dynamic Vector Shield Emblem */}
        <svg
          className="privex-shield-emblem-svg"
          viewBox="0 0 100 115"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="shieldFillGrad" x1="0" y1="0" x2="100" y2="115" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#2563EB" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#7C4DFF" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="shieldStrokeGrad" x1="0" y1="0" x2="100" y2="115" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#00E5FF" />
              <stop offset="100%" stopColor="#A78BFA" />
            </linearGradient>
          </defs>
          {/* Outer Shield Shell */}
          <path
            d="M50 8 L88 24 L88 64 Q50 106 50 106 Q12 64 12 64 L12 24 Z"
            fill="url(#shieldFillGrad)"
            stroke="url(#shieldStrokeGrad)"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />
          {/* Inner Geometric Core Lines */}
          <path
            d="M50 20 L76 33 L76 60 Q50 90 50 90 Q24 60 24 60 L24 33 Z"
            stroke="#00E5FF"
            strokeWidth="1.5"
            strokeDasharray="4 2"
            fill="none"
          />
          {/* Centered Lock / Check Vector Icon */}
          <path
            d="M40 54 L47 62 L62 44"
            stroke="#FFFFFF"
            strokeWidth="3.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>

      {/* Clean Security Interface: Password Security, Request Monitoring, Security Alert */}
      <div className="privex-status-cards" role="list">
        {statusItems.map((item, index) => (
          <div
            key={item.label}
            className="privex-status-card"
            style={{ animationDelay: `${index * 0.12}s` }}
            role="listitem"
          >
            <span style={{ color: '#E2E8F0', fontWeight: 600 }}>{item.label}</span>
            <span
              className="privex-status-pill"
              style={{
                backgroundColor: `${item.color}22`,
                border: `1px solid ${item.color}`,
                color: item.color
              }}
            >
              {item.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
