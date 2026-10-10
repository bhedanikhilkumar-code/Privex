import React from 'react';
import { INTRO_CONFIG } from './introConfig';

export const IntroSceneNetwork: React.FC = () => {
  const { warningLabel, requestFlow } = INTRO_CONFIG.scenes.scene2;

  return (
    <div className="privex-hud-overlay" role="region" aria-label="Network Activity Detection">
      <div className="privex-network-card">
        {/* Warning Indicator */}
        <div className="privex-amber-badge" role="status">
          <span aria-hidden="true">⚠️</span>
          <span>{warningLabel}</span>
        </div>

        {/* Request Packet Flow: REQUEST → REQUEST → REQUEST → UNKNOWN SOURCE */}
        <div className="privex-request-flow" aria-label="Network request stream">
          {requestFlow.map((nodeText, idx) => {
            const isLast = idx === requestFlow.length - 1;
            return (
              <React.Fragment key={idx}>
                <span className={`privex-flow-node ${isLast ? 'danger-node' : ''}`}>
                  {nodeText}
                </span>
                {!isLast && (
                  <span className="privex-flow-arrow" aria-hidden="true">
                    ➔
                  </span>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};
