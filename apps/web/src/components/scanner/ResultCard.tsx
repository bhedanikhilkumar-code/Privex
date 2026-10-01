import React, { useState, useEffect } from 'react';
import { Verdict } from '@private-protection/core';
import { ScanResultViewData } from '../../scanner/types';
import { getVerdictVisuals, formatSeverity } from '../../lib/formatters';

interface ResultCardProps {
  result: ScanResultViewData;
  onReset?: () => void;
}

export const ResultCard: React.FC<ResultCardProps> = ({ result, onReset }) => {
  const visuals = getVerdictVisuals(result.verdict);
  const isDangerous = result.verdict === Verdict.DANGEROUS || result.verdict === Verdict.SUSPICIOUS;

  // 5-second friction gate for dangerous threats
  const [frictionSeconds, setFrictionSeconds] = useState<number>(isDangerous ? 5 : 0);
  const [userBypassed, setUserBypassed] = useState<boolean>(false);

  useEffect(() => {
    if (isDangerous && frictionSeconds > 0) {
      const timer = setTimeout(() => {
        setFrictionSeconds((prev) => prev - 1);
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [isDangerous, frictionSeconds]);

  return (
    <article
      aria-labelledby="scan-result-verdict"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderRadius: '0.75rem',
        border: `1px solid ${visuals.borderColor}`,
        padding: '1.75rem',
        marginTop: '1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.4)'
      }}
    >
      {/* 1. Header Banner & Verdict */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          borderBottom: '1px solid var(--border-color)',
          paddingBottom: '1rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span
            id="scan-result-verdict"
            style={{
              display: 'inline-block',
              padding: '0.4rem 1rem',
              backgroundColor: visuals.badgeBg,
              color: visuals.badgeText,
              borderRadius: '9999px',
              fontSize: '0.875rem',
              fontWeight: 800,
              letterSpacing: '0.05em',
              textTransform: 'uppercase',
              border: `1px solid ${visuals.borderColor}`
            }}
          >
            {visuals.label}
          </span>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            Target: <strong style={{ color: '#ffffff' }}>{result.targetPreview}</strong>
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: '#34d399' }}>
          <span>⚡ Local Latency: {result.executionTimeMs} ms</span>
        </div>
      </div>

      {/* 2. Risk Score & Severity Meter */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          padding: '1rem',
          backgroundColor: 'rgba(0, 0, 0, 0.2)',
          borderRadius: '0.5rem'
        }}
      >
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Risk Score:</span>
            <strong style={{ fontSize: '1rem', color: visuals.borderColor }}>
              {result.overallScore} / 100
            </strong>
          </div>
          <div
            role="progressbar"
            aria-valuenow={result.overallScore}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Threat Risk Score Progress"
            style={{
              width: '100%',
              height: '0.5rem',
              backgroundColor: '#334155',
              borderRadius: '9999px',
              overflow: 'hidden'
            }}
          >
            <div
              style={{
                width: `${result.overallScore}%`,
                height: '100%',
                backgroundColor: visuals.borderColor,
                transition: 'width 0.4s ease'
              }}
            />
          </div>
        </div>

        <div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Severity Level:</span>
          <p style={{ fontSize: '1rem', fontWeight: 600, color: visuals.borderColor }}>
            {formatSeverity(result.severity as any)}
          </p>
        </div>

        <div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Confidence:</span>
          <p style={{ fontSize: '1rem', fontWeight: 600 }}>
            {Math.round(result.confidence * 100)}%
          </p>
        </div>
      </div>

      {/* 3. Action Recommendation & Friction Gate */}
      <div
        style={{
          padding: '1rem',
          backgroundColor: isDangerous ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
          borderLeft: `4px solid ${visuals.borderColor}`,
          borderRadius: '0 0.5rem 0.5rem 0'
        }}
      >
        <h4 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.25rem' }}>
          Recommended Action: {result.recommendation.action}
        </h4>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          {result.recommendation.suggestedAction}
        </p>

        {isDangerous && (
          <div style={{ marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {frictionSeconds > 0 ? (
              <span style={{ fontSize: '0.8rem', color: '#fca5a5', fontWeight: 600 }}>
                ⏳ Safety Friction Gate: Action blocked for {frictionSeconds} seconds to prevent impulsive clicks.
              </span>
            ) : !userBypassed ? (
              <button
                type="button"
                onClick={() => setUserBypassed(true)}
                style={{
                  padding: '0.4rem 0.85rem',
                  backgroundColor: 'transparent',
                  border: '1px solid #ef4444',
                  color: '#ef4444',
                  borderRadius: '0.375rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Acknowledge Risk & Proceed Anyway
              </button>
            ) : (
              <span style={{ fontSize: '0.8rem', color: '#f59e0b', fontWeight: 600 }}>
                ⚠️ Risk acknowledged by user. Proceed with extreme caution.
              </span>
            )}
          </div>
        )}
      </div>

      {/* 4. AI Security Assistant Explanation (Grade 6 Reading Level) */}
      {result.aiExplanation && (
        <section
          aria-labelledby="assistant-explanation-title"
          style={{
            padding: '1.25rem',
            backgroundColor: 'rgba(30, 41, 59, 0.7)',
            border: '1px solid #334155',
            borderRadius: '0.5rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <h4 id="assistant-explanation-title" style={{ fontSize: '0.95rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>🤖</span> AI Security Assistant Explanation
            </h4>
            <span
              style={{
                fontSize: '0.7rem',
                padding: '0.2rem 0.5rem',
                borderRadius: '9999px',
                backgroundColor: result.aiExplanation.inferenceStatus === 'LOCAL_MODEL' ? '#1e3a8a' : '#334155',
                color: '#93c5fd'
              }}
            >
              {result.aiExplanation.inferenceStatus === 'LOCAL_MODEL' ? 'On-Device Model' : 'Deterministic Template'}
            </span>
          </div>

          <h5 style={{ fontSize: '0.875rem', fontWeight: 600, color: visuals.badgeText, marginBottom: '0.4rem' }}>
            {result.aiExplanation.headline}
          </h5>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.75rem', lineHeight: 1.6 }}>
            {result.aiExplanation.summaryParagraph}
          </p>

          {result.aiExplanation.dangerFactors.length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <strong style={{ fontSize: '0.75rem', color: '#f8fafc' }}>Why this is dangerous:</strong>
              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.25rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {result.aiExplanation.dangerFactors.map((factor, idx) => (
                  <li key={idx}>{factor}</li>
                ))}
              </ul>
            </div>
          )}

          {result.aiExplanation.recommendedSteps.length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <strong style={{ fontSize: '0.75rem', color: '#f8fafc' }}>What you should do:</strong>
              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.25rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {result.aiExplanation.recommendedSteps.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ul>
            </div>
          )}

          <p style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.5rem', fontStyle: 'italic' }}>
            Notice: {result.aiExplanation.uncertaintyNote}
          </p>
        </section>
      )}

      {/* 5. Evidence Chain Table */}
      {result.evidence.length > 0 && (
        <section aria-labelledby="evidence-chain-title">
          <h4 id="evidence-chain-title" style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            Detected Threat Signals ({result.evidence.length})
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {result.evidence.map((item, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '0.6rem 0.85rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  borderRadius: '0.375rem',
                  fontSize: '0.8rem'
                }}
              >
                <div>
                  <strong style={{ color: '#ffffff' }}>{item.name}</strong>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
                    {item.description}
                  </p>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span style={{ color: visuals.borderColor, fontWeight: 700 }}>
                    +{item.scoreContribution || item.weight} pts
                  </span>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>
                    {item.source}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* 6. Privacy & Action Footer */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          paddingTop: '0.75rem',
          borderTop: '1px solid var(--border-color)',
          fontSize: '0.75rem',
          color: '#64748b'
        }}
      >
        <span>🔒 {result.privacyGuarantee}</span>
        {onReset && (
          <button
            type="button"
            onClick={onReset}
            style={{
              padding: '0.4rem 0.85rem',
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-primary)',
              borderRadius: '0.375rem',
              cursor: 'pointer',
              fontSize: '0.75rem',
              fontWeight: 500
            }}
          >
            Clear Result
          </button>
        )}
      </div>
    </article>
  );
};
