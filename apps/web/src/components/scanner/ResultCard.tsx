import React, { useState, useEffect } from 'react';
import { Verdict } from '@private-protection/core';
import { animateCountUp } from '@private-protection/ui';
import { ScanResultViewData } from '../../scanner/types';
import { formatSeverity } from '../../lib/formatters';

interface ResultCardProps {
  result: ScanResultViewData;
  onReset?: () => void;
}

export const ResultCard: React.FC<ResultCardProps> = ({ result, onReset }) => {
  const isDangerous = result.verdict === Verdict.DANGEROUS || result.verdict === Verdict.SUSPICIOUS;
  const isSafe = result.verdict === Verdict.ALLOW;

  // Animated display score (0 -> result.overallScore)
  const [displayScore, setDisplayScore] = useState<number>(0);

  useEffect(() => {
    const cancel = animateCountUp(0, result.overallScore, 360, (val: number) => {
      setDisplayScore(val);
    });
    return cancel;
  }, [result.id, result.overallScore]);

  // 5-second friction gate for dangerous threats
  const [frictionSeconds, setFrictionSeconds] = useState<number>(isDangerous ? 5 : 0);
  const [userBypassed, setUserBypassed] = useState<boolean>(false);

  // Reset friction gate state whenever a new scan result arrives without unmounting
  useEffect(() => {
    setFrictionSeconds(isDangerous ? 5 : 0);
    setUserBypassed(false);
  }, [result.id, result.targetPreview, result.timestamp, isDangerous]);

  useEffect(() => {
    if (isDangerous && frictionSeconds > 0) {
      const timer = setTimeout(() => {
        setFrictionSeconds((prev) => prev - 1);
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [isDangerous, frictionSeconds]);

  // Color mapping for brutalist banner
  const bannerBg = isDangerous ? 'var(--color-danger)' : isSafe ? 'var(--color-safe)' : 'var(--color-caution)';
  const bannerTextColor = '#FFFFFF';
  const headerVerdictLabel = isDangerous
    ? 'ACCESS BLOCKED / DANGEROUS THREAT'
    : isSafe
    ? 'SAFE / NO IMMEDIATE THREAT DETECTED'
    : 'POTENTIAL RISK DETECTED';

  return (
    <article
      aria-labelledby="scan-result-verdict"
      className={isDangerous ? 'motion-threat-alert' : 'motion-fade-up'}
      style={{
        backgroundColor: 'var(--bg-card)',
        border: '2px solid var(--border-dark)',
        boxShadow: 'var(--shadow-brutal-xl)',
        marginTop: '1.75rem',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}
    >
      {/* 1. Header Banner & Verdict (Matches Safe Result, Warning Result & High-Risk Blocked designs) */}
      <div
        style={{
          backgroundColor: bannerBg,
          color: bannerTextColor,
          padding: '1.25rem 1.75rem',
          borderBottom: '2px solid var(--border-dark)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <span style={{ fontSize: '1.5rem' }}>
            {isDangerous ? '🚨' : isSafe ? '🛡️' : '⚠️'}
          </span>
          <div>
            <div
              id="scan-result-verdict"
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '1rem',
                fontWeight: 900,
                letterSpacing: '0.04em',
                textTransform: 'uppercase'
              }}
            >
              {headerVerdictLabel}
            </div>
            <div style={{ fontSize: '0.8rem', opacity: 0.95, marginTop: '0.15rem' }}>
              Target: <strong style={{ color: '#FFFFFF', textDecoration: 'underline' }}>{result.targetPreview}</strong>
            </div>
          </div>
        </div>

        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            fontWeight: 800,
            backgroundColor: '#111111',
            color: '#FFFFFF',
            padding: '0.35rem 0.75rem',
            border: '1px solid rgba(255,255,255,0.4)'
          }}
        >
          ⚡ LATENCY: {result.executionTimeMs} ms
        </div>
      </div>

      <div style={{ padding: '1.75rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* 2. 3-Stat Metric Cards in a Row (Safe Result.png / High-Risk Blocked.png) */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '1rem'
          }}
        >
          <div
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px #111111',
              padding: '1rem'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              <span style={{ color: 'var(--text-muted)' }}>Risk Score</span>
              <strong style={{ fontSize: '0.9rem', color: isDangerous ? 'var(--color-danger)' : isSafe ? 'var(--color-safe)' : 'var(--color-caution)' }}>
                {displayScore} / 100
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
                height: '0.65rem',
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-dark)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  width: `${result.overallScore}%`,
                  height: '100%',
                  backgroundColor: isDangerous ? 'var(--color-danger)' : isSafe ? 'var(--color-safe)' : 'var(--color-caution)',
                  transition: 'width var(--motion-duration-emphasis-fast) var(--motion-ease-enter)'
                }}
              />
            </div>
          </div>

          <div
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px var(--border-dark)',
              padding: '1rem',
              fontFamily: 'var(--font-mono)'
            }}
          >
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
              Severity Level
            </span>
            <p style={{ fontSize: '1.1rem', fontWeight: 800, margin: '0.2rem 0 0 0', color: isDangerous ? 'var(--color-danger)' : 'var(--text-primary)' }}>
              {formatSeverity(result.severity as any)}
            </p>
          </div>

          <div
            style={{
              backgroundColor: 'var(--bg-secondary)',
              border: '2px solid var(--border-dark)',
              boxShadow: '2px 2px 0px var(--border-dark)',
              padding: '1rem',
              fontFamily: 'var(--font-mono)'
            }}
          >
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
              Detector Confidence
            </span>
            <p style={{ fontSize: '1.1rem', fontWeight: 800, margin: '0.2rem 0 0 0', color: 'var(--text-primary)' }}>
              {Math.round(result.confidence * 100)}%
            </p>
          </div>
        </div>

        {/* 3. Action Recommendation & Friction Gate */}
        <div
          style={{
            padding: '1.25rem',
            backgroundColor: isDangerous ? 'var(--color-danger-bg)' : isSafe ? 'var(--color-safe-bg)' : 'var(--color-caution-bg)',
            border: '2px solid var(--border-dark)',
            boxShadow: '3px 3px 0px var(--border-dark)'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase' }}>
              RECOMMENDED ACTION:
            </span>
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                fontWeight: 900,
                color: isDangerous ? 'var(--color-danger)' : 'var(--text-primary)',
                textTransform: 'uppercase'
              }}
            >
              {result.recommendation.action}
            </span>
          </div>

          <p style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0, lineHeight: 1.5 }}>
            {result.recommendation.suggestedAction}
          </p>

          {isDangerous && (
            <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-dark)' }}>
              {frictionSeconds > 0 ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-danger)', fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                  <span>⏳</span>
                  <span>Safety Friction Gate: Action blocked for {frictionSeconds} seconds to prevent impulsive clicks.</span>
                </div>
              ) : !userBypassed ? (
                <button
                  type="button"
                  onClick={() => setUserBypassed(true)}
                  className="cut-corner-btn"
                  style={{
                    padding: '0.5rem 1rem',
                    backgroundColor: 'var(--bg-card)',
                    border: '2px solid var(--color-danger)',
                    boxShadow: '2px 2px 0px var(--color-danger)',
                    color: 'var(--color-danger)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    fontWeight: 800,
                    textTransform: 'uppercase',
                    cursor: 'pointer'
                  }}
                >
                  Acknowledge Risk &amp; Proceed Anyway
                </button>
              ) : (
                <div style={{ color: 'var(--color-caution)', fontWeight: 800, fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                  ⚠️ Risk acknowledged by user. Proceed with extreme caution.
                </div>
              )}
            </div>
          )}
        </div>

        {/* 4. AI Security Assistant Explanation (Grade 6 Reading Level) */}
        {result.aiExplanation && (
          <section
            aria-labelledby="assistant-explanation-title"
            style={{
              padding: '1.5rem',
              backgroundColor: 'var(--bg-card)',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <h4 id="assistant-explanation-title" style={{ fontFamily: 'var(--font-serif)', fontSize: '1.15rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
                <span>🤖</span> AI Security Assistant Explanation
              </h4>
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  fontWeight: 800,
                  padding: '0.2rem 0.5rem',
                  backgroundColor: 'var(--bg-secondary)',
                  border: '1px solid var(--border-dark)',
                  textTransform: 'uppercase'
                }}
              >
                {result.aiExplanation.inferenceStatus === 'LOCAL_MODEL' ? 'On-Device Model' : 'Deterministic Template'}
              </span>
            </div>

            <h5 style={{ fontFamily: 'var(--font-sans)', fontSize: '1.05rem', fontWeight: 800, color: isDangerous ? 'var(--color-danger)' : 'var(--color-brand)', marginBottom: '0.5rem' }}>
              {result.aiExplanation.headline}
            </h5>

            <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', marginBottom: '1rem', lineHeight: 1.6 }}>
              {result.aiExplanation.summaryParagraph}
            </p>

            {result.aiExplanation.dangerFactors.length > 0 && (
              <div style={{ marginBottom: '0.85rem' }}>
                <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--color-danger)', textTransform: 'uppercase' }}>
                  Why this is dangerous:
                </strong>
                <ul style={{ paddingLeft: '1.25rem', marginTop: '0.35rem', fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                  {result.aiExplanation.dangerFactors.map((factor, idx) => (
                    <li key={idx} style={{ marginBottom: '0.2rem' }}>{factor}</li>
                  ))}
                </ul>
              </div>
            )}

            {result.aiExplanation.recommendedSteps.length > 0 && (
              <div style={{ marginBottom: '0.85rem' }}>
                <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--color-brand)', textTransform: 'uppercase' }}>
                  What you should do:
                </strong>
                <ul style={{ paddingLeft: '1.25rem', marginTop: '0.35rem', fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                  {result.aiExplanation.recommendedSteps.map((step, idx) => (
                    <li key={idx} style={{ marginBottom: '0.2rem' }}>{step}</li>
                  ))}
                </ul>
              </div>
            )}

            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.75rem', fontStyle: 'italic', margin: 0 }}>
              Notice: {result.aiExplanation.uncertaintyNote}
            </p>

            {result.aiExplanation.autoTaskPlan && result.aiExplanation.autoTaskPlan.tasks.length > 0 && (
              <div style={{ marginTop: '1.25rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', border: '1.5px solid var(--border-dark)', borderRadius: '2px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 900, textTransform: 'uppercase', color: 'var(--color-brand)' }}>
                    ⚡ Autonomous Security Actions ({result.aiExplanation.autoTaskPlan.autoExecutedCount} Auto-Applied)
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', backgroundColor: 'var(--color-safe-bg)', color: 'var(--color-safe)', padding: '0.15rem 0.45rem', fontWeight: 800 }}>
                    ACTIVE PROTECTION
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {result.aiExplanation.autoTaskPlan.tasks.map((task) => (
                    <div key={task.taskId} style={{ padding: '0.5rem 0.75rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-dark)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                        <strong style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>{task.title}</strong>
                        <span style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)', fontWeight: 800, color: task.priority === 'CRITICAL' ? 'var(--color-danger)' : 'var(--color-brand)' }}>
                          [{task.priority}]
                        </span>
                      </div>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0 0 0.35rem 0' }}>{task.reasoning}</p>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                        {task.plannedActions.map((action) => (
                          <span
                            key={action.id}
                            style={{
                              fontSize: '0.675rem',
                              fontFamily: 'var(--font-mono)',
                              padding: '0.15rem 0.4rem',
                              border: '1px solid var(--border-dark)',
                              backgroundColor: action.canAutoExecute ? 'var(--color-safe-bg)' : 'var(--color-caution-bg)',
                              color: 'var(--text-primary)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.25rem'
                            }}
                          >
                            <span>{action.canAutoExecute ? '✓' : '⚠️'}</span>
                            <span>{action.title}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        )}

        {/* 5. Evidence Chain Table */}
        {result.evidence.length > 0 && (
          <section aria-labelledby="evidence-chain-title">
            <h4 id="evidence-chain-title" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 800, textTransform: 'uppercase', marginBottom: '0.75rem', letterSpacing: '0.04em' }}>
              Detected Threat Signals ({result.evidence.length})
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              {result.evidence.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.85rem 1.15rem',
                    backgroundColor: 'var(--bg-secondary)',
                    border: '1px solid var(--border-dark)',
                    boxShadow: '1px 1px 0px var(--border-dark)',
                    fontSize: '0.85rem'
                  }}
                >
                  <div>
                    <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{item.name}</strong>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0.15rem 0 0 0' }}>
                      {item.description}
                    </p>
                  </div>
                  <div style={{ textAlign: 'right', minWidth: '90px' }}>
                    <span style={{ color: isDangerous ? 'var(--color-danger)' : 'var(--color-brand)', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                      +{item.scoreContribution || item.weight} pts
                    </span>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
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
            gap: '1rem',
            paddingTop: '1rem',
            borderTop: '2px solid var(--border-dark)',
            fontSize: '0.8rem',
            fontFamily: 'var(--font-mono)'
          }}
        >
          <span style={{ color: 'var(--text-muted)' }}>🔒 {result.privacyGuarantee}</span>
          {onReset && (
            <button
              type="button"
              onClick={onReset}
              className="cut-corner-btn"
              style={{
                padding: '0.55rem 1.25rem',
                backgroundColor: 'var(--color-brand)',
                color: '#FFFFFF',
                border: '2px solid var(--border-dark)',
                boxShadow: '2px 2px 0px var(--border-dark)',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                fontWeight: 800,
                textTransform: 'uppercase'
              }}
            >
              Clear Result
            </button>
          )}
        </div>
      </div>
    </article>
  );
};
