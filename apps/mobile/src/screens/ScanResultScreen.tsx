import React, { useState } from 'react';
import { MobileScanResult } from '../types/mobile.types';
import { Verdict } from '@private-protection/core';
import { SecurityBadge } from '../components/SecurityBadge';
import { EvidenceCard } from '../components/EvidenceCard';
import { FrictionGateModal } from '../components/FrictionGateModal';

interface ScanResultScreenProps {
  result: MobileScanResult;
  onReset: () => void;
  onDone: () => void;
}

export const ScanResultScreen: React.FC<ScanResultScreenProps> = ({ result, onReset, onDone }) => {
  const [showFrictionModal, setShowFrictionModal] = useState<boolean>(false);
  const [hasOverridden, setHasOverridden] = useState<boolean>(result.overridden);

  const isCritical = result.verdict === Verdict.DANGEROUS;

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Top Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase' }}>
            {result.targetType} Scan Result
          </span>
          <h2 style={{ margin: 0, fontSize: '1.25rem', color: '#f8fafc' }}>
            Analysis Verdict
          </h2>
        </div>
        <SecurityBadge verdict={result.verdict} score={result.overallScore} />
      </div>

      {/* Target Details Card */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem' }}>
        <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.25rem' }}>Scanned Target:</div>
        <div style={{ wordBreak: 'break-all', fontSize: '0.9rem', color: '#38bdf8', fontFamily: 'monospace' }}>
          {result.sanitizedTarget}
        </div>
        <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', fontSize: '0.75rem', color: '#64748b' }}>
          <span>Confidence: {Math.round(result.confidence * 100)}%</span>
          <span>Latency: {result.executionTimeMs} ms</span>
          <span>Category: {result.threatCategory}</span>
        </div>
      </div>

      {/* AI Security Assistant Plain-Language Briefing */}
      {result.aiExplanation ? (
        <div
          style={{
            backgroundColor: '#0f172a',
            border: '1px solid #38bdf8',
            borderRadius: '16px',
            padding: '1.25rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '1.25rem' }}>🤖</span>
            <h4 style={{ margin: 0, fontSize: '1rem', color: '#38bdf8' }}>
              {result.aiExplanation.headline}
            </h4>
          </div>
          <p style={{ margin: '0 0 0.75rem 0', fontSize: '0.9rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            {result.aiExplanation.summaryParagraph}
          </p>

          {result.aiExplanation.dangerFactors.length > 0 && (
            <div style={{ marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.8rem', color: '#f87171', fontWeight: 600 }}>Identified Risk Factors:</span>
              <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
                {result.aiExplanation.dangerFactors.map((df, i) => (
                  <li key={i}>{df}</li>
                ))}
              </ul>
            </div>
          )}

          {result.aiExplanation.recommendedSteps.length > 0 && (
            <div>
              <span style={{ fontSize: '0.8rem', color: '#34d399', fontWeight: 600 }}>Defensive Guidance:</span>
              <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.25rem', fontSize: '0.85rem', color: '#cbd5e1' }}>
                {result.aiExplanation.recommendedSteps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        <div style={{ backgroundColor: '#1e293b', borderRadius: '12px', padding: '1rem', fontSize: '0.85rem', color: '#94a3b8' }}>
          <strong style={{ color: '#f8fafc', display: 'block', marginBottom: '0.25rem' }}>Recommendation:</strong>
          {result.recommendation.suggestedAction}
        </div>
      )}

      {/* Technical Evidence Telemetry */}
      <div>
        <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.95rem', color: '#cbd5e1' }}>Technical Evidence Tokens:</h4>
        <EvidenceCard evidence={result.evidence} />
      </div>

      {/* User Action Buttons */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
        <button
          type="button"
          onClick={onReset}
          style={{
            padding: '0.85rem',
            backgroundColor: '#38bdf8',
            color: '#0f172a',
            fontWeight: 700,
            borderRadius: '12px',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.95rem'
          }}
        >
          Scan Another Target
        </button>

        {isCritical && !hasOverridden && (
          <button
            type="button"
            onClick={() => setShowFrictionModal(true)}
            style={{
              padding: '0.75rem',
              backgroundColor: 'transparent',
              color: '#f87171',
              fontWeight: 600,
              borderRadius: '8px',
              border: '1px solid #7f1d1d',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            I Understand the Risk — Request Override
          </button>
        )}

        {hasOverridden && (
          <div style={{ textAlign: 'center', fontSize: '0.8rem', color: '#fca5a5' }}>
            ⚠️ User override acknowledged for this session.
          </div>
        )}

        <button
          type="button"
          onClick={onDone}
          style={{
            padding: '0.65rem',
            backgroundColor: '#1e293b',
            color: '#94a3b8',
            borderRadius: '8px',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.85rem'
          }}
        >
          Return to Dashboard
        </button>
      </div>

      {/* Friction Gate Modal */}
      <FrictionGateModal
        isOpen={showFrictionModal}
        threatCategory={result.threatCategory}
        durationSec={5}
        onConfirmBypass={() => {
          setHasOverridden(true);
          setShowFrictionModal(false);
        }}
        onCancel={() => setShowFrictionModal(false)}
      />
    </div>
  );
};
