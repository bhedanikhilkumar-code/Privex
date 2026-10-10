import React, { useState } from 'react';
import { MobileScanResult } from '../types/mobile.types';
import { Verdict, WebsiteAuditReport, ExposedEntryPoint } from '@private-protection/core';
import { SecurityBadge } from '../components/SecurityBadge';
import { EvidenceCard } from '../components/EvidenceCard';
import { FrictionGateModal } from '../components/FrictionGateModal';

interface ScanResultScreenProps {
  result: MobileScanResult;
  auditReport?: WebsiteAuditReport | null;
  onReset: () => void;
  onDone: () => void;
}

export const ScanResultScreen: React.FC<ScanResultScreenProps> = ({ result, auditReport, onReset, onDone }) => {
  const [showFrictionModal, setShowFrictionModal] = useState<boolean>(false);
  const [hasOverridden, setHasOverridden] = useState<boolean>(result.overridden);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2500);
    }
  };

  const isCritical = result.verdict === Verdict.DANGEROUS;

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Top Bar with Analysis Verdict title & SecurityBadge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {result.targetType} Scan Result
          </span>
          <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#f8fafc' }}>
            Analysis Verdict
          </h2>
        </div>
        <SecurityBadge verdict={result.verdict} score={result.overallScore} />
      </div>

      {/* Hero Verdict Badge */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', paddingTop: '0.25rem' }}>
        <div
          style={{
            width: '110px',
            height: '110px',
            borderRadius: '50%',
            backgroundColor: isCritical ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
            border: `2px solid ${isCritical ? '#ef4444' : '#10b981'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: isCritical ? '0 0 35px rgba(239, 68, 68, 0.35)' : '0 0 35px rgba(16, 185, 129, 0.35)'
          }}
        >
          <div
            style={{
              width: '60px',
              height: '60px',
              borderRadius: '50%',
              backgroundColor: isCritical ? '#ef4444' : '#10b981',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '2rem',
              color: '#ffffff'
            }}
          >
            {isCritical ? '⚠️' : '✓'}
          </div>
        </div>

        <h1
          style={{
            margin: '0.85rem 0 0.35rem 0',
            fontSize: '1.5rem',
            fontWeight: 900,
            color: isCritical ? '#f87171' : '#34d399',
            letterSpacing: '0.04em',
            textTransform: 'uppercase'
          }}
        >
          {isCritical ? 'THREAT DETECTED' : (result.verdict === Verdict.SUSPICIOUS ? 'SUSPICIOUS ACTIVITY' : 'ALL CLEAR / SAFE')}
        </h1>

        <div
          style={{
            padding: '0.3rem 0.85rem',
            borderRadius: '9999px',
            backgroundColor: '#111b2e',
            border: '1px solid #27364b',
            fontSize: '0.8rem',
            fontWeight: 800,
            color: isCritical ? '#f87171' : (result.verdict === Verdict.SUSPICIOUS ? '#fcd34d' : '#34d399'),
            letterSpacing: '0.05em'
          }}
        >
          RISK SCORE: {result.overallScore}/100
        </div>
      </div>

      {/* Target Details Card */}
      <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.15rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
          <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            {result.targetType} ANALYSIS
          </span>
          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Just now</span>
        </div>
        <div style={{ wordBreak: 'break-all', fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc', lineHeight: 1.4 }}>
          {result.sanitizedTarget}
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.75rem', fontSize: '0.74rem', color: '#64748b', borderTop: '1px solid #1e293b', paddingTop: '0.5rem' }}>
          <span>Confidence: {Math.round(result.confidence * 100)}%</span>
          <span>•</span>
          <span>Latency: {result.executionTimeMs} ms</span>
          <span>•</span>
          <span>Category: {result.threatCategory}</span>
        </div>
      </div>

      {/* Analysis Breakdown — 4 Explanation Pillars */}
      <div>
        <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
          Analysis Breakdown
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {/* 1. What happened? */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '14px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#38bdf8' }} />
              <strong style={{ fontSize: '0.88rem', color: '#38bdf8' }}>What happened?</strong>
            </div>
            <p style={{ margin: 0, fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.4 }}>
              {result.aiExplanation?.headline || `Evaluated ${result.targetType} structures on-device against security heuristics.`}
            </p>
          </div>

          {/* 2. Why it matters? */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '14px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#f59e0b' }} />
              <strong style={{ fontSize: '0.88rem', color: '#fcd34d' }}>Why it matters?</strong>
            </div>
            <p style={{ margin: 0, fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.4 }}>
              {result.aiExplanation?.dangerFactors?.[0] || 'Unverified targets can result in credential theft, financial loss, or unauthorized execution.'}
            </p>
          </div>

          {/* 3. What Privex did? */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '14px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#10b981' }} />
              <strong style={{ fontSize: '0.88rem', color: '#34d399' }}>What Privex did?</strong>
            </div>
            <p style={{ margin: 0, fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.4 }}>
              The threat was analyzed strictly inside volatile RAM. No unencrypted content was transmitted to external servers.
            </p>
          </div>

          {/* 4. Next steps */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '14px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#ef4444' }} />
              <strong style={{ fontSize: '0.88rem', color: '#f87171' }}>Next steps</strong>
            </div>
            <p style={{ margin: 0, fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.4 }}>
              {result.aiExplanation?.recommendedSteps?.[0] || result.recommendation?.suggestedAction || 'Do not interact with the payload or enter personal credentials.'}
            </p>
          </div>
        </div>
      </div>

      {/* Open Points & Port Remediation Blueprint (If Audit Data Exists) */}
      {auditReport && auditReport.openEntryPoints && auditReport.openEntryPoints.length > 0 && (
        <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.15rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                PERIMETER ATTACK SURFACE AUDIT
              </span>
              <h4 style={{ margin: '0.1rem 0 0 0', fontSize: '0.95rem', fontWeight: 800, color: '#f8fafc' }}>
                Open Entry Points & Hacker Vectors ({auditReport.openPointsDetected})
              </h4>
            </div>
            <span
              style={{
                padding: '4px 8px',
                borderRadius: '6px',
                fontSize: '0.7rem',
                fontWeight: 800,
                backgroundColor:
                  auditReport.overallExposureRisk === 'CRITICAL'
                    ? 'rgba(239, 68, 68, 0.2)'
                    : auditReport.overallExposureRisk === 'HIGH'
                    ? 'rgba(249, 115, 22, 0.2)'
                    : 'rgba(234, 179, 8, 0.2)',
                color:
                  auditReport.overallExposureRisk === 'CRITICAL'
                    ? '#f87171'
                    : auditReport.overallExposureRisk === 'HIGH'
                    ? '#fb923c'
                    : '#fde047'
              }}
            >
              {auditReport.overallExposureRisk} EXPOSURE
            </span>
          </div>

          <p style={{ margin: 0, fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.4 }}>
            {auditReport.summaryExplanation}
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.25rem' }}>
            {auditReport.openEntryPoints.map((point: ExposedEntryPoint) => (
              <div
                key={point.id}
                style={{
                  backgroundColor: '#0b1220',
                  border: '1px solid #1e293b',
                  borderRadius: '12px',
                  padding: '0.85rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '0.85rem', color: '#f8fafc' }}>{point.name}</strong>
                  <span style={{ fontSize: '0.72rem', fontFamily: 'monospace', color: '#38bdf8', fontWeight: 700 }}>
                    {point.target}
                  </span>
                </div>

                <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                  {point.description}
                </div>

                {/* Hacker Vector */}
                <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', padding: '0.6rem', fontSize: '0.75rem', color: '#fca5a5' }}>
                  <strong style={{ display: 'block', marginBottom: '2px' }}>
                    🥷 How Hackers Exploit This Point:
                  </strong>
                  {point.hackerAttackVector}
                </div>

                {/* Remediation & Code Directive */}
                <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '8px', padding: '0.6rem', fontSize: '0.75rem', color: '#6ee7b7' }}>
                  <strong style={{ display: 'block', marginBottom: '2px' }}>
                    🛠️ Remediation / How to Fix:
                  </strong>
                  <div style={{ marginBottom: '4px', fontWeight: 600 }}>
                    {point.remediationSolution.summary}
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '14px' }}>
                    {point.remediationSolution.steps.map((st: string, i: number) => (
                      <li key={i} style={{ marginBottom: '2px' }}>{st}</li>
                    ))}
                  </ul>

                  {point.remediationSolution.technicalCodeSnippet && (
                    <div style={{ marginTop: '6px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                        <span style={{ fontSize: '0.7rem', fontWeight: 700 }}>Directive / Config Snippet:</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(point.remediationSolution.technicalCodeSnippet!, point.id)}
                          style={{
                            padding: '2px 6px',
                            backgroundColor: '#1e293b',
                            border: '1px solid #334155',
                            color: '#38bdf8',
                            fontSize: '0.65rem',
                            borderRadius: '4px',
                            cursor: 'pointer'
                          }}
                        >
                          {copiedId === point.id ? '✓ Copied' : '📋 Copy'}
                        </button>
                      </div>
                      <pre style={{ margin: 0, padding: '6px', backgroundColor: '#090e1a', color: '#a3e635', borderRadius: '4px', fontSize: '0.7rem', overflowX: 'auto', fontFamily: 'monospace' }}>
                        {point.remediationSolution.technicalCodeSnippet}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technical Evidence Telemetry */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
            Technical Evidence
          </h4>
          <span style={{ fontSize: '0.75rem', color: '#38bdf8', fontWeight: 600 }}>
            {result.evidence?.length || 0} Detections
          </span>
        </div>
        <EvidenceCard evidence={result.evidence} />
      </div>

      {/* User Action Buttons */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
        <button
          type="button"
          onClick={onDone}
          style={{
            padding: '0.9rem',
            backgroundColor: '#38bdf8',
            color: '#0b1220',
            fontWeight: 800,
            borderRadius: '14px',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.95rem',
            boxShadow: '0 4px 12px rgba(56, 189, 248, 0.3)'
          }}
        >
          Return to Dashboard
        </button>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            type="button"
            onClick={onReset}
            style={{
              flex: 1,
              padding: '0.75rem',
              backgroundColor: '#111b2e',
              border: '1px solid #27364b',
              color: '#f8fafc',
              fontWeight: 700,
              borderRadius: '12px',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            + New Scan
          </button>

          {isCritical && !hasOverridden && (
            <button
              type="button"
              onClick={() => setShowFrictionModal(true)}
              style={{
                flex: 1,
                padding: '0.75rem',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid #ef4444',
                color: '#f87171',
                fontWeight: 700,
                borderRadius: '12px',
                cursor: 'pointer',
                fontSize: '0.85rem'
              }}
            >
              Request Override
            </button>
          )}
        </div>

        {hasOverridden && (
          <div style={{ textAlign: 'center', fontSize: '0.8rem', color: '#fca5a5' }}>
            ⚠️ User override acknowledged for this session.
          </div>
        )}
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
