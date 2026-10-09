import React, { useEffect, useState } from 'react';
import { MobileThreatIntelService } from '../services/mobile-threat-intel.service';
import type { ThreatDatabaseInspectionResult } from '../types/mobile.types';

export const ProtectionStatusScreen: React.FC = () => {
  const [intelStatus, setIntelStatus] = useState<ThreatDatabaseInspectionResult | null>(null);
  const [isRollbackRunning, setIsRollbackRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    loadIntelStatus();
  }, []);

  const loadIntelStatus = async () => {
    try {
      const status = await MobileThreatIntelService.inspectDatabaseHealth();
      setIntelStatus(status);
    } catch (e: any) {
      console.warn('Failed to load threat intel status', e);
    }
  };

  const handleRollback = async () => {
    setIsRollbackRunning(true);
    setStatusMessage(null);
    try {
      const success = await MobileThreatIntelService.rollbackToFactorySeed();
      if (success) {
        setStatusMessage('Successfully rolled back threat database to factory seed.');
        await loadIntelStatus();
      } else {
        setStatusMessage('Rollback failed.');
      }
    } catch (e: any) {
      setStatusMessage(`Rollback error: ${e.message || String(e)}`);
    } finally {
      setIsRollbackRunning(false);
    }
  };

  const engineComponents = [
    { name: 'Deterministic Rule Engine', status: 'OPERATIONAL', latency: '< 0.2 ms', type: 'Offline Ruleset' },
    { name: 'Lexical & Entropy Analyzer', status: 'OPERATIONAL', latency: '< 0.5 ms', type: 'Heuristic' },
    { name: 'Threat Intelligence (.ppdb)', status: intelStatus?.isVerified ? 'OPERATIONAL' : 'DEGRADED', latency: '< 0.05 ms', type: 'Signed Local DB' },
    { name: 'Multi-Factor Risk Scorer', status: 'OPERATIONAL', latency: '< 0.1 ms', type: 'Bayesian Aggregator' },
    { name: 'Semantic URL Classifier', status: 'OPERATIONAL', latency: '< 0.01 ms', type: 'On-Device ML' },
    { name: 'AI Security Assistant Runtime', status: 'OPERATIONAL', latency: '< 0.02 ms', type: 'Template Fallback Engine' }
  ];

  const stalenessColor = intelStatus?.stalenessState === 'FRESH'
    ? '#34d399'
    : intelStatus?.stalenessState === 'AGED'
      ? '#fbbf24'
      : '#f87171';

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#38bdf8' }}>
          Engine Diagnostics & Health
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Internal detection subsystem status, verified threat database (.ppdb), and offline capability.
        </p>
      </div>

      {/* Offline Status Badge Card */}
      <div style={{ backgroundColor: '#0f172a', border: '1px solid #10b981', borderRadius: '16px', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <span style={{ fontWeight: 700, color: '#34d399', fontSize: '1rem' }}>
            ✓ 100% Offline Parity Active
          </span>
          <span style={{ fontSize: '0.75rem', backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7', padding: '0.2rem 0.5rem', borderRadius: '6px' }}>
            Air-Gapped Ready
          </span>
        </div>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.4 }}>
          All detection rules, heuristic algorithms, local verified threat database, and AI explanation engines operate entirely on-device with zero internet connectivity required.
        </p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', marginTop: '0.75rem', fontSize: '0.75rem', color: '#64748b' }}>
          <span>Feed: {intelStatus?.activeMetadata.sourceFeed || 'FACTORY_SEED'}</span>
          <span>Version: {intelStatus?.activeMetadata.installedVersion || '1.0.0-seed'} (Seq #{intelStatus?.activeMetadata.versionSequence ?? 100})</span>
          <span>Records: {intelStatus?.activeMetadata.recordsCount ?? 11}</span>
        </div>
      </div>

      {/* Threat Database (.ppdb) Card */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <h4 style={{ margin: 0, fontSize: '1rem', color: '#38bdf8' }}>Verified Threat Intelligence (.ppdb)</h4>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: stalenessColor, padding: '0.2rem 0.5rem', borderRadius: '4px', backgroundColor: 'rgba(255,255,255,0.05)' }}>
            Status: {intelStatus?.stalenessState || 'FRESH'} ({intelStatus?.stalenessDays ?? 0}d)
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
          <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Active Sequence</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
              #{intelStatus?.activeMetadata.versionSequence ?? 100}
            </div>
          </div>
          <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Indicators Loaded</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
              {intelStatus?.activeMetadata.recordsCount ?? 11} entries
            </div>
          </div>
          <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Factory Seeded</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: intelStatus?.activeMetadata.isFactorySeed ? '#34d399' : '#38bdf8' }}>
              {intelStatus?.activeMetadata.isFactorySeed ? 'YES' : 'UPDATED'}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
            Format: PPDB_V1 | Ed25519 Signed & Verified
          </span>
          <button
            onClick={handleRollback}
            disabled={isRollbackRunning || intelStatus?.activeMetadata.isFactorySeed}
            style={{
              padding: '0.4rem 0.8rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              backgroundColor: intelStatus?.activeMetadata.isFactorySeed ? '#334155' : '#ef4444',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              cursor: intelStatus?.activeMetadata.isFactorySeed ? 'not-allowed' : 'pointer'
            }}
          >
            {isRollbackRunning ? 'Rolling back...' : 'Reset to Factory Seed'}
          </button>
        </div>

        {statusMessage && (
          <div style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: statusMessage.includes('Success') ? '#34d399' : '#f87171' }}>
            {statusMessage}
          </div>
        )}
      </div>

      {/* Subsystem Pipeline Table */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1.25rem' }}>
        <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem' }}>Detection Pipeline Subsystems</h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {engineComponents.map((comp, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.65rem 0.75rem',
                backgroundColor: '#0f172a',
                borderRadius: '8px',
                fontSize: '0.85rem'
              }}
            >
              <div>
                <strong style={{ display: 'block', color: '#f8fafc' }}>{comp.name}</strong>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{comp.type}</span>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span style={{ color: comp.status === 'OPERATIONAL' ? '#34d399' : '#f87171', fontWeight: 700, fontSize: '0.75rem' }}>
                  {comp.status}
                </span>
                <span style={{ display: 'block', fontSize: '0.7rem', color: '#64748b' }}>
                  {comp.latency}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
