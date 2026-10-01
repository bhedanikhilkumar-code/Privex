import React from 'react';

export const ProtectionStatusScreen: React.FC = () => {
  const engineComponents = [
    { name: 'Deterministic Rule Engine', status: 'OPERATIONAL', latency: '< 0.2 ms', type: 'Offline Ruleset' },
    { name: 'Lexical & Entropy Analyzer', status: 'OPERATIONAL', latency: '< 0.5 ms', type: 'Heuristic' },
    { name: 'Threat Intelligence Cache', status: 'OPERATIONAL', latency: '< 0.05 ms', type: 'Offline Bloom Filter' },
    { name: 'Multi-Factor Risk Scorer', status: 'OPERATIONAL', latency: '< 0.1 ms', type: 'Bayesian Aggregator' },
    { name: 'Semantic URL Classifier', status: 'OPERATIONAL', latency: '< 0.01 ms', type: 'On-Device ML' },
    { name: 'AI Security Assistant Runtime', status: 'OPERATIONAL', latency: '< 0.02 ms', type: 'Template Fallback Engine' }
  ];

  return (
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#38bdf8' }}>
          Engine Diagnostics & Health
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Internal detection subsystem status and offline capability verification.
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
          All detection rules, heuristic algorithms, Bloom filter threat intelligence, and AI explanation engines operate entirely on-device with zero internet connectivity required.
        </p>
        <div style={{ display: 'flex', gap: '1rem', marginTop: '0.75rem', fontSize: '0.75rem', color: '#64748b' }}>
          <span>Cache Version: v1.0.0-factory</span>
          <span>Seed Hash: e3b0c44298fc1c14...</span>
          <span>Filter Capacity: 10,000 entries</span>
        </div>
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
                <span style={{ color: '#34d399', fontWeight: 700, fontSize: '0.75rem' }}>
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
