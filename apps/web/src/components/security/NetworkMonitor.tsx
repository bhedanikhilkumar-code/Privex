import React, { useState } from 'react';
import { MonitoredRequest, NetworkMonitorConfig } from '../../lib/security/request-monitor';

interface NetworkMonitorProps {
  requests: MonitoredRequest[];
  config: NetworkMonitorConfig;
  onClear: () => void;
  onSimulateRequest: (url: string, method?: string, status?: number) => void;
  onSimulateBurst: (domain: string, count?: number) => void;
  onUpdateConfig: (config: Partial<NetworkMonitorConfig>) => void;
}

export const NetworkMonitor: React.FC<NetworkMonitorProps> = ({
  requests,
  config,
  onClear,
  onSimulateRequest,
  onSimulateBurst,
  onUpdateConfig
}) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [showConfig, setShowConfig] = useState<boolean>(false);
  const [burstDomain, setBurstDomain] = useState<string>('analytics-tracker.com');

  const filteredRequests = requests.filter((r) => {
    if (filterType === 'ALL') return true;
    if (filterType === 'FIRST_PARTY') return r.destinationType === 'FIRST_PARTY';
    if (filterType === 'THIRD_PARTY') return r.destinationType === 'THIRD_PARTY';
    if (filterType === 'SUSPICIOUS') return r.destinationType === 'UNKNOWN_SUSPICIOUS' || r.riskLevel === 'SUSPICIOUS';
    return true;
  });

  const firstPartyCount = requests.filter((r) => r.destinationType === 'FIRST_PARTY').length;
  const thirdPartyCount = requests.filter((r) => r.destinationType === 'THIRD_PARTY').length;
  const suspiciousCount = requests.filter(
    (r) => r.destinationType === 'UNKNOWN_SUSPICIOUS' || r.riskLevel === 'SUSPICIOUS'
  ).length;

  return (
    <div
      className="cyber-panel"
      style={{
        backgroundColor: 'var(--bg-card)',
        padding: '1.75rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem'
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <span
            style={{
              padding: '0.2rem 0.5rem',
              backgroundColor: 'var(--color-brand)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              fontWeight: 800,
              textTransform: 'uppercase'
            }}
          >
            ACTIVE RUNTIME TELEMETRY
          </span>
          <h3
            style={{
              fontFamily: 'var(--font-serif)',
              fontSize: '1.4rem',
              fontWeight: 800,
              margin: '0.4rem 0 0 0',
              color: 'var(--text-primary)'
            }}
          >
            URL &amp; Network Request Monitor
          </h3>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            onClick={() => setShowConfig(!showConfig)}
            style={{
              padding: '0.45rem 0.8rem',
              backgroundColor: '#FFFFFF',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            ⚙️ Thresholds
          </button>
          <button
            type="button"
            onClick={onClear}
            disabled={requests.length === 0}
            style={{
              padding: '0.45rem 0.8rem',
              backgroundColor: '#FFFFFF',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: requests.length > 0 ? 'pointer' : 'default',
              opacity: requests.length > 0 ? 1 : 0.5
            }}
          >
            Clear Log
          </button>
        </div>
      </div>

      <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
        Monitors application network requests in volatile RAM to detect unknown third parties, suspicious destinations, and request overload spikes.
        All query parameters containing sensitive tokens are automatically redacted.
      </p>

      {/* Config Drawer */}
      {showConfig && (
        <div
          style={{
            backgroundColor: 'var(--bg-secondary)',
            border: '2px solid var(--border-dark)',
            padding: '1rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem'
          }}
        >
          <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
            Overload Detection Thresholds:
          </strong>
          <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
            <label style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
              Request Threshold (per window):
              <input
                type="number"
                min="5"
                max="200"
                value={config.requestOverloadThreshold}
                onChange={(e) =>
                  onUpdateConfig({ requestOverloadThreshold: parseInt(e.target.value, 10) || 50 })
                }
                style={{ marginLeft: '0.5rem', padding: '0.2rem 0.4rem', width: '70px', border: '1px solid var(--border-dark)' }}
              />
            </label>

            <label style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
              Time Window (ms):
              <input
                type="number"
                step="1000"
                min="1000"
                max="60000"
                value={config.timeWindowMs}
                onChange={(e) =>
                  onUpdateConfig({ timeWindowMs: parseInt(e.target.value, 10) || 10000 })
                }
                style={{ marginLeft: '0.5rem', padding: '0.2rem 0.4rem', width: '85px', border: '1px solid var(--border-dark)' }}
              />
            </label>
          </div>
        </div>
      )}

      {/* Stats Summary Bar */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: '0.75rem'
        }}
      >
        <div
          style={{
            backgroundColor: '#FAFAF8',
            border: '1px solid var(--border-dark)',
            padding: '0.85rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Total Monitored
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {requests.length}
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'var(--color-safe-bg)',
            border: '1px solid var(--border-dark)',
            padding: '0.85rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--color-safe)', textTransform: 'uppercase', fontWeight: 700 }}>
            First-Party
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {firstPartyCount}
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'var(--color-caution-bg)',
            border: '1px solid var(--border-dark)',
            padding: '0.85rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: '#886000', textTransform: 'uppercase', fontWeight: 700 }}>
            Third-Party
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
            {thirdPartyCount}
          </div>
        </div>

        <div
          style={{
            backgroundColor: suspiciousCount > 0 ? 'var(--color-danger-bg)' : '#FAFAF8',
            border: '1px solid var(--border-dark)',
            padding: '0.85rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: suspiciousCount > 0 ? 'var(--color-danger)' : 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
            Suspicious / Unknown
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: suspiciousCount > 0 ? 'var(--color-danger)' : '#111111' }}>
            {suspiciousCount}
          </div>
        </div>
      </div>

      {/* Simulator Quick Testing Bar */}
      <div
        style={{
          border: '1px solid var(--border-dark)',
          backgroundColor: '#FAFAF8',
          padding: '0.85rem 1rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', fontWeight: 700, textTransform: 'uppercase' }}>
            Traffic Simulator:
          </span>
          <button
            type="button"
            onClick={() => onSimulateRequest('https://localhost:8080/api/v1/health')}
            style={{
              padding: '0.25rem 0.55rem',
              backgroundColor: '#FFFFFF',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              cursor: 'pointer'
            }}
          >
            + 1st Party Request
          </button>
          <button
            type="button"
            onClick={() => onSimulateRequest('https://cdnjs.cloudflare.com/ajax/libs/react/18.3.1/umd/react.production.min.js')}
            style={{
              padding: '0.25rem 0.55rem',
              backgroundColor: '#FFFFFF',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              cursor: 'pointer'
            }}
          >
            + 3rd Party CDN
          </button>
          <button
            type="button"
            onClick={() => onSimulateRequest('http://192.168.1.105/exfiltrate?token=secret9988')}
            style={{
              padding: '0.25rem 0.55rem',
              backgroundColor: 'var(--color-danger-bg)',
              color: 'var(--color-danger)',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.7rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            + Suspicious Raw IP &amp; Token
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <input
            type="text"
            value={burstDomain}
            onChange={(e) => setBurstDomain(e.target.value)}
            aria-label="Target domain for overload burst simulation"
            style={{
              padding: '0.2rem 0.4rem',
              fontSize: '0.7rem',
              fontFamily: 'var(--font-mono)',
              border: '1px solid var(--border-dark)',
              width: '150px'
            }}
          />
          <button
            type="button"
            onClick={() => onSimulateBurst(burstDomain, config.requestOverloadThreshold + 2)}
            style={{
              padding: '0.3rem 0.7rem',
              backgroundColor: 'var(--color-caution)',
              color: '#111111',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.725rem',
              fontWeight: 800,
              cursor: 'pointer'
            }}
          >
            ⚡ Trigger High Activity Burst ({config.requestOverloadThreshold + 2} reqs)
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
        {[
          { key: 'ALL', label: `All (${requests.length})` },
          { key: 'FIRST_PARTY', label: `1st Party (${firstPartyCount})` },
          { key: 'THIRD_PARTY', label: `3rd Party (${thirdPartyCount})` },
          { key: 'SUSPICIOUS', label: `Suspicious (${suspiciousCount})` }
        ].map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setFilterType(tab.key)}
            style={{
              padding: '0.35rem 0.75rem',
              backgroundColor: filterType === tab.key ? 'var(--color-brand)' : '#FFFFFF',
              color: filterType === tab.key ? '#FFFFFF' : '#111111',
              border: '1px solid var(--border-dark)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Request Table / Log */}
      <div style={{ maxHeight: '360px', overflowY: 'auto', border: '1px solid var(--border-dark)' }}>
        {filteredRequests.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
            No network requests recorded matching filter. Use the Traffic Simulator above to generate test requests.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-secondary)', borderBottom: '1px solid var(--border-dark)', textAlign: 'left' }}>
                <th style={{ padding: '0.5rem 0.75rem' }}>Status</th>
                <th style={{ padding: '0.5rem 0.75rem' }}>Method</th>
                <th style={{ padding: '0.5rem 0.75rem' }}>Destination</th>
                <th style={{ padding: '0.5rem 0.75rem' }}>Type</th>
                <th style={{ padding: '0.5rem 0.75rem' }}>Risk Indicator</th>
                <th style={{ padding: '0.5rem 0.75rem' }}>Sanitized URL</th>
              </tr>
            </thead>
            <tbody>
              {filteredRequests.map((req, idx) => {
                let badgeColor = 'var(--color-safe)';
                let badgeText = '✓ Safe';
                let leftBorderColor = 'var(--color-safe)';
                if (req.riskLevel === 'SUSPICIOUS' || req.destinationType === 'UNKNOWN_SUSPICIOUS') {
                  badgeColor = 'var(--color-danger)';
                  badgeText = '🔴 Suspicious';
                  leftBorderColor = 'var(--color-danger)';
                } else if (req.riskLevel === 'WARNING') {
                  badgeColor = 'var(--color-caution)';
                  badgeText = '⚠ Warning';
                  leftBorderColor = 'var(--color-caution)';
                } else if (req.destinationType === 'THIRD_PARTY') {
                  leftBorderColor = 'var(--motion-color-cyber)';
                }

                return (
                  <tr
                    key={req.id}
                    className={idx < 8 ? 'motion-fade-down' : ''}
                    style={{
                      borderBottom: '1px solid #EEEEEE',
                      borderLeft: `3px solid ${leftBorderColor}`,
                      backgroundColor: req.riskLevel === 'SUSPICIOUS' ? '#FFF5F3' : '#FFFFFF',
                      transition: 'background-color var(--motion-duration-micro) var(--motion-ease-standard)'
                    }}
                  >
                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span
                        style={{
                          padding: '0.1rem 0.35rem',
                          backgroundColor: req.status === 200 ? 'var(--color-safe-bg)' : '#F3F3F3',
                          border: '1px solid var(--border-dark)',
                          fontSize: '0.7rem',
                          fontWeight: 700
                        }}
                      >
                        {req.status ?? '—'}
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem', fontWeight: 700 }}>
                      {req.method}
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem', fontWeight: 700, color: '#111111' }}>
                      {req.domain}
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span
                        style={{
                          fontSize: '0.7rem',
                          padding: '0.1rem 0.4rem',
                          backgroundColor: req.destinationType === 'FIRST_PARTY' ? '#EAEAEA' : '#FAF3DF',
                          border: '1px solid #CCC'
                        }}
                      >
                        {req.destinationType}
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem', color: badgeColor, fontWeight: 700 }}>
                      {badgeText}
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                      {req.url}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
