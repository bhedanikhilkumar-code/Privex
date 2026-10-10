import React, { useState } from 'react';
import { useSecurityMonitor } from '../../hooks/useSecurityMonitor';
import { PasswordChecker } from './PasswordChecker';
import { PasswordGenerator } from './PasswordGenerator';
import { NetworkMonitor } from './NetworkMonitor';
import { SecurityAlertBanner } from './SecurityAlertBanner';

export const SecurityDashboardView: React.FC = () => {
  const {
    requests,
    events,
    activeAlerts,
    config,
    updateConfig,
    dismissAlert,
    clearRequests,
    clearEvents,
    simulateRequest,
    simulateBurstRequests
  } = useSecurityMonitor();

  const [activeSection, setActiveSection] = useState<'PASSWORD' | 'NETWORK' | 'EVENTS'>('PASSWORD');
  const [showPasswordChangeModal, setShowPasswordChangeModal] = useState<boolean>(false);

  const suspiciousCount = requests.filter(
    (r) => r.destinationType === 'UNKNOWN_SUSPICIOUS' || r.riskLevel === 'SUSPICIOUS'
  ).length;

  const thirdPartyCount = requests.filter((r) => r.destinationType === 'THIRD_PARTY').length;

  // Determine Overall System Security Status
  let systemStatus: 'Protected' | 'Warning' | 'Attention Required' = 'Protected';
  let systemStatusColor = 'var(--color-safe)';
  let systemStatusBg = 'var(--color-safe-bg)';

  if (activeAlerts.some((a) => a.severity === 'high' || a.severity === 'critical') || suspiciousCount > 0) {
    systemStatus = 'Attention Required';
    systemStatusColor = 'var(--color-danger)';
    systemStatusBg = 'var(--color-danger-bg)';
  } else if (activeAlerts.length > 0 || thirdPartyCount > 20) {
    systemStatus = 'Warning';
    systemStatusColor = '#886000';
    systemStatusBg = 'var(--color-caution-bg)';
  }

  const handleReviewActivity = () => {
    setActiveSection('EVENTS');
  };

  const handleChangePasswordClick = () => {
    setShowPasswordChangeModal(true);
    setActiveSection('PASSWORD');
  };

  return (
    <section aria-labelledby="security-monitor-heading" style={{ maxWidth: '1100px', margin: '0 auto' }}>
      {/* Top Header */}
      <div style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <span
            style={{
              padding: '0.2rem 0.6rem',
              backgroundColor: 'var(--color-brand)',
              color: '#FFFFFF',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              fontWeight: 800,
              textTransform: 'uppercase'
            }}
          >
            PRIVACY-FIRST MONITORING
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            LOCAL-FIRST TELEMETRY • VOLATILE RAM • ZERO CLOUD EGRESS
          </span>
        </div>

        <h2
          id="security-monitor-heading"
          className="font-headline-lg"
          style={{
            letterSpacing: '-0.02em',
            marginBottom: '0.5rem',
            color: 'var(--text-primary)'
          }}
        >
          Password Security &amp; Network Protection
        </h2>
        <p className="font-body-md" style={{ color: 'var(--text-muted)', maxWidth: '750px', lineHeight: 1.5, margin: 0 }}>
          Evaluate credential strength, generate cryptographically secure passwords, monitor application requests,
          and detect suspicious network destinations in real time.
        </p>
      </div>

      {/* Security Alert Banner (if any active alerts) */}
      <SecurityAlertBanner
        alerts={activeAlerts}
        onDismiss={dismissAlert}
        onReviewActivity={handleReviewActivity}
        onChangePasswordClick={handleChangePasswordClick}
      />

      {/* Top System Status & Metric Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1.25rem',
          marginBottom: '2rem'
        }}
      >
        <div
          className="cyber-panel"
          style={{
            backgroundColor: systemStatusBg,
            padding: '1.25rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
            System Status
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 900, color: systemStatusColor, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>{systemStatus === 'Protected' ? '🟢' : systemStatus === 'Warning' ? '🟡' : '🔴'}</span>
            <span>{systemStatus}</span>
          </div>
          <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.4rem', margin: 0 }}>
            {systemStatus === 'Protected'
              ? 'All endpoints verified. Safe traffic patterns.'
              : systemStatus === 'Warning'
              ? 'Unusual activity or multiple third parties observed.'
              : 'Suspicious destination or request spike detected.'}
          </p>
        </div>

        <div
          className="cyber-panel"
          style={{
            backgroundColor: 'var(--bg-card)',
            padding: '1.25rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
            Network Activity
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {requests.length} <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 600 }}>requests</span>
          </div>
          <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.4rem', margin: 0 }}>
            Recorded in volatile rolling memory.
          </p>
        </div>

        <div
          className="cyber-panel"
          style={{
            backgroundColor: 'var(--bg-card)',
            padding: '1.25rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
            Third-Party Requests
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {thirdPartyCount}
          </div>
          <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.4rem', margin: 0 }}>
            CDNs, fonts &amp; external endpoints.
          </p>
        </div>

        <div
          className="cyber-panel"
          style={{
            backgroundColor: 'var(--bg-card)',
            padding: '1.25rem'
          }}
        >
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 800, textTransform: 'uppercase', color: suspiciousCount > 0 ? 'var(--color-danger)' : 'var(--text-muted)', marginBottom: '0.35rem' }}>
            Suspicious Requests
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: suspiciousCount > 0 ? 'var(--color-danger)' : 'var(--text-primary)' }}>
            {suspiciousCount}
          </div>
          <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.4rem', margin: 0 }}>
            Raw IPs, high-abuse TLDs, or anomalies.
          </p>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          marginBottom: '1.5rem',
          borderBottom: '2px solid var(--border-dark)',
          paddingBottom: '0.5rem'
        }}
      >
        <button
          type="button"
          onClick={() => setActiveSection('PASSWORD')}
          className="cut-corner-btn"
          style={{
            padding: '0.65rem 1.25rem',
            backgroundColor: activeSection === 'PASSWORD' ? 'var(--color-brand)' : 'var(--bg-card)',
            color: activeSection === 'PASSWORD' ? '#FFFFFF' : 'var(--text-primary)',
            border: '2px solid var(--border-dark)',
            boxShadow: activeSection === 'PASSWORD' ? 'var(--shadow-brutal-sm)' : 'none',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 800,
            cursor: 'pointer'
          }}
        >
          🔑 Password Security &amp; Generator
        </button>

        <button
          type="button"
          onClick={() => setActiveSection('NETWORK')}
          style={{
            padding: '0.65rem 1.25rem',
            backgroundColor: activeSection === 'NETWORK' ? 'var(--color-brand)' : '#FFFFFF',
            color: activeSection === 'NETWORK' ? '#FFFFFF' : '#111111',
            border: '2px solid var(--border-dark)',
            boxShadow: activeSection === 'NETWORK' ? '2px 2px 0px #111111' : 'none',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 800,
            cursor: 'pointer'
          }}
        >
          🌐 Network &amp; Request Monitor ({requests.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveSection('EVENTS')}
          style={{
            padding: '0.65rem 1.25rem',
            backgroundColor: activeSection === 'EVENTS' ? 'var(--color-brand)' : '#FFFFFF',
            color: activeSection === 'EVENTS' ? '#FFFFFF' : '#111111',
            border: '2px solid var(--border-dark)',
            boxShadow: activeSection === 'EVENTS' ? '2px 2px 0px #111111' : 'none',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            fontWeight: 800,
            cursor: 'pointer'
          }}
        >
          🚨 Security Events &amp; Alerts ({events.length})
        </button>
      </div>

      {/* Main Content Area */}
      {activeSection === 'PASSWORD' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          <PasswordChecker />
          <PasswordGenerator />
        </div>
      )}

      {activeSection === 'NETWORK' && (
        <NetworkMonitor
          requests={requests}
          config={config}
          onClear={clearRequests}
          onSimulateRequest={simulateRequest}
          onSimulateBurst={simulateBurstRequests}
          onUpdateConfig={updateConfig}
        />
      )}

      {activeSection === 'EVENTS' && (
        <div
          style={{
            backgroundColor: '#FFFFFF',
            border: '2px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
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
                EVENT FEED
              </span>
              <h3
                style={{
                  fontFamily: 'var(--font-serif)',
                  fontSize: '1.4rem',
                  fontWeight: 800,
                  margin: '0.4rem 0 0 0',
                  color: '#111111'
                }}
              >
                Recent Security Events
              </h3>
            </div>

            <button
              type="button"
              onClick={clearEvents}
              disabled={events.length === 0}
              style={{
                padding: '0.45rem 0.8rem',
                backgroundColor: '#FFFFFF',
                border: '1px solid var(--border-dark)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem',
                fontWeight: 700,
                cursor: events.length > 0 ? 'pointer' : 'default',
                opacity: events.length > 0 ? 1 : 0.5
              }}
            >
              Clear Events
            </button>
          </div>

          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
            Audit log of security triggers, threshold violations, and protective notifications.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {events.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                Zero security events recorded. System operating nominally.
              </div>
            ) : (
              events.map((evt) => {
                const isCrit = evt.severity === 'critical' || evt.severity === 'high';
                const isMed = evt.severity === 'medium';
                const tagColor = isCrit ? 'var(--color-danger)' : isMed ? 'var(--color-caution)' : 'var(--color-safe)';

                return (
                  <div
                    key={evt.id}
                    style={{
                      border: '1px solid var(--border-dark)',
                      borderLeft: `4px solid ${tagColor}`,
                      backgroundColor: evt.dismissed ? '#FBFBFA' : isCrit ? '#FFF5F3' : '#FFFFFF',
                      padding: '1rem',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '0.75rem'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span
                          style={{
                            padding: '0.15rem 0.4rem',
                            backgroundColor: tagColor,
                            color: isMed ? '#111111' : '#FFFFFF',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.675rem',
                            fontWeight: 800,
                            textTransform: 'uppercase'
                          }}
                        >
                          {evt.severity}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 700 }}>
                          {evt.type}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.875rem', color: '#222222' }}>
                        {evt.message}
                      </div>
                    </div>

                    {!evt.dismissed && (
                      <button
                        type="button"
                        onClick={() => dismissAlert(evt.id)}
                        style={{
                          padding: '0.25rem 0.5rem',
                          backgroundColor: '#FFFFFF',
                          border: '1px solid var(--border-dark)',
                          fontSize: '0.7rem',
                          fontFamily: 'var(--font-mono)',
                          cursor: 'pointer'
                        }}
                      >
                        Dismiss
                      </button>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Password Change Modal / Dialog */}
      {showPasswordChangeModal && (
        <div
          role="dialog"
          aria-modal="true"
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: '1rem'
          }}
        >
          <div
            style={{
              backgroundColor: '#FFFFFF',
              border: '2px solid var(--border-dark)',
              boxShadow: 'var(--shadow-brutal-lg)',
              padding: '2rem',
              maxWidth: '500px',
              width: '100%'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ fontFamily: 'var(--font-serif)', fontSize: '1.35rem', fontWeight: 800, margin: 0 }}>
                🔐 Account Security Notice
              </h3>
              <button
                type="button"
                onClick={() => setShowPasswordChangeModal(false)}
                style={{ background: 'none', border: 'none', fontSize: '1.25rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: '1.25rem' }}>
              We detected unusual activity in recent requests. For maximum digital protection, ensure that you update your account
              credentials using a unique high-entropy password.
            </p>

            <div
              style={{
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border-dark)',
                padding: '0.85rem',
                fontSize: '0.8rem',
                fontFamily: 'var(--font-mono)',
                marginBottom: '1.5rem'
              }}
            >
              ✓ Password update instructions sent to volatile state.
              <br />
              ✓ Use the generator below to create a 16+ character password.
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setShowPasswordChangeModal(false)}
                style={{
                  padding: '0.6rem 1.25rem',
                  backgroundColor: 'var(--color-brand)',
                  color: '#FFFFFF',
                  border: '2px solid var(--border-dark)',
                  boxShadow: '2px 2px 0px #111111',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.8rem',
                  fontWeight: 800,
                  cursor: 'pointer'
                }}
              >
                Got It, Thank You
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
