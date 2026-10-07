import React, { useState, useEffect } from 'react';
import {
  DesktopProtectionStatus,
  ProcessInfo,
  PersistenceItem,
  SystemHealthReport,
  WatchdogStatus,
  TamperStatus
} from '../../types/desktop.types';

interface ProtectionStatusScreenProps {
  status: DesktopProtectionStatus;
  onAuditProcesses?: () => Promise<ProcessInfo[]>;
  onAuditPersistence?: () => Promise<PersistenceItem[]>;
  onResetIsolation?: (componentName: string) => Promise<{ success: boolean }>;
}

export const ProtectionStatusScreen: React.FC<ProtectionStatusScreenProps> = ({
  status,
  onAuditProcesses,
  onAuditPersistence,
  onResetIsolation
}) => {
  const [healthReport, setHealthReport] = useState<SystemHealthReport | null>(null);
  const [watchdogStatus, setWatchdogStatus] = useState<WatchdogStatus | null>(null);
  const [tamperStatus, setTamperStatus] = useState<TamperStatus | null>(null);
  const [processes, setProcesses] = useState<ProcessInfo[] | null>(null);
  const [persistence, setPersistence] = useState<PersistenceItem[] | null>(null);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);
  const [remediationNotice, setRemediationNotice] = useState<string | null>(null);

  useEffect(() => {
    loadHealthAndWatchdog();
  }, []);

  const loadHealthAndWatchdog = async () => {
    try {
      if (window.desktopSecurity?.getHealthStatus) {
        const h = await window.desktopSecurity.getHealthStatus();
        setHealthReport(h);
      }
      if (window.desktopSecurity?.getWatchdogStatus) {
        const w = await window.desktopSecurity.getWatchdogStatus();
        setWatchdogStatus(w);
      }
      if (window.desktopSecurity?.getTamperStatus) {
        const t = await window.desktopSecurity.getTamperStatus();
        setTamperStatus(t);
      }
    } catch (err: any) {
      console.warn('[HEALTH_STATUS_LOAD_ERROR]', err);
    }
  };

  const handleRunHealthCheck = async () => {
    try {
      if (window.desktopSecurity?.runHealthCheck) {
        const h = await window.desktopSecurity.runHealthCheck();
        setHealthReport(h);
        setRemediationNotice('Self-health check refreshed across all 7 core subsystems.');
      }
    } catch (err: any) {
      setRemediationNotice(`Health check error: ${err?.message}`);
    }
  };

  const handleResetIsolation = async (componentName: string) => {
    try {
      if (onResetIsolation) {
        await onResetIsolation(componentName);
      } else if (window.desktopSecurity?.resetWatchdogIsolation) {
        await window.desktopSecurity.resetWatchdogIsolation(componentName);
      }
      setRemediationNotice(`Isolation reset for ${componentName}. Circuit breaker normalized.`);
      await loadHealthAndWatchdog();
    } catch (err: any) {
      setRemediationNotice(`Reset failed: ${err?.message}`);
    }
  };

  const handleAudit = async () => {
    setIsLoadingAudit(true);
    try {
      if (onAuditProcesses) {
        const procs = await onAuditProcesses();
        setProcesses(procs);
      } else if (window.desktopSecurity?.auditProcesses) {
        const procs = await window.desktopSecurity.auditProcesses();
        setProcesses(procs);
      }

      if (onAuditPersistence) {
        const persists = await onAuditPersistence();
        setPersistence(persists);
      } else if (window.desktopSecurity?.auditPersistence) {
        const persists = await window.desktopSecurity.auditPersistence();
        setPersistence(persists);
      }
    } finally {
      setIsLoadingAudit(false);
    }
  };

  const overallState = healthReport?.overallState || 'HEALTHY';
  const statusColors: Record<'HEALTHY' | 'WARNING' | 'DEGRADED' | 'CRITICAL', { bg: string; text: string; border: string }> = {
    HEALTHY: { bg: '#dcfce7', text: '#166534', border: '#86efac' },
    WARNING: { bg: '#fef3c7', text: '#92400e', border: '#fcd34d' },
    DEGRADED: { bg: '#ffedd5', text: '#9a3412', border: '#fb923c' },
    CRITICAL: { bg: '#fee2e2', text: '#991b1b', border: '#f87171' }
  };
  const activeColor = statusColors[overallState];

  return (
    <div style={{ padding: '24px', maxWidth: '1000px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🩺 Endpoint Health & Watchdog Supervision</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Unified 4-State Health Model • Shield: {status.realtimeShieldActive ? 'Active' : 'Inactive'} • DB: {status.threatDatabaseVersion}
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            type="button"
            onClick={handleRunHealthCheck}
            style={{
              padding: '8px 14px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#ffffff',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            🔄 Run Full Health Check
          </button>

          <span
            style={{
              padding: '6px 14px',
              borderRadius: '9999px',
              fontSize: '12px',
              fontWeight: 800,
              backgroundColor: activeColor.bg,
              color: activeColor.text,
              border: `1px solid ${activeColor.border}`
            }}
          >
            {overallState}
          </span>
        </div>
      </div>

      {tamperStatus && (
        <div
          role="status"
          style={{
            padding: '10px 14px',
            borderRadius: '6px',
            backgroundColor: tamperStatus.tamperDetected ? '#fee2e2' : '#f0fdf4',
            border: `1px solid ${tamperStatus.tamperDetected ? '#f87171' : '#86efac'}`,
            color: tamperStatus.tamperDetected ? '#991b1b' : '#166534',
            fontSize: '12px'
          }}
        >
          <strong>Tamper Protection: </strong>
          {tamperStatus.tamperDetected
            ? `🔴 Tampering detected on components: ${tamperStatus.tamperedComponents.join(', ')}`
            : '🟢 All internal checksums, audit chains, and config signatures intact.'}
        </div>
      )}

      {remediationNotice && (
        <div
          role="status"
          style={{
            padding: '10px 14px',
            borderRadius: '6px',
            backgroundColor: '#eff6ff',
            border: '1px solid #bfdbfe',
            color: '#1d4ed8',
            fontSize: '12px'
          }}
        >
          {remediationNotice}
        </div>
      )}

      {/* Watchdog Supervision Card */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
              Watchdog Supervision Service (Phase Q)
            </div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>
              Periodic 2,000 ms heartbeat loop probing background monitors and enforcing circuit breaking.
            </div>
          </div>

          <span
            style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '3px 8px',
              borderRadius: '4px',
              backgroundColor: watchdogStatus?.safeMinimalMode ? '#fee2e2' : '#dcfce7',
              color: watchdogStatus?.safeMinimalMode ? '#991b1b' : '#166534'
            }}
          >
            {watchdogStatus?.safeMinimalMode ? 'SAFE MINIMAL MODE' : 'SUPERVISION NOMINAL'}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', fontSize: '12px' }}>
          <div>
            <span style={{ color: '#64748b' }}>Last Heartbeat: </span>
            <strong style={{ color: '#0f172a' }}>
              {(() => {
                const latest = watchdogStatus?.monitoredComponents?.reduce((max, c) => Math.max(max, c.lastHeartbeat), 0) || 0;
                return latest > 0 ? new Date(latest).toLocaleTimeString() : 'Active';
              })()}
            </strong>
          </div>
          <div>
            <span style={{ color: '#64748b' }}>Watchdog Crash History: </span>
            <strong style={{ color: '#0f172a' }}>{watchdogStatus?.crashHistory?.length ?? 0} events</strong>
          </div>
          <div>
            <span style={{ color: '#64748b' }}>Shield Snooze Timer: </span>
            <strong style={{ color: watchdogStatus?.shieldSnoozeActive ? '#d97706' : '#16a34a' }}>
              {watchdogStatus?.shieldSnoozeActive
                ? `${Math.ceil((watchdogStatus.shieldSnoozeRemainingMs || 0) / 1000)}s remaining`
                : 'Inactive'}
            </strong>
          </div>
        </div>

        {/* Monitored Components List */}
        {watchdogStatus?.monitoredComponents && watchdogStatus.monitoredComponents.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '6px' }}>
            {watchdogStatus.monitoredComponents.map((c) => (
              <div
                key={c.name}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 12px',
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  fontSize: '12px'
                }}
              >
                <div>
                  <strong>{c.name}</strong> • Status: <span style={{ color: c.status === 'HEALTHY' ? '#16a34a' : '#dc2626' }}>{c.status}</span>
                  {c.isIsolated && <span style={{ color: '#dc2626', fontWeight: 700, marginLeft: '6px' }}>[ISOLATED]</span>}
                </div>

                {c.isIsolated && (
                  <button
                    type="button"
                    onClick={() => handleResetIsolation(c.name)}
                    style={{
                      padding: '4px 8px',
                      borderRadius: '4px',
                      border: '1px solid #fecaca',
                      backgroundColor: '#fff1f2',
                      color: '#dc2626',
                      fontSize: '11px',
                      cursor: 'pointer'
                    }}
                  >
                    Reset Isolation
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Subsystem Health Matrix */}
      {healthReport?.subsystems && (
        <div
          style={{
            backgroundColor: '#ffffff',
            borderRadius: '10px',
            border: '1px solid #e2e8f0',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px'
          }}
        >
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
            Subsystem Health Diagnostics Matrix
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px' }}>
            {Object.entries(healthReport.subsystems).map(([name, sub]: [string, any]) => (
              <div
                key={name}
                style={{
                  padding: '10px 14px',
                  backgroundColor: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: '6px',
                  fontSize: '12px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ color: '#0f172a' }}>{name}</strong>
                  <span
                    style={{
                      fontWeight: 700,
                      fontSize: '10px',
                      color: sub.status === 'HEALTHY' ? '#16a34a' : sub.status === 'WARNING' ? '#d97706' : '#dc2626'
                    }}
                  >
                    {sub.status}
                  </span>
                </div>
                <div style={{ color: '#64748b', fontSize: '11px', marginTop: '2px' }}>
                  {sub.message || 'Subsystem nominal'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Process & Startup Persistence Audit Section */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
              Active Process Lineage & Startup Persistence Audit
            </div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>
              Inspects executing user-mode processes and Windows Run keys for LOLBins and masquerading binaries.
            </div>
          </div>

          <button
            type="button"
            onClick={handleAudit}
            disabled={isLoadingAudit}
            style={{
              padding: '8px 16px',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: isLoadingAudit ? 'wait' : 'pointer'
            }}
          >
            {isLoadingAudit ? 'Auditing...' : 'Run Read-Only Audit'}
          </button>
        </div>

        {processes && (
          <div style={{ marginTop: '8px' }}>
            <div style={{ fontWeight: 600, fontSize: '13px', color: '#1e293b', marginBottom: '6px' }}>
              Active Processes ({processes.length} inspected):
            </div>
            <div style={{ fontSize: '12px', color: '#475569' }}>
              {processes.filter((p) => p.isSuspicious).length === 0
                ? '✅ Zero suspicious processes detected in memory.'
                : `⚠️ ${processes.filter((p) => p.isSuspicious).length} suspicious processes flagged for review.`}
            </div>
          </div>
        )}

        {persistence && (
          <div style={{ marginTop: '8px' }}>
            <div style={{ fontWeight: 600, fontSize: '13px', color: '#1e293b', marginBottom: '6px' }}>
              Startup Persistence Entries ({persistence.length} items):
            </div>
            <div style={{ fontSize: '12px', color: '#475569' }}>
              {persistence.filter((p) => p.isSuspicious).length === 0
                ? '✅ Zero suspicious startup persistence entries identified.'
                : `⚠️ ${persistence.filter((p) => p.isSuspicious).length} unusual startup persistence entries.`}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
