import React from 'react';
import { DesktopNavTab } from '../components/Sidebar';
import {
  DesktopProtectionStatus,
  SystemHealthReport,
  WatchdogStatus,
  ThreatIntelStatus,
  RansomwareShieldStatus,
  ScanSchedulerState
} from '../../types/desktop.types';

interface HomeScreenProps {
  onNavigate: (tab: DesktopNavTab) => void;
  threatsCount?: number;
  quarantineCount?: number;
  filesScannedTotal?: number;
  status: DesktopProtectionStatus;
  healthReport?: SystemHealthReport | null;
  watchdogStatus?: WatchdogStatus | null;
  threatIntelStatus?: ThreatIntelStatus | null;
  ransomwareStatus?: RansomwareShieldStatus | null;
  schedulerState?: ScanSchedulerState | null;
  onQuickScanLaunch?: () => void;
  onReEnableShield?: () => void;
}

export const HomeScreen: React.FC<HomeScreenProps> = ({
  onNavigate,
  threatsCount = 0,
  quarantineCount = 0,
  filesScannedTotal = 0,
  status,
  healthReport,
  watchdogStatus,
  threatIntelStatus,
  ransomwareStatus,
  schedulerState,
  onQuickScanLaunch,
  onReEnableShield
}) => {
  // Derive authoritative 3-tier posture state from real backend
  const isCritical =
    threatsCount > 0 ||
    healthReport?.overallState === 'CRITICAL' ||
    healthReport?.overallState === 'DEGRADED' ||
    !status.realtimeShieldActive && !watchdogStatus?.shieldSnoozeActive;

  const isAttention =
    !isCritical &&
    (healthReport?.overallState === 'WARNING' ||
      watchdogStatus?.shieldSnoozeActive ||
      threatIntelStatus?.stalenessState === 'STALE' ||
      threatIntelStatus?.stalenessState === 'EXPIRED_CACHE');

  const postureState: 'PROTECTED' | 'ATTENTION' | 'ACTION_REQUIRED' = isCritical
    ? 'ACTION_REQUIRED'
    : isAttention
    ? 'ATTENTION'
    : 'PROTECTED';

  const postureTheme = {
    PROTECTED: {
      title: '🟢 System Protected',
      subtitle: 'All real-time shields are active, definitions are verified, and no threats are present.',
      bg: '#f0fdf4',
      border: '#86efac',
      titleColor: '#166534',
      textColor: '#15803d',
      buttonBg: '#16a34a',
      buttonText: '#ffffff',
      buttonLabel: '⚡ Run Quick Scan',
      action: onQuickScanLaunch || (() => onNavigate('quick-scan'))
    },
    ATTENTION: {
      title: '🟡 Attention Required',
      subtitle: watchdogStatus?.shieldSnoozeActive
        ? `Real-Time Shield is snoozed (resumes automatically in ${Math.ceil((watchdogStatus.shieldSnoozeRemainingMs || 0) / 1000)}s).`
        : 'A protection subsystem reported a warning. Inspect health diagnostics.',
      bg: '#fffbeb',
      border: '#fcd34d',
      titleColor: '#92400e',
      textColor: '#b45309',
      buttonBg: '#d97706',
      buttonText: '#ffffff',
      buttonLabel: watchdogStatus?.shieldSnoozeActive ? '🛡️ Resume Shield Now' : '🩺 Inspect Health',
      action: watchdogStatus?.shieldSnoozeActive && onReEnableShield ? onReEnableShield : () => onNavigate('status')
    },
    ACTION_REQUIRED: {
      title: '🔴 Action Required',
      subtitle: threatsCount > 0
        ? `${threatsCount} unquarantined threat(s) detected on your computer!`
        : 'Real-time protection is disabled or a critical component failed.',
      bg: '#fef2f2',
      border: '#f87171',
      titleColor: '#991b1b',
      textColor: '#b91c1c',
      buttonBg: '#dc2626',
      buttonText: '#ffffff',
      buttonLabel: threatsCount > 0 ? '☣️ Quarantine Threats Now' : '🛡️ Enable Real-Time Shield',
      action: threatsCount > 0 ? () => onNavigate('results') : (onReEnableShield || (() => onNavigate('realtime')))
    }
  }[postureState];

  return (
    <div
      style={{
        padding: '24px',
        maxWidth: '1040px',
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        gap: '24px'
      }}
    >
      {/* 3-Tier Posture Hero Banner */}
      <section
        role="region"
        aria-labelledby="dashboard-posture-title"
        style={{
          backgroundColor: postureTheme.bg,
          border: `2px solid ${postureTheme.border}`,
          borderRadius: '12px',
          padding: '24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          boxShadow: '0 2px 4px rgba(0,0,0,0.02)'
        }}
      >
        <div style={{ maxWidth: '640px' }}>
          <h2
            id="dashboard-posture-title"
            style={{
              margin: '0 0 6px 0',
              fontSize: '22px',
              fontWeight: 800,
              color: postureTheme.titleColor
            }}
          >
            {postureTheme.title}
          </h2>
          <p style={{ margin: 0, fontSize: '14px', color: postureTheme.textColor, lineHeight: 1.5 }}>
            {postureTheme.subtitle}
          </p>

          <div
            style={{
              display: 'flex',
              gap: '12px',
              marginTop: '14px',
              fontSize: '12px',
              color: postureTheme.titleColor
            }}
          >
            <span>• 100% On-Device Processing</span>
            <span>• Zero Cloud Telemetry</span>
            <span>• Ed25519 Signed Definitions</span>
          </div>
        </div>

        <button
          type="button"
          onClick={postureTheme.action}
          style={{
            backgroundColor: postureTheme.buttonBg,
            color: postureTheme.buttonText,
            border: 'none',
            borderRadius: '8px',
            padding: '12px 20px',
            fontSize: '14px',
            fontWeight: 700,
            cursor: 'pointer',
            boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
            whiteSpace: 'nowrap'
          }}
        >
          {postureTheme.buttonLabel}
        </button>
      </section>

      {/* 4-Metric Overview Counters */}
      <section
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '16px'
        }}
      >
        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '16px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0'
          }}
        >
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, letterSpacing: '0.05em' }}>
            FILES INSPECTED
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#0f172a', marginTop: '4px' }}>
            {filesScannedTotal.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: '#16a34a', marginTop: '4px' }}>CleanFileCache Active</div>
        </div>

        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '16px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0'
          }}
        >
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, letterSpacing: '0.05em' }}>
            ACTIVE THREATS
          </div>
          <div
            style={{
              fontSize: '24px',
              fontWeight: 800,
              color: threatsCount > 0 ? '#dc2626' : '#16a34a',
              marginTop: '4px'
            }}
          >
            {threatsCount}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
            {threatsCount > 0 ? 'Requires attention' : 'Clean endpoint'}
          </div>
        </div>

        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '16px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0'
          }}
        >
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, letterSpacing: '0.05em' }}>
            QUARANTINE VAULT
          </div>
          <div style={{ fontSize: '24px', fontWeight: 800, color: '#f59e0b', marginTop: '4px' }}>
            {quarantineCount}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>PPVAULT2 encrypted blobs</div>
        </div>

        <div
          style={{
            backgroundColor: '#ffffff',
            padding: '16px',
            borderRadius: '8px',
            border: '1px solid #e2e8f0'
          }}
        >
          <div style={{ fontSize: '11px', color: '#64748b', fontWeight: 700, letterSpacing: '0.05em' }}>
            THREAT DEFINITIONS
          </div>
          <div style={{ fontSize: '18px', fontWeight: 800, color: '#0f172a', marginTop: '8px' }}>
            Seq #{threatIntelStatus?.currentVersionSequence ?? 1}
          </div>
          <div style={{ fontSize: '11px', color: '#0284c7', marginTop: '4px' }}>
            {threatIntelStatus?.installedVersion || 'Embedded seed'}
          </div>
        </div>
      </section>

      {/* Subsystems Live Status Grid */}
      <section>
        <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', color: '#0f172a', fontWeight: 700 }}>
          Protection Subsystem Matrix
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px' }}>
          {/* Real-Time Shield */}
          <div
            onClick={() => onNavigate('realtime')}
            style={{
              backgroundColor: '#ffffff',
              padding: '14px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>🛡️ Real-Time Shield</span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: status.realtimeShieldActive ? '#16a34a' : '#dc2626'
                }}
              >
                {status.realtimeShieldActive ? 'ACTIVE' : watchdogStatus?.shieldSnoozeActive ? 'SNOOZED' : 'DISABLED'}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
              Monitoring: {status.monitoredPaths.join(', ') || 'Downloads, Temp'}
            </div>
          </div>

          {/* Ransomware Shield */}
          <div
            onClick={() => onNavigate('ransomware')}
            style={{
              backgroundColor: '#ffffff',
              padding: '14px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>🔒 Ransomware Shield</span>
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#16a34a' }}>
                {ransomwareStatus?.mode === 'strict' ? 'STRICT' : 'SMART'}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
              Canaries: {ransomwareStatus?.activeCanariesCount ?? 3} Active • Protected Folders: {ransomwareStatus?.protectedFolders?.length ?? 3}
            </div>
          </div>

          {/* Web & MOTW Protection */}
          <div
            onClick={() => onNavigate('web-protection')}
            style={{
              backgroundColor: '#ffffff',
              padding: '14px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>🌐 Web Protection</span>
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#16a34a' }}>ON-DEVICE</span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
              NTFS :Zone.Identifier inspection • Phishing scanner
            </div>
          </div>

          {/* Scheduled Scanning */}
          <div
            onClick={() => onNavigate('scheduled-scan')}
            style={{
              backgroundColor: '#ffffff',
              padding: '14px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>📅 Scheduled Scans</span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: schedulerState?.config?.enabled ? '#16a34a' : '#64748b'
                }}
              >
                {schedulerState?.config?.enabled ? 'SCHEDULED' : 'DISABLED'}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
              {schedulerState?.config?.frequency
                ? `${schedulerState.config.frequency.toUpperCase()} at ${schedulerState.config.timeOfDay}`
                : 'Configured for daily quick scan'}
            </div>
          </div>

          {/* Watchdog & Health */}
          <div
            onClick={() => onNavigate('status')}
            style={{
              backgroundColor: '#ffffff',
              padding: '14px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>🩺 Watchdog Health</span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: watchdogStatus?.safeMinimalMode ? '#dc2626' : '#16a34a'
                }}
              >
                {watchdogStatus?.safeMinimalMode ? 'CIRCUIT OPEN' : '2,000ms LOOP'}
              </span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
              Auto-recovery armed • Health: {healthReport?.overallState || 'HEALTHY'}
            </div>
          </div>

          {/* Forensic Audit Log */}
          <div
            onClick={() => onNavigate('history')}
            style={{
              backgroundColor: '#ffffff',
              padding: '14px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#1e293b' }}>📜 Forensic Audit</span>
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#16a34a' }}>HMAC CHAIN</span>
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
              Append-only tamper-evident audit trail (RULE-18 scrubbed)
            </div>
          </div>
        </div>
      </section>

      {/* Quick Launch Scanning Cards */}
      <section>
        <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', color: '#0f172a', fontWeight: 700 }}>
          On-Demand Security Scans
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          <div
            onClick={() => onNavigate('quick-scan')}
            style={{
              backgroundColor: '#ffffff',
              padding: '18px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer',
              transition: 'border-color 0.15s ease'
            }}
          >
            <div style={{ fontSize: '22px', marginBottom: '6px' }}>⚡</div>
            <h4 style={{ margin: '0 0 4px 0', fontSize: '15px', color: '#0f172a' }}>Quick Scan</h4>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b', lineHeight: 1.4 }}>
              Sweeps high-risk vectors: Downloads, %TEMP%, Desktop, Active Processes, and Startup items in &lt;10s.
            </p>
          </div>

          <div
            onClick={() => onNavigate('full-scan')}
            style={{
              backgroundColor: '#ffffff',
              padding: '18px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ fontSize: '22px', marginBottom: '6px' }}>🔍</div>
            <h4 style={{ margin: '0 0 4px 0', fontSize: '15px', color: '#0f172a' }}>Full PC Scan</h4>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b', lineHeight: 1.4 }}>
              Recursive multi-threaded scan across all fixed drives accelerated by the 65,536-entry CleanFileCache.
            </p>
          </div>

          <div
            onClick={() => onNavigate('custom-scan')}
            style={{
              backgroundColor: '#ffffff',
              padding: '18px',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              cursor: 'pointer'
            }}
          >
            <div style={{ fontSize: '22px', marginBottom: '6px' }}>📁</div>
            <h4 style={{ margin: '0 0 4px 0', fontSize: '15px', color: '#0f172a' }}>Custom & USB Scan</h4>
            <p style={{ margin: 0, fontSize: '12px', color: '#64748b', lineHeight: 1.4 }}>
              Targeted scan of user folders, drag-and-drop files, or newly mounted USB removable drives.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};
