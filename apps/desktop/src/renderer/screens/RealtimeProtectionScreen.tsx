import React, { useState } from 'react';
import {
  DesktopProtectionStatus,
  DesktopSettings,
  WatchdogStatus,
  RealtimeThreatEvent
} from '../../types/desktop.types';

interface RealtimeProtectionScreenProps {
  status: DesktopProtectionStatus;
  settings: DesktopSettings;
  watchdogStatus?: WatchdogStatus | null;
  onUpdateSettings: (settings: Partial<DesktopSettings>) => Promise<void>;
  onSnoozeShield: (durationMs: number) => Promise<void>;
  onResumeShield: () => Promise<void>;
  onRequestFrictionGate: (action: string, onConfirm: () => void) => void;
  recentEvents?: RealtimeThreatEvent[];
}

export const RealtimeProtectionScreen: React.FC<RealtimeProtectionScreenProps> = ({
  status,
  settings,
  watchdogStatus,
  onUpdateSettings,
  onSnoozeShield,
  onResumeShield,
  onRequestFrictionGate,
  recentEvents = []
}) => {
  const [snoozeMenuOpen, setSnoozeMenuOpen] = useState<boolean>(false);

  const isSnoozed = Boolean(watchdogStatus?.shieldSnoozeActive);
  const isActive = status.realtimeShieldActive && !isSnoozed;

  const handleToggleMasterShield = () => {
    if (isActive) {
      // Disabling or snoozing requires Friction Gate
      onRequestFrictionGate('Pause Real-Time Shield', () => {
        setSnoozeMenuOpen(true);
      });
    } else {
      onResumeShield();
    }
  };

  const handleSelectSnooze = (durationMs: number) => {
    setSnoozeMenuOpen(false);
    onSnoozeShield(durationMs);
  };

  const handleToggleSubShield = async (key: keyof DesktopSettings, value: boolean) => {
    await onUpdateSettings({ [key]: value });
  };

  return (
    <div style={{ padding: '24px', maxWidth: '880px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>🛡️ Real-Time Protection Shield</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Continuous recursive filesystem monitoring powered by Windows ReadDirectoryChangesW.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span
            style={{
              padding: '4px 10px',
              borderRadius: '9999px',
              fontSize: '11px',
              fontWeight: 700,
              backgroundColor: isActive ? '#dcfce7' : isSnoozed ? '#fef3c7' : '#fee2e2',
              color: isActive ? '#166534' : isSnoozed ? '#92400e' : '#991b1b',
              border: `1px solid ${isActive ? '#86efac' : isSnoozed ? '#fcd34d' : '#f87171'}`
            }}
          >
            {isActive ? 'SHIELD ACTIVE' : isSnoozed ? 'TEMPORARILY SNOOZED' : 'SHIELD DISABLED'}
          </span>
        </div>
      </div>

      {/* Master Shield Card */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: '#0f172a' }}>
            Master Filesystem Interceptor
          </div>
          <div style={{ fontSize: '13px', color: '#64748b', marginTop: '2px', maxWidth: '520px' }}>
            Inspects every file written or modified on disk in real time before execution. Zero cloud dependencies.
          </div>
          {isSnoozed && (
            <div style={{ marginTop: '8px', fontSize: '12px', fontWeight: 600, color: '#b45309' }}>
              ⏱️ Auto-resumes in {Math.ceil((watchdogStatus?.shieldSnoozeRemainingMs || 0) / 1000)} seconds (RULE-19 Hard Gate).
            </div>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {isSnoozed ? (
            <button
              type="button"
              onClick={onResumeShield}
              style={{
                backgroundColor: '#16a34a',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                padding: '9px 16px',
                fontSize: '13px',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Resume Protection Now
            </button>
          ) : (
            <button
              type="button"
              onClick={handleToggleMasterShield}
              style={{
                backgroundColor: isActive ? '#fff1f2' : '#16a34a',
                color: isActive ? '#e11d48' : '#ffffff',
                border: `1px solid ${isActive ? '#fecdd3' : '#16a34a'}`,
                borderRadius: '6px',
                padding: '9px 16px',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              {isActive ? 'Pause / Snooze Shield...' : 'Enable Shield'}
            </button>
          )}
        </div>
      </div>

      {/* Snooze Options Dialog / Dropdown */}
      {snoozeMenuOpen && (
        <div
          role="dialog"
          aria-labelledby="snooze-dialog-title"
          style={{
            backgroundColor: '#fffbeb',
            border: '1px solid #fcd34d',
            borderRadius: '10px',
            padding: '16px',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px'
          }}
        >
          <div id="snooze-dialog-title" style={{ fontSize: '14px', fontWeight: 700, color: '#92400e' }}>
            Select Auto-Resume Snooze Duration (Permanent disable is forbidden by RULE-19)
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: '#78350f' }}>
            The Watchdog Service will strictly re-arm the Real-Time Shield once this timer counts down to zero.
          </p>
          <div style={{ display: 'flex', gap: '10px', marginTop: '6px' }}>
            <button
              type="button"
              onClick={() => handleSelectSnooze(15 * 60 * 1000)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid #d97706',
                backgroundColor: '#ffffff',
                color: '#92400e',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              15 Minutes
            </button>
            <button
              type="button"
              onClick={() => handleSelectSnooze(30 * 60 * 1000)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid #d97706',
                backgroundColor: '#ffffff',
                color: '#92400e',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              30 Minutes
            </button>
            <button
              type="button"
              onClick={() => handleSelectSnooze(60 * 60 * 1000)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid #d97706',
                backgroundColor: '#ffffff',
                color: '#92400e',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              1 Hour
            </button>
            <button
              type="button"
              onClick={() => setSnoozeMenuOpen(false)}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                backgroundColor: '#f8fafc',
                color: '#475569',
                fontSize: '12px',
                cursor: 'pointer'
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Sub-Shield Toggles */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px'
        }}
      >
        <div style={{ fontSize: '14px', fontWeight: 700, color: '#0f172a' }}>
          Configured Ingress Sub-Shields
        </div>

        <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#1e293b' }}>📥 Downloads Directory Ingress Shield</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Monitors downloaded browser binaries and archives immediately.</div>
          </div>
          <input
            type="checkbox"
            checked={settings.monitorDownloads}
            onChange={(e) => handleToggleSubShield('monitorDownloads', e.target.checked)}
            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#1e293b' }}>⚡ System Temp (%TEMP%) Guard</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Detects dropped droppers, staging scripts, and un-packed payload files.</div>
          </div>
          <input
            type="checkbox"
            checked={settings.monitorTemp}
            onChange={(e) => handleToggleSubShield('monitorTemp', e.target.checked)}
            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#1e293b' }}>☣️ Auto-Quarantine Critical Threats</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Automatically seals confirmed malware in PPVAULT2 without waiting for clicks.</div>
          </div>
          <input
            type="checkbox"
            checked={settings.autoQuarantineCritical}
            onChange={(e) => handleToggleSubShield('autoQuarantineCritical', e.target.checked)}
            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#1e293b' }}>📐 Shannon Byte Entropy Heuristics</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Calculates bit entropy (H &gt; 7.5) to catch packed and encrypted malware payloads.</div>
          </div>
          <input
            type="checkbox"
            checked={settings.entropyDetectionEnabled}
            onChange={(e) => handleToggleSubShield('entropyDetectionEnabled', e.target.checked)}
            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
          />
        </label>
      </div>

      {/* Monitored Locations Card */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px'
        }}
      >
        <div style={{ fontSize: '14px', fontWeight: 700, color: '#0f172a', marginBottom: '8px' }}>
          Active Monitored Locations ({status.monitoredPaths.length})
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {status.monitoredPaths.map((p) => (
            <span
              key={p}
              style={{
                backgroundColor: '#f1f5f9',
                border: '1px solid #cbd5e1',
                borderRadius: '6px',
                padding: '4px 10px',
                fontSize: '12px',
                fontFamily: 'monospace',
                color: '#334155'
              }}
            >
              📁 {p}
            </span>
          ))}
        </div>
      </div>

      {/* Recent Interceptions Feed */}
      <div
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px'
        }}
      >
        <div style={{ fontSize: '14px', fontWeight: 700, color: '#0f172a', marginBottom: '8px' }}>
          Recent Intercepted Events ({recentEvents.length})
        </div>
        {recentEvents.length === 0 ? (
          <div style={{ fontSize: '12px', color: '#94a3b8' }}>
            Zero threat events intercepted since application launch. Endpoint is secure.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {recentEvents.slice(0, 10).map((ev) => (
              <div
                key={ev.threat.id}
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
                  <strong>{ev.threat.fileName}</strong> • <span style={{ color: '#dc2626' }}>{ev.threat.threatName}</span>
                </div>
                <div style={{ color: '#64748b', fontSize: '11px' }}>
                  {ev.actionTaken} • {new Date(ev.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
