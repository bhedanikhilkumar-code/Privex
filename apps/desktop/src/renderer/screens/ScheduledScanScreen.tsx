import React, { useState, useEffect } from 'react';
import {
  ScanSchedulerState,
  ScanScheduleConfig,
  ScanResult
} from '../../types/desktop.types';

interface ScheduledScanScreenProps {
  onScanTriggered?: (result: ScanResult) => void;
}

export const ScheduledScanScreen: React.FC<ScheduledScanScreenProps> = ({ onScanTriggered }) => {
  const [scheduleState, setScheduleState] = useState<ScanSchedulerState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [runningNow, setRunningNow] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Form State
  const [enabled, setEnabled] = useState<boolean>(true);
  const [frequency, setFrequency] = useState<'daily' | 'weekly'>('daily');
  const [scanType, setScanType] = useState<'quick' | 'full'>('quick');
  const [timeOfDay, setTimeOfDay] = useState<string>('12:00');
  const [dayOfWeek, setDayOfWeek] = useState<number>(1); // Monday
  const [batteryGuard, setBatteryGuard] = useState<boolean>(true);
  const [catchUpMissed, setCatchUpMissed] = useState<boolean>(true);

  useEffect(() => {
    fetchSchedule();
  }, []);

  const fetchSchedule = async () => {
    setLoading(true);
    try {
      if (window.desktopSecurity?.getScanSchedule) {
        const state = await window.desktopSecurity.getScanSchedule();
        setScheduleState(state);
        if (state.config) {
          setEnabled(state.config.enabled);
          setFrequency(state.config.frequency);
          setScanType(state.config.scanType);
          setTimeOfDay(state.config.timeOfDay);
          setDayOfWeek(state.config.weekday ?? 1);
          setBatteryGuard(state.config.pauseOnBattery ?? true);
          setCatchUpMissed(state.config.runMissedOnStartup ?? true);
        }
      }
    } catch (err: any) {
      setErrorMsg(`Failed to load schedule: ${err?.message || 'IPC error'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setErrorMsg(null);
    setSaveSuccess(null);

    const config: ScanScheduleConfig = {
      enabled,
      frequency,
      scanType,
      timeOfDay,
      weekday: frequency === 'weekly' ? dayOfWeek : undefined,
      pauseOnBattery: batteryGuard,
      runMissedOnStartup: catchUpMissed,
      autoQuarantine: true
    };

    try {
      if (window.desktopSecurity?.saveScanSchedule) {
        const res = await window.desktopSecurity.saveScanSchedule(config);
        if (res.success) {
          setScheduleState(res.state);
          setSaveSuccess('Scan schedule saved and armed successfully.');
        } else {
          setErrorMsg('Failed to arm scan schedule on backend.');
        }
      }
    } catch (err: any) {
      setErrorMsg(`Error saving schedule: ${err?.message || 'Storage error'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleRunNow = async () => {
    setRunningNow(true);
    setErrorMsg(null);
    try {
      if (window.desktopSecurity?.runScheduledScanNow) {
        const result = await window.desktopSecurity.runScheduledScanNow();
        onScanTriggered?.(result);
        setSaveSuccess(`Scheduled scan executed: ${result.totalFilesScanned} files scanned, ${result.threats.length} threats found.`);
        await fetchSchedule();
      }
    } catch (err: any) {
      setErrorMsg(`Failed to execute scheduled scan: ${err?.message || 'Scan error'}`);
    } finally {
      setRunningNow(false);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '24px', maxWidth: '800px', margin: '0 auto', color: '#64748b' }}>
        Loading scheduled scan configuration...
      </div>
    );
  }

  return (
    <div style={{ padding: '24px', maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '20px', color: '#0f172a' }}>📅 Scheduled & Automated Scans</h2>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
            Automate background endpoint scans with battery guards and missed-scan startup recovery.
          </p>
        </div>

        <span
          style={{
            padding: '4px 10px',
            borderRadius: '9999px',
            fontSize: '11px',
            fontWeight: 700,
            backgroundColor: enabled ? '#dcfce7' : '#f1f5f9',
            color: enabled ? '#166534' : '#64748b',
            border: `1px solid ${enabled ? '#86efac' : '#cbd5e1'}`
          }}
        >
          {enabled ? 'SCHEDULE ACTIVE' : 'SCHEDULE DISABLED'}
        </span>
      </div>

      {saveSuccess && (
        <div
          role="status"
          style={{
            backgroundColor: '#f0fdf4',
            border: '1px solid #86efac',
            color: '#166534',
            borderRadius: '8px',
            padding: '12px',
            marginBottom: '16px',
            fontSize: '13px'
          }}
        >
          ✅ {saveSuccess}
        </div>
      )}

      {errorMsg && (
        <div
          role="alert"
          style={{
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            color: '#991b1b',
            borderRadius: '8px',
            padding: '12px',
            marginBottom: '16px',
            fontSize: '13px'
          }}
        >
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Schedule Form */}
      <form
        onSubmit={handleSave}
        style={{
          backgroundColor: '#ffffff',
          borderRadius: '10px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px'
        }}
      >
        {/* Enable Toggle */}
        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ width: '16px', height: '16px', cursor: 'pointer' }}
          />
          <div>
            <div style={{ fontSize: '14px', fontWeight: 600, color: '#0f172a' }}>
              Enable Background Scheduled Scans
            </div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>
              Periodically sweep system without requiring manual scan clicks.
            </div>
          </div>
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Scan Type & Frequency */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
              Scan Type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value as 'quick' | 'full')}
              disabled={!enabled}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px'
              }}
            >
              <option value="quick">⚡ Quick Scan (Downloads, Temp, Startup)</option>
              <option value="full">🔍 Full PC Scan (All fixed drives)</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
              Frequency
            </label>
            <select
              value={frequency}
              onChange={(e) => setFrequency(e.target.value as 'daily' | 'weekly')}
              disabled={!enabled}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px'
              }}
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </div>
        </div>

        {/* Time of Day & Day of Week */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
              Execution Time (HH:MM)
            </label>
            <input
              type="time"
              value={timeOfDay}
              onChange={(e) => setTimeOfDay(e.target.value)}
              disabled={!enabled}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                boxSizing: 'border-box'
              }}
            />
          </div>

          {frequency === 'weekly' && (
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
                Day of Week
              </label>
              <select
                value={dayOfWeek}
                onChange={(e) => setDayOfWeek(parseInt(e.target.value, 10))}
                disabled={!enabled}
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  border: '1px solid #cbd5e1',
                  fontSize: '13px'
                }}
              >
                <option value={1}>Monday</option>
                <option value={2}>Tuesday</option>
                <option value={3}>Wednesday</option>
                <option value={4}>Thursday</option>
                <option value={5}>Friday</option>
                <option value={6}>Saturday</option>
                <option value={0}>Sunday</option>
              </select>
            </div>
          )}
        </div>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Guard Flags */}
        <fieldset style={{ border: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <legend style={{ fontSize: '13px', fontWeight: 600, color: '#334155', marginBottom: '6px' }}>
            Resource & Power Protection Guards
          </legend>

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', color: '#1e293b' }}>
            <input
              type="checkbox"
              checked={batteryGuard}
              onChange={(e) => setBatteryGuard(e.target.checked)}
              disabled={!enabled}
            />
            Pause scheduled scan if host machine is on battery power (&lt;20% charge)
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13px', color: '#1e293b' }}>
            <input
              type="checkbox"
              checked={catchUpMissed}
              onChange={(e) => setCatchUpMissed(e.target.checked)}
              disabled={!enabled}
            />
            Run missed scan immediately upon Windows startup if PC was powered off during scheduled time
          </label>
        </fieldset>

        {/* Buttons */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
          <button
            type="button"
            onClick={handleRunNow}
            disabled={runningNow}
            style={{
              padding: '9px 16px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#f8fafc',
              color: '#334155',
              fontSize: '13px',
              fontWeight: 600,
              cursor: runningNow ? 'wait' : 'pointer'
            }}
          >
            {runningNow ? '⏳ Running Scan...' : '▶️ Run Scheduled Scan Now'}
          </button>

          <button
            type="submit"
            disabled={saving}
            style={{
              padding: '9px 20px',
              borderRadius: '6px',
              border: 'none',
              backgroundColor: '#2563eb',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 700,
              cursor: saving ? 'wait' : 'pointer'
            }}
          >
            {saving ? 'Saving...' : '💾 Save & Arm Schedule'}
          </button>
        </div>
      </form>

      {/* Execution Telemetry Card */}
      {scheduleState && (
        <div
          style={{
            marginTop: '20px',
            backgroundColor: '#ffffff',
            borderRadius: '10px',
            border: '1px solid #e2e8f0',
            padding: '16px'
          }}
        >
          <div style={{ fontSize: '13px', fontWeight: 700, color: '#334155', marginBottom: '8px' }}>
            Schedule Execution Status
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '12px' }}>
            <div>
              <span style={{ color: '#64748b' }}>Next Calculated Run: </span>
              <strong style={{ color: '#0f172a' }}>
                {scheduleState.nextScheduledRun
                  ? new Date(scheduleState.nextScheduledRun).toLocaleString()
                  : 'Armed upon configuration save'}
              </strong>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Last Run Result: </span>
              <strong style={{ color: '#0f172a' }}>
                {scheduleState.lastStatus
                  ? `${scheduleState.lastStatus} ${scheduleState.lastScheduledRun ? `(${new Date(scheduleState.lastScheduledRun).toLocaleTimeString()})` : ''}`
                  : 'No scheduled runs yet'}
              </strong>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
