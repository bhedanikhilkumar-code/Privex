import React, { useState, useEffect } from 'react';
import { DesktopSettings } from '../../types/desktop.types';

interface SettingsScreenProps {
  initialSettings: DesktopSettings;
  onSaveSettings: (settings: Partial<DesktopSettings>) => Promise<void>;
}

export const SettingsScreen: React.FC<SettingsScreenProps> = ({
  initialSettings,
  onSaveSettings
}) => {
  const [settings, setSettings] = useState<DesktopSettings>(initialSettings);
  const [isSaved, setIsSaved] = useState(false);

  useEffect(() => {
    setSettings(initialSettings);
  }, [initialSettings]);

  const handleToggle = (key: keyof DesktopSettings) => {
    setSettings((prev) => ({
      ...prev,
      [key]: !prev[key]
    }));
    setIsSaved(false);
  };

  const handleSave = async () => {
    await onSaveSettings(settings);
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 3000);
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px' }}>
      <h2 style={{ margin: '0 0 6px 0', fontSize: '22px', color: '#0f172a' }}>⚙️ Protection Settings</h2>
      <p style={{ margin: '0 0 20px 0', color: '#64748b', fontSize: '14px' }}>
        Configure on-device heuristics, ingress monitoring, and performance safeguards
      </p>

      <div style={{ backgroundColor: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Real-time Shield */}
        <label style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}>
          <div>
            <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '14px' }}>Real-Time Ingress Protection</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Monitors newly downloaded and written files on this PC</div>
          </div>
          <input
            type="checkbox"
            checked={settings.realtimeShieldEnabled}
            onChange={() => handleToggle('realtimeShieldEnabled')}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Monitor Downloads */}
        <label style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}>
          <div>
            <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '14px' }}>Monitor Downloads Directory</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Watches user Downloads folder for inbound malicious files</div>
          </div>
          <input
            type="checkbox"
            checked={settings.monitorDownloads}
            onChange={() => handleToggle('monitorDownloads')}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Monitor Temp */}
        <label style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}>
          <div>
            <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '14px' }}>Monitor System Temp Directory</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Watches system temporary folder for dropped executables and scripts</div>
          </div>
          <input
            type="checkbox"
            checked={settings.monitorTemp}
            onChange={() => handleToggle('monitorTemp')}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Entropy Detection */}
        <label style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}>
          <div>
            <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '14px' }}>Shannon Byte Entropy Heuristics</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Detects encrypted or packed code in disguised documents</div>
          </div>
          <input
            type="checkbox"
            checked={settings.entropyDetectionEnabled}
            onChange={() => handleToggle('entropyDetectionEnabled')}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Auto Quarantine */}
        <label style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}>
          <div>
            <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '14px' }}>Auto-Quarantine Critical Threats</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Automatically moves critical threats to vault immediately</div>
          </div>
          <input
            type="checkbox"
            checked={settings.autoQuarantineCritical}
            onChange={() => handleToggle('autoQuarantineCritical')}
          />
        </label>

        <hr style={{ border: 'none', borderTop: '1px solid #f1f5f9', margin: 0 }} />

        {/* Max File Size */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontWeight: 600, color: '#1e293b', fontSize: '14px' }}>Scan File Size Limit</div>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Skip deep body hashing for files larger than this value</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <input
              type="number"
              min="1"
              max="2048"
              value={settings.scanLargeFilesLimitMb}
              onChange={(e) => setSettings({ ...settings, scanLargeFilesLimitMb: parseInt(e.target.value, 10) || 50 })}
              style={{ width: '60px', padding: '4px 8px', borderRadius: '4px', border: '1px solid #cbd5e1' }}
            />
            <span style={{ fontSize: '13px', color: '#64748b' }}>MB</span>
          </div>
        </div>

        <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            type="button"
            onClick={handleSave}
            style={{
              backgroundColor: '#2563eb',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              padding: '10px 20px',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer'
            }}
          >
            Save Settings
          </button>
          {isSaved && <span style={{ color: '#16a34a', fontSize: '13px', fontWeight: 600 }}>Settings saved securely.</span>}
        </div>
      </div>
    </div>
  );
};
