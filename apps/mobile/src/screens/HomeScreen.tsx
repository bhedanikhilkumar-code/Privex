import React, { useState, useEffect } from 'react';
import { DeviceAuditService } from '../services/device-audit.service';
import { SecureStorageService, ScanHistoryRecord } from '../services/secure-storage.service';
import { DeviceSecurityPosture, MobileSettings } from '../types/mobile.types';
import { DevicePostureCard } from '../components/DevicePostureCard';

interface HomeScreenProps {
  onNavigate: (tab: any) => void;
  onSelectResult: (record: ScanHistoryRecord) => void;
}

export const HomeScreen: React.FC<HomeScreenProps> = ({ onNavigate }) => {
  const [posture, setPosture] = useState<DeviceSecurityPosture | null>(null);
  const [settings, setSettings] = useState<MobileSettings | null>(null);
  const [history, setHistory] = useState<ScanHistoryRecord[]>([]);

  useEffect(() => {
    const auditService = new DeviceAuditService();
    setPosture(auditService.auditSecurityPosture());

    SecureStorageService.getSettings().then(setSettings);
    SecureStorageService.getScanHistory().then(setHistory);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem', color: '#f8fafc' }}>
      {/* Header Banner */}
      <div
        style={{
          backgroundColor: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '16px',
          padding: '1.25rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <div>
          <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 800, color: '#38bdf8' }}>
            PRIVEX
          </h2>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
            On-Device AI Security Engine (Android)
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: settings?.protectionEnabled ? '#10b981' : '#f59e0b' }} />
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: settings?.protectionEnabled ? '#34d399' : '#fcd34d' }}>
            {settings?.protectionEnabled ? 'Active' : 'Paused'}
          </span>
        </div>
      </div>

      {/* Quick Action Buttons */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <button
          type="button"
          onClick={() => onNavigate('URL_SCAN')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #38bdf8',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>🔗</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Scan URL</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Analyze links for phishing</span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('QR_SCAN')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #f472b6',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>📷</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Scan QR Code</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Camera barcode analysis</span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('TEXT_SCAN')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #818cf8',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>💬</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Scan Message</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Detect scams & extortion</span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('FILE_SCAN')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #34d399',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>📁</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Inspect File</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Magic bytes & entropy</span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('STATUS')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #cbd5e1',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>⚙️</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Engine Diagnostics</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Offline Bloom filter health</span>
        </button>
      </div>

      {/* Device Posture Card */}
      {posture && <DevicePostureCard posture={posture} />}

      {/* Recent Scans (Non-sensitive metadata) */}
      <div style={{ backgroundColor: '#1e293b', borderRadius: '16px', padding: '1.25rem', border: '1px solid #334155' }}>
        <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem' }}>Recent Scans</h4>
        {history.length === 0 ? (
          <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
            No recent scans recorded. Scan a link or message to get started.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {history.slice(0, 5).map((rec, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.5rem',
                  backgroundColor: '#0f172a',
                  borderRadius: '8px',
                  fontSize: '0.85rem'
                }}
              >
                <div>
                  <span style={{ fontWeight: 600, color: '#f8fafc' }}>{rec.targetType}: </span>
                  <span style={{ color: '#94a3b8' }}>{rec.sanitizedSummary}</span>
                </div>
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    color: rec.verdict === 'DANGEROUS' ? '#f87171' : (rec.verdict === 'SUSPICIOUS' ? '#fcd34d' : '#34d399')
                  }}
                >
                  {rec.verdict}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
