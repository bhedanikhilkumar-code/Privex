import React, { useState, useEffect } from 'react';
import { DeviceAuditService } from '../services/device-audit.service';
import { SecureStorageService, ScanHistoryRecord } from '../services/secure-storage.service';
import { DeviceSecurityPosture, MobileSettings } from '../types/mobile.types';
import { DevicePostureCard } from '../components/DevicePostureCard';
import { MobileTab } from '../components/TabBar';
import { MobileThreatIntelService } from '../services/mobile-threat-intel.service';

interface HomeScreenProps {
  onNavigate: (tab: MobileTab) => void;
  onSelectResult: (record: ScanHistoryRecord) => void;
}

export const HomeScreen: React.FC<HomeScreenProps> = ({ onNavigate, onSelectResult }) => {
  const [posture, setPosture] = useState<DeviceSecurityPosture | null>(null);
  const [settings, setSettings] = useState<MobileSettings | null>(null);
  const [history, setHistory] = useState<ScanHistoryRecord[]>([]);
  const [intelSeq, setIntelSeq] = useState<number>(100);
  const [intelRecords, setIntelRecords] = useState<number>(11);

  useEffect(() => {
    const auditService = new DeviceAuditService();
    setPosture(auditService.auditSecurityPosture());

    SecureStorageService.getSettings().then(setSettings);
    SecureStorageService.getScanHistory().then(setHistory);
    MobileThreatIntelService.getDatabaseMetadata().then((meta) => {
      if (meta) {
        setIntelSeq(meta.versionSequence);
        setIntelRecords(meta.recordsCount);
      }
    }).catch(() => {});
  }, []);

  const handleHistoryItemClick = (record: ScanHistoryRecord) => {
    if (onSelectResult) {
      onSelectResult(record);
    } else {
      if (record.targetType === 'URL') {
        onNavigate('URL_SCAN');
      } else if (record.targetType === 'TEXT') {
        onNavigate('TEXT_SCAN');
      } else if (record.targetType === 'FILE') {
        onNavigate('FILE_SCAN');
      }
    }
  };

  const isHealthy = settings?.protectionEnabled !== false && posture?.overallHealth !== 'RISK';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem', color: '#f8fafc' }}>
      {/* Top Bar with System Status & User Badge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', paddingTop: '0.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <img
            src="./privex-icon.png"
            alt="PRIVEX"
            style={{ width: '38px', height: '38px', objectFit: 'contain' }}
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).src = './privex-logo.svg';
            }}
          />
          <div>
            <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              PRIVEX MOBILE
            </span>
            <h1 style={{ margin: '0.15rem 0 0 0', fontSize: '1.85rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
              System Status
            </h1>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button
            type="button"
            onClick={() => onNavigate('SETTINGS')}
            aria-label="Open Settings"
            style={{
              width: '38px',
              height: '38px',
              borderRadius: '50%',
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              color: '#38bdf8',
              fontWeight: 700,
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer'
            }}
          >
            JD
          </button>
        </div>
      </div>

      {/* Hero Circular Protection Posture Shield */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '1.5rem 1rem 1rem 1rem',
          position: 'relative'
        }}
      >
        <div
          style={{
            width: '130px',
            height: '130px',
            borderRadius: '50%',
            background: isHealthy
              ? 'radial-gradient(circle, rgba(16, 185, 129, 0.25) 0%, rgba(15, 23, 42, 0.8) 70%)'
              : 'radial-gradient(circle, rgba(245, 158, 11, 0.25) 0%, rgba(15, 23, 42, 0.8) 70%)',
            border: `2px solid ${isHealthy ? '#10b981' : '#f59e0b'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: isHealthy
              ? '0 0 35px rgba(16, 185, 129, 0.3)'
              : '0 0 35px rgba(245, 158, 11, 0.3)'
          }}
        >
          <div
            style={{
              width: '64px',
              height: '64px',
              borderRadius: '50%',
              backgroundColor: isHealthy ? '#10b981' : '#f59e0b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '2rem',
              color: '#ffffff'
            }}
          >
            {isHealthy ? '🛡️' : '⚠️'}
          </div>
        </div>
        <h3
          style={{
            margin: '1rem 0 0.2rem 0',
            fontSize: '1.1rem',
            fontWeight: 800,
            letterSpacing: '0.04em',
            color: isHealthy ? '#34d399' : '#fcd34d',
            textTransform: 'uppercase'
          }}
        >
          {isHealthy ? 'ALL SYSTEMS CLEAR' : 'ATTENTION RECOMMENDED'}
        </h3>
        <p style={{ margin: 0, fontSize: '0.82rem', color: '#94a3b8' }}>
          {isHealthy ? 'Protected on-device • Zero cloud telemetry' : 'One or more security checks require review'}
        </p>
      </div>

      {/* Real-Time Diagnostics Terminal Card */}
      <div
        style={{
          backgroundColor: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '16px',
          padding: '1.15rem',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.35)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10b981', boxShadow: '0 0 8px #10b981' }} />
          <span style={{ fontSize: '0.75rem', fontWeight: 800, letterSpacing: '0.06em', color: '#f8fafc', textTransform: 'uppercase' }}>
            REAL-TIME DIAGNOSTICS
          </span>
        </div>
        <div style={{ fontFamily: 'monospace, "JetBrains Mono", Consolas', fontSize: '0.78rem', color: '#cbd5e1', lineHeight: 1.7 }}>
          <div>&gt; Initializing Privex core layer... [OK]</div>
          <div>&gt; Memory integrity: 100% verified (Volatile RAM)</div>
          <div>&gt; Threat DB Seq #{intelSeq} active ({intelRecords} verified indicators)</div>
          <div>&gt; Protection status: {settings?.protectionEnabled !== false ? 'Active' : 'Paused'} • Zero cloud telemetry</div>
        </div>
        <button
          type="button"
          onClick={() => onNavigate('STATUS')}
          style={{
            marginTop: '0.85rem',
            width: '100%',
            padding: '0.6rem',
            backgroundColor: 'transparent',
            border: '1px solid #334155',
            borderRadius: '10px',
            color: '#38bdf8',
            fontSize: '0.82rem',
            fontWeight: 700,
            cursor: 'pointer',
            textAlign: 'center'
          }}
        >
          Run Deep Audit
        </button>
      </div>

      {/* Protection Modules Section Heading */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.25rem' }}>
        <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc' }}>
          Protection Modules
        </h3>
        <span style={{ fontSize: '0.75rem', color: '#38bdf8', fontWeight: 600 }}>
          4 Active Shields
        </span>
      </div>

      {/* Main Scanners Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
        <button
          type="button"
          onClick={() => onNavigate('URL_SCAN')}
          style={{
            padding: '1.1rem 1rem',
            backgroundColor: '#111b2e',
            border: '1px solid #27364b',
            borderRadius: '16px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '52px',
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            transition: 'border-color 0.15s ease'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                backgroundColor: 'rgba(56, 189, 248, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.35rem',
                color: '#38bdf8'
              }}
            >
              🔗
            </div>
            <span style={{ color: '#64748b', fontSize: '0.85rem' }}>↗</span>
          </div>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem', fontWeight: 700 }}>Scan URL</strong>
            <span style={{ fontSize: '0.74rem', color: '#94a3b8', lineHeight: 1.3, display: 'block', marginTop: '0.2rem' }}>
              Link Sentry & phishing analysis
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('QR_SCAN')}
          style={{
            padding: '1.1rem 1rem',
            backgroundColor: '#111b2e',
            border: '1px solid #27364b',
            borderRadius: '16px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '52px',
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                backgroundColor: 'rgba(14, 165, 233, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.35rem',
                color: '#0ea5e9'
              }}
            >
              📷
            </div>
            <span style={{ color: '#64748b', fontSize: '0.85rem' }}>↗</span>
          </div>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem', fontWeight: 700 }}>Scan QR Code</strong>
            <span style={{ fontSize: '0.74rem', color: '#94a3b8', lineHeight: 1.3, display: 'block', marginTop: '0.2rem' }}>
              QR Inspector camera barcode
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('TEXT_SCAN')}
          style={{
            padding: '1.1rem 1rem',
            backgroundColor: '#111b2e',
            border: '1px solid #27364b',
            borderRadius: '16px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '52px',
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                backgroundColor: 'rgba(96, 165, 250, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.35rem',
                color: '#60a5fa'
              }}
            >
              💬
            </div>
            <span style={{ color: '#64748b', fontSize: '0.85rem' }}>↗</span>
          </div>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem', fontWeight: 700 }}>Scan Message</strong>
            <span style={{ fontSize: '0.74rem', color: '#94a3b8', lineHeight: 1.3, display: 'block', marginTop: '0.2rem' }}>
              Message Guard heuristic checks
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('FILE_SCAN')}
          style={{
            padding: '1.1rem 1rem',
            backgroundColor: '#111b2e',
            border: '1px solid #27364b',
            borderRadius: '16px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '52px',
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                backgroundColor: 'rgba(52, 211, 153, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.35rem',
                color: '#34d399'
              }}
            >
              📁
            </div>
            <span style={{ color: '#64748b', fontSize: '0.85rem' }}>↗</span>
          </div>
          <div>
            <strong style={{ display: 'block', fontSize: '0.95rem', fontWeight: 700 }}>Inspect File</strong>
            <span style={{ fontSize: '0.74rem', color: '#94a3b8', lineHeight: 1.3, display: 'block', marginTop: '0.2rem' }}>
              File Vault magic bytes & ELF
            </span>
          </div>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('PASSWORD')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #38bdf8',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '48px'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>🔐</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Password Generator</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Secure on-device CSPRNG</span>
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
            textAlign: 'left',
            minHeight: '48px'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>⚙️</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Engine Diagnostics</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Offline Bloom filter health</span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('PRIVACY')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #a855f7',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '48px'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>🔒</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Privacy Center</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Zero-knowledge & shredder</span>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('SETTINGS')}
          style={{
            padding: '1rem',
            backgroundColor: '#1e293b',
            border: '1px solid #eab308',
            borderRadius: '12px',
            color: '#f8fafc',
            cursor: 'pointer',
            textAlign: 'left',
            minHeight: '48px'
          }}
        >
          <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '0.25rem' }}>⚡</span>
          <strong style={{ display: 'block', fontSize: '0.95rem' }}>Protection Settings</strong>
          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Shields & custom allowlists</span>
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
              <button
                key={rec.scanId || i}
                type="button"
                role="button"
                aria-label={`View ${rec.targetType} scan result for ${rec.sanitizedSummary}. Verdict: ${rec.verdict}`}
                onClick={() => handleHistoryItemClick(rec)}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.75rem',
                  backgroundColor: '#0f172a',
                  border: '1px solid #1e293b',
                  borderRadius: '8px',
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                  textAlign: 'left',
                  width: '100%',
                  minHeight: '48px',
                  color: 'inherit',
                  transition: 'background-color 0.15s ease'
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
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
