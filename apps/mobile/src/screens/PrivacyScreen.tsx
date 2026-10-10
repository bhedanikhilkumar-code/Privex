import React, { useState, useEffect, useCallback, useRef } from 'react';
import { PermissionsPrivacyService } from '../services/permissions-privacy.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { NotificationService } from '../services/notification.service';
import type { PermissionsPrivacyReportDTO } from '../types/mobile.types';

interface PrivacyScreenProps {
  onBack?: () => void;
}

export const PrivacyScreen: React.FC<PrivacyScreenProps> = ({ onBack }) => {
  const [report, setReport] = useState<PermissionsPrivacyReportDTO | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [shredded, setShredded] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const service = PermissionsPrivacyService.getInstance();
  const shredTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadReport = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await service.getPermissionsPrivacyReport();
      setReport(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load permissions report');
    } finally {
      setLoading(false);
    }
  }, [service]);

  useEffect(() => {
    loadReport();

    const handleResume = () => {
      loadReport();
    };
    if (typeof window !== 'undefined') {
      window.addEventListener('privateprotection:app_resume', handleResume);
    }
    return () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener('privateprotection:app_resume', handleResume);
      }
      if (shredTimerRef.current) {
        clearTimeout(shredTimerRef.current);
      }
    };
  }, [loadReport]);

  const handleCryptoShred = async () => {
    await SecureStorageService.purgeAllData();
    NotificationService.clearNotifications();
    setShredded(true);
    if (shredTimerRef.current) {
      clearTimeout(shredTimerRef.current);
    }
    shredTimerRef.current = setTimeout(() => {
      if (typeof window !== 'undefined') {
        setShredded(false);
      }
    }, 3000);
    loadReport();
  };

  const renderBadge = (statusText: string, tone: 'GREEN' | 'YELLOW' | 'RED' | 'BLUE') => {
    const colors = {
      GREEN: { bg: 'rgba(16, 185, 129, 0.2)', text: '#34d399', border: '#10b981' },
      YELLOW: { bg: 'rgba(245, 158, 11, 0.2)', text: '#fcd34d', border: '#f59e0b' },
      RED: { bg: 'rgba(239, 68, 68, 0.2)', text: '#f87171', border: '#ef4444' },
      BLUE: { bg: 'rgba(56, 189, 248, 0.2)', text: '#38bdf8', border: '#0284c7' }
    };
    const c = colors[tone] || colors.BLUE;
    return (
      <span
        style={{
          display: 'inline-block',
          padding: '0.2rem 0.55rem',
          borderRadius: '9999px',
          fontSize: '0.7rem',
          fontWeight: 700,
          backgroundColor: c.bg,
          color: c.text,
          border: `1px solid ${c.border}`
        }}
      >
        {statusText}
      </span>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem', color: '#f8fafc' }}>
      {/* Top Header matching Privacy Center.png */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {onBack && (
            <button
              type="button"
              onClick={onBack}
              aria-label="Back"
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                backgroundColor: '#111b2e',
                border: '1px solid #27364b',
                color: '#38bdf8',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: '1rem'
              }}
            >
              ←
            </button>
          )}
          <div>
            <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              PRIVACY CENTER
            </span>
            <h1 style={{ margin: '0.1rem 0 0 0', fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
              Privacy Audit
            </h1>
          </div>
        </div>
        <span
          style={{
            fontSize: '0.7rem',
            padding: '0.25rem 0.65rem',
            borderRadius: '9999px',
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            color: '#34d399',
            border: '1px solid #10b981',
            fontWeight: 700
          }}
        >
          100% PRIVATE
        </span>
      </div>

      {error && (
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', borderRadius: '8px', color: '#f87171', fontSize: '0.85rem' }}>
          {error}
        </div>
      )}

      {/* Hero Zero-Knowledge Card matching Privacy Center.png */}
      <div
        style={{
          backgroundColor: '#111b2e',
          border: '1px solid #27364b',
          borderRadius: '20px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              width: '44px',
              height: '44px',
              borderRadius: '12px',
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.5rem',
              color: '#34d399'
            }}
          >
            🔒
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
              Zero-Knowledge Architecture
            </h3>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              Privacy Architecture & Guarantees
            </span>
          </div>
        </div>
        <p style={{ margin: 0, fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.5 }}>
          Your data never leaves this device. All detection models, URL heuristics, text analysis, and password entropy operations run completely on-device without cloud telemetry.
        </p>
      </div>

      {/* Data Boundaries Section matching Privacy Center.png */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
          Data Boundaries
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ fontSize: '1.1rem' }}>📱</span>
              <strong style={{ fontSize: '0.85rem', color: '#f8fafc' }}>On-Device Only</strong>
            </div>
            <p style={{ margin: 0, fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
              URLs, messages, file hashes & clipboard content
            </p>
          </div>

          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ fontSize: '1.1rem' }}>🚫</span>
              <strong style={{ fontSize: '0.85rem', color: '#f8fafc' }}>Zero Cloud Sync</strong>
            </div>
            <p style={{ margin: 0, fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
              No analytics, no ad tracking & no user telemetry
            </p>
          </div>
        </div>
      </div>

      {/* Permissions Audit Group */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
          Permissions Audit
        </h3>

        {loading && !report ? (
          <div style={{ textAlign: 'center', padding: '1.5rem', color: '#94a3b8' }}>
            Auditing Android security & permission state...
          </div>
        ) : report ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {/* Storage & SAF */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '0.9rem', color: '#f8fafc' }}>Storage & Scoped Files</strong>
                {report.storage.status === 'GRANTED_SAF' && renderBadge('SAF GRANTED', 'GREEN')}
                {report.storage.status === 'GRANTED_LEGACY' && renderBadge('LEGACY GRANTED', 'GREEN')}
                {report.storage.status === 'LIMITED' && renderBadge('MEDIASTORE', 'YELLOW')}
                {report.storage.status === 'DENIED' && renderBadge('DENIED', 'RED')}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
                {report.storage.accessibleScope}
              </div>
            </div>

            {/* Notifications */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '0.9rem', color: '#f8fafc' }}>Security Notifications</strong>
                {report.notifications.areNotificationsEnabled ? renderBadge('ENABLED', 'GREEN') : renderBadge('DISABLED', 'RED')}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
                {report.notifications.dependentFeatures}
              </div>
            </div>

            {/* VPN / Web Shield */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '0.9rem', color: '#f8fafc' }}>Local DNS Web Shield</strong>
                {report.vpnWebShield.serviceState === 'ACTIVE' && renderBadge('ACTIVE', 'GREEN')}
                {report.vpnWebShield.serviceState === 'CONSENT_PENDING' && renderBadge('CONSENT PENDING', 'YELLOW')}
                {report.vpnWebShield.serviceState === 'COEXISTENCE_CONFLICT' && renderBadge('COEXISTENCE CONFLICT', 'YELLOW')}
                {report.vpnWebShield.serviceState === 'STOPPED' && renderBadge('STOPPED', 'BLUE')}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', lineHeight: 1.4 }}>
                {report.vpnWebShield.privacyGuarantee}
              </div>
            </div>

            {/* Telemetry Collection Guarantee */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #10b981', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <strong style={{ fontSize: '0.9rem', color: '#34d399' }}>Network Telemetry Collection</strong>
                {renderBadge('ZERO COLLECTION', 'GREEN')}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#cbd5e1', lineHeight: 1.4 }}>
                Payloads Transmitted: 0 Bytes • {report.telemetry.explanation}
              </div>
            </div>
          </div>
        ) : null}
      </div>

      {/* Crypto-Shredder Card matching Privacy Center.png */}
      <div style={{ backgroundColor: '#111b2e', border: '1px solid #ef4444', borderRadius: '20px', padding: '1.25rem', marginTop: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <span style={{ fontSize: '1.5rem' }}>🗑️</span>
          <div>
            <h4 style={{ margin: 0, fontSize: '1rem', color: '#f87171', fontWeight: 800 }}>
              One-Click Crypto-Shredder
            </h4>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              Cryptographic shredding of volatile state
            </span>
          </div>
        </div>
        <p style={{ margin: '0 0 1rem 0', fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.4 }}>
          Instantly purge all local application state, custom allowlists, preferences, and scan history records from this device.
        </p>

        {shredded ? (
          <div style={{ padding: '0.75rem', backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#34d399', borderRadius: '10px', textAlign: 'center', fontSize: '0.85rem', fontWeight: 700 }}>
            ✓ All local data and memory purged successfully.
          </div>
        ) : (
          <button
            type="button"
            onClick={handleCryptoShred}
            style={{
              padding: '0.85rem',
              backgroundColor: '#dc2626',
              color: '#ffffff',
              fontWeight: 700,
              borderRadius: '10px',
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.9rem',
              width: '100%',
              boxShadow: '0 4px 12px rgba(220, 38, 38, 0.3)'
            }}
          >
            Crypto-Shred All Local Data
          </button>
        )}
      </div>
    </div>
  );
};
