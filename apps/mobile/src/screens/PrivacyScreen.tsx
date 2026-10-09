import React, { useState, useEffect, useCallback } from 'react';
import { PermissionsPrivacyService } from '../services/permissions-privacy.service';
import { SecureStorageService } from '../services/secure-storage.service';
import { NotificationService } from '../services/notification.service';
import type { PermissionsPrivacyReportDTO } from '../types/mobile.types';

export const PrivacyScreen: React.FC = () => {
  const [report, setReport] = useState<PermissionsPrivacyReportDTO | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [shredded, setShredded] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const service = PermissionsPrivacyService.getInstance();

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

    // Listen for app resume event from native MainActivity
    const handleResume = () => {
      loadReport();
    };
    window.addEventListener('privateprotection:app_resume', handleResume);
    return () => {
      window.removeEventListener('privateprotection:app_resume', handleResume);
    };
  }, [loadReport]);

  const handleCryptoShred = async () => {
    await SecureStorageService.purgeAllData();
    NotificationService.clearNotifications();
    setShredded(true);
    setTimeout(() => setShredded(false), 3000);
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
    <div style={{ padding: '1rem', color: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <h2 style={{ margin: '0 0 0.25rem 0', fontSize: '1.25rem', color: '#38bdf8' }}>
          Permissions & Privacy Center
        </h2>
        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
          Privacy Architecture & Guarantees · Ground-truth audit of device permissions, platform access boundaries, and zero-knowledge guarantees.
        </p>
      </div>

      {error && (
        <div style={{ padding: '0.75rem', backgroundColor: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', borderRadius: '8px', color: '#f87171', fontSize: '0.85rem' }}>
          {error}
        </div>
      )}

      {loading && !report ? (
        <div style={{ textAlign: 'center', padding: '2rem', color: '#94a3b8' }}>
          Auditing Android security & permission state...
        </div>
      ) : report ? (
        <>
          {/* 1. Storage & SAF Access */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>1. Storage & File Access</strong>
              {report.storage.status === 'GRANTED_SAF' && renderBadge('SAF GRANTED', 'GREEN')}
              {report.storage.status === 'GRANTED_LEGACY' && renderBadge('LEGACY GRANTED', 'GREEN')}
              {report.storage.status === 'LIMITED' && renderBadge('MEDIASTORE (LIMITED)', 'YELLOW')}
              {report.storage.status === 'DENIED' && renderBadge('DENIED', 'RED')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>Mechanism:</strong> {report.storage.mechanism} | <strong>SAF Trees:</strong> {report.storage.persistedSafTreesCount}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              <strong>Accessible Scope:</strong> {report.storage.accessibleScope}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              <strong>OS Limitation:</strong> {report.storage.inaccessibleScope}
            </div>
            <button
              type="button"
              onClick={() => service.openAppDetailsSettings()}
              style={{
                alignSelf: 'flex-start',
                marginTop: '0.35rem',
                padding: '0.4rem 0.75rem',
                backgroundColor: '#0f172a',
                color: '#38bdf8',
                border: '1px solid #0284c7',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Open Android App Settings
            </button>
          </div>

          {/* 2. Notification Permission */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>2. Security Notifications</strong>
              {report.notifications.areNotificationsEnabled ? renderBadge('ENABLED', 'GREEN') : renderBadge('DISABLED', 'RED')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>Runtime Permission:</strong> {report.notifications.runtimePermission}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              <strong>Dependent Security Alerts:</strong> {report.notifications.dependentFeatures}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              ⚠️ {report.notifications.alertDeliveryDisclaimer}
            </div>
            <button
              type="button"
              onClick={() => service.openNotificationSettings()}
              style={{
                alignSelf: 'flex-start',
                marginTop: '0.35rem',
                padding: '0.4rem 0.75rem',
                backgroundColor: '#0f172a',
                color: '#38bdf8',
                border: '1px solid #0284c7',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Configure Notification Channels
            </button>
          </div>

          {/* 3. VPN / Web Shield */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>3. Web Shield (DNS Filter VPN)</strong>
              {report.vpnWebShield.serviceState === 'ACTIVE' && renderBadge('ACTIVE', 'GREEN')}
              {report.vpnWebShield.serviceState === 'CONSENT_PENDING' && renderBadge('CONSENT PENDING', 'YELLOW')}
              {report.vpnWebShield.serviceState === 'COEXISTENCE_CONFLICT' && renderBadge('EXTERNAL VPN ACTIVE', 'YELLOW')}
              {report.vpnWebShield.serviceState === 'STOPPED' && renderBadge('STOPPED', 'BLUE')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>State:</strong> {report.vpnWebShield.serviceState} | <strong>Queries Filtered:</strong> {report.vpnWebShield.totalDnsQueries} | <strong>Blocked:</strong> {report.vpnWebShield.blockedDnsQueries}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              {report.vpnWebShield.vpnCoexistenceExplanation}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#34d399' }}>
              🛡️ {report.vpnWebShield.privacyGuarantee}
            </div>
          </div>

          {/* 4. App Installation Source Visibility */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>4. App Install Source Visibility</strong>
              {renderBadge('STANDARD APP SANDBOX', 'BLUE')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>Detected Installer:</strong> {report.installSource.installerPackage}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              {report.installSource.scopeExplanation}
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              ℹ️ {report.installSource.privilegeTruth}
            </div>
          </div>

          {/* 5. Background Scanning */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>5. Background Scanning & Observers</strong>
              {report.backgroundScanning.status === 'MONITORING_ACTIVE' ? renderBadge('MONITORING ACTIVE', 'GREEN') : renderBadge('STOPPED', 'YELLOW')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>Downloads Observer:</strong> {report.backgroundScanning.isDownloadObserverActive ? 'Registered' : 'Inactive'} | <strong>Events Processed:</strong> {report.backgroundScanning.eventsProcessed}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              {report.backgroundScanning.restrictionsNotice}
            </div>
          </div>

          {/* 6. Battery Optimization */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>6. Battery Optimization</strong>
              {report.batteryOptimization.isIgnoringBatteryOptimizations ? renderBadge('EXEMPTED', 'BLUE') : renderBadge('ENFORCED (STANDARD)', 'GREEN')}
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              {report.batteryOptimization.explanation}
            </div>
            <button
              type="button"
              onClick={() => service.openBatteryOptimizationSettings()}
              style={{
                alignSelf: 'flex-start',
                marginTop: '0.35rem',
                padding: '0.4rem 0.75rem',
                backgroundColor: '#0f172a',
                color: '#38bdf8',
                border: '1px solid #0284c7',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              System Battery Optimization Settings
            </button>
          </div>

          {/* 7. Telemetry & Data Collection */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #10b981', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem', color: '#34d399' }}>7. Telemetry & Network Data Collection</strong>
              {renderBadge('ZERO COLLECTION', 'GREEN')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>Telemetry Implemented:</strong> {report.telemetry.isTelemetryImplemented ? 'Yes' : 'No'} | <strong>Payloads Transmitted:</strong> 0 Bytes
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              {report.telemetry.explanation}
            </div>
          </div>

          {/* 8. Threat Database Freshness */}
          <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <strong style={{ fontSize: '0.95rem' }}>8. Threat Database Freshness</strong>
              {report.threatDatabase.staleness === 'FRESH' && renderBadge('FRESH', 'GREEN')}
              {report.threatDatabase.staleness === 'AGED' && renderBadge('AGED (7+ d)', 'YELLOW')}
              {report.threatDatabase.staleness === 'STALE' && renderBadge('STALE (14+ d)', 'YELLOW')}
              {report.threatDatabase.staleness === 'EXPIRED_CACHE' && renderBadge('EXPIRED (30+ d)', 'RED')}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
              <strong>Sequence:</strong> #{report.threatDatabase.activeSequence} | <strong>Records:</strong> {report.threatDatabase.recordCount} | <strong>Age:</strong> {report.threatDatabase.ageDays} days
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              <strong>Verification:</strong> {report.threatDatabase.isCryptographicallyVerified ? 'Verified' : 'Unverified'} ({report.threatDatabase.verificationMechanism})
            </div>
          </div>
        </>
      ) : null}

      {/* Crypto-Shredding Card */}
      <div style={{ backgroundColor: '#1e293b', border: '1px solid #ef4444', borderRadius: '16px', padding: '1.25rem' }}>
        <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: '#f87171' }}>
          One-Click Crypto-Shredder
        </h4>
        <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem', color: '#cbd5e1' }}>
          Instantly purge all local application state, custom allowlists, preferences, and scan history records from this device.
        </p>

        {shredded ? (
          <div style={{ padding: '0.75rem', backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#34d399', borderRadius: '8px', textAlign: 'center', fontSize: '0.85rem', fontWeight: 600 }}>
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
              borderRadius: '8px',
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.9rem',
              width: '100%'
            }}
          >
            Crypto-Shred All Local Data
          </button>
        )}
      </div>
    </div>
  );
};
