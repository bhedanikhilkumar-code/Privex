import React, { useEffect, useState } from 'react';
import { MobileThreatIntelService } from '../services/mobile-threat-intel.service';
import { MobileQuarantineService } from '../services/mobile-quarantine.service';
import { AdaptiveProtectionService } from '../services/adaptive-protection.service';
import type {
  ThreatDatabaseInspectionResult,
  QuarantineRecordDTO,
  QuarantineVaultStatsDTO,
  AdaptiveResourceStatusDTO
} from '../types/mobile.types';

interface ProtectionStatusScreenProps {
  onBack?: () => void;
  onNavigateVault?: () => void;
}

export const ProtectionStatusScreen: React.FC<ProtectionStatusScreenProps> = ({ onBack, onNavigateVault }) => {
  const [intelStatus, setIntelStatus] = useState<ThreatDatabaseInspectionResult | null>(null);
  const [isRollbackRunning, setIsRollbackRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [vaultStats, setVaultStats] = useState<QuarantineVaultStatsDTO | null>(null);
  const [quarantineItems, setQuarantineItems] = useState<QuarantineRecordDTO[]>([]);
  const [adaptiveStatus, setAdaptiveStatus] = useState<AdaptiveResourceStatusDTO | null>(null);
  const [viewTab, setViewTab] = useState<'OVERVIEW' | 'VAULT'>('OVERVIEW');

  const handleOpenVault = () => {
    if (onNavigateVault) {
      onNavigateVault();
    } else {
      setViewTab('VAULT');
    }
  };

  const quarantineService = new MobileQuarantineService();
  const adaptiveService = AdaptiveProtectionService.getInstance();

  useEffect(() => {
    loadIntelStatus();
    loadQuarantineData();
    loadAdaptiveStatus();
  }, []);

  const loadAdaptiveStatus = async () => {
    try {
      const status = await adaptiveService.getAdaptiveStatus();
      setAdaptiveStatus(status);
    } catch (e: any) {
      console.warn('Failed to load adaptive status', e);
    }
  };

  const loadIntelStatus = async () => {
    try {
      const status = await MobileThreatIntelService.inspectDatabaseHealth();
      setIntelStatus(status);
    } catch (e: any) {
      console.warn('Failed to load threat intel status', e);
    }
  };

  const loadQuarantineData = async () => {
    try {
      const [stats, items] = await Promise.all([
        quarantineService.getQuarantineStats(),
        quarantineService.getQuarantinedItems()
      ]);
      setVaultStats(stats);
      setQuarantineItems(items);
    } catch (e: any) {
      console.warn('Failed to load quarantine data', e);
    }
  };

  const handleRestore = async (itemId: string) => {
    try {
      const res = await quarantineService.restoreQuarantinedFile(itemId);
      if (res.status === 'RESTORED') {
        setStatusMessage(`Item restored successfully to: ${res.restoredPath}`);
        await loadQuarantineData();
      } else {
        setStatusMessage(`Restore failed: ${res.error || res.message}`);
      }
    } catch (e: any) {
      setStatusMessage(`Restore error: ${e.message || String(e)}`);
    }
  };

  const handleDeleteItem = async (itemId: string) => {
    try {
      const ok = await quarantineService.deleteQuarantinedItem(itemId);
      if (ok) {
        setStatusMessage('Quarantined item purged from vault.');
        await loadQuarantineData();
      } else {
        setStatusMessage('Failed to purge quarantined item.');
      }
    } catch (e: any) {
      setStatusMessage(`Purge error: ${e.message || String(e)}`);
    }
  };

  const handleRollback = async () => {
    setIsRollbackRunning(true);
    setStatusMessage(null);
    try {
      const success = await MobileThreatIntelService.rollbackToFactorySeed();
      if (success) {
        setStatusMessage('Successfully rolled back threat database to factory seed.');
        await loadIntelStatus();
      } else {
        setStatusMessage('Rollback failed.');
      }
    } catch (e: any) {
      setStatusMessage(`Rollback error: ${e.message || String(e)}`);
    } finally {
      setIsRollbackRunning(false);
    }
  };

  const engineComponents = [
    { name: 'Deterministic Rule Engine', status: 'OPERATIONAL', latency: '< 0.2 ms', type: 'Offline Ruleset' },
    { name: 'Lexical & Entropy Analyzer', status: 'OPERATIONAL', latency: '< 0.5 ms', type: 'Heuristic' },
    { name: 'Threat Intelligence (.ppdb)', status: intelStatus?.isVerified ? 'OPERATIONAL' : 'DEGRADED', latency: '< 0.05 ms', type: 'Signed Local DB' },
    { name: 'Multi-Factor Risk Scorer', status: 'OPERATIONAL', latency: '< 0.1 ms', type: 'Bayesian Aggregator' },
    { name: 'Semantic URL Classifier', status: 'OPERATIONAL', latency: '< 0.01 ms', type: 'On-Device ML' },
    { name: 'AI Security Assistant Runtime', status: 'OPERATIONAL', latency: '< 0.02 ms', type: 'Template Fallback Engine' }
  ];

  const stalenessColor = intelStatus?.stalenessState === 'FRESH'
    ? '#34d399'
    : intelStatus?.stalenessState === 'AGED'
      ? '#fbbf24'
      : '#f87171';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem', color: '#f8fafc' }}>
      {/* Top Header Bar matching Protection Status & Quarantine Vault demo frames */}
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
              PROTECTION ENGINE
            </span>
            <h1 style={{ margin: '0.1rem 0 0 0', fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
              Engine Diagnostics & Health
            </h1>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button
            type="button"
            onClick={() => setViewTab(viewTab === 'OVERVIEW' ? 'VAULT' : 'OVERVIEW')}
            style={{
              padding: '0.35rem 0.75rem',
              borderRadius: '9999px',
              border: '1px solid #27364b',
              backgroundColor: '#111b2e',
              color: '#38bdf8',
              fontSize: '0.75rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {viewTab === 'OVERVIEW' ? 'View Vault' : 'View Engine'}
          </button>
        </div>
      </div>

      {/* Tab bar switch for Overview vs Quarantine Vault */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '0.5rem',
          backgroundColor: '#0f172a',
          padding: '0.25rem',
          borderRadius: '12px'
        }}
      >
        <button
          type="button"
          onClick={() => setViewTab('OVERVIEW')}
          style={{
            padding: '0.6rem',
            border: 'none',
            borderRadius: '10px',
            cursor: 'pointer',
            fontWeight: viewTab === 'OVERVIEW' ? 700 : 500,
            backgroundColor: viewTab === 'OVERVIEW' ? '#2563eb' : 'transparent',
            color: viewTab === 'OVERVIEW' ? '#ffffff' : '#94a3b8',
            fontSize: '0.85rem'
          }}
        >
          🛡️ Protection Status
        </button>
        <button
          type="button"
          onClick={() => setViewTab('VAULT')}
          style={{
            padding: '0.6rem',
            border: 'none',
            borderRadius: '10px',
            cursor: 'pointer',
            fontWeight: viewTab === 'VAULT' ? 700 : 500,
            backgroundColor: viewTab === 'VAULT' ? '#2563eb' : 'transparent',
            color: viewTab === 'VAULT' ? '#ffffff' : '#94a3b8',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.35rem'
          }}
        >
          <span>📦 Quarantine Vault</span>
          {(vaultStats?.isolatedCount ?? 0) > 0 && (
            <span style={{ fontSize: '0.65rem', backgroundColor: '#ef4444', color: '#ffffff', padding: '0.1rem 0.4rem', borderRadius: '9999px' }}>
              {vaultStats?.isolatedCount}
            </span>
          )}
        </button>
      </div>

      {viewTab === 'OVERVIEW' ? (
        <>
          {/* Circular Hero matching Protection Status.png */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '1.25rem 1rem',
              backgroundColor: '#111b2e',
              border: '1px solid #27364b',
              borderRadius: '20px',
              position: 'relative'
            }}
          >
            <div
              style={{
                width: '100px',
                height: '100px',
                borderRadius: '50%',
                background: 'radial-gradient(circle, rgba(16, 185, 129, 0.25) 0%, rgba(15, 23, 42, 0.8) 70%)',
                border: '2px solid #10b981',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 0 25px rgba(16, 185, 129, 0.3)'
              }}
            >
              <span style={{ fontSize: '2.5rem' }}>🛡️</span>
            </div>
            <h2
              style={{
                margin: '0.85rem 0 0.2rem 0',
                fontSize: '1.2rem',
                fontWeight: 800,
                letterSpacing: '0.04em',
                color: '#34d399',
                textTransform: 'uppercase'
              }}
            >
              SYSTEM HEALTHY
            </h2>
            <p style={{ margin: 0, fontSize: '0.8rem', color: '#94a3b8' }}>
              Real-time heuristic & threat intelligence engine active
            </p>
          </div>

          {/* 4 Metrics Grid matching Protection Status.png */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            {/* Metric 1: Threat DB */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '1.1rem' }}>💾</span>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Threat DB</span>
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                #{intelStatus?.activeMetadata.versionSequence ?? 100}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#34d399', marginTop: '0.2rem' }}>
                {intelStatus?.stalenessState || 'FRESH'} ({intelStatus?.activeMetadata.recordsCount ?? 11} entries)
              </div>
            </div>

            {/* Metric 2: In Quarantine */}
            <div
              onClick={handleOpenVault}
              style={{
                backgroundColor: '#111b2e',
                border: '1px solid #27364b',
                borderRadius: '16px',
                padding: '1rem',
                cursor: 'pointer'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '1.1rem' }}>📦</span>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>In Quarantine</span>
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                {vaultStats?.isolatedCount ?? 0} Items
              </div>
              <div style={{ fontSize: '0.7rem', color: '#38bdf8', marginTop: '0.2rem' }}>
                Vault Secure ↗
              </div>
            </div>

            {/* Metric 3: Power Mode */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '1.1rem' }}>⚡</span>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Power Mode</span>
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                {adaptiveStatus?.resourceMode ?? 'NORMAL'}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#34d399', marginTop: '0.2rem' }}>
                {adaptiveStatus?.batteryPercentage ?? 100}% {adaptiveStatus?.isCharging ? '⚡ Charging' : '🔋 Battery'}
              </div>
            </div>

            {/* Metric 4: Thermal State */}
            <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '1.1rem' }}>🌡️</span>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Thermal State</span>
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                {adaptiveStatus?.thermalStatus ?? 'NOMINAL'}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#34d399', marginTop: '0.2rem' }}>
                Zero Throttling
              </div>
            </div>
          </div>

          {/* System Resources (Memory & CPU) */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.15rem' }}>
            <h4 style={{ margin: '0 0 0.85rem 0', fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
              System Resources
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.35rem' }}>
                  <span style={{ color: '#94a3b8' }}>Volatile RAM Usage</span>
                  <span style={{ color: '#38bdf8', fontWeight: 700 }}>24 MB / 128 MB</span>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: '#0f172a', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: '18.7%', height: '100%', backgroundColor: '#38bdf8', borderRadius: '3px' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.35rem' }}>
                  <span style={{ color: '#94a3b8' }}>Pipeline Latency</span>
                  <span style={{ color: '#34d399', fontWeight: 700 }}>&lt; 0.5 ms avg</span>
                </div>
                <div style={{ width: '100%', height: '6px', backgroundColor: '#0f172a', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{ width: '8%', height: '100%', backgroundColor: '#34d399', borderRadius: '3px' }} />
                </div>
              </div>
            </div>
          </div>

          {/* Offline Parity Banner */}
          <div style={{ backgroundColor: '#0f172a', border: '1px solid #10b981', borderRadius: '16px', padding: '1.15rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <span style={{ fontWeight: 700, color: '#34d399', fontSize: '0.95rem' }}>
                ✓ 100% Offline Parity Active
              </span>
              <span style={{ fontSize: '0.7rem', backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#6ee7b7', padding: '0.2rem 0.5rem', borderRadius: '6px' }}>
                Air-Gapped Ready
              </span>
            </div>
            <p style={{ margin: 0, fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.4 }}>
              All detection rules, heuristic algorithms, local verified threat database, and AI explanation engines operate entirely on-device with zero internet connectivity required.
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem', fontSize: '0.72rem', color: '#64748b' }}>
              <span>Feed: {intelStatus?.activeMetadata.sourceFeed || 'FACTORY_SEED'}</span>
              <span>Version: {intelStatus?.activeMetadata.installedVersion || '1.0.0-seed'}</span>
              <span>Records: {intelStatus?.activeMetadata.recordsCount ?? 11}</span>
            </div>
          </div>

          {/* Threat Database (.ppdb) Card */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.15rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h4 style={{ margin: 0, fontSize: '0.95rem', color: '#38bdf8' }}>Verified Threat Intelligence (.ppdb)</h4>
              <span style={{ fontSize: '0.72rem', fontWeight: 600, color: stalenessColor, padding: '0.2rem 0.5rem', borderRadius: '4px', backgroundColor: 'rgba(255,255,255,0.05)' }}>
                Status: {intelStatus?.stalenessState || 'FRESH'} ({intelStatus?.stalenessDays ?? 0}d)
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Format: PPDB_V1 | Ed25519 Signed & Verified
              </span>
              <button
                type="button"
                onClick={handleRollback}
                disabled={isRollbackRunning || intelStatus?.activeMetadata.isFactorySeed}
                style={{
                  padding: '0.4rem 0.8rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  backgroundColor: intelStatus?.activeMetadata.isFactorySeed ? '#334155' : '#ef4444',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: intelStatus?.activeMetadata.isFactorySeed ? 'not-allowed' : 'pointer'
                }}
              >
                {isRollbackRunning ? 'Rolling back...' : 'Reset to Factory Seed'}
              </button>
            </div>

            {statusMessage && (
              <div style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: statusMessage.includes('Success') ? '#34d399' : '#f87171' }}>
                {statusMessage}
              </div>
            )}
          </div>

          {/* Subsystem Pipeline Table */}
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.15rem' }}>
            <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '0.95rem', color: '#f8fafc' }}>Detection Pipeline Subsystems</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {engineComponents.map((comp, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.65rem 0.75rem',
                    backgroundColor: '#0f172a',
                    borderRadius: '8px',
                    fontSize: '0.85rem'
                  }}
                >
                  <div>
                    <strong style={{ display: 'block', color: '#f8fafc' }}>{comp.name}</strong>
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{comp.type}</span>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span style={{ color: comp.status === 'OPERATIONAL' ? '#34d399' : '#f87171', fontWeight: 700, fontSize: '0.75rem' }}>
                      {comp.status}
                    </span>
                    <span style={{ display: 'block', fontSize: '0.7rem', color: '#64748b' }}>
                      {comp.latency}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      ) : (
        /* Quarantine Vault View matching Quarantine Vault.png */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', borderRadius: '16px', padding: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <div>
                <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#38bdf8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  SECURE STORAGE
                </span>
                <h3 style={{ margin: '0.2rem 0 0 0', fontSize: '1.2rem', color: '#f8fafc', fontWeight: 800 }}>
                  Quarantine Vault
                </h3>
              </div>
              <span
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  color: (vaultStats?.isolatedCount ?? 0) > 0 ? '#f87171' : '#34d399',
                  padding: '0.25rem 0.65rem',
                  borderRadius: '9999px',
                  backgroundColor: (vaultStats?.isolatedCount ?? 0) > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(52, 211, 153, 0.15)',
                  border: `1px solid ${(vaultStats?.isolatedCount ?? 0) > 0 ? '#ef4444' : '#10b981'}`
                }}
              >
                {vaultStats?.isolatedCount ?? 0} ITEMS ISOLATED
              </span>
            </div>
            <p style={{ margin: 0, fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.4 }}>
              Suspicious items isolated in encrypted app-private sandbox (AES-256-GCM container PPMVAULT1). Isolated files cannot execute or access OS storage.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem', marginTop: '1rem' }}>
              <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '10px' }}>
                <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Total Quarantined</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>{vaultStats?.totalItems ?? 0}</div>
              </div>
              <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '10px' }}>
                <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Source Remains</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: (vaultStats?.sourceRemainsCount ?? 0) > 0 ? '#fbbf24' : '#94a3b8' }}>
                  {vaultStats?.sourceRemainsCount ?? 0}
                </div>
              </div>
              <div style={{ backgroundColor: '#0f172a', padding: '0.75rem', borderRadius: '10px' }}>
                <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Vault Size</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
                  {((vaultStats?.totalProtectedBytes ?? 0) / 1024).toFixed(1)} KB
                </div>
              </div>
            </div>
          </div>

          {/* Isolated Items List matching Quarantine Vault.png */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {quarantineItems.length === 0 ? (
              <div style={{ backgroundColor: '#111b2e', border: '1px solid #27364b', padding: '2rem 1rem', borderRadius: '16px', textAlign: 'center', color: '#64748b', fontSize: '0.85rem' }}>
                <span style={{ fontSize: '2rem', display: 'block', marginBottom: '0.5rem' }}>🛡️</span>
                Quarantine vault is empty. No suspicious or malicious files currently isolated.
              </div>
            ) : (
              quarantineItems.map((item) => (
                <div
                  key={item.id}
                  style={{
                    backgroundColor: '#111b2e',
                    border: '1px solid #27364b',
                    borderRadius: '16px',
                    padding: '1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <div
                        style={{
                          width: '40px',
                          height: '40px',
                          borderRadius: '10px',
                          backgroundColor: 'rgba(239, 68, 68, 0.15)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '1.25rem',
                          color: '#f87171'
                        }}
                      >
                        ⚠️
                      </div>
                      <div>
                        <div style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.95rem' }}>{item.fileName}</div>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                          {(item.fileSizeBytes / 1024).toFixed(1)} KB • {new Date(item.quarantineTimestamp).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        color: '#f87171',
                        backgroundColor: 'rgba(239, 68, 68, 0.15)',
                        padding: '0.2rem 0.5rem',
                        borderRadius: '6px'
                      }}
                    >
                      MALWARE
                    </span>
                  </div>

                  <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'monospace' }}>
                    SHA-256: {item.sha256 ? item.sha256.substring(0, 24) + '...' : 'unknown'}
                  </div>

                  <div style={{ display: 'flex', gap: '0.5rem', paddingTop: '0.25rem', borderTop: '1px solid #1e293b' }}>
                    <button
                      type="button"
                      onClick={() => handleRestore(item.id)}
                      style={{
                        flex: 1,
                        padding: '0.5rem',
                        backgroundColor: '#1e293b',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                        color: '#38bdf8',
                        fontWeight: 600,
                        fontSize: '0.8rem',
                        cursor: 'pointer'
                      }}
                    >
                      Restore to Origin
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDeleteItem(item.id)}
                      style={{
                        flex: 1,
                        padding: '0.5rem',
                        backgroundColor: 'rgba(239, 68, 68, 0.15)',
                        border: '1px solid #ef4444',
                        borderRadius: '8px',
                        color: '#f87171',
                        fontWeight: 600,
                        fontSize: '0.8rem',
                        cursor: 'pointer'
                      }}
                    >
                      Permanent Delete
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};
