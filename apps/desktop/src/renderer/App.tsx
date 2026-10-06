import React, { useState, useEffect } from 'react';
import { Sidebar, DesktopNavTab } from './components/Sidebar';
import { Header } from './components/Header';
import { HomeScreen } from './screens/HomeScreen';
import { QuickScanScreen } from './screens/QuickScanScreen';
import { FullScanScreen } from './screens/FullScanScreen';
import { CustomScanScreen } from './screens/CustomScanScreen';
import { ScanResultsScreen } from './screens/ScanResultsScreen';
import { QuarantineScreen } from './screens/QuarantineScreen';
import { ProtectionStatusScreen } from './screens/ProtectionStatusScreen';
import { AssistantScreen } from './screens/AssistantScreen';
import { PrivacyScreen } from './screens/PrivacyScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import { UpdateStatusScreen } from './screens/UpdateStatusScreen';
import {
  DetectedThreat,
  QuarantineItem,
  ScanResult,
  DesktopProtectionStatus,
  DesktopSettings,
  RealtimeThreatEvent
} from '../types/desktop.types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<DesktopNavTab>('home');
  const [threats, setThreats] = useState<DetectedThreat[]>([]);
  const [quarantineItems, setQuarantineItems] = useState<QuarantineItem[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<DetectedThreat | null>(null);
  const [filesScannedTotal, setFilesScannedTotal] = useState<number>(0);
  const [realtimeAlert, setRealtimeAlert] = useState<RealtimeThreatEvent | null>(null);

  const [status, setStatus] = useState<DesktopProtectionStatus>({
    realtimeShieldActive: true,
    monitoredPaths: ['Downloads', 'Temp'],
    threatDatabaseVersion: '2026.10-offline-seed',
    threatDatabaseTimestamp: 1760000000000,
    coreEngineVersion: '1.0.0-verified',
    mlAssistantReady: true,
    offlineMode: true,
    quarantinedCount: 0,
    memoryRssBytes: 0,
    heapUsedBytes: 0
  });

  const [settings, setSettings] = useState<DesktopSettings>({
    realtimeShieldEnabled: true,
    monitorDownloads: true,
    monitorTemp: true,
    scanLargeFilesLimitMb: 50,
    entropyDetectionEnabled: true,
    autoQuarantineCritical: false,
    frictionGateEnabled: true,
    cognitiveLevel: 'grade6',
    excludedPaths: []
  });

  const handleStartQuickScan = async () => {
    setActiveTab('quick-scan');
    if (window.desktopSecurity?.startQuickScan) {
      try {
        const result = await window.desktopSecurity.startQuickScan();
        handleScanComplete(result);
      } catch (err) {
        console.warn('[TRAY_QUICK_SCAN_ERROR]', err);
      }
    }
  };

  useEffect(() => {
    const cleanupFns: Array<() => void> = [];

    // Initial fetch from desktop security bridge if available
    if (window.desktopSecurity?.listQuarantine) {
      window.desktopSecurity.listQuarantine().then(setQuarantineItems).catch(() => {});
    }
    if (window.desktopSecurity?.getProtectionStatus) {
      window.desktopSecurity.getProtectionStatus().then(setStatus).catch(() => {});
    }
    if (window.desktopSecurity?.getSettings) {
      window.desktopSecurity.getSettings().then(setSettings).catch(() => {});
    }

    // Subscribe to real-time ingress threat events (GAP-14)
    if (window.desktopSecurity?.onRealtimeThreat) {
      const unsubscribeRealtime = window.desktopSecurity.onRealtimeThreat((event: RealtimeThreatEvent) => {
        setThreats((prev) => {
          const exists = prev.some(
            (t) => t.id === event.threat.id || t.filePath === event.threat.filePath
          );
          if (exists) {
            return prev.map((t) =>
              t.id === event.threat.id || t.filePath === event.threat.filePath ? event.threat : t
            );
          }
          return [event.threat, ...prev];
        });

        if (event.actionTaken === 'AUTO_QUARANTINED' && event.quarantineItem) {
          setQuarantineItems((prev) => {
            const exists = prev.some(
              (q) => q.quarantineId === event.quarantineItem!.quarantineId
            );
            return exists ? prev : [event.quarantineItem!, ...prev];
          });
        }

        setRealtimeAlert(event);
      });
      cleanupFns.push(unsubscribeRealtime);
    }

    // Subscribe to System Tray Quick Scan trigger (SEC-E-02)
    if (window.desktopSecurity?.onTriggerQuickScan) {
      const unsubscribeTrayQuick = window.desktopSecurity.onTriggerQuickScan(() => {
        void handleStartQuickScan();
      });
      cleanupFns.push(unsubscribeTrayQuick);
    }

    return () => {
      cleanupFns.forEach((fn) => {
        try {
          fn();
        } catch {
          // ignore
        }
      });
    };
  }, []);

  const handleScanComplete = (result: ScanResult) => {
    setFilesScannedTotal((prev) => prev + result.totalFilesScanned);
    if (result.threats.length > 0) {
      setThreats((prev) => {
        const byPath = new Map<string, DetectedThreat>();
        for (const t of result.threats) {
          byPath.set(t.filePath, t);
        }
        for (const existing of prev) {
          if (!byPath.has(existing.filePath)) {
            byPath.set(existing.filePath, existing);
          }
        }
        return Array.from(byPath.values());
      });
      setActiveTab('results');
    }
  };

  const handleSelectThreat = (threat: DetectedThreat) => {
    setSelectedThreat(threat);
    setActiveTab('results');
  };

  const handleExplainThreat = (threat: DetectedThreat) => {
    setSelectedThreat(threat);
    setActiveTab('assistant');
  };

  const handleIsolateThreat = async (threat: DetectedThreat) => {
    if (!window.desktopSecurity?.isolateFile) {
      throw new Error('DESKTOP_BRIDGE_UNAVAILABLE: Native quarantine vault requires the desktop runtime.');
    }
    const qItem = await window.desktopSecurity.isolateFile(threat.filePath);
    setQuarantineItems((prev) => [qItem, ...prev]);

    setThreats((prev) =>
      prev.map((t) => (t.id === threat.id ? { ...t, quarantined: true } : t))
    );
  };

  const handleRestoreQuarantine = async (item: QuarantineItem) => {
    if (window.desktopSecurity?.restoreQuarantine) {
      await window.desktopSecurity.restoreQuarantine(item.quarantineId);
    }
    setQuarantineItems((prev) => prev.filter((q) => q.quarantineId !== item.quarantineId));
  };

  const handleDeleteQuarantine = async (item: QuarantineItem) => {
    if (window.desktopSecurity?.deleteQuarantine) {
      await window.desktopSecurity.deleteQuarantine(item.quarantineId);
    }
    setQuarantineItems((prev) => prev.filter((q) => q.quarantineId !== item.quarantineId));
  };

  const handlePurgeAllQuarantine = async () => {
    if (window.desktopSecurity?.privacyShred) {
      await window.desktopSecurity.privacyShred();
    }
    setQuarantineItems([]);
    setThreats([]);
  };

  const handleSaveSettings = async (newSettings: Partial<DesktopSettings>) => {
    if (window.desktopSecurity?.saveSettings) {
      await window.desktopSecurity.saveSettings(newSettings);
    }
    setSettings((prev) => ({ ...prev, ...newSettings }));
    if (window.desktopSecurity?.getProtectionStatus) {
      window.desktopSecurity.getProtectionStatus().then(setStatus).catch(() => {});
    }
  };

  const renderActiveScreen = () => {
    switch (activeTab) {
      case 'home':
        return (
          <HomeScreen
            onNavigate={setActiveTab}
            threatsCount={threats.filter((t) => !t.quarantined).length}
            quarantineCount={quarantineItems.length}
            filesScannedTotal={filesScannedTotal}
          />
        );
      case 'quick-scan':
        return (
          <QuickScanScreen
            onScanComplete={handleScanComplete}
            onSelectThreat={handleSelectThreat}
          />
        );
      case 'full-scan':
        return (
          <FullScanScreen
            onScanComplete={handleScanComplete}
            onSelectThreat={handleSelectThreat}
          />
        );
      case 'custom-scan':
        return (
          <CustomScanScreen
            onScanComplete={handleScanComplete}
            onSelectThreat={handleSelectThreat}
          />
        );
      case 'results':
        return (
          <ScanResultsScreen
            threats={threats}
            onIsolateThreat={handleIsolateThreat}
            onExplainThreat={handleExplainThreat}
          />
        );
      case 'quarantine':
        return (
          <QuarantineScreen
            items={quarantineItems}
            onRestore={handleRestoreQuarantine}
            onDelete={handleDeleteQuarantine}
            onPurgeAll={handlePurgeAllQuarantine}
          />
        );
      case 'status':
        return (
          <ProtectionStatusScreen
            status={status}
            onAuditProcesses={
              window.desktopSecurity?.auditProcesses
                ? () => window.desktopSecurity!.auditProcesses()
                : async () => []
            }
            onAuditPersistence={
              window.desktopSecurity?.auditPersistence
                ? () => window.desktopSecurity!.auditPersistence()
                : async () => []
            }
          />
        );
      case 'assistant':
        return (
          <AssistantScreen
            selectedThreat={selectedThreat}
            onExplainThreat={
              window.desktopSecurity?.explainThreat
                ? (threat, level) => window.desktopSecurity!.explainThreat(threat, level)
                : async () => ({
                    threatTitle: selectedThreat?.threatName || 'Threat Briefing',
                    summary: 'Suspicious file detected and flagged by on-device rules.',
                    explanation: 'The file contains suspicious patterns common to malware.',
                    riskLevel: selectedThreat?.severity.toUpperCase() || 'HIGH',
                    recommendedActions: ['Keep file in quarantine', 'Do not run or open file'],
                    cognitiveLevel: 'grade6'
                  })
            }
          />
        );
      case 'privacy':
        return <PrivacyScreen onCryptoShred={handlePurgeAllQuarantine} />;
      case 'settings':
        return (
          <SettingsScreen
            initialSettings={settings}
            onSaveSettings={handleSaveSettings}
          />
        );
      case 'updates':
        return <UpdateStatusScreen />;
      default:
        return <div>Unknown View</div>;
    }
  };

  return (
    <div style={{ display: 'flex', height: '100vh', width: '100vw', overflow: 'hidden', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        quarantineCount={quarantineItems.length}
        threatsCount={threats.filter((t) => !t.quarantined).length}
      />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', backgroundColor: '#f8fafc' }}>
        <Header
          threatsCount={threats.filter((t) => !t.quarantined).length}
          engineActive={status.realtimeShieldActive}
          offline={status.offlineMode}
        />

        {realtimeAlert && (
          <div
            data-testid="realtime-threat-alert"
            style={{
              backgroundColor:
                realtimeAlert.actionTaken === 'AUTO_QUARANTINED' ? '#fef2f2' : '#fffbeb',
              borderBottom: `2px solid ${
                realtimeAlert.actionTaken === 'AUTO_QUARANTINED' ? '#ef4444' : '#f59e0b'
              }`,
              padding: '14px 24px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <strong style={{ color: '#991b1b', fontSize: '14px' }}>
                  REAL-TIME INGRESS THREAT DETECTED
                </strong>
                <span
                  data-testid="realtime-action-badge"
                  style={{
                    backgroundColor:
                      realtimeAlert.actionTaken === 'AUTO_QUARANTINED' ? '#dc2626' : '#d97706',
                    color: '#ffffff',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 700
                  }}
                >
                  ACTION TAKEN: {realtimeAlert.actionTaken}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setRealtimeAlert(null)}
                style={{
                  border: '1px solid #cbd5e1',
                  backgroundColor: '#ffffff',
                  borderRadius: '4px',
                  padding: '4px 10px',
                  fontSize: '12px',
                  cursor: 'pointer'
                }}
              >
                Dismiss
              </button>
            </div>

            <div style={{ fontSize: '13px', color: '#1e293b', display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              <span><strong>File:</strong> {realtimeAlert.threat.fileName}</span>
              <span><strong>Verdict:</strong> {realtimeAlert.threat.verdict}</span>
              <span><strong>Severity:</strong> {realtimeAlert.threat.severity.toUpperCase()}</span>
              <span><strong>Risk Score:</strong> {realtimeAlert.threat.riskScore}/100</span>
            </div>

            <div style={{ fontSize: '12px', color: '#475569' }}>
              <strong>Reason / Evidence:</strong> {realtimeAlert.threat.evidenceFactors.join(' • ')}
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              {realtimeAlert.actionTaken === 'ALERTED' && !realtimeAlert.threat.quarantined && (
                <button
                  type="button"
                  onClick={async () => {
                    await handleIsolateThreat(realtimeAlert.threat);
                    setRealtimeAlert((prev) =>
                      prev
                        ? {
                            ...prev,
                            actionTaken: 'AUTO_QUARANTINED',
                            threat: { ...prev.threat, quarantined: true }
                          }
                        : null
                    );
                  }}
                  style={{
                    backgroundColor: '#dc2626',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '6px 12px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Quarantine Threat Now
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  handleExplainThreat(realtimeAlert.threat);
                  setRealtimeAlert(null);
                }}
                style={{
                  backgroundColor: '#e2e8f0',
                  color: '#1e293b',
                  border: 'none',
                  borderRadius: '4px',
                  padding: '6px 12px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Explain Threat
              </button>
            </div>
          </div>
        )}

        <main style={{ flex: 1, overflowY: 'auto' }}>
          {renderActiveScreen()}
        </main>
      </div>
    </div>
  );
};
