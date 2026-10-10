import React, { useState, useEffect } from 'react';
import { Sidebar, DesktopNavTab } from './components/Sidebar';
import { Header } from './components/Header';
import { FrictionGateModal } from './components/FrictionGateModal';
import { ThreatDetectionModal } from './components/ThreatDetectionModal';

// All 20 Required Screens
import { HomeScreen } from './screens/HomeScreen';
import { QuickScanScreen } from './screens/QuickScanScreen';
import { FullScanScreen } from './screens/FullScanScreen';
import { CustomScanScreen } from './screens/CustomScanScreen';
import { ScheduledScanScreen } from './screens/ScheduledScanScreen';
import { RealtimeProtectionScreen } from './screens/RealtimeProtectionScreen';
import { ScanResultsScreen } from './screens/ScanResultsScreen';
import { AssistantScreen } from './screens/AssistantScreen';
import { QuarantineScreen } from './screens/QuarantineScreen';
import { HistoryScreen } from './screens/HistoryScreen';
import { RansomwareShieldScreen } from './screens/RansomwareShieldScreen';
import { WebProtectionScreen } from './screens/WebProtectionScreen';
import { NotificationsScreen } from './screens/NotificationsScreen';
import { ProtectionStatusScreen } from './screens/ProtectionStatusScreen';
import { UpdateStatusScreen } from './screens/UpdateStatusScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import { ExclusionsScreen } from './screens/ExclusionsScreen';
import { TrustedAppsScreen } from './screens/TrustedAppsScreen';
import { RecoveryScreen } from './screens/RecoveryScreen';
import { AboutSecurityScreen } from './screens/AboutSecurityScreen';

import {
  DetectedThreat,
  QuarantineItem,
  ScanResult,
  DesktopProtectionStatus,
  DesktopSettings,
  RealtimeThreatEvent,
  SystemHealthReport,
  WatchdogStatus,
  ThreatIntelStatus,
  RansomwareShieldStatus,
  ScanSchedulerState
} from '../types/desktop.types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<DesktopNavTab>('home');
  const [threats, setThreats] = useState<DetectedThreat[]>([]);
  const [quarantineItems, setQuarantineItems] = useState<QuarantineItem[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<DetectedThreat | null>(null);
  const [filesScannedTotal, setFilesScannedTotal] = useState<number>(0);
  const [realtimeAlert, setRealtimeAlert] = useState<RealtimeThreatEvent | null>(null);
  const [recentThreatEvents, setRecentThreatEvents] = useState<RealtimeThreatEvent[]>([]);
  const [unreadNotificationsCount, setUnreadNotificationsCount] = useState<number>(0);

  // Subsystem Backend States
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

  const [healthReport, setHealthReport] = useState<SystemHealthReport | null>(null);
  const [watchdogStatus, setWatchdogStatus] = useState<WatchdogStatus | null>(null);
  const [threatIntelStatus, setThreatIntelStatus] = useState<ThreatIntelStatus | null>(null);
  const [ransomwareStatus, setRansomwareStatus] = useState<RansomwareShieldStatus | null>(null);
  const [schedulerState, setSchedulerState] = useState<ScanSchedulerState | null>(null);

  // Friction Gate Modal State
  const [frictionGate, setFrictionGate] = useState<{
    isOpen: boolean;
    title: string;
    description: string;
    onConfirm: () => void;
  }>({
    isOpen: false,
    title: '',
    description: '',
    onConfirm: () => {}
  });

  const requestFrictionGate = (actionDesc: string, onConfirm: () => void) => {
    if (!settings.frictionGateEnabled) {
      onConfirm();
      return;
    }
    setFrictionGate({
      isOpen: true,
      title: '⚠️ Security Friction Gate Confirmation',
      description: `This operation lowers or modifies security protection: "${actionDesc}". Confirm only if you trust this action.`,
      onConfirm: () => {
        setFrictionGate((prev) => ({ ...prev, isOpen: false }));
        onConfirm();
      }
    });
  };

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

  const handleReEnableShield = async () => {
    if (window.desktopSecurity?.snoozeShield) {
      await window.desktopSecurity.snoozeShield(0);
    }
    if (window.desktopSecurity?.saveSettings) {
      await window.desktopSecurity.saveSettings({ realtimeShieldEnabled: true });
    }
    setSettings((prev) => ({ ...prev, realtimeShieldEnabled: true }));
    if (window.desktopSecurity?.getProtectionStatus) {
      const s = await window.desktopSecurity.getProtectionStatus();
      setStatus(s);
    }
    if (window.desktopSecurity?.getWatchdogStatus) {
      const w = await window.desktopSecurity.getWatchdogStatus();
      setWatchdogStatus(w);
    }
  };

  useEffect(() => {
    const cleanupFns: Array<() => void> = [];

    // Hydrate backend state
    if (window.desktopSecurity?.listQuarantine) {
      window.desktopSecurity.listQuarantine().then(setQuarantineItems).catch(() => {});
    }
    if (window.desktopSecurity?.getProtectionStatus) {
      window.desktopSecurity.getProtectionStatus().then(setStatus).catch(() => {});
    }
    if (window.desktopSecurity?.getSettings) {
      window.desktopSecurity.getSettings().then(setSettings).catch(() => {});
    }
    if (window.desktopSecurity?.getHealthStatus) {
      window.desktopSecurity.getHealthStatus().then(setHealthReport).catch(() => {});
    }
    if (window.desktopSecurity?.getWatchdogStatus) {
      window.desktopSecurity.getWatchdogStatus().then(setWatchdogStatus).catch(() => {});
    }
    if (window.desktopSecurity?.getThreatIntelStatus) {
      window.desktopSecurity.getThreatIntelStatus().then(setThreatIntelStatus).catch(() => {});
    }
    if (window.desktopSecurity?.getRansomwareStatus) {
      window.desktopSecurity.getRansomwareStatus().then(setRansomwareStatus).catch(() => {});
    }
    if (window.desktopSecurity?.getScanSchedule) {
      window.desktopSecurity.getScanSchedule().then(setSchedulerState).catch(() => {});
    }
    if (window.desktopSecurity?.getNotificationInboxState) {
      window.desktopSecurity.getNotificationInboxState().then((s) => setUnreadNotificationsCount(s.unreadCount)).catch(() => {});
    }

    // Subscribe to Realtime Ingress Threat Events (Screen 07 Interstitial trigger)
    if (window.desktopSecurity?.onRealtimeThreat) {
      const unsub = window.desktopSecurity.onRealtimeThreat((event: RealtimeThreatEvent) => {
        setThreats((prev) => {
          const exists = prev.some((t) => t.id === event.threat.id || t.filePath === event.threat.filePath);
          if (exists) {
            return prev.map((t) => (t.id === event.threat.id || t.filePath === event.threat.filePath ? event.threat : t));
          }
          return [event.threat, ...prev];
        });

        if (event.actionTaken === 'AUTO_QUARANTINED' && event.quarantineItem) {
          setQuarantineItems((prev) => {
            const exists = prev.some((q) => q.quarantineId === event.quarantineItem!.quarantineId);
            return exists ? prev : [event.quarantineItem!, ...prev];
          });
        }

        setRecentThreatEvents((prev) => [event, ...prev.slice(0, 19)]);
        setRealtimeAlert(event);
      });
      cleanupFns.push(unsub);
    }

    // Subscribe to System Tray Quick Scan trigger
    if (window.desktopSecurity?.onTriggerQuickScan) {
      const unsub = window.desktopSecurity.onTriggerQuickScan(() => {
        void handleStartQuickScan();
      });
      cleanupFns.push(unsub);
    }

    // Subscribe to Notification Events
    if (window.desktopSecurity?.onNotificationEvent) {
      const unsub = window.desktopSecurity.onNotificationEvent(() => {
        setUnreadNotificationsCount((prev) => prev + 1);
      });
      cleanupFns.push(unsub);
    }

    // Subscribe to Health & Watchdog Events
    if (window.desktopSecurity?.onHealthEvent) {
      const unsub = window.desktopSecurity.onHealthEvent((data: any) => {
        if (data && typeof data === 'object') setHealthReport(data);
      });
      cleanupFns.push(unsub);
    }
    if (window.desktopSecurity?.onWatchdogEvent) {
      const unsub = window.desktopSecurity.onWatchdogEvent((data: any) => {
        if (data && typeof data === 'object') setWatchdogStatus(data);
      });
      cleanupFns.push(unsub);
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
      throw new Error('DESKTOP_BRIDGE_UNAVAILABLE: Native quarantine vault requires desktop runtime.');
    }
    const qItem = await window.desktopSecurity.isolateFile(threat.filePath);
    setQuarantineItems((prev) => [qItem, ...prev]);
    setThreats((prev) =>
      prev.map((t) => (t.id === threat.id ? { ...t, quarantined: true } : t))
    );
  };

  const handleRestoreQuarantine = async (item: QuarantineItem) => {
    requestFrictionGate(`Restore quarantined file '${item.originalPath}' to disk`, async () => {
      if (window.desktopSecurity?.restoreQuarantine) {
        await window.desktopSecurity.restoreQuarantine(item.quarantineId);
      }
      setQuarantineItems((prev) => prev.filter((q) => q.quarantineId !== item.quarantineId));
    });
  };

  const handleDeleteQuarantine = async (item: QuarantineItem) => {
    if (window.desktopSecurity?.deleteQuarantine) {
      await window.desktopSecurity.deleteQuarantine(item.quarantineId);
    }
    setQuarantineItems((prev) => prev.filter((q) => q.quarantineId !== item.quarantineId));
  };

  const handlePurgeAllQuarantine = async () => {
    requestFrictionGate('Permanently shred ALL quarantined files in PPVAULT2', async () => {
      if (window.desktopSecurity?.privacyShred) {
        await window.desktopSecurity.privacyShred();
      }
      setQuarantineItems([]);
      setThreats([]);
    });
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

  const handleSnoozeShield = async (durationMs: number) => {
    if (window.desktopSecurity?.snoozeShield) {
      await window.desktopSecurity.snoozeShield(durationMs);
      const w = await window.desktopSecurity.getWatchdogStatus();
      setWatchdogStatus(w);
    }
  };

  // Derive top-level posture
  const unquarantinedThreatsCount = threats.filter((t) => !t.quarantined).length;
  const isCrit =
    unquarantinedThreatsCount > 0 ||
    healthReport?.overallState === 'CRITICAL' ||
    healthReport?.overallState === 'DEGRADED' ||
    (!status.realtimeShieldActive && !watchdogStatus?.shieldSnoozeActive);

  const isAttn =
    !isCrit &&
    (healthReport?.overallState === 'WARNING' ||
      Boolean(watchdogStatus?.shieldSnoozeActive) ||
      threatIntelStatus?.stalenessState === 'STALE');

  const postureStatus: 'PROTECTED' | 'ATTENTION' | 'ACTION_REQUIRED' = isCrit
    ? 'ACTION_REQUIRED'
    : isAttn
    ? 'ATTENTION'
    : 'PROTECTED';

  const renderActiveScreen = () => {
    switch (activeTab) {
      case 'home':
        return (
          <HomeScreen
            onNavigate={setActiveTab}
            threatsCount={unquarantinedThreatsCount}
            quarantineCount={quarantineItems.length}
            filesScannedTotal={filesScannedTotal}
            status={status}
            healthReport={healthReport}
            watchdogStatus={watchdogStatus}
            threatIntelStatus={threatIntelStatus}
            ransomwareStatus={ransomwareStatus}
            schedulerState={schedulerState}
            onQuickScanLaunch={handleStartQuickScan}
            onReEnableShield={handleReEnableShield}
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

      case 'scheduled-scan':
        return (
          <ScheduledScanScreen
            onScanTriggered={handleScanComplete}
          />
        );

      case 'realtime':
        return (
          <RealtimeProtectionScreen
            status={status}
            settings={settings}
            watchdogStatus={watchdogStatus}
            onUpdateSettings={handleSaveSettings}
            onSnoozeShield={handleSnoozeShield}
            onResumeShield={handleReEnableShield}
            onRequestFrictionGate={requestFrictionGate}
            recentEvents={recentThreatEvents}
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

      case 'assistant':
        return (
          <AssistantScreen
            selectedThreat={selectedThreat}
            onExplainThreat={async (threat, level) => {
              if (window.desktopSecurity?.explainThreat) {
                return window.desktopSecurity.explainThreat(threat, level);
              }
              return {
                threatTitle: threat.threatName,
                summary: `This file was blocked because it exhibits suspicious executable signals (${threat.evidenceFactors.join(', ')}).`,
                explanation: 'The system inspected the header bytes and found indicators common to deceptive files designed to trick users into running hidden software.',
                riskLevel: threat.severity.toUpperCase(),
                recommendedActions: ['Do not run or open this file', 'Keep the file in the quarantine vault', 'Delete the file if you did not expect it'],
                cognitiveLevel: level
              };
            }}
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

      case 'history':
        return <HistoryScreen />;

      case 'ransomware':
        return (
          <RansomwareShieldScreen
            onRequestFrictionGate={requestFrictionGate}
            onNavigateToTrustedApps={() => setActiveTab('trusted-apps')}
          />
        );

      case 'web-protection':
        return <WebProtectionScreen />;

      case 'notifications':
        return <NotificationsScreen />;

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
            onResetIsolation={
              window.desktopSecurity?.resetWatchdogIsolation
                ? (name) => window.desktopSecurity!.resetWatchdogIsolation(name)
                : undefined
            }
          />
        );

      case 'updates':
        return <UpdateStatusScreen />;

      case 'settings':
        return (
          <SettingsScreen
            initialSettings={settings}
            onSaveSettings={handleSaveSettings}
          />
        );

      case 'exclusions':
        return <ExclusionsScreen onRequestFrictionGate={requestFrictionGate} />;

      case 'trusted-apps':
        return <TrustedAppsScreen onRequestFrictionGate={requestFrictionGate} />;

      case 'recovery':
        return <RecoveryScreen onRequestFrictionGate={requestFrictionGate} />;

      case 'about':
        return <AboutSecurityScreen />;

      default:
        return <div>Unknown Screen</div>;
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        height: '100vh',
        width: '100vw',
        overflow: 'hidden',
        fontFamily: 'system-ui, -apple-system, sans-serif'
      }}
    >
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        quarantineCount={quarantineItems.length}
        threatsCount={unquarantinedThreatsCount}
        unreadNotificationsCount={unreadNotificationsCount}
      />

      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          backgroundColor: '#f8fafc'
        }}
      >
        <Header
          threatsCount={unquarantinedThreatsCount}
          engineActive={status.realtimeShieldActive}
          offline={status.offlineMode}
          unreadNotificationsCount={unreadNotificationsCount}
          postureStatus={postureStatus}
          onOpenNotifications={() => setActiveTab('notifications')}
          onOpenStatus={() => setActiveTab('status')}
        />

        <main style={{ flex: 1, overflowY: 'auto' }}>
          <div key={activeTab} className="motion-tab-panel">
            {renderActiveScreen()}
          </div>
        </main>
      </div>

      {/* Screen 07: High-Priority Threat Detection Modal Interstitial */}
      {realtimeAlert && (
        <ThreatDetectionModal
          alert={realtimeAlert}
          onAcknowledge={() => setRealtimeAlert(null)}
          onInspectEvidence={(t) => {
            setSelectedThreat(t);
            setActiveTab('results');
            setRealtimeAlert(null);
          }}
          onRequestRestore={(t) => {
            requestFrictionGate(`Restore malicious threat '${t.fileName}'`, async () => {
              setRealtimeAlert(null);
            });
          }}
        />
      )}

      {/* Security Friction Gate Modal */}
      <FrictionGateModal
        isOpen={frictionGate.isOpen}
        title={frictionGate.title}
        description={frictionGate.description}
        confirmLabel="Confirm Security Modification"
        countdownSeconds={3}
        onConfirm={frictionGate.onConfirm}
        onCancel={() => setFrictionGate((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
