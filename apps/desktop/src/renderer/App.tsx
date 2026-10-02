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
  DesktopSettings
} from '../types/desktop.types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<DesktopNavTab>('home');
  const [threats, setThreats] = useState<DetectedThreat[]>([]);
  const [quarantineItems, setQuarantineItems] = useState<QuarantineItem[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<DetectedThreat | null>(null);
  const [filesScannedTotal, setFilesScannedTotal] = useState<number>(142);

  const [status, setStatus] = useState<DesktopProtectionStatus>({
    realtimeShieldActive: true,
    monitoredPaths: ['Downloads', 'Temp'],
    threatDatabaseVersion: '2026.10-offline-seed',
    threatDatabaseTimestamp: 1760000000000,
    coreEngineVersion: '1.0.0-verified',
    mlAssistantReady: true,
    offlineMode: true,
    quarantinedCount: 0,
    memoryRssBytes: 45 * 1024 * 1024,
    heapUsedBytes: 22 * 1024 * 1024
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

  useEffect(() => {
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
  }, []);

  const handleScanComplete = (result: ScanResult) => {
    setFilesScannedTotal((prev) => prev + result.totalFilesScanned);
    if (result.threats.length > 0) {
      setThreats((prev) => [...result.threats, ...prev]);
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
    if (window.desktopSecurity?.isolateFile) {
      const qItem = await window.desktopSecurity.isolateFile(threat.filePath);
      setQuarantineItems((prev) => [qItem, ...prev]);
    } else {
      const isolatedItem: QuarantineItem = {
        quarantineId: `quarantine-${Date.now()}`,
        originalPath: threat.filePath,
        fileName: threat.fileName,
        fileSize: threat.fileSize,
        sha256: threat.sha256,
        threatName: threat.threatName,
        riskScore: threat.riskScore,
        severity: threat.severity,
        quarantinedAt: Date.now(),
        evidenceFactors: threat.evidenceFactors,
        blobPath: 'quarantine-vault'
      };
      setQuarantineItems((prev) => [isolatedItem, ...prev]);
    }

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
        <main style={{ flex: 1, overflowY: 'auto' }}>
          {renderActiveScreen()}
        </main>
      </div>
    </div>
  );
};
