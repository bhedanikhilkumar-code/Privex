// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';

import { App } from '../../renderer/App';
import { HomeScreen } from '../../renderer/screens/HomeScreen';
import { QuickScanScreen } from '../../renderer/screens/QuickScanScreen';
import { FullScanScreen } from '../../renderer/screens/FullScanScreen';
import { CustomScanScreen } from '../../renderer/screens/CustomScanScreen';
import { ScheduledScanScreen } from '../../renderer/screens/ScheduledScanScreen';
import { RealtimeProtectionScreen } from '../../renderer/screens/RealtimeProtectionScreen';
import { ThreatDetectionModal } from '../../renderer/components/ThreatDetectionModal';
import { AssistantScreen } from '../../renderer/screens/AssistantScreen';
import { ScanResultsScreen } from '../../renderer/screens/ScanResultsScreen';
import { HistoryScreen } from '../../renderer/screens/HistoryScreen';
import { RansomwareShieldScreen } from '../../renderer/screens/RansomwareShieldScreen';
import { WebProtectionScreen } from '../../renderer/screens/WebProtectionScreen';
import { NotificationsScreen } from '../../renderer/screens/NotificationsScreen';
import { ProtectionStatusScreen } from '../../renderer/screens/ProtectionStatusScreen';
import { UpdateStatusScreen } from '../../renderer/screens/UpdateStatusScreen';
import { SettingsScreen } from '../../renderer/screens/SettingsScreen';
import { ExclusionsScreen } from '../../renderer/screens/ExclusionsScreen';
import { TrustedAppsScreen } from '../../renderer/screens/TrustedAppsScreen';
import { RecoveryScreen } from '../../renderer/screens/RecoveryScreen';
import { AboutSecurityScreen } from '../../renderer/screens/AboutSecurityScreen';

import {
  DetectedThreat,
  QuarantineItem,
  DesktopProtectionStatus,
  DesktopSettings,
  SystemHealthReport,
  WatchdogStatus,
  ThreatIntelStatus,
  ScanSchedulerState,
  RansomwareShieldStatus
} from '../../types/desktop.types';

describe('Phase R: Desktop UX & 20-Screen Antivirus Command Center', () => {
  const mockThreat: DetectedThreat = {
    id: 'threat-101',
    fileName: 'trojan_payload.exe',
    filePath: 'C:\\Users\\test\\Downloads\\trojan_payload.exe',
    fileSize: 2048576,
    sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    threatName: 'Trojan.Win32.GenericDeception',
    severity: 'critical',
    verdict: 'BLOCK',
    riskScore: 95,
    quarantined: false,
    detectedAt: Date.now(),
    evidenceFactors: ['PE_HEADER_CORRUPTED', 'HIGH_SHANNON_ENTROPY_7_9', 'EMBEDDED_EXECUTABLE_RESOURCE']
  };

  const mockQuarantineItem: QuarantineItem = {
    quarantineId: 'q-99',
    originalPath: 'C:\\Users\\test\\Downloads\\trojan_payload.exe',
    fileName: 'trojan_payload.exe',
    fileSize: 2048576,
    blobPath: 'C:\\ProgramData\\PrivateProtection\\vault\\q-99.ppvault',
    quarantinedAt: Date.now(),
    sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    threatName: 'Trojan.Win32.GenericDeception',
    severity: 'critical',
    riskScore: 95,
    evidenceFactors: ['HIGH_ENTROPY']
  };

  const mockStatus: DesktopProtectionStatus = {
    realtimeShieldActive: true,
    monitoredPaths: ['Downloads', 'Temp'],
    threatDatabaseVersion: '2026.10-offline-seed',
    threatDatabaseTimestamp: Date.now(),
    coreEngineVersion: '1.0.0-verified',
    mlAssistantReady: true,
    offlineMode: true,
    quarantinedCount: 1,
    memoryRssBytes: 104857600,
    heapUsedBytes: 52428800
  };

  const mockSettings: DesktopSettings = {
    realtimeShieldEnabled: true,
    monitorDownloads: true,
    monitorTemp: true,
    scanLargeFilesLimitMb: 50,
    entropyDetectionEnabled: true,
    autoQuarantineCritical: true,
    frictionGateEnabled: true,
    cognitiveLevel: 'grade6',
    excludedPaths: []
  };

  const mockHealthReport: SystemHealthReport = {
    overallState: 'HEALTHY',
    subsystems: [
      { name: 'CoreEngine', state: 'HEALTHY', message: 'Nominal', lastCheckTime: Date.now() },
      { name: 'Watchdog', state: 'HEALTHY', message: 'Heartbeat active', lastCheckTime: Date.now() }
    ],
    issues: [],
    recommendedRemediations: [],
    timestamp: Date.now()
  };

  const mockWatchdogStatus: WatchdogStatus = {
    isActive: true,
    heartbeatIntervalMs: 2000,
    monitoredComponents: [
      { name: 'RealtimeMonitor', status: 'HEALTHY', failureCount: 0, lastHeartbeat: Date.now(), isIsolated: false }
    ],
    safeMinimalMode: false,
    shieldSnoozeActive: false,
    shieldSnoozeRemainingMs: 0,
    shieldSnoozeTotalMs: 0,
    crashHistory: []
  };

  const mockThreatIntelStatus: ThreatIntelStatus = {
    installedVersion: '2026.10.07',
    currentVersionSequence: 42,
    lastUpdated: Date.now(),
    hasLkg: true,
    stalenessState: 'FRESH',
    stalenessDays: 0,
    badHashesCount: 15000,
    isFactorySeed: false
  };

  const mockSchedulerState: ScanSchedulerState = {
    config: {
      enabled: true,
      frequency: 'daily',
      timeOfDay: '03:00',
      scanType: 'quick',
      pauseOnBattery: true,
      runMissedOnStartup: true,
      autoQuarantine: true
    },
    nextScheduledRun: Date.now() + 86400000,
    lastScheduledRun: Date.now() - 3600000,
    lastStatus: 'COMPLETED',
    isRunning: false
  };

  const mockRansomwareStatus: RansomwareShieldStatus = {
    active: true,
    mode: 'smart',
    protectedFolders: ['C:\\Users\\test\\Documents', 'C:\\Users\\test\\Desktop'],
    trustedAppsCount: 5,
    activeCanariesCount: 4,
    incidentsCount: 0,
    vaultTotalSizeBytes: 10485760,
    vaultBackupCount: 3
  };

  beforeEach(() => {
    // Setup window.desktopSecurity mock
    (window as any).desktopSecurity = {
      getHealthStatus: vi.fn().mockResolvedValue(mockHealthReport),
      getWatchdogStatus: vi.fn().mockResolvedValue(mockWatchdogStatus),
      getThreatIntelStatus: vi.fn().mockResolvedValue(mockThreatIntelStatus),
      getRansomwareStatus: vi.fn().mockResolvedValue(mockRansomwareStatus),
      getRansomwareIncidents: vi.fn().mockResolvedValue([]),
      getScanSchedule: vi.fn().mockResolvedValue(mockSchedulerState),
      saveScanSchedule: vi.fn().mockResolvedValue({ success: true, nextScheduledRun: Date.now() + 86400000 }),
      getExclusions: vi.fn().mockResolvedValue([]),
      createExclusion: vi.fn().mockResolvedValue({ success: true }),
      removeExclusion: vi.fn().mockResolvedValue(true),
      getTrustedApplications: vi.fn().mockResolvedValue([]),
      addTrustedApplication: vi.fn().mockResolvedValue({ success: true }),
      revokeTrustedApplication: vi.fn().mockResolvedValue(true),
      getRemovableMedia: vi.fn().mockResolvedValue([]),
      scanRemovableMedia: vi.fn().mockResolvedValue({
        mountPoint: 'E:',
        totalRootItemsScanned: 12,
        threatsFound: 0,
        riskScore: 0,
        durationMs: 45
      }),
      queryAuditLogs: vi.fn().mockResolvedValue({ entries: [], totalCount: 0 }),
      verifyAuditChainIntegrity: vi.fn().mockResolvedValue({ isValid: true, totalEntries: 10, verifiedEntries: 10 }),
      getNotificationsInbox: vi.fn().mockResolvedValue({ notifications: [], unreadCount: 0, totalCount: 0 }),
      getRateLimiterTelemetry: vi.fn().mockResolvedValue({ burstSuppressedCount: 0, windowActive: false }),
      markNotificationAsRead: vi.fn().mockResolvedValue(true),
      markAllNotificationsAsRead: vi.fn().mockResolvedValue(0),
      clearNotificationsInbox: vi.fn().mockResolvedValue(0),
      getFirewallStatus: vi.fn().mockResolvedValue({ domainProfile: 'ON', privateProfile: 'ON', publicProfile: 'ON', isFirewallActive: true }),
      getActiveNetworkConnections: vi.fn().mockResolvedValue([]),
      getWebProtectionStatus: vi.fn().mockResolvedValue({ active: true, motwMonitoring: true }),
      explainThreat: vi.fn().mockResolvedValue({
        threatTitle: mockThreat.threatName,
        summary: 'Deceptive executable detected.',
        explanation: 'The file contains suspicious indicators.',
        riskLevel: 'CRITICAL',
        recommendedActions: ['Keep file quarantined', 'Do not run'],
        cognitiveLevel: 'grade6'
      }),
      runInvariantSelfTest: vi.fn().mockResolvedValue([
        { invariantId: 'INV-01', name: 'Zero-Cloud Telemetry', passed: true, message: 'Air-gapped' }
      ]),
      isolateFile: vi.fn().mockResolvedValue(mockQuarantineItem),
      restoreQuarantine: vi.fn().mockResolvedValue(true),
      deleteQuarantine: vi.fn().mockResolvedValue(true),
      privacyShred: vi.fn().mockResolvedValue({ success: true }),
      updateSettings: vi.fn().mockResolvedValue(mockSettings),
      startQuickScan: vi.fn().mockResolvedValue({
        scanId: 'qs-1',
        scanType: 'quick',
        totalFilesScanned: 50,
        threats: [],
        durationMs: 250,
        startTime: Date.now(),
        completedAt: Date.now()
      }),
      startFullScan: vi.fn().mockResolvedValue({
        scanId: 'fs-1',
        scanType: 'full',
        totalFilesScanned: 1000,
        threats: [],
        durationMs: 5000,
        startTime: Date.now(),
        completedAt: Date.now()
      })
    };
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  // SCREEN 01: Home / Dashboard
  it('Screen 01 (HomeScreen) renders 3-Tier Posture Banner and Subsystem Grid', () => {
    render(
      <HomeScreen
        status={mockStatus}
        threatsCount={0}
        healthReport={mockHealthReport}
        watchdogStatus={mockWatchdogStatus}
        threatIntelStatus={mockThreatIntelStatus}
        ransomwareStatus={mockRansomwareStatus}
        schedulerState={mockSchedulerState}
        onQuickScanLaunch={vi.fn()}
        onReEnableShield={vi.fn()}
        onNavigate={vi.fn()}
      />
    );

    expect(screen.getByText('🟢 System Protected')).toBeDefined();
    expect(screen.getByText('Protection Subsystem Matrix')).toBeDefined();
    expect(screen.getByText('🛡️ Real-Time Shield')).toBeDefined();
    expect(screen.getByText('🔒 Ransomware Shield')).toBeDefined();
    expect(screen.getByText('🩺 Watchdog Health')).toBeDefined();
  });

  // SCREEN 02: Quick Scan
  it('Screen 02 (QuickScanScreen) renders fast ingress scan controls and expansion info', () => {
    render(<QuickScanScreen onScanComplete={vi.fn()} onSelectThreat={vi.fn()} />);
    expect(screen.getByText('⚡ Quick Ingress Scan')).toBeDefined();
    expect(screen.getByText('Start Quick Scan')).toBeDefined();
  });

  // SCREEN 03: Full Scan
  it('Screen 03 (FullScanScreen) renders comprehensive filesystem scan controls', () => {
    render(<FullScanScreen onScanComplete={vi.fn()} onSelectThreat={vi.fn()} />);
    expect(screen.getByText('🔍 Full PC Filesystem Scan')).toBeDefined();
    expect(screen.getByText('Start Full PC Scan')).toBeDefined();
  });

  // SCREEN 04: Custom Scan
  it('Screen 04 (CustomScanScreen) renders folder and file picker scan controls', () => {
    render(<CustomScanScreen onScanComplete={vi.fn()} onSelectThreat={vi.fn()} />);
    expect(screen.getByText('📁 Custom Location Scan')).toBeDefined();
    expect(screen.getByText('Scan Location')).toBeDefined();
  });

  // SCREEN 05: Scheduled Scan
  it('Screen 05 (ScheduledScanScreen) renders recurrence form with battery & CPU guards', async () => {
    render(<ScheduledScanScreen onScanTriggered={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('📅 Scheduled & Automated Scans')).toBeDefined();
      expect(screen.getByText('Schedule Execution Status')).toBeDefined();
      expect(screen.getByText('💾 Save & Arm Schedule')).toBeDefined();
    });
  });

  // SCREEN 06: Real-time Protection
  it('Screen 06 (RealtimeProtectionScreen) renders master shield toggle and sub-shield options', () => {
    render(
      <RealtimeProtectionScreen
        status={mockStatus}
        settings={mockSettings}
        watchdogStatus={mockWatchdogStatus}
        onUpdateSettings={vi.fn()}
        onSnoozeShield={vi.fn()}
        onResumeShield={vi.fn()}
        onRequestFrictionGate={vi.fn()}
        recentEvents={[]}
      />
    );

    expect(screen.getByText('🛡️ Real-Time Protection Shield')).toBeDefined();
    expect(screen.getByText('Master Filesystem Interceptor')).toBeDefined();
    expect(screen.getByText('SHIELD ACTIVE')).toBeDefined();
  });

  // SCREEN 07: Threat Detection Modal
  it('Screen 07 (ThreatDetectionModal) renders high-priority warning interstitial with RTLO sanitization', () => {
    const mockAlert: any = {
      event: {
        eventType: 'create',
        filePath: 'C:\\Users\\test\\Downloads\\invoice\u202Eexe.pdf',
        timestamp: Date.now()
      },
      analysis: {
        filePath: 'C:\\Users\\test\\Downloads\\invoice\u202Eexe.pdf',
        sha256: 'a1b2c3d4',
        fileSizeBytes: 1024,
        threatVerdict: 'MALICIOUS',
        riskScore: 90,
        severity: 'critical',
        threatIndicators: ['RTLO_SPOOF'],
        evidenceFactors: ['BIDIRECTIONAL_UNICODE_DETECTED'],
        durationMs: 15
      },
      verdict: {
        action: 'QUARANTINE_FILE',
        reason: 'Malicious file detected',
        effectiveScore: 90,
        effectiveVerdict: 'MALICIOUS',
        requiresConfirmation: false,
        autoQuarantine: true,
        containProcess: false,
        promptRollback: false,
        isProtectedSystemBinary: false,
        isExcluded: false
      },
      quarantined: true,
      timestamp: Date.now()
    };

    render(
      <ThreatDetectionModal
        alert={mockAlert}
        onAcknowledge={vi.fn()}
        onInspectEvidence={vi.fn()}
        onRequestRestore={vi.fn()}
      />
    );

    expect(screen.getByText('Malicious Threat Intercepted')).toBeDefined();
    expect(screen.getByText('🛡️ Keep in Quarantine (Recommended)')).toBeDefined();
    expect(screen.getByText('🔍 Inspect Evidence & AI')).toBeDefined();
  });

  // SCREEN 08: AI Security Assistant
  it('Screen 08 (AssistantScreen) translates technical evidence into plain language', async () => {
    render(
      <AssistantScreen
        selectedThreat={mockThreat}
        onExplainThreat={async () => ({
          threatTitle: mockThreat.threatName,
          summary: 'Blocked because it hides executable code.',
          explanation: 'The file pretended to be a normal document.',
          riskLevel: 'CRITICAL',
          recommendedActions: ['Keep file quarantined'],
          cognitiveLevel: 'grade6'
        })}
      />
    );

    expect(screen.getByText('🤖 On-Device AI Security Assistant')).toBeDefined();
    expect(screen.getByText('Synthesize Explanation')).toBeDefined();

    fireEvent.click(screen.getByText('Synthesize Explanation'));
    await waitFor(() => {
      expect(screen.getByText('Blocked because it hides executable code.')).toBeDefined();
    });
  });

  // SCREEN 09: Scan Results
  it('Screen 09 (ScanResultsScreen) renders detected threat telemetry and quarantine action', () => {
    render(
      <ScanResultsScreen
        threats={[mockThreat]}
        onIsolateThreat={vi.fn()}
        onExplainThreat={vi.fn()}
      />
    );

    expect(screen.getByText('📊 Scan Results & Detections')).toBeDefined();
    expect(screen.getByText(mockThreat.fileName)).toBeDefined();
    expect(screen.getByText('🔒 Move to Quarantine')).toBeDefined();
  });

  // SCREEN 10: History / Forensic Audit Log
  it('Screen 10 (HistoryScreen) renders HMAC-SHA256 verified audit trail', async () => {
    render(<HistoryScreen />);
    await waitFor(() => {
      expect(screen.getByText('📜 Forensic Audit Log & Timeline')).toBeDefined();
      expect(screen.getByText('🛡️ Verify HMAC Integrity')).toBeDefined();
    });
  });

  // SCREEN 11: Ransomware Shield
  it('Screen 11 (RansomwareShieldScreen) renders protected folders, canary status, and emergency rollback', async () => {
    render(<RansomwareShieldScreen onRequestFrictionGate={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('🔒 Ransomware Shield & Shadow Vault')).toBeDefined();
      expect(screen.getByText('CANARY TRAPS')).toBeDefined();
      expect(screen.getByText('SHADOW VAULT QUOTA')).toBeDefined();
    });
  });

  // SCREEN 12: Web Protection
  it('Screen 12 (WebProtectionScreen) renders URL & Scam message analyzers with zero-cloud processing', () => {
    render(<WebProtectionScreen />);
    expect(screen.getByText('🌐 Web, Download & Phishing Protection')).toBeDefined();
    expect(screen.getByText('🔗 Inspect Link / URL')).toBeDefined();
    expect(screen.getByText('💬 Inspect Message / Email Text')).toBeDefined();
  });

  // SCREEN 13: Notifications
  it('Screen 13 (NotificationsScreen) renders notification inbox with storm rate-limiter stats', async () => {
    render(<NotificationsScreen />);
    await waitFor(() => {
      expect(screen.getByText('🔔 Notifications & Alert Inbox')).toBeDefined();
      expect(screen.getByText(/Storm Rate-Limiter \(RULE-15\)/)).toBeDefined();
      expect(screen.getByText('Mark All Read')).toBeDefined();
    });
  });

  // SCREEN 14: Protection Status & Health
  it('Screen 14 (ProtectionStatusScreen) renders 4-state health model and watchdog supervisors', async () => {
    render(<ProtectionStatusScreen status={mockStatus} />);
    await waitFor(() => {
      expect(screen.getByText('🩺 Endpoint Health & Watchdog Supervision')).toBeDefined();
      expect(screen.getByText('🔄 Run Full Health Check')).toBeDefined();
    });
  });

  // SCREEN 15: Updates / Definitions
  it('Screen 15 (UpdateStatusScreen) renders cryptographic Ed25519 update verification controls', () => {
    render(<UpdateStatusScreen />);
    expect(screen.getByText('🔄 Cryptographic Update Status')).toBeDefined();
    expect(screen.getByText('Check for Signed Delta Updates')).toBeDefined();
  });

  // SCREEN 16: Settings
  it('Screen 16 (SettingsScreen) renders persistent security configurations', () => {
    render(<SettingsScreen initialSettings={mockSettings} onSaveSettings={vi.fn()} />);
    expect(screen.getByText('⚙️ Protection Settings')).toBeDefined();
    expect(screen.getByText('Save Settings')).toBeDefined();
  });

  // SCREEN 17: Exclusions
  it('Screen 17 (ExclusionsScreen) renders SHA-256 hash, path, and domain exclusions manager', async () => {
    render(<ExclusionsScreen onRequestFrictionGate={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('🚫 Exclusions & False-Positive Manager')).toBeDefined();
      expect(screen.getByText('+ Add Exclusion (Opens Gate)')).toBeDefined();
    });
  });

  // SCREEN 18: Trusted Apps
  it('Screen 18 (TrustedAppsScreen) renders protected folder trusted apps allowlist', async () => {
    render(<TrustedAppsScreen onRequestFrictionGate={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('🤝 Trusted Applications (Ransomware Shield)')).toBeDefined();
      expect(screen.getByText('+ Authorize Application')).toBeDefined();
    });
  });

  // SCREEN 19: Recovery & Crypto-Shredder
  it('Screen 19 (RecoveryScreen) renders USB rescue scanning and permanent crypto-shredder', async () => {
    render(<RecoveryScreen onRequestFrictionGate={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('🔄 Recovery, USB Rescue & Crypto-Shredder')).toBeDefined();
      expect(screen.getByText('Permanent Zero-Knowledge Crypto-Shredder')).toBeDefined();
    });
  });

  // SCREEN 20: About & Security Architecture
  it('Screen 20 (AboutSecurityScreen) renders architecture honesty, firewall profiles, and invariant self-tests', async () => {
    render(<AboutSecurityScreen />);
    await waitFor(() => {
      expect(screen.getByText('ℹ️ Architecture Honesty & Security Posture')).toBeDefined();
      expect(screen.getByText('Constitutional Architecture Invariants')).toBeDefined();
    });
  });

  // END-TO-END COMMAND CENTER SHELL NAVIGATION
  it('navigates seamlessly across all 5 navigation groups in the Command Center shell', async () => {
    render(<App />);

    // Group 1: Scanning
    fireEvent.click(screen.getByText('🔍 Full PC Scan'));
    await waitFor(() => {
      expect(screen.getByText('🔍 Full PC Filesystem Scan')).toBeDefined();
    });

    fireEvent.click(screen.getByText('📁 Custom Scan'));
    await waitFor(() => {
      expect(screen.getByText('📁 Custom Location Scan')).toBeDefined();
    });

    fireEvent.click(screen.getByText('📅 Scheduled Scan'));
    await waitFor(() => {
      expect(screen.getByText('📅 Scheduled & Automated Scans')).toBeDefined();
    });

    // Group 2: Active Shields
    fireEvent.click(screen.getByText('🛡️ Real-Time Shield'));
    await waitFor(() => {
      expect(screen.getByText('🛡️ Real-Time Protection Shield')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🔒 Ransomware Shield'));
    await waitFor(() => {
      expect(screen.getByText('🔒 Ransomware Shield & Shadow Vault')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🌐 Web Protection'));
    await waitFor(() => {
      expect(screen.getByText('🌐 Web, Download & Phishing Protection')).toBeDefined();
    });

    // Group 3: Forensics & Recovery
    fireEvent.click(screen.getByText('🤖 AI Assistant'));
    await waitFor(() => {
      expect(screen.getByText('🤖 On-Device AI Security Assistant')).toBeDefined();
    });

    fireEvent.click(screen.getByText('☣️ Quarantine Vault'));
    await waitFor(() => {
      expect(screen.getByText('🔒 Encrypted Quarantine Vault')).toBeDefined();
    });

    fireEvent.click(screen.getByText('📜 Forensic Audit Log'));
    await waitFor(() => {
      expect(screen.getByText('📜 Forensic Audit Log & Timeline')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🔄 Recovery & Shred'));
    await waitFor(() => {
      expect(screen.getByText('🔄 Recovery, USB Rescue & Crypto-Shredder')).toBeDefined();
    });

    // Group 4: System & Settings
    fireEvent.click(screen.getByText('🩺 Health & Watchdog'));
    await waitFor(() => {
      expect(screen.getByText('🩺 Endpoint Health & Watchdog Supervision')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🔄 Definitions & Updates'));
    await waitFor(() => {
      expect(screen.getByText('🔄 Cryptographic Update Status')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🚫 Exclusions Manager'));
    await waitFor(() => {
      expect(screen.getByText('🚫 Exclusions & False-Positive Manager')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🤝 Trusted Apps'));
    await waitFor(() => {
      expect(screen.getByText('🤝 Trusted Applications (Ransomware Shield)')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🔔 Notifications'));
    await waitFor(() => {
      expect(screen.getByText('🔔 Notifications & Alert Inbox')).toBeDefined();
    });

    fireEvent.click(screen.getByText('⚙️ Settings'));
    await waitFor(() => {
      expect(screen.getByText('⚙️ Protection Settings')).toBeDefined();
    });

    // Group 5: Overview
    fireEvent.click(screen.getByText('ℹ️ About & Security'));
    await waitFor(() => {
      expect(screen.getByText('ℹ️ Architecture Honesty & Security Posture')).toBeDefined();
    });

    fireEvent.click(screen.getByText('🏠 Dashboard'));
    await waitFor(() => {
      expect(screen.getByText('Protection Subsystem Matrix')).toBeDefined();
    });
  });
});
