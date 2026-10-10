import React, { useState, useEffect } from 'react';
import { MobileSecurityAdapter } from './adapters/mobile-security-adapter';
import { UrlScannerService } from './services/url-scanner.service';
import { TextScannerService } from './services/text-scanner.service';
import { FileScannerService } from './services/file-scanner.service';
import { CameraScannerService } from './services/camera-scanner.service';
import { TabBar, MobileTab } from './components/TabBar';
import { HomeScreen } from './screens/HomeScreen';
import { UrlScannerScreen } from './screens/UrlScannerScreen';
import { TextScannerScreen } from './screens/TextScannerScreen';
import { FileScannerScreen } from './screens/FileScannerScreen';
import { QrScannerScreen } from './screens/QrScannerScreen';
import { AssistantScreen } from './screens/AssistantScreen';
import { ProtectionStatusScreen } from './screens/ProtectionStatusScreen';
import { PrivacyScreen } from './screens/PrivacyScreen';
import { SettingsScreen } from './screens/SettingsScreen';
import { PasswordGeneratorScreen } from './screens/PasswordGeneratorScreen';
import { WebsiteVulnerabilityScreen } from './screens/WebsiteVulnerabilityScreen';
import { PortScannerScreen } from './screens/PortScannerScreen';

import { PreThreatWarningModal } from './components/PreThreatWarningModal';
import { PreThreatWarningService } from './services/pre-threat-warning.service';
import { SecureStorageService } from './services/secure-storage.service';
import { PreThreatWarningPayload, PreThreatActionType } from './types/mobile.types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<MobileTab>('HOME');

  const [adapter] = useState(() => new MobileSecurityAdapter());
  const [urlService] = useState(() => new UrlScannerService(adapter));
  const [textService] = useState(() => new TextScannerService(adapter));
  const [fileService] = useState(() => new FileScannerService());
  const [cameraService] = useState(() => new CameraScannerService(adapter));
  const [preThreatService] = useState(() => PreThreatWarningService.getInstance());

  // Inbound Intent state (cold-start or warm-start)
  const [inboundUrl, setInboundUrl] = useState<string | undefined>(undefined);
  const [inboundText, setInboundText] = useState<string | undefined>(undefined);
  const [autoScanTrigger, setAutoScanTrigger] = useState<boolean>(false);
  const [activePreThreatWarning, setActivePreThreatWarning] = useState<PreThreatWarningPayload | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    // 0. Load persisted theme preference
    SecureStorageService.getSettings()
      .then((settings) => {
        const activeTheme = settings.theme === 'light' ? 'light' : 'dark';
        setTheme(activeTheme);
        if (typeof document !== 'undefined') {
          document.documentElement.setAttribute('data-theme', activeTheme);
        }
      })
      .catch(() => {});

    // 1. Notify native Android bridge that UI is ready (BLOCKER-05)
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.notifyClientReady) {
      try {
        (window as any).AndroidSecurityBridge.notifyClientReady();
      } catch (err) {
        // Safe fallback
      }
    }

    // 2. Subscribe to Pre-Threat Warning service
    const unsubscribeWarnings = preThreatService.subscribeToWarnings((warning) => {
      setActivePreThreatWarning(warning);
    });

    // 3. Consume any pending cold-start intent atomically
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.consumePendingIntent) {
      try {
        const rawPending = (window as any).AndroidSecurityBridge.consumePendingIntent();
        if (rawPending) {
          const parsed = JSON.parse(rawPending);
          if (parsed.action === 'SHARED_TEXT' && parsed.payload) {
            setInboundText(parsed.payload);
            setAutoScanTrigger(true);
            setCurrentTab('TEXT_SCAN');
          } else if (parsed.action === 'DEEP_LINK_URL' && parsed.payload) {
            setInboundUrl(parsed.payload);
            setAutoScanTrigger(true);
            setCurrentTab('URL_SCAN');
          } else if (parsed.action === 'PRE_THREAT_WARNING' && parsed.payload) {
            const warningPayload = typeof parsed.payload === 'string' ? JSON.parse(parsed.payload) : parsed.payload;
            preThreatService.setActiveWarning(warningPayload);
          }
        }
      } catch (err) {
        // Safe fallback
      }
    }

    // 4. Register warm-start listeners for runtime Intents
    const handleSharedText = (event: any) => {
      const text = event.detail?.text;
      if (text && typeof text === 'string') {
        setInboundText(text);
        setAutoScanTrigger(true);
        setCurrentTab('TEXT_SCAN');
      }
    };

    const handleDeepLink = (event: any) => {
      const url = event.detail?.url;
      if (url && typeof url === 'string') {
        setInboundUrl(url);
        setAutoScanTrigger(true);
        setCurrentTab('URL_SCAN');
      }
    };

    window.addEventListener('privateprotection:shared_text', handleSharedText);
    window.addEventListener('privateprotection:deep_link_url', handleDeepLink);

    return () => {
      unsubscribeWarnings();
      window.removeEventListener('privateprotection:shared_text', handleSharedText);
      window.removeEventListener('privateprotection:deep_link_url', handleDeepLink);
    };
  }, [preThreatService]);

  const handlePreThreatAction = async (action: PreThreatActionType, bypassed: boolean) => {
    if (!activePreThreatWarning) return;

    await preThreatService.recordDecision({
      warningId: activePreThreatWarning.warningId,
      targetIdentifier: activePreThreatWarning.targetIdentifier,
      selectedAction: action,
      timestamp: Date.now(),
      bypassedWithFrictionGate: bypassed
    });

    preThreatService.clearActiveWarning();
    setActivePreThreatWarning(null);

    if (action === 'GO_BACK' || action === 'CANCEL_INSTALL' || action === 'DELETE_DOWNLOAD') {
      setCurrentTab('HOME');
    }
  };

  const handleThemeToggle = async (newTheme?: 'dark' | 'light') => {
    const targetTheme = newTheme || (theme === 'dark' ? 'light' : 'dark');
    setTheme(targetTheme);
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', targetTheme);
    }
    await SecureStorageService.saveSettings({ theme: targetTheme });
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        backgroundColor: 'var(--bg-primary)',
        color: 'var(--text-primary)',
        fontFamily: 'system-ui, -apple-system, sans-serif'
      }}
    >
      <main style={{ flex: 1, paddingBottom: '4rem' }}>
        {currentTab === 'HOME' && (
          <HomeScreen
            theme={theme}
            onToggleTheme={() => handleThemeToggle()}
            onNavigate={(tab) => {
              setAutoScanTrigger(false);
              setCurrentTab(tab);
            }}
            onSelectResult={(record) => {
              setAutoScanTrigger(false);
              if (record.targetType === 'URL') {
                setInboundUrl(record.sanitizedSummary.startsWith('http') ? record.sanitizedSummary : undefined);
                setCurrentTab('URL_SCAN');
              } else if (record.targetType === 'TEXT') {
                setInboundText(record.sanitizedSummary);
                setCurrentTab('TEXT_SCAN');
              } else if (record.targetType === 'FILE') {
                setCurrentTab('FILE_SCAN');
              }
            }}
          />
        )}
        {currentTab === 'URL_SCAN' && (
          <UrlScannerScreen
            scannerService={urlService}
            initialUrl={inboundUrl}
            autoScan={autoScanTrigger}
            onNavigateHome={() => {
              setInboundUrl(undefined);
              setAutoScanTrigger(false);
              setCurrentTab('HOME');
            }}
            onNavigateVulnerabilityAudit={(targetUrl) => {
              if (targetUrl) setInboundUrl(targetUrl);
              setCurrentTab('VULNERABILITY_AUDIT');
            }}
          />
        )}
        {currentTab === 'TEXT_SCAN' && (
          <TextScannerScreen
            scannerService={textService}
            initialText={inboundText}
            autoScan={autoScanTrigger}
            onNavigateHome={() => {
              setInboundText(undefined);
              setAutoScanTrigger(false);
              setCurrentTab('HOME');
            }}
          />
        )}
        {currentTab === 'QR_SCAN' && (
          <QrScannerScreen
            cameraService={cameraService}
            onNavigateHome={() => setCurrentTab('HOME')}
          />
        )}
        {currentTab === 'FILE_SCAN' && (
          <FileScannerScreen
            scannerService={fileService}
            onNavigateHome={() => setCurrentTab('HOME')}
          />
        )}
        {currentTab === 'PASSWORD' && (
          <PasswordGeneratorScreen onBack={() => setCurrentTab('HOME')} />
        )}
        {currentTab === 'ASSISTANT' && <AssistantScreen />}
        {currentTab === 'STATUS' && <ProtectionStatusScreen />}
        {currentTab === 'PRIVACY' && <PrivacyScreen />}
        {currentTab === 'SETTINGS' && (
          <SettingsScreen
            theme={theme}
            onThemeChange={(t) => handleThemeToggle(t)}
            onBack={() => setCurrentTab('HOME')}
          />
        )}
        {currentTab === 'VULNERABILITY_AUDIT' && (
          <WebsiteVulnerabilityScreen
            initialUrl={inboundUrl}
            onNavigateHome={() => {
              setInboundUrl(undefined);
              setAutoScanTrigger(false);
              setCurrentTab('HOME');
            }}
          />
        )}
        {currentTab === 'PORT_SCAN' && (
          <PortScannerScreen
            initialHost={inboundUrl}
            onNavigateHome={() => {
              setInboundUrl(undefined);
              setAutoScanTrigger(false);
              setCurrentTab('HOME');
            }}
            onNavigateVulnerabilityAudit={(target) => {
              if (target) setInboundUrl(target);
              setCurrentTab('VULNERABILITY_AUDIT');
            }}
          />
        )}
      </main>

      <TabBar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          setAutoScanTrigger(false);
          setCurrentTab(tab);
        }}
      />

      <PreThreatWarningModal
        warning={activePreThreatWarning}
        onActionSelected={handlePreThreatAction}
      />
    </div>
  );
};

export default App;
