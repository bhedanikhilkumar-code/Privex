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

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<MobileTab>('HOME');

  const [adapter] = useState(() => new MobileSecurityAdapter());
  const [urlService] = useState(() => new UrlScannerService(adapter));
  const [textService] = useState(() => new TextScannerService(adapter));
  const [fileService] = useState(() => new FileScannerService());
  const [cameraService] = useState(() => new CameraScannerService(adapter));

  // Inbound Intent state (cold-start or warm-start)
  const [inboundUrl, setInboundUrl] = useState<string | undefined>(undefined);
  const [inboundText, setInboundText] = useState<string | undefined>(undefined);
  const [autoScanTrigger, setAutoScanTrigger] = useState<boolean>(false);

  useEffect(() => {
    // 1. Notify native Android bridge that UI is ready (BLOCKER-05)
    if (typeof window !== 'undefined' && (window as any).AndroidSecurityBridge?.notifyClientReady) {
      try {
        (window as any).AndroidSecurityBridge.notifyClientReady();
      } catch (err) {
        // Safe fallback
      }
    }

    // 2. Consume any pending cold-start intent atomically
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
          }
        }
      } catch (err) {
        // Safe fallback
      }
    }

    // 3. Register warm-start listeners for runtime Intents
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
      window.removeEventListener('privateprotection:shared_text', handleSharedText);
      window.removeEventListener('privateprotection:deep_link_url', handleDeepLink);
    };
  }, []);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
        backgroundColor: '#0b1120',
        fontFamily: 'system-ui, -apple-system, sans-serif'
      }}
    >
      <main style={{ flex: 1, paddingBottom: '4rem' }}>
        {currentTab === 'HOME' && (
          <HomeScreen
            onNavigate={(tab) => {
              setAutoScanTrigger(false);
              setCurrentTab(tab);
            }}
            onSelectResult={() => {}}
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
        {currentTab === 'ASSISTANT' && <AssistantScreen />}
        {currentTab === 'STATUS' && <ProtectionStatusScreen />}
        {currentTab === 'PRIVACY' && <PrivacyScreen />}
        {currentTab === 'SETTINGS' && <SettingsScreen />}
      </main>

      <TabBar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          setAutoScanTrigger(false);
          setCurrentTab(tab);
        }}
      />
    </div>
  );
};

export default App;
