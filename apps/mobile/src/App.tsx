import React, { useState } from 'react';
import { MobileSecurityAdapter } from './adapters/mobile-security-adapter';
import { UrlScannerService } from './services/url-scanner.service';
import { TextScannerService } from './services/text-scanner.service';
import { FileScannerService } from './services/file-scanner.service';
import { TabBar, MobileTab } from './components/TabBar';
import { HomeScreen } from './screens/HomeScreen';
import { UrlScannerScreen } from './screens/UrlScannerScreen';
import { TextScannerScreen } from './screens/TextScannerScreen';
import { FileScannerScreen } from './screens/FileScannerScreen';
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
            onNavigate={(tab) => setCurrentTab(tab)}
            onSelectResult={() => {}}
          />
        )}
        {currentTab === 'URL_SCAN' && (
          <UrlScannerScreen
            scannerService={urlService}
            onNavigateHome={() => setCurrentTab('HOME')}
          />
        )}
        {currentTab === 'TEXT_SCAN' && (
          <TextScannerScreen
            scannerService={textService}
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

      <TabBar currentTab={currentTab} onSelectTab={setCurrentTab} />
    </div>
  );
};

export default App;
