import { app, BrowserWindow, ipcMain, session } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { IpcHandler } from '../ipc/ipc-handler';

let mainWindow: BrowserWindow | null = null;
let ipcHandler: IpcHandler | null = null;

function getStorageDir(): string {
  const customArg = process.argv.find((arg) => arg.startsWith('--storage-dir='));
  if (customArg) {
    return customArg.split('=')[1];
  }
  return path.join(app.getPath('userData'), 'security-vault');
}

function createMainWindow(isHeadlessVerify: boolean): BrowserWindow {
  const preloadPath = path.resolve(__dirname, '../preload/electron-preload.cjs');

  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 960,
    minHeight: 640,
    title: 'Private Protection — On-Device Desktop Security',
    show: !isHeadlessVerify,
    backgroundColor: '#f8fafc',
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  });

  // Block any navigation away from the local application UI
  win.webContents.on('will-navigate', (event, navigationUrl) => {
    if (!navigationUrl.startsWith('file://')) {
      event.preventDefault();
    }
  });

  // Deny all new window / popup creation requests
  win.webContents.setWindowOpenHandler(() => {
    return { action: 'deny' };
  });

  const rendererHtmlPath = path.resolve(__dirname, '../renderer/index.html');
  win.loadFile(rendererHtmlPath);

  win.on('closed', () => {
    mainWindow = null;
  });

  return win;
}

async function runHeadlessRuntimeVerification(win: BrowserWindow): Promise<void> {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-electron-e2e-'));
  const scanDir = path.join(tempRoot, 'scan-target');
  const subDir = path.join(scanDir, 'nested');
  fs.mkdirSync(subDir, { recursive: true });

  const safeFile = path.join(scanDir, 'readme-notes.txt');
  fs.writeFileSync(safeFile, 'This is a completely benign text note for Private Protection desktop verification.\n', 'utf8');

  const nestedSafeFile = path.join(subDir, 'config.json');
  fs.writeFileSync(nestedSafeFile, JSON.stringify({ app: 'private-protection', offline: true }), 'utf8');

  // Create a synthetic suspicious double-extension file with MZ PE header + high-risk strings (no real malware)
  const suspiciousFile = path.join(scanDir, 'urgent_invoice_payment.pdf.exe');
  const mzHeader = Buffer.from('4d5a90000300000004000000ffff0000b8000000000000004000000000000000', 'hex');
  const suspiciousPayload = Buffer.from(
    'powershell.exe -EncodedCommand VirtualAlloc WriteProcessMemory CreateRemoteThread Mimikatz vssadmin delete shadows /all /quiet',
    'ascii'
  );
  fs.writeFileSync(suspiciousFile, Buffer.concat([mzHeader, suspiciousPayload]));

  try {
    // Execute verification inside the real Electron Renderer context using window.desktopSecurity
    const rendererProof = await win.webContents.executeJavaScript(`
      (async () => {
        if (typeof window.desktopSecurity !== 'object' || window.desktopSecurity === null) {
          throw new Error('window.desktopSecurity is missing in renderer');
        }
        const progressEvents = [];
        const unsubscribe = window.desktopSecurity.onScanProgress((p) => {
          progressEvents.push(p);
        });

        const status = await window.desktopSecurity.getProtectionStatus();
        const scanResult = await window.desktopSecurity.startCustomScan([${JSON.stringify(scanDir)}]);
        unsubscribe();

        if (scanResult.totalFilesScanned < 3) {
          throw new Error('Expected at least 3 files scanned, got ' + scanResult.totalFilesScanned);
        }
        if (scanResult.threats.length < 1) {
          throw new Error('Expected synthetic double-extension PE file to be detected as threat');
        }

        const detectedThreat = scanResult.threats[0];
        const explanation = await window.desktopSecurity.explainThreat(detectedThreat, 'grade6');
        const qItem = await window.desktopSecurity.isolateFile(detectedThreat.filePath);
        const qListAfterIsolate = await window.desktopSecurity.listQuarantine();

        const restoredPath = await window.desktopSecurity.restoreQuarantine(qItem.quarantineId);
        const qListAfterRestore = await window.desktopSecurity.listQuarantine();

        return {
          bridgeAvailable: true,
          nodeIntegrationDisabled: typeof process === 'undefined' || typeof process.versions === 'undefined',
          rootTitleRendered: document.body.innerText.includes('System Protection Overview') || document.body.innerText.includes('Private Protection'),
          protectionStatus: status,
          progressEventsReceived: progressEvents.length,
          scanResult: {
            scanId: scanResult.scanId,
            scanType: scanResult.scanType,
            status: scanResult.status,
            totalFilesScanned: scanResult.totalFilesScanned,
            threatsDetected: scanResult.threats.length,
            firstThreatName: detectedThreat.threatName,
            firstThreatScore: detectedThreat.riskScore,
            firstThreatSeverity: detectedThreat.severity,
            firstThreatSha256: detectedThreat.sha256
          },
          assistantExplanation: {
            threatTitle: explanation.threatTitle,
            riskLevel: explanation.riskLevel,
            cognitiveLevel: explanation.cognitiveLevel
          },
          quarantineLifecycle: {
            quarantineId: qItem.quarantineId,
            vaultCountAfterIsolate: qListAfterIsolate.length,
            restoredPath,
            vaultCountAfterRestore: qListAfterRestore.length
          }
        };
      })();
    `);

    const restoredExists = fs.existsSync(suspiciousFile);
    const fullReport = {
      verifiedAt: new Date().toISOString(),
      electronVersion: process.versions.electron,
      chromeVersion: process.versions.chrome,
      nodeVersion: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      restoredFileVerifiedOnDisk: restoredExists,
      ...rendererProof
    };

    console.log('[ELECTRON_E2E_PROOF] ' + JSON.stringify(fullReport));
    fs.rmSync(tempRoot, { recursive: true, force: true });
    app.exit(0);
  } catch (err: any) {
    console.error('[ELECTRON_E2E_ERROR] ' + (err?.stack || err?.message || String(err)));
    fs.rmSync(tempRoot, { recursive: true, force: true });
    app.exit(1);
  }
}

app.whenReady().then(() => {
  // Enforce strict Content-Security-Policy on all local responses
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        ]
      }
    });
  });

  const storageDir = getStorageDir();
  ipcHandler = new IpcHandler({
    vaultDir: path.join(storageDir, 'vault'),
    configDir: path.join(storageDir, 'config')
  });
  ipcHandler.registerElectronHandlers(ipcMain, () => mainWindow?.webContents ?? null);

  const watchDirs = [path.join(os.homedir(), 'Downloads'), os.tmpdir()].filter((dir) =>
    fs.existsSync(dir)
  );
  if (watchDirs.length > 0) {
    ipcHandler.getRealtimeMonitor().start(watchDirs);
  }

  const isHeadlessVerify = process.argv.includes('--headless-verify');
  mainWindow = createMainWindow(isHeadlessVerify);

  if (isHeadlessVerify) {
    mainWindow.webContents.once('did-finish-load', () => {
      runHeadlessRuntimeVerification(mainWindow!);
    });
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createMainWindow(false);
    }
  });
});

app.on('will-quit', () => {
  ipcHandler?.getRealtimeMonitor().stop();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
