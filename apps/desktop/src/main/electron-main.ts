import { app, BrowserWindow, ipcMain, session } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { IpcHandler } from '../ipc/ipc-handler';

let mainWindow: BrowserWindow | null = null;
let ipcHandler: IpcHandler | null = null;

if (process.argv.includes('--no-sandbox') || process.env.ELECTRON_DISABLE_SANDBOX) {
  app.commandLine.appendSwitch('no-sandbox');
}
if (process.argv.includes('--disable-gpu')) {
  app.commandLine.appendSwitch('disable-gpu');
  app.commandLine.appendSwitch('disable-software-rasterizer');
  app.commandLine.appendSwitch('disable-dev-shm-usage');
}

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
  const watchDir = path.join(tempRoot, 'watch-target');
  fs.mkdirSync(subDir, { recursive: true });
  fs.mkdirSync(watchDir, { recursive: true });

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
    // Point RealtimeMonitorService at watchDir to test end-to-end realtime event -> IPC -> Renderer -> Auto-Quarantine
    ipcHandler!.getRealtimeMonitor().start([watchDir]);

    const rendererProof = await win.webContents.executeJavaScript(`
      (async () => {
        if (typeof window.desktopSecurity !== 'object' || window.desktopSecurity === null) {
          throw new Error('window.desktopSecurity is missing in renderer');
        }
        const progressEvents = [];
        const unsubscribeProgress = window.desktopSecurity.onScanProgress((p) => {
          progressEvents.push(p);
        });

        window.__realtimeEvents = [];
        window.__unsubscribeRealtime = window.desktopSecurity.onRealtimeThreat((ev) => {
          window.__realtimeEvents.push(ev);
        });

        const status = await window.desktopSecurity.getProtectionStatus();
        const scanResult = await window.desktopSecurity.startCustomScan([${JSON.stringify(scanDir)}]);
        unsubscribeProgress();

        if (scanResult.totalFilesScanned < 3) {
          throw new Error('Expected at least 3 files scanned, got ' + scanResult.totalFilesScanned);
        }
        if (scanResult.threats.length < 1) {
          throw new Error('Expected synthetic double-extension PE file to be detected as threat');
        }

        // GAP-16 verification: benign file quarantine must be rejected
        let benignQuarantineRejected = false;
        try {
          await window.desktopSecurity.isolateFile(${JSON.stringify(safeFile)});
        } catch (err) {
          benignQuarantineRejected = String(err.message || err).includes('QUARANTINE_POLICY_REJECTED');
        }
        if (!benignQuarantineRejected) {
          throw new Error('Expected benign file quarantine to be rejected with QUARANTINE_POLICY_REJECTED');
        }

        const detectedThreat = scanResult.threats[0];
        const explanation = await window.desktopSecurity.explainThreat(detectedThreat, 'grade6');
        const qItem = await window.desktopSecurity.isolateFile(detectedThreat.filePath);
        const qListAfterIsolate = await window.desktopSecurity.listQuarantine();

        const restoredPath = await window.desktopSecurity.restoreQuarantine(qItem.quarantineId);
        const qListAfterRestore = await window.desktopSecurity.listQuarantine();

        // Enable autoQuarantineCritical via saveSettings (GAP-15)
        await window.desktopSecurity.saveSettings({ autoQuarantineCritical: true });

        return {
          bridgeAvailable: true,
          nodeIntegrationDisabled: typeof process === 'undefined' || typeof process.versions === 'undefined',
          rootTitleRendered: document.body.innerText.includes('System Protection Overview') || document.body.innerText.includes('Private Protection'),
          protectionStatus: status,
          progressEventsReceived: progressEvents.length,
          benignQuarantineRejected,
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

    // Re-point RealtimeMonitorService to watchDir after saveSettings and drop a synthetic critical file to verify GAP-14
    ipcHandler!.getRealtimeMonitor().start([watchDir]);
    const droppedThreatPath = path.join(watchDir, 'dropped_payroll_bonus.pdf.exe');
    fs.writeFileSync(droppedThreatPath, Buffer.concat([mzHeader, suspiciousPayload]));
    await new Promise((r) => setTimeout(r, 450));

    const realtimeProof = await win.webContents.executeJavaScript(`
      (() => {
        if (window.__unsubscribeRealtime) window.__unsubscribeRealtime();
        return {
          realtimeEventsCount: (window.__realtimeEvents || []).length,
          firstRealtimeEvent: (window.__realtimeEvents || [])[0] || null,
          alertBannerRendered: document.body.innerText.includes('REAL-TIME INGRESS THREAT DETECTED')
        };
      })();
    `);

    const restoredExists = fs.existsSync(suspiciousFile);
    const SafeFileStillExists = fs.existsSync(safeFile);
    const droppedThreatQuarantined = !fs.existsSync(droppedThreatPath);

    const fullReport = {
      verifiedAt: new Date().toISOString(),
      electronVersion: process.versions.electron,
      chromeVersion: process.versions.chrome,
      nodeVersion: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      restoredFileVerifiedOnDisk: restoredExists,
      safeFilePreservedOnDisk: SafeFileStillExists,
      droppedThreatAutoQuarantinedFromDisk: droppedThreatQuarantined,
      ...rendererProof,
      ...realtimeProof
    };

    console.log('[ELECTRON_E2E_PROOF] ' + JSON.stringify(fullReport));
    ipcHandler?.getRealtimeMonitor().stop();
    fs.rmSync(tempRoot, { recursive: true, force: true });
    win.destroy();
    app.exit(0);
  } catch (err: any) {
    console.error('[ELECTRON_E2E_ERROR] ' + (err?.stack || err?.message || String(err)));
    ipcHandler?.getRealtimeMonitor().stop();
    fs.rmSync(tempRoot, { recursive: true, force: true });
    win.destroy();
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
    configDir: path.join(storageDir, 'config'),
    autoStartRealtime: true
  });
  ipcHandler.registerElectronHandlers(ipcMain, () => mainWindow?.webContents ?? null);

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
