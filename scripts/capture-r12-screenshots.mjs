import { spawn, execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const extDist = path.resolve('apps/extension/dist');
const port = 9595;
const tempDir = path.resolve('scratch_screenshots_' + Date.now());
const screenshotsDir = path.resolve('docs/screenshots');
fs.mkdirSync(tempDir, { recursive: true });
fs.mkdirSync(screenshotsDir, { recursive: true });

async function saveScreenshot(send, sessionId, filename) {
  const { data } = await send('Page.captureScreenshot', { format: 'png' }, sessionId);
  const outPath = path.join(screenshotsDir, filename);
  fs.writeFileSync(outPath, Buffer.from(data, 'base64'));
  const size = fs.statSync(outPath).size;
  console.log(`[+] Captured real screenshot: ${filename} (${size} bytes)`);
}

async function main() {
  console.log('=== CAPTURING REAL R12 PRODUCT SCREENSHOTS ===\n');

  const proc = spawn(chromePath, [
    '--enable-unsafe-extension-debugging',
    `--disable-extensions-except=${extDist}`,
    `--load-extension=${extDist}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--window-size=1280,800',
    '--remote-debugging-port=' + port,
    '--user-data-dir=' + tempDir,
    'about:blank'
  ]);

  try {
    let versionData = null;
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 200));
      try {
        const res = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (res.ok) { versionData = await res.json(); break; }
      } catch (e) {}
    }
    if (!versionData) throw new Error('Could not connect to Chrome CDP');

    const ws = new WebSocket(versionData.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

    let id = 1;
    const callbacks = new Map();
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && callbacks.has(msg.id)) {
        const { res, rej } = callbacks.get(msg.id);
        callbacks.delete(msg.id);
        if (msg.error) rej(msg.error); else res(msg.result);
      }
    };
    function send(method, params = {}, sessionId = undefined) {
      return new Promise((res, rej) => {
        const msgId = id++;
        callbacks.set(msgId, { res, rej });
        const payload = { id: msgId, method, params };
        if (sessionId) payload.sessionId = sessionId;
        ws.send(JSON.stringify(payload));
      });
    }

    // 1. WEB HOME
    console.log('[+] Loading Web Home (https://private-protection.pages.dev)...');
    const { targetId: webTargetId } = await send('Target.createTarget', { url: 'https://private-protection.pages.dev' });
    const { sessionId: webSessionId } = await send('Target.attachToTarget', { targetId: webTargetId, flatten: true });
    await send('Page.enable', {}, webSessionId);
    await send('Runtime.enable', {}, webSessionId);
    await new Promise(r => setTimeout(r, 3500));
    await saveScreenshot(send, webSessionId, '01_web_home.png');

    // 2. WEB SAFE RESULT
    console.log('[+] Performing Safe Scan on Web...');
    await send('Runtime.evaluate', {
      expression: `(() => {
        const btn = document.getElementById('tab-url_scan');
        if (btn) btn.click();
      })()`
    }, webSessionId);
    await new Promise(r => setTimeout(r, 400));

    await send('Runtime.evaluate', {
      expression: `(async () => {
        const input = document.getElementById('url-scan-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'https://en.wikipedia.org/wiki/Computer_security');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const form = document.querySelector('form');
        form.requestSubmit();
        let elapsed = 0;
        while (elapsed < 3000) {
          await new Promise(r => setTimeout(r, 100));
          elapsed += 100;
          if (document.body.innerText.includes('SAFE')) break;
        }
      })()`,
      awaitPromise: true
    }, webSessionId);
    await new Promise(r => setTimeout(r, 500));
    await saveScreenshot(send, webSessionId, '02_web_safe_result.png');

    // 3. WEB PHISHING WARNING
    console.log('[+] Performing Phishing Scan on Web...');
    await send('Runtime.evaluate', {
      expression: `(async () => {
        const input = document.getElementById('url-scan-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'http://192.168.1.100/secure-banking/login');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const form = document.querySelector('form');
        form.requestSubmit();
        let elapsed = 0;
        while (elapsed < 3000) {
          await new Promise(r => setTimeout(r, 100));
          elapsed += 100;
          if (document.body.innerText.includes('DANGEROUS')) break;
        }
      })()`,
      awaitPromise: true
    }, webSessionId);
    await new Promise(r => setTimeout(r, 500));
    await saveScreenshot(send, webSessionId, '03_web_phishing_warning.png');

    // 4. EXTENSION POPUP & INTERSTITIAL
    const loadResult = await send('Extensions.loadUnpacked', { path: extDist });
    const extId = loadResult.id;
    console.log(`[+] Loaded Extension ID: ${extId}`);

    // Extension Popup
    const { targetId: popupTargetId } = await send('Target.createTarget', { url: `chrome-extension://${extId}/popup.html` });
    const { sessionId: popupSessionId } = await send('Target.attachToTarget', { targetId: popupTargetId, flatten: true });
    await send('Page.enable', {}, popupSessionId);
    await send('Runtime.enable', {}, popupSessionId);
    await new Promise(r => setTimeout(r, 1500));
    await saveScreenshot(send, popupSessionId, '04_extension_popup.png');

    // Extension Interstitial Warning
    const { targetId: interTargetId } = await send('Target.createTarget', {
      url: `chrome-extension://${extId}/interstitial.html?tabId=1&target=http://192.168.1.100/login`
    });
    const { sessionId: interSessionId } = await send('Target.attachToTarget', { targetId: interTargetId, flatten: true });
    await send('Page.enable', {}, interSessionId);
    await send('Runtime.enable', {}, interSessionId);
    await new Promise(r => setTimeout(r, 1500));
    await saveScreenshot(send, interSessionId, '05_extension_interstitial_warning.png');

    // 5. DESKTOP RENDERER UI
    const desktopHtml = path.resolve('apps/desktop/dist/renderer/index.html');
    if (fs.existsSync(desktopHtml)) {
      console.log('[+] Capturing Desktop Renderer UI...');
      const { targetId: deskTargetId } = await send('Target.createTarget', { url: 'file:///' + desktopHtml.replace(/\\/g, '/') });
      const { sessionId: deskSessionId } = await send('Target.attachToTarget', { targetId: deskTargetId, flatten: true });
      await send('Page.enable', {}, deskSessionId);
      await send('Runtime.enable', {}, deskSessionId);
      await new Promise(r => setTimeout(r, 1500));
      await saveScreenshot(send, deskSessionId, '06_desktop_renderer.png');
    }

    ws.close();
    console.log('\n======================================================');
    console.log('✓ REAL PRODUCT SCREENSHOTS CAPTURED TO docs/screenshots/');
    console.log('======================================================');
  } finally {
    try { execSync('taskkill /F /T /PID ' + proc.pid); } catch (e) {}
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
  }
}

main().catch(err => {
  console.error('Fatal Screenshot Capture Error:', err);
  process.exit(1);
});
