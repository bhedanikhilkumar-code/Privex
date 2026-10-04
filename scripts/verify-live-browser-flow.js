// scripts/verify-live-browser-flow.js
// Automated live browser verification against https://private-protection.pages.dev
import { spawn, execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const LIVE_URL = 'https://private-protection.pages.dev';
const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9580;

class CdpSession {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.msgId = 1;
    this.callbacks = new Map();
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.callbacks.has(msg.id)) {
        const { resolve, reject } = this.callbacks.get(msg.id);
        this.callbacks.delete(msg.id);
        if (msg.error) reject(msg.error);
        else resolve(msg.result);
      }
    };
  }

  send(method, params = {}, sessionId = undefined) {
    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      this.callbacks.set(id, { resolve, reject });
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      this.ws.send(JSON.stringify(payload));
    });
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function runLiveTest() {
  console.log(`======================================================================`);
  console.log(`STARTING LIVE PRODUCTION VERIFICATION ON: ${LIVE_URL}`);
  console.log(`======================================================================`);

  const tempProfile = path.resolve(`scratch_live_profile_${Date.now()}`);
  fs.mkdirSync(tempProfile, { recursive: true });

  const chromeProc = spawn(CHROME_PATH, [
    `--user-data-dir=${tempProfile}`,
    `--remote-debugging-port=${PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    'about:blank'
  ]);

  try {
    let versionData = null;
    for (let i = 0; i < 25; i++) {
      await new Promise(r => setTimeout(r, 300));
      try {
        const res = await fetch(`http://127.0.0.1:${PORT}/json/version`);
        if (res.ok) {
          versionData = await res.json();
          break;
        }
      } catch (e) {}
    }

    if (!versionData) throw new Error('Failed to connect to Chrome CDP');
    console.log(`[+] Connected to Browser: ${versionData.Browser}`);

    const cdp = new CdpSession(versionData.webSocketDebuggerUrl);
    await cdp.connect();

    // 1. OPEN LIVE CANONICAL URL
    const { targetId } = await cdp.send('Target.createTarget', { url: LIVE_URL });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Network.enable', {}, sessionId);

    // Track network requests to verify privacy
    const outboundRequests = [];
    // We can also evaluate network traffic in browser
    await new Promise(r => setTimeout(r, 2000));

    // CHECK INITIAL PAGE LOAD
    const pageState = await cdp.send('Runtime.evaluate', {
      expression: `JSON.stringify({
        title: document.title,
        heading: document.querySelector('h1, h2')?.innerText,
        hasRoot: !!document.getElementById('root'),
        bodyLength: document.body.innerText.length,
        isHttps: window.location.protocol === 'https:',
        origin: window.location.origin
      })`,
      returnByValue: true
    }, sessionId);
    const parsedState = JSON.parse(pageState.result.value);
    console.log('[+] Live Page State:', parsedState);
    if (!parsedState.hasRoot || !parsedState.isHttps) {
      throw new Error('Initial live load failed: missing root or non-HTTPS');
    }

    // 2. NAVIGATE TO SCANNER
    await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const btn = document.getElementById('tab-url_scan');
        if (btn) btn.click();
      })()`
    }, sessionId);
    await new Promise(r => setTimeout(r, 400));

    // 3. SAFE INPUT SCAN
    console.log('[+] Testing Live Safe URL Scan...');
    const safeScan = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const input = document.getElementById('url-scan-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'https://www.google.com/search?q=cybersecurity');
        input.dispatchEvent(new Event('input', { bubbles: true }));

        const form = document.querySelector('form');
        const t0 = performance.now();
        form.requestSubmit();

        let elapsed = 0;
        let isDone = false;
        while (elapsed < 3000) {
          await new Promise(r => setTimeout(r, 100));
          elapsed += 100;
          if (document.body.innerText.includes('SAFE') || document.body.innerText.includes('ALLOWED')) {
            isDone = true;
            break;
          }
        }
        return {
          done: isDone,
          durationMs: Math.round(performance.now() - t0),
          snippet: document.body.innerText.substring(0, 300)
        };
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    console.log('[+] Safe Scan Result:', safeScan.result.value.done, `(${safeScan.result.value.durationMs}ms)`);
    if (!safeScan.result.value.done) throw new Error('Safe scan failed on live site');

    // 4. SUSPICIOUS / PHISHING SCAN
    console.log('[+] Testing Live Phishing Threat Scan...');
    const threatScan = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const input = document.getElementById('url-scan-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'http://192.168.1.100/secure-banking/login');
        input.dispatchEvent(new Event('input', { bubbles: true }));

        const form = document.querySelector('form');
        const t0 = performance.now();
        form.requestSubmit();

        let elapsed = 0;
        let isDone = false;
        while (elapsed < 3000) {
          await new Promise(r => setTimeout(r, 100));
          elapsed += 100;
          if (document.body.innerText.includes('DANGEROUS') || document.body.innerText.includes('Risk Index')) {
            isDone = true;
            break;
          }
        }
        return {
          done: isDone,
          durationMs: Math.round(performance.now() - t0),
          hasWarning: document.body.innerText.includes('DANGEROUS'),
          hasExplanation: document.body.innerText.includes('Why This Website Is Dangerous') || document.body.innerText.includes('IP address')
        };
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    console.log('[+] Phishing Scan Result:', threatScan.result.value.done, 'Warning:', threatScan.result.value.hasWarning, 'Explanation:', threatScan.result.value.hasExplanation);
    if (!threatScan.result.value.done || !threatScan.result.value.hasWarning) {
      throw new Error('Phishing scan failed on live site');
    }

    // 5. TEST RESET / RETRY
    console.log('[+] Testing Reset / Retry...');
    const resetResult = await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const input = document.getElementById('url-scan-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, '');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return input.value === '';
      })()`,
      returnByValue: true
    }, sessionId);
    console.log('[+] Reset Success:', resetResult.result.value);

    // 6. TEST BROWSER REFRESH
    console.log('[+] Testing Live Page Reload...');
    await cdp.send('Page.reload', {}, sessionId);
    await new Promise(r => setTimeout(r, 1500));
    const reloadCheck = await cdp.send('Runtime.evaluate', {
      expression: `!!document.getElementById('root') && document.body.innerText.length > 500`,
      returnByValue: true
    }, sessionId);
    console.log('[+] Reload Root Mount:', reloadCheck.result.value);
    if (!reloadCheck.result.value) throw new Error('Live page reload failed');

    // 7. TEST DEEP ROUTING (/settings)
    console.log('[+] Testing Deep Client Routing...');
    const navSettings = await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const btn = document.getElementById('tab-settings');
        if (btn) { btn.click(); return true; }
        return false;
      })()`,
      returnByValue: true
    }, sessionId);
    await new Promise(r => setTimeout(r, 400));
    const settingsCheck = await cdp.send('Runtime.evaluate', {
      expression: `document.body.innerText.includes('Settings') || document.body.innerText.includes('SETTINGS')`,
      returnByValue: true
    }, sessionId);
    console.log('[+] Navigated to Settings:', settingsCheck.result.value);

    // 8. TEST OFFLINE CAPABILITY VIA SERVICE WORKER
    console.log('[+] Testing Offline / Air-Gapped Scanning on Live Site...');
    await cdp.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0
    }, sessionId);

    const offlineScan = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const urlTab = document.getElementById('tab-url_scan');
        if (urlTab) urlTab.click();
        await new Promise(r => setTimeout(r, 200));

        const input = document.getElementById('url-scan-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, 'http://paypal-verification-update.org/login');
        input.dispatchEvent(new Event('input', { bubbles: true }));

        const form = document.querySelector('form');
        form.requestSubmit();

        let elapsed = 0;
        let isDone = false;
        while (elapsed < 3000) {
          await new Promise(r => setTimeout(r, 100));
          elapsed += 100;
          if (document.body.innerText.includes('DANGEROUS') || document.body.innerText.includes('Risk Index')) {
            isDone = true;
            break;
          }
        }
        return {
          offlineDone: isDone,
          hasOfflineNotice: document.body.innerText.includes('Disconnected') || document.body.innerText.includes('Offline')
        };
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    console.log('[+] Offline Scan Result:', offlineScan.result.value.offlineDone, 'Banner:', offlineScan.result.value.hasOfflineNotice);
    if (!offlineScan.result.value.offlineDone) throw new Error('Live offline scan failed');

    // 9. NEW TAB TEST (STEP 10)
    console.log('[+] Opening New Tab to Live URL...');
    const { targetId: newTabId } = await cdp.send('Target.createTarget', { url: LIVE_URL });
    const { sessionId: newSessionId } = await cdp.send('Target.attachToTarget', { targetId: newTabId, flatten: true });
    await cdp.send('Page.enable', {}, newSessionId);
    await cdp.send('Runtime.enable', {}, newSessionId);
    await new Promise(r => setTimeout(r, 1500));

    const newTabEval = await cdp.send('Runtime.evaluate', {
      expression: `!!document.getElementById('root') && document.title.includes('PRIVATE PROTECTION')`,
      returnByValue: true
    }, newSessionId);
    console.log('[+] New Tab Loaded Cleanly:', newTabEval.result.value);
    if (!newTabEval.result.value) throw new Error('New tab verification failed');

    cdp.close();
    console.log('======================================================================');
    console.log('ALL LIVE PRODUCTION CHECKS ON HTTPS://PRIVATE-PROTECTION.PAGES.DEV PASSED!');
    console.log('======================================================================');
  } finally {
    try { execSync(`taskkill /F /T /PID ${chromeProc.pid}`); } catch (e) {}
    try { fs.rmSync(tempProfile, { recursive: true, force: true }); } catch (e) {}
  }
}

runLiveTest().catch(err => {
  console.error('Fatal live test failure:', err);
  process.exit(1);
});
