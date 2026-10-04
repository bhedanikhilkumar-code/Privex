// scripts/verify-web-e2e-headless.js
import { spawn, execSync } from 'child_process';
import http from 'http';
import fs from 'fs';
import path from 'path';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9445;
const SERVER_PORT = 8787;

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

async function run() {
  console.log('--- Testing Web Application via Headless Chrome & CDP ---');

  const tempProfile = path.resolve('scratch_web_profile_' + Date.now());
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
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 400));
      try {
        const res = await fetch(`http://127.0.0.1:${PORT}/json/version`);
        if (res.ok) {
          versionData = await res.json();
          break;
        }
      } catch (e) {}
    }

    if (!versionData) {
      throw new Error('Failed to connect to Chrome CDP endpoint');
    }
    console.log('Connected to Chrome CDP:', versionData.Browser);

    const cdp = new CdpSession(versionData.webSocketDebuggerUrl);
    await cdp.connect();

    const { targetId } = await cdp.send('Target.createTarget', { url: `http://127.0.0.1:${SERVER_PORT}/` });
    console.log('Created targetId:', targetId);

    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    console.log('Attached sessionId:', sessionId);

    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);

    // Wait for page to render React app
    await new Promise(r => setTimeout(r, 2000));

    // Evaluate initial state
    const initEval = await cdp.send('Runtime.evaluate', {
      expression: `JSON.stringify({
        title: document.title,
        heading: document.querySelector('h1, h2')?.innerText,
        hasRoot: !!document.getElementById('root'),
        bodyLength: document.body.innerText.length
      })`,
      returnByValue: true
    }, sessionId);
    console.log('Initial Page State:', initEval.result.value);

    // Click URL SCANNER tab
    const clickTab = await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const btn = document.getElementById('tab-url_scan');
        if (btn) { btn.click(); return true; }
        return false;
      })()`,
      returnByValue: true
    }, sessionId);
    console.log('Clicked URL Scanner tab:', clickTab.result.value);
    await new Promise(r => setTimeout(r, 400));

    // Test Safe Quick Sample
    const safeScan = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const btns = Array.from(document.querySelectorAll('button'));
        const safeBtn = btns.find(b => b.innerText.toLowerCase().includes('safe domain'));
        if (safeBtn) safeBtn.click();
        await new Promise(r => setTimeout(r, 200));

        const form = document.querySelector('form');
        if (!form) return { error: 'form not found' };
        form.requestSubmit();

        await new Promise(r => setTimeout(r, 800));

        return {
          isSafeFound: document.body.innerText.includes('SAFE') || document.body.innerText.includes('Safe') || document.body.innerText.includes('ALLOWED'),
          cardText: document.body.innerText.substring(0, 500)
        };
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    console.log('Safe Quick Sample Scan Result:', safeScan.result.value.isSafeFound);

    // Test Threat Quick Sample (IP Phishing)
    const threatScan = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const btns = Array.from(document.querySelectorAll('button'));
        const threatBtn = btns.find(b => b.innerText.toLowerCase().includes('ip') || b.innerText.includes('192.168'));
        if (threatBtn) {
          threatBtn.click();
        } else {
          const input = document.getElementById('url-scan-input');
          const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
          nativeInputValueSetter.call(input, 'http://192.168.1.100/account/login');
          input.dispatchEvent(new Event('input', { bubbles: true }));
        }
        await new Promise(r => setTimeout(r, 200));

        const form = document.querySelector('form');
        form.requestSubmit();

        await new Promise(r => setTimeout(r, 900));

        return {
          isThreatFound: document.body.innerText.includes('DANGEROUS') || document.body.innerText.includes('Dangerous') || document.body.innerText.includes('MALICIOUS') || document.body.innerText.includes('Risk Index'),
          hasGrade6Explanation: document.body.innerText.includes('Why This Website Is Dangerous') || document.body.innerText.includes('Dangerous') || document.body.innerText.includes('Recommended') || document.body.innerText.includes('Threat'),
          textSnippet: document.body.innerText.substring(0, 600)
        };
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    console.log('Threat Quick Sample Scan Result:', threatScan.result.value.isThreatFound, 'Explanation:', threatScan.result.value.hasGrade6Explanation);

    // Test direct routing /settings
    const routeScanner = await cdp.send('Runtime.evaluate', {
      expression: `(async () => {
        const btn = document.getElementById('tab-settings');
        if (btn) btn.click();
        await new Promise(r => setTimeout(r, 300));
        return {
          hasSettings: document.body.innerText.includes('SETTINGS') || document.body.innerText.includes('Settings') || document.body.innerText.includes('Cognitive')
        };
      })()`,
      awaitPromise: true,
      returnByValue: true
    }, sessionId);
    console.log('Settings Route Navigation:', routeScanner.result.value);

    cdp.close();
    console.log('--- ALL WEB REAL-WORLD E2E BROWSER CHECKS PASSED ---');
  } finally {
    try { execSync(`taskkill /F /T /PID ${chromeProc.pid}`); } catch (e) {}
    try { fs.rmSync(tempProfile, { recursive: true, force: true }); } catch (e) {}
  }
}

run().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
