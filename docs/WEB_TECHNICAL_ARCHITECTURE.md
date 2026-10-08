# WEB_TECHNICAL_ARCHITECTURE.md — Client-Side Next.js Web App & PWA Architecture

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVEX WEB DASHBOARD**  
> This document specifies the web application dashboard architecture, detailing the static client-side export, WebAssembly worker execution, Progressive Web App (PWA) offline caching, Content Security Policy, and zero-server privacy guarantees.

---

## 1. THE ZERO-SERVER WEB PARADIGM

> **WEB CONSTITUTIONAL INVARIANT**: The Web Application is a **100% CLIENT-SIDE COMPUTATIONAL TOOL**. When a user types or pastes a URL, text message, or file header into the web dashboard, **NO HTTP POST REQUEST IS EVER TRANSMITTED TO ANY BACKEND SERVER**.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ USER'S BROWSER SANDBOX                                                                                 │
│                                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ USER INTERACTION THREAD (Next.js Static Export • React 18+ Client Components)                  │   │
│   │ • Manual URL Inspection Form & Scam Message Analyzer                                           │   │
│   │ • Interactive Threat Decomposition Cards & Grade 6 Educational Explanations                    │   │
│   │ • Security Self-Assessment & Phishing Awareness Simulator                                      │   │
│   │ • Local Audit Report Viewer (Reads client IndexedDB)                                           │   │
│   └────────────────────────────────────────┬───────────────────────────────────────────────────────┘   │
│                                            │                                                           │
│                                            ▼ Web Worker Message Channel (Zero UI Freezing)             │
│   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ DEDICATED WEB WORKER (`detection-worker.ts`)                                                   │   │
│   │ • Instantiates `@private-protection/core` WebAssembly Module                                   │   │
│   │ • Loads binary Bloom filter into SharedArrayBuffer / ArrayBuffer (< 3.5 MB)                    │   │
│   │ • Executes Normalization -> Heuristics -> Scoring in < 1.0 ms                                  │   │
│   │ • Runs ONNX Runtime Web (WebGPU / WASM SIMD) for intent classification                         │   │
│   └────────────────────────────────────────┬───────────────────────────────────────────────────────┘   │
│                                            │                                                           │
│                                            ▼ Web Crypto API                                            │
│   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ LOCAL ENCRYPTED INDEXEDDB                                                                      │   │
│   │ • AES-256-GCM encrypted local scan history (Zero-Knowledge)                                    │   │
│   └────────────────────────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. STATIC SITE GENERATION (SSG) & PWA OFFLINE CAPABILITY

1. **Static Export Configuration**:
   - Built using Next.js App Router with `output: 'export'` in `next.config.js`.
   - Produces a deterministic collection of static HTML, CSS, JavaScript, and `.wasm` binaries.
   - Hosted on static object storage (Cloudflare Pages, Vercel Edge, AWS S3) with immutable caching headers.
2. **Service Worker Offline Cache**:
   - Conforms to Progressive Web App (PWA) standards via `manifest.json` and a registered Service Worker (`sw.js`).
   - Caching Strategy: **Cache-First (Stale-While-Revalidate)** for application shell and WASM assets.
   - Once loaded, the user can turn off their Wi-Fi/cellular connection or enter Airplane Mode; the entire scanner continues functioning with 100% operational parity.

---

## 3. ASYNCHRONOUS WEB WORKER EXECUTION

To guarantee 60 fps smooth user interactions without frame drops during heavy regex tokenization or entropy computation:
1. **Web Worker Isolation**:
   - Scanning logic runs in an isolated `Worker` instance (`worker.postMessage({ type: 'SCAN_URL', url })`).
   - The main browser thread remains completely unblocked.
2. **WebAssembly SIMD Acceleration**:
   - The `@private-protection/core` WASM binary utilizes fixed-width 128-bit SIMD (Single Instruction, Multiple Data) instructions where supported by the browser, executing Shannon entropy calculations across 2,048-byte URL buffers in under $80\text{ microseconds}$.

---

## 4. CONTENT SECURITY POLICY (CSP) DEFENSE

The web application enforces an uncompromising Content Security Policy via HTTP response headers and `<meta http-equiv="Content-Security-Policy">`:

```http
Content-Security-Policy: default-src 'self';
  script-src 'self' 'wasm-unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  connect-src 'self';
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'none';
  frame-ancestors 'none';
```

### Policy Justification
- `connect-src 'self'`: **Prohibits any outbound API calls** to external third-party hosts. Even if malicious JavaScript was somehow injected into the DOM, the browser would block any attempt to exfiltrate user data.
- `'wasm-unsafe-eval'`: Strictly allows compiling local WebAssembly binaries; disallows generic JavaScript `eval()`.
- `frame-ancestors 'none'`: Prevents clickjacking attacks by blocking the dashboard from being embedded inside hostile iframes.

---

## 5. SEPARATION BETWEEN WEB & NATIVE CLIENTS

| Capability | Web Application (PWA) | Desktop Software | Mobile Application | Browser Extension |
|---|---|---|---|---|
| **Manual URL/Text Scan** | **YES (Full Local)** | **YES (Full Local)** | **YES (Full Local)** | **YES (Full Local)** |
| **Air-Gapped Operation** | **YES (Once Cached)** | **YES (Native)** | **YES (Native)** | **YES (Native)** |
| **Download Folder Watcher**| ❌ No (Sandbox limit) | **YES (Native)** | ❌ No (Sandbox limit)| ❌ No (Sandbox limit) |
| **Inbound SMS Interception**| ❌ No (Sandbox limit) | ❌ No (Sandbox limit)| **YES (Android)** | ❌ No (Sandbox limit) |
| **Pre-Navigation Intercept**| ❌ No (Sandbox limit) | ❌ No (Sandbox limit)| ❌ No (Sandbox limit)| **YES (MV3 Extension)**|
| **Live Camera QR HUD** | Supported (WebCam) | ❌ No | **YES (Native Camera)**| ❌ No |
| **Zero Server Data Leak** | **100% Guaranteed** | **100% Guaranteed** | **100% Guaranteed** | **100% Guaranteed** |
