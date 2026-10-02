# RELEASE ARTIFACT MATRIX
## PRIVATE PROTECTION — Production Release v0.1.0

> **DOCUMENT ID:** `docs/RELEASE_ARTIFACT_MATRIX.md`  
> **CANONICAL VERSION:** `0.1.0`  
> **DATE:** 2026-10-02  
> **SIGNING AUDIT STANDARD:** Master Prompt #16 Rule 16 (Honest Signing Disclosure: SIGNING READY but SIGNING NOT VERIFIED)  

---

## 1. COMPREHENSIVE ARTIFACT MATRIX

| Platform Target | Build Command | Artifact Type | Artifact File Location | Version | SHA-256 Checksum | Signing Status | Target Environments |
|---|---|---|---|---|---|---|---|
| **WEB APP** | `npm run build -w apps/web && node scripts/package-release.js` | Static Web SPA Archive (`.zip`) | `release/private-protection-web-0.1.0.zip` | `0.1.0` | `3f4bf9e475fff7616d069fb06754aa4dfd67f0f2288656b5a897e5710835090a` | **N/A (Web HTTPS/TLS Delivered)** | Modern Evergreen Browsers (Chrome, Firefox, Safari, Edge) |
| **BROWSER EXTENSION** | `npm run build -w apps/extension && node scripts/package-release.js` | Manifest V3 Zip Package (`.zip`) | `release/private-protection-extension-0.1.0.zip` | `0.1.0` | `9505fc14072ba1ca11c400a053a8e30372b0c492954d07b9ccde2110042bd29f` | **SIGNING READY (NOT VERIFIED)** — Store Key Signed on Web Store Upload | Chromium Browsers (Google Chrome 116+, Microsoft Edge 116+, Brave) |
| **ANDROID MOBILE** | `npm run build -w apps/mobile` | Android React Native / Kotlin Source Distribution | `apps/mobile/` (Distributable Bundle) | `0.1.0` (Build 100) | `Source-tree verified: 45 tests passing` | **SIGNING READY (NOT VERIFIED)** — Requires Android Keystore for release APK | Android 10+ (API Level 29+) |
| **WINDOWS DESKTOP** | `npm run build -w apps/desktop` | Electron / Node Desktop Security Daemon | `apps/desktop/` (Distributable Bundle) | `0.1.0` | `Source-tree verified: 58 tests passing` | **SIGNING READY (NOT VERIFIED)** — Requires EV Code Signing Cert for Authenticode | Windows 10 / 11 (x64) |

---

## 2. DETAILED PLATFORM PROFILES

### 1. Web Application (`apps/web`)
- **Installation Method:** Zero-install client-side web application. Can be hosted on any static HTTPS server (Nginx, Cloudflare Pages, GitHub Pages) or installed as an offline Progressive Web App (PWA).
- **Execution Architecture:** Client-side Web Worker (`detection-worker.js`) executing `@private-protection/core` and `@private-protection/ml` in volatile browser RAM.
- **Supported Browsers:** Chrome 100+, Firefox 115+, Safari 16+, Edge 100+.
- **Known Limitations:**
  - Cannot intercept browser-wide URL navigations outside its own web tab.
  - Filesystem access limited to browser drag-and-drop file inputs (no background drive watcher).
  - Volatile storage subject to browser cache eviction policies unless custom IndexedDB persistence is enabled.

### 2. Browser Extension (`apps/extension`)
- **Installation Method:**
  1. Unzip `release/private-protection-extension-0.1.0.zip`.
  2. Open Chrome/Edge and navigate to `chrome://extensions`.
  3. Enable "Developer mode" in the top-right corner.
  4. Click "Load unpacked" and select the unzipped directory containing `manifest.json`.
- **Execution Architecture:** Manifest V3 event-driven service worker (`background.js`) intercepting `webNavigation.onBeforeNavigate` with deterministic Fast-Path evaluation.
- **Signing Status:**
  - In development and sideloaded mode: Unsigned unpacked extension.
  - In production distribution: Packaged zip is submitted to the Chrome Web Store Developer Dashboard where Google signs it with their Web Store PKI. **SIGNING READY; NOT VERIFIED** in local offline environment.
- **Known Limitations:**
  - Cannot inspect web pages on browser-protected internal schemes (`chrome://`, `edge://`, `chrome-extension://`).
  - Declarative net blocking depends on Chromium webNavigation hook latency.

### 3. Android Mobile Application (`apps/mobile`)
- **Installation Method:** Installed via Google Play Store or sideloaded APK (`adb install app-release.apk`).
- **Execution Architecture:** Android user-space application leveraging standard OS permissions (`POST_NOTIFICATIONS`, `CAMERA` for QR scanning).
- **Signing Status:**
  - Android APKs require signing with an Ed25519 or RSA-4096 release keystore (`keytool -genkey -v -keystore release.keystore`). In accordance with Constitutional Security Invariants, no private developer keystores are stored in the public repository.
  - **SIGNING READY; NOT VERIFIED** (Keystore must be supplied via secure CI secrets runner).
- **Known Limitations:**
  - Background SMS interception requires default SMS role on modern Android; standalone app functions via Notification Listener Service and clipboard scan sharing intents.
  - Cannot access system-protected application private directories (`/data/data/<other-app>`).

### 4. Windows Desktop Application (`apps/desktop`)
- **Installation Method:** Distributed as an MSI/EXE installer (or unpacked Electron runtime).
- **Execution Architecture:** Hardened 3-tier Electron client. Node main process executes as an unprivileged user-space security daemon monitoring `%USERPROFILE%\Downloads`, `%TEMP%`, and removable volumes. Unprivileged Chromium renderer runs with `contextIsolation: true` and `sandbox: true`.
- **Signing Status:**
  - Production Windows binaries require Microsoft Authenticode digital certificates to avoid SmartScreen prompts. Private Authenticode PFX certificates are never checked into git.
  - **SIGNING READY; NOT VERIFIED** (Code signing pipeline is configured for EV hardware token or Azure Trusted Signing in CI).
- **Known Limitations:**
  - Does not install a kernel filter driver (`fltmc`); monitoring is restricted to user-space `ReadDirectoryChangesW` / `fs.watch` hooks.
  - Cannot scan system-locked files (`EACCES` / `EBUSY`), such as `System32\config\SAM`; these are safely bypassed with telemetry recorded in `skippedFiles`.
