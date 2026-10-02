# PHASE 16 RELEASE ARTIFACT MATRIX

**Phase:** Phase 16 — Final Release Hardening + Release Candidate (Master Prompt #34)  
**Date:** 2026-10-03  
**Target Release Version:** `0.1.0`  
**Git Base Commit:** `4f014449d524a64e44478d0b75c79a370f18b483`  
**Working Tree Status:** Hardened & Clean  

---

## 1. OFFICIAL RELEASE ARTIFACT MATRIX

| Surface | Artifact Name / Path | Build Command | Version | Commit SHA | SHA-256 Checksum | Size (Bytes) | Build Status | Runtime Verification | Release Status |
|---|---|---|---|---|---|---|---|---|---|
| **WEB** | `release/private-protection-web-0.1.0.zip`<br>(Contains `dist/index.html`, `dist/assets/index-6YHdHnpo.js`, `dist/assets/detection-worker-QJYSzE1M.js`, `dist/sw.js`) | `npm run build -w apps/web && node scripts/package-release.js` | `0.1.0` | `4f01444` | `735d2c15008041f39e67765ebcaba93eab1146649223722768e03576d8e68fad` | 118,166 B | **SUCCESS** | **VERIFIED** (All 52 unit/browser tests pass; PWA Service Worker offline cache verified) | **RELEASE CANDIDATE READY** |
| **ANDROID** | `apps/mobile/android/app/build/outputs/apk/debug/app-debug.apk`<br>(Packaging: `classes*.dex`, `assets/index.html`, `assets/assets/index-Bj4SFWBC.js`) | `npm run build:apk -w apps/mobile`<br>(`npm run build && ./gradlew assembleDebug`) | `0.1.0` (code: 1) | `8a788cf` | `d86a5e844a712920bac236b96faf3a8d8ae37193aa1b59307e5844c5d0d230f6` | 4,444,025 B | **SUCCESS** | **VERIFIED** (Live Android emulator API 37: 8/8 URLs, 8/8 messages, 8/8 SAF real files, native posture bridge, 100% offline) | **RELEASE CANDIDATE READY** |
| **DESKTOP** | `apps/desktop/release/PrivateProtection-win32-x64/PrivateProtection.exe`<br>(Portable Electron executable bundling `dist/main/electron-main.cjs`, `dist/preload/electron-preload.cjs`, `dist/renderer/renderer.js`) | `npm run package -w apps/desktop`<br>(`node scripts/build-desktop.js --package`) | `0.1.0` | `4f01444` | `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` | 245,726,208 B | **SUCCESS** | **VERIFIED** (Native Electron 44.5.1 headless verify exit code 0; AES-256-GCM quarantine vault, path safety, offline parity) | **RELEASE CANDIDATE READY** |
| **EXTENSION** | `release/private-protection-extension-0.1.0.zip`<br>(Contains `dist/manifest.json`, `dist/background.js`, `dist/content.js`, `dist/popup.html`, `dist/interstitial.html`, `dist/options.html`) | `npm run build -w apps/extension && node scripts/package-release.js` | `0.1.0` | `4f01444` | `4cceb25c258df9fd4b4deef198b5bab7f8af1b50aef315d0ac843a75fa220fdc` | 93,513 B | **SUCCESS** | **VERIFIED** (All 51 tests pass; strict CSP `connect-src 'none'; object-src 'none'`, privileged IPC isolation, 5s friction gate) | **RELEASE CANDIDATE READY** |

---

## 2. COMPONENT BUNDLE CHECKSUMS & ARTIFACT DETAILS

### 2.1 Browser Extension (`apps/extension/dist`)
- `dist/manifest.json`: `0eee540118fa4fb0222a87bf1067af2dc9b54a7428e84d79f58ecb8e06bd6373` (1,076 B)
- `dist/background.js`: `005291b7d24ebea09b5f6ee26730dd221d7a1517ae9ffd4024a4044675729478` (85,930 B)
- `dist/content.js`: `e8a7c07fdbbcdb09bb0e88b95e8347032c2bf1b437bb81e2e93200d017a2ce0f` (4,127 B)
- `release/private-protection-extension-0.1.0.zip`: `4cceb25c258df9fd4b4deef198b5bab7f8af1b50aef315d0ac843a75fa220fdc` (93,513 B)

### 2.2 Web Application (`apps/web/dist`)
- `dist/index.html`: `63d0041530c3a6386335ad44ee57efa6fb21fb95b5bdcdf6c2f1fb11b09fb791` (1,738 B)
- `dist/assets/index-6YHdHnpo.js`: `2f79df892d7e8313b933ad735ff0d57812cacd67315de3ed5df7c05c57be27aa` (281,529 B)
- `dist/assets/detection-worker-QJYSzE1M.js`: `5c38f83ca1670bef14ad6735134375fb1168985dc9d1fb5d786896257e821bcb` (93,306 B)
- `dist/sw.js`: `73650220a232f3f9059f131a1a729e844a49c631980838321d491ebda9a9cfb0` (2,361 B)
- `release/private-protection-web-0.1.0.zip`: `735d2c15008041f39e67765ebcaba93eab1146649223722768e03576d8e68fad` (118,166 B)

### 2.3 Android Mobile Client (`apps/mobile`)
- `android/app/build/outputs/apk/debug/app-debug.apk`: `d86a5e844a712920bac236b96faf3a8d8ae37193aa1b59307e5844c5d0d230f6` (4,444,025 B)
- `dist/assets/index-Bj4SFWBC.js`: `82b39c3d3160438821bdcc50ff5057d0e64b60a18649ddaa6a1e6a442e3fd828` (300,050 B)
- `dist/index.html`: `3031c6cc75dcaf54f5ba10aff7c1efc8aee002aaa78efe732cb407cef39812d2` (1,845 B)

### 2.4 Desktop Security Application (`apps/desktop`)
- `release/PrivateProtection-win32-x64/PrivateProtection.exe`: `49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa` (245,726,208 B)
- `dist/main/electron-main.cjs`: `dcc1f06592a5b1937499e356f63d1bd7b87071dcb9363f1a7db4026f014aa41b` (227,230 B)
- `dist/preload/electron-preload.cjs`: `f9bbe2b36cf0b1d721cdb67a1aac5cef88c834336f0a32b4428c91f87af40927` (6,168 B)
- `dist/renderer/renderer.js`: `46cf687044872eba148a462e4b1e4b5ef687c349a7a7db939334c09f6a854686` (207,596 B)
- `release/PrivateProtection-win32-x64/ARTIFACT_MANIFEST.json`: Verified present and synchronized with version `0.1.0`.

---

## 3. MASTER CHECKSUM FILE (`release/SHA256SUMS.txt`)

```text
4cceb25c258df9fd4b4deef198b5bab7f8af1b50aef315d0ac843a75fa220fdc  private-protection-extension-0.1.0.zip
735d2c15008041f39e67765ebcaba93eab1146649223722768e03576d8e68fad  private-protection-web-0.1.0.zip
d86a5e844a712920bac236b96faf3a8d8ae37193aa1b59307e5844c5d0d230f6  private-protection-mobile-0.1.0.apk
49b61a030a520fc36a4b8fa5cce53fb4e935a7bdbbe4b80e9222f598e49cc7fa  PrivateProtection-0.1.0-win-x64.exe
```
