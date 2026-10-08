# Phase 10: Mobile Native Architecture Decision

**Project:** PRIVEX (PS-05)  
**Phase:** 10 — Mobile Native Implementation & Real Device Validation  
**Date:** October 2026  
**Status:** APPROVED & ACTIVE  

---

## 1. Executive Summary & Objective

Phase 8 and Phase 9 audits identified `GAP-03` (**Mobile Native Implementation**): the mobile project contained TypeScript domain logic and test mocks, but lacked concrete native runtime compilation and real OS platform integration.

The objective of Phase 10 is to resolve `GAP-03` by establishing a **fully functional native Android implementation** and real platform integration for PRIVEX while rigorously adhering to the constitutional mandates:
- **LOCAL-FIRST • PRIVACY-FIRST • DATA-MINIMIZATION • ZERO-KNOWLEDGE • ZERO-CLOUD-DEPENDENCE**

---

## 2. Platform Scoping Decisions

### 2.1 Android Platform Scope (IN SCOPE)
- **Host Development OS:** Windows 11 x64.
- **Android SDK:** Installed at `C:\Users\bheda\AppData\Local\Android\Sdk` (API Platforms: 28, 30, 31, 33, 34, 36; Build Tools: 34.0.0, 35.0.0, 36.0.0).
- **Target SDK Version:** Android 14 (API 34).
- **Minimum SDK Version:** Android 8.0 Oreo (API 26) — ensures hardware-backed Keystore, Notification Channels, and modern background isolation.
- **Scope Status:** **100% Fully Implemented and Validated**.

### 2.2 iOS Platform Scope (NOT IN SCOPE FOR HOST COMPILATION)
- **Technical Barrier:** Apple iOS compilation, Xcode toolchain, and Swift compile-time linking strictly require Apple macOS hardware. Attempting to build an `.ipa` or compile Swift on a Windows host without macOS hardware or remote Mac build nodes is physically impossible.
- **Architectural Traceability:** Per `AGENTS.md` Rule 8.5 (*"No Claiming Impossible Capabilities"*), iOS compilation is transparently documented as deferred to macOS CI/CD environments. iOS contract specifications and Apple `IdentityLookup` designs remain documented in `docs/MOBILE_TECHNICAL_ARCHITECTURE.md`.

---

## 3. Native Architecture & Bridge Topology

To maximize performance, security, and offline deterministic execution while retaining shared core engine parity across platforms, PRIVEX Mobile employs a **Sandboxed Native WebView Host + Direct Native Security Bridge**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ANDROID NATIVE RUNTIME                          │
│                                                                        │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │   MainApplication (Zero-Knowledge Native Lifecycle)          │     │
│   └──────────────────────────────┬───────────────────────────────┘     │
│                                  │                                     │
│   ┌──────────────────────────────▼───────────────────────────────┐     │
│   │   MainActivity (Sandboxed Android WebView Container)         │     │
│   │   • Mixed content strictly disabled (MIXED_CONTENT_NEVER_ALLOW)    │     │
│   │   • External navigation blocked; air-gapped asset isolation  │     │
│   └───────────────┬──────────────────────────────▲───────────────┘     │
│                   │                              │                     │
│    Native Events  │                              │ @JavascriptInterface│
│   (Share/DeepLink)│                              │ Security Bridge     │
│                   ▼                              │                     │
│   ┌──────────────────────────────────────────────┴───────────────┐     │
│   │   AndroidSecurityBridge                                      │     │
│   │   • Hardware Encrypted SharedPreferences (get/put/clear)    │     │
│   │   • System Notification Dispatch (High-Priority Channel)     │     │
│   │   • Haptic Threat Vibration (Double-pulse alert)             │     │
│   │   • Camera Permission Verification & Dispatch               │     │
│   │   • Platform Security Metadata Query                         │     │
│   └──────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 ON-DEVICE MOBILE ENGINE & CLIENT LAYER                 │
│                                                                        │
│   ┌──────────────────────────────┐     ┌───────────────────────────┐   │
│   │  @private-protection/core   │     │   @private-protection/ml  │   │
│   │  • Deterministic Heuristics  │     │   • Intent Classifiers    │   │
│   │  • Shannon Entropy           │     │   • AI Security Assistant │   │
│   │  • Typosquatting Matcher     │     │   • Grade 6/8 Readability │   │
│   └──────────────┬───────────────┘     └─────────────┬─────────────┘   │
│                  └───────────────┬───────────────────┘                 │
│                                  ▼                                     │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │  Mobile Services:                                              │   │
│   │  • UrlScannerService      • TextScannerService                 │   │
│   │  • FileScannerService     • CameraScannerService (QR Codes)    │   │
│   │  • DeepLinkValidator      • DeviceAuditService (Posture)       │   │
│   │  • SecureStorageService   • NotificationService                │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Subsystem Specifications

### 4.1 Inbound Data Ingestion & Intent Handling
1. **Share Target (`android.intent.action.SEND`, `text/plain`):**
   - Inbound SMS or messaging snippets shared by the user directly trigger native analysis.
   - Evaluated securely in volatile memory without cloud transmission.
2. **Custom Scheme Deep Links (`privateprotection://scan?url=...`):**
   - Strictly validated by `DeepLinkValidatorService`.
   - Length capped at 2,048 bytes for URLs and 10,000 bytes for text.
   - Administrative and configuration verbs (`bypass`, `disable`, `toggle`, `shred`) are strictly blocked.
3. **Camera QR Code Scanning:**
   - Real-time on-device payload extraction via `CameraScannerService`.
   - Native `CAMERA` runtime permission requested strictly just-in-time.
   - Decoded payloads routed through deterministic URL/Text pipelines.

### 4.2 Sandboxed Local Storage & Crypto-Shredding
- **Storage Target:** Android private app sandbox (`Context.MODE_PRIVATE`).
- **Encrypted SharedPreferences:** Keys derived from Android OS keystore.
- **Zero Tier 1 Persistence:** Visited URLs, message bodies, file bytes, and QR payloads are strictly ephemeral in volatile RAM.
- **Crypto-Shredding:** One-touch purge method (`purgeAllData`) that wipes SharedPreferences and volatile stores instantly.

### 4.3 Warnings & Notifications
- **Notification Channel:** `threat_alerts_channel` registered with `NotificationManager.IMPORTANCE_HIGH`.
- **Haptic Alerts:** Hardware `Vibrator` pulses (aggressive double-pulse for `DANGEROUS`/`CRITICAL` verdicts, single-pulse for `SUSPICIOUS`).
- **Friction Gates:** Unambiguous warnings dispatched within 50 ms.

### 4.4 Permission Manifest Audit (Least Privilege)
The native `AndroidManifest.xml` grants only 4 explicit permissions:
1. `android.permission.POST_NOTIFICATIONS` — Threat warnings.
2. `android.permission.VIBRATE` — Haptic warning motor.
3. `android.permission.CAMERA` — QR code visual scanning.
4. `android.permission.INTERNET` — Reserved for cryptographically signed OTA Bloom updates.

**Strictly Prohibited & Audited as Absent:**
`READ_CONTACTS`, `READ_SMS`, `READ_CALL_LOG`, `ACCESS_FINE_LOCATION`, `READ_EXTERNAL_STORAGE`, `RECORD_AUDIO`, `BIND_ACCESSIBILITY_SERVICE`.

---

## 5. Architectural Verdict
The mobile native architecture provides a production-grade on-device security runtime matching all PS-05 capabilities, air-gapped offline parity, and zero cloud dependency.
