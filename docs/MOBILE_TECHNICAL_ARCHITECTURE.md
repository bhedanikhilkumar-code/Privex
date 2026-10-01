# MOBILE_TECHNICAL_ARCHITECTURE.md — Android & iOS Mobile Client Architecture

> **SYSTEM STATUS: PRE-CODING GOVERNANCE PHASE ACTIVE**  
> **CANONICAL SPECIFICATION — PRIVATE PROTECTION MOBILE CLIENT**  
> This document specifies the mobile client architecture across Android and iOS, detailing the Flutter presentation layer, native OS platform channels, permission models, notification listeners, QR camera scanning, and explicit platform sandboxing restrictions.

---

## 1. MOBILE LAYERED SYSTEM TOPOLOGY

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ MOBILE CLIENT APPLICATION (FLUTTER 3.x RUNTIME)                                                        │
│                                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ PRESENTATION LAYER (Dart / Flutter Widgets)                                                    │   │
│   │ • 60/120 fps Warning Modals & Friction Gates (< 50 ms render SLA)                              │   │
│   │ • Live Camera QR Code Scanner with Red/Green HUD Overlay                                       │   │
│   │ • Security Dashboard, Allowlist Manager, and Threat Breakdown Cards                           │   │
│   └────────────────────────────────────────┬───────────────────────────────────────────────────────┘   │
│                                            │                                                           │
│                                            ▼ Platform Channels (MethodChannel / FFI)                   │
│   ┌────────────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │ CORE BINDING & PERSISTENCE (dart:ffi / SQLCipher)                                              │   │
│   │ • Directly loads `@private-protection/core` compiled C-ABI / WASM runtime                      │   │
│   │ • SQLCipher encrypted local database using AES-256-GCM                                         │   │
│   └────────────────────────┬───────────────────────────────────────────────┬───────────────────────┘   │
└────────────────────────────┼───────────────────────────────────────────────┼───────────────────────────┘
                             │                                               │
             Android Platform Channel (JNI)                  iOS Platform Channel (Swift FFI)
                             ▼                                               ▼
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────────────────┐
│ ANDROID NATIVE DAEMONS (KOTLIN)              │ │ iOS EXTENSION POINTS (SWIFT)                         │
│ • NotificationListenerService                │ │ • IdentityLookup App Extension (SMS/MMS Filter)     │
│   (Parses inbound notification text in RAM)  │ │   (Apple-sandboxed offline classification engine)    │
│ • Share Target Receiver (Screenshots)        │ │ • Share Sheet Extension (Shared screenshots)        │
│ • Android Keystore Master Key Derivation     │ │ • iOS Keychain Hardware Key Derivation (Enclave)     │
└──────────────────────────────────────────────┘ └──────────────────────────────────────────────────────┘
```

---

## 2. ANDROID ARCHITECTURE & INTEGRATION HOOKS

### 2.1 Inbound Threat Interception (`NotificationListenerService`)
1. **Event Ingestion**:
   - The user explicitly grants the Android Notification Access permission (`android.permission.BIND_NOTIFICATION_LISTENER_SERVICE`).
   - The OS routes inbound status bar notifications (SMS, WhatsApp, Telegram, Email) to `PrivateProtectionNotificationService`.
2. **Volatile RAM Inspection**:
   - The service extracts the notification title and body text into an ephemeral Kotlin `CharSequence`.
   - The payload is handed to `@private-protection/core` via JNI.
   - If the risk score $\ge 70$, the service dispatches an instant, high-priority heads-up warning notification alert advising the user *not* to tap the original notification.
3. **Memory Zeroing**:
   - The string buffer is cleared immediately. Raw notification content is **never** written to Android shared preferences, logcat, or SQLite.

### 2.2 Share Target Intent (Screenshot Analysis)
- Registered via `android.intent.action.SEND` for `image/*` MIME types.
- When a user shares a screenshot of a suspicious message or email from their gallery, the bitmap is decoded in volatile RAM, processed via on-device OCR (Google ML Kit Text Recognition running locally), and passed to `MessageAnalyzer`.

---

## 3. iOS ARCHITECTURE & SANDBOX BOUNDARIES

### 3.1 SMS & MMS Message Filtering (`IdentityLookup`)
1. **Apple Sandbox Constraints**:
   - iOS strictly prohibits third-party apps from reading user SMS messages in the background.
   - PRIVATE PROTECTION utilizes Apple's official `IdentityLookup` framework (`ILMessageFilterExtension`).
2. **Offline Execution Boundary**:
   - When an SMS from an unknown sender arrives, iOS wakes `MessageFilterExtension` in an isolated, air-gapped sandbox.
   - **Zero Network Entitlement**: The extension is forbidden from accessing the network.
   - The extension queries the local bundled `@private-protection/core` rules.
   - If a threat is detected, it returns `.junk` or `.promotion` to iOS, automatically routing the scam message to the user's Junk folder without alerting them.

### 3.2 Share Extension
- Implemented as an `ActionExtension` conforming to `kUTTypeImage`.
- Performs on-device text recognition using Apple's local Vision framework (`VNRecognizeTextRequest`) and passes extracted text to the detection engine.

---

## 4. LIVE CAMERA QR CODE SCANNING

1. **Viewfinder Pipeline**:
   - Camera frame stream processed at 30 fps using local barcode detectors (ZXing / ML Kit).
   - Once a QR code containing a URL or text is decoded:
     - URL is evaluated by `DetectionEngine` in $< 1.0\text{ ms}$.
2. **Instant HUD Feedback**:
   - If **Safe**: Viewfinder bounding box highlights **Green**.
   - If **Suspicious / Dangerous**: Viewfinder bounding box flashes **Red**, device triggers a distinct haptic warning vibration, and a warning bottom-sheet pops up *before* the user can tap to open the link.

---

## 5. PERMISSIONS MATRIX & MINIMAL PRIVILEGE

| Permission | Platform | Mandatory / Optional | Purpose |
|---|---|---|---|
| `POST_NOTIFICATIONS` | Android 13+ | Mandatory | To display threat alerts and warning modals. |
| `BIND_NOTIFICATION_LISTENER` | Android | Optional (User Opt-In) | Inbound SMS/chat notification threat monitoring. |
| `CAMERA` | Android / iOS | Optional (User Opt-In) | Live camera QR code threat scanning. |
| `VIBRATE` | Android | Mandatory | Haptic feedback warning upon threat detection. |
| `READ_EXTERNAL_STORAGE` | Android | **REJECTED (Forbidden)** | App does not request broad external storage access. |
| `ACCESS_FINE_LOCATION` | Android / iOS | **REJECTED (Forbidden)** | App never requests user location. |
| `READ_CONTACTS` | Android / iOS | **REJECTED (Forbidden)** | App never reads user address book. |

---

## 6. PLATFORM RESTRICTIONS & ARCHITECTURAL HONESTY

> **CONSTITUTIONAL DIRECTIVE**: PRIVATE PROTECTION will never claim impossible mobile capabilities forbidden by OS security models.

1. **No Background SMS Interception on iOS**: Apple does not allow reading SMS messages in the background. We use the official `IdentityLookup` extension, which filters unknown senders into the Junk tab, but we cannot inspect messages from existing contacts or arbitrary chat apps (iMessage/WhatsApp) on iOS.
2. **No Whole-Device Network Interception Without VPN**: The mobile app cannot intercept system-wide HTTP traffic from other mobile apps without configuring a local `VpnService` dummy loopback tunnel.
3. **No Battery-Draining Background Loops**: Detection is strictly event-driven. The app does not hold persistent CPU wake locks, ensuring zero noticeable impact on battery life.
