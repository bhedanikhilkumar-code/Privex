# docs/PHASE_T_MOBILE_SECURITY_ANALYSIS.md — Phase T Mobile Security Pre-Implementation Specialist Analysis

> **DOCUMENT STATUS:** CANONICAL ARCHITECTURAL FEASIBILITY & PRE-IMPLEMENTATION SPECIALIST ASSESSMENT  
> **TARGET MILESTONE:** Phase T (Android Mobile Security Subsystem Transformation)  
> **AUTHORING BODY:** Mobile Security Architecture Analysis Team & Independent Security Review Board  
> **GOVERNING CONSTITUTION:** rules.md (Rules 01–29), AGENTS.md (Constitutional Invariants 1–2), memory.md  
> **EXECUTION BOUNDARY:** ANALYSIS & FEASIBILITY ONLY — ZERO CODE MODIFICATIONS  

---

## 1. Executive Summary

Privex has successfully completed Phases A through S for Windows Desktop (`apps/desktop/`), establishing a verified, local-first endpoint protection suite. The objective of Phase T is to translate and expand these capabilities to real physical Android smartphones (`apps/mobile/`), meeting the core mandate of **Problem Statement PS-05**: on-device, real-time threat, phishing, scam, and malware protection without cloud dependency.

However, an enterprise-grade antivirus cannot be ported from Windows to Android by naive analogy. Windows grants privileged user-mode services broad filesystem visibility (`ReadDirectoryChangesW`, direct disk handles, full path traversal) and process inspection primitives (`Win32_ProcessStartTrace`, ETW). In stark contrast, modern Android (Android 8.0 Oreo through Android 14/15, API levels 26–35) enforces a rigorous zero-trust sandbox:
1. **Linux UID Process Isolation:** Every application executes in its own distinct Linux UID (`u0_aXXX`). Direct process inspection, memory access, or cross-app execution blocking is prohibited by Linux kernel permissions and SELinux policies.
2. **Scoped Storage (`Storage Access Framework` & `MediaStore`):** Broad filesystem access (`/sdcard`, `/data/data`, `/storage/emulated/0/Android/data`) is blocked. Direct file operations on files written by other applications cannot be performed via standard `java.io.File` APIs without user mediation or restricted permissions.
3. **Package Management Sandbox:** A standard third-party application cannot intercept, inject into, or block the Android System `PackageInstaller`. Pre-execution blocking of app installations is restricted to Device Owner (MDM/Enterprise) or platform-signed system apps.
4. **Network & Web Sandboxing:** Third-party applications cannot intercept outbound browser traffic without a local network loopback (`VpnService`) or explicit user sharing.

**Core Feasibility Verdict:** Phase T is **technically feasible and architecturally sound**, but it requires a **strict separation between native Android OS capabilities and desktop-style expectations**. Any claim that a standard third-party Android app can silently block package installations, inspect other apps' private directories, or intercept HTTPS traffic without clear platform constraints violates `rules.md` Rule 26 (**Architectural Honesty Rule**). 

The mobile architecture must execute as a **hybrid multi-layer endpoint shield**:
- Real-time post-install APK audit and user-mediated uninstall dispatch via `ACTION_PACKAGE_ADDED` and `PackageInfo`.
- Asynchronous download auditing via `ContentObserver` on `MediaStore.Downloads` with `IS_PENDING` stabilization tracking.
- High-speed, privacy-preserving phishing protection via a **local-loopback `VpnService` DNS filter** that evaluates domain Bloom filters in volatile RAM with zero TLS decryption.
- User-mediated file inspection and quarantine via Storage Access Framework (`ACTION_OPEN_DOCUMENT`, `ACTION_CREATE_DOCUMENT`).
- 100% offline detection parity powered by the existing `@private-protection/core` and `@private-protection/ml` packages running on-device.

---

## 2. Current Mobile Architecture (As-Inspected Ground Truth)

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            CURRENT MOBILE TOPOLOGY                               │
│                                                                                  │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │ ANDROID NATIVE RUNTIME (apps/mobile/android/)                            │   │
│   │ • Min SDK: 26 (Android 8.0) | Target SDK: 34 (Android 14)                │   │
│   │ • Java 17 | AGP 8.2.2 | Gradle 8.4 | R8 Shrinking + Minification        │   │
│   │ • MainActivity.java (SingleTask Host Container)                          │   │
│   │ • SecureStorageManager.java (MasterKey + EncryptedSharedPreferences)     │   │
│   │ • QrCodeDecoder.java (ZXing Core 3.5.3 Camera Barcode Decoding)          │   │
│   │ • AndroidSecurityBridge (@JavascriptInterface native IPC)                │   │
│   │ • WebViewAssetLoader (Serves appassets.androidplatform.net virtually)    │   │
│   └────────────────────────────────────┬─────────────────────────────────────┘   │
│                                        │ WebMessage / Bridge                     │
│                                        ▼                                         │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │ HYBRID REACT WEBVIEW UI (apps/mobile/src/)                               │   │
│   │ • React 18 + TypeScript + Vite 6.0                                       │   │
│   │ • Screens: Home, URL, Text, File (Single SAF), QR Scanner, Posture, AI   │   │
│   │ • MobileSecurityAdapter -> DetectionPipeline (@private-protection/core) │   │
│   │ • AISecurityAssistant (@private-protection/ml, read-only)                │   │
│   │ • Shims: buffer-shim.ts, crypto-shim.ts (WebCrypto / Native Bridge)      │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Concrete Repository Inventory
1. **Android Build Configuration (`apps/mobile/android/app/build.gradle`):**
   - `namespace`: `com.privateprotection.mobile`
   - `compileSdkVersion`: `34` (Android 14)
   - `minSdkVersion`: `26` (Android 8.0 Oreo)
   - `targetSdkVersion`: `34` (Android 14)
   - `sourceCompatibility`: `JavaVersion.VERSION_17`
   - ProGuard / R8: Enabled (`minifyEnabled true`, `shrinkResources true`, `proguard-rules.pro`).
   - Native Libraries & AndroidX: `androidx.appcompat:1.6.1`, `androidx.core:core-ktx:1.12.0`, `androidx.security:security-crypto:1.1.0-alpha06`, `androidx.webkit:webkit:1.10.0`, `com.google.zxing:core:3.5.3`.
2. **Manifest & Permissions (`apps/mobile/android/app/src/main/AndroidManifest.xml`):**
   - Declared: `POST_NOTIFICATIONS`, `VIBRATE`, `CAMERA` (feature optional), `INTERNET` (reserved for OTA).
   - Network Security: `android:usesCleartextTraffic="false"`, `network_security_config.xml` (TLS only).
   - Backup: `android:allowBackup="false"` (prevents ADB data extraction).
   - Intent Handlers: `ACTION_MAIN` / `LAUNCHER`, `ACTION_VIEW` (`privateprotection://scan?url=...`), `ACTION_SEND` (`text/plain` share target).
3. **Storage & Native Bridge:**
   - Hardware Keystore-backed AES-256-GCM / AES-256-SIV via `androidx.security.crypto.EncryptedSharedPreferences`.
   - Bridge exposes: `getPlatformMetadata`, `notifyClientReady`, `consumePendingIntent`, `secureStorageGet/Put/Remove/Clear`, `decodeQrFrame`, `triggerWarningHaptics`, `dispatchNativeNotification`, `hasCameraPermission`, `requestCameraPermission`, and `getDeviceSecurityPosture`.
4. **Current Functional Limitations (Pre-Phase T):**
   - **No Background Services:** No `Service`, `JobService`, `WorkManager`, or `BroadcastReceiver` currently declared in `AndroidManifest.xml`. All scanning is active foreground only.
   - **Single-File File Picker Only:** File scanning relies entirely on user-initiated SAF file selection (`WebChromeClient.onShowFileChooser`). No automated download observation.
   - **No App Installation Awareness:** App is completely blind to package installs, updates, or removals.
   - **No Web / Phishing Interception:** Relies solely on manual URL typing, QR camera scan, or deep link.
   - **WebView UI Thread Bound:** Long-running operations execute in the WebView JavaScript runtime, risking frame drops if scanning large files.

---

## 3. Phase T Capability Matrix (T1 – T16)

| Capability ID | Capability Name | Required Android APIs & Components | Required Permissions | Lifecycle & Execution Mode | Storage & Privilege Boundary | Impl. / Test Complexity | Fallback Strategy |
|---|---|---|---|---|---|---|---|
| **T1** | **Mobile Security Core** | `WorkManager`, `ForegroundService`, Android Native Worker Threads | `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC` (API 34+) | Background / Foreground Service | App-private data (`Context.getFilesDir()`), SQLCipher / EncryptedSharedPreferences | High / High | Degrade to sequential on-demand scanning when memory constrained. |
| **T2** | **App Installation Shield** | `BroadcastReceiver`, `PackageManager`, `PackageInfo`, `PackageInstaller` | `RECEIVE_BOOT_COMPLETED`, `QUERY_ALL_PACKAGES` (or `<queries>`) | Event-driven background broadcast receiver | Read `/data/app/.../base.apk` (read-only system access) | Med / Med | If `QUERY_ALL_PACKAGES` rejected by policy, use user-initiated APK file scanning via SAF. |
| **T3** | **Universal Download / File Shield** | `ContentObserver`, `MediaStore.Downloads`, `FileObserver` | `READ_EXTERNAL_STORAGE` (API 26-28), `READ_MEDIA_*` (API 33+), SAF | Background observer daemon | Scoped Storage read access via `ContentResolver.openInputStream(uri)` | High / High | If MediaStore read is restricted on API 30+, fallback to SAF folder tree selection. |
| **T4** | **Full Device Scan** | `WorkManager`, `DocumentFile`, `MediaStore.Files`, `PackageManager` | MediaStore permissions, persistent SAF Tree URI | Deferred background worker (`BatteryNotLow`, `DeviceIdle`) | User-granted SAF tree + MediaStore public indices | High / High | Explicitly document as "Accessible Storage & Installed Apps Scan"; never claim raw `/data/` access. |
| **T5** | **Real-Time Download Protection** | `ContentObserver` on `MediaStore.Downloads.EXTERNAL_CONTENT_URI` | MediaStore read access | Event-driven background listener | Ephemeral stream in RAM; `IS_PENDING=0` check | High / High | Poll Downloads directory on app resume if observer events are killed by Doze. |
| **T6** | **Phishing / Web Shield** | `VpnService`, Local Tun interface, Non-blocking DNS UDP Parser | `BIND_VPN_SERVICE` | Continuous foreground service with persistent status notification | Loopback UDP socket (port 53); zero external socket redirection | Very High / Very High | Fallback to Share Target URL scanner and browser extension pairing. |
| **T7** | **Pre-Threat Warning** | `NotificationManager`, Fullscreen Intent (high-risk only), System Dialog | `POST_NOTIFICATIONS`, `SYSTEM_ALERT_WINDOW` (optional, reject if possible) | Immediate push notification / foreground modal | UI layer (< 50 ms render SLA) | Med / Med | Standard High-Priority Notification banner with destructive action intent. |
| **T8** | **Password Generator** | `java.security.SecureRandom`, CharArray wiping, Android Keystore | None (zero permissions) | Synchronous on-demand | Volatile RAM only; strict clipboard auto-clear timer (30s) | Low / Low | Deterministic CSPRNG fallback. |
| **T9** | **Mobile Threat Intelligence** | Memory-mapped `.ppdb` binary format, SQLite / Room, Ed25519 verifier | `INTERNET` (optional OTA) | Scheduled background worker via `WorkManager` | Encrypted local database (`threat_intel.db.enc`) | High / Med | Embedded read-only factory seed Bloom filter asset. |
| **T10** | **Mobile Quarantine / Remediation** | Encrypted App-Private Storage (`PPVAULT2`), `MediaStore.createDeleteRequest` | MediaStore delete entitlement (Android 11+ system prompt) | Interactive user confirmation flow | App-private `/data/user/0/.../quarantine/` | High / High | File renaming to `.quarantine_isolated` + prompt user to delete file manually. |
| **T11** | **Permission & Privacy Center** | `PackageManager`, `AppOpsManager`, `PermissionChecker` | None (introspects own and system permissions) | Foreground UI dashboard | Read-only OS inspection | Med / Low | Static permission guidance cards. |
| **T12** | **Battery / Thermal / Low-RAM Mode** | `PowerManager`, `BatteryManager`, `ComponentCallbacks2.onTrimMemory` | None | System broadcast callbacks | Throttle worker pools to 1 thread; drop hash caches | Med / Med | Skip high-entropy and deep archive parsing during low-battery state. |
| **T13** | **Mobile Notifications** | `NotificationManager`, `NotificationChannel`, Token-Bucket Rate Limiter | `POST_NOTIFICATIONS`, `VIBRATE` | Immediate event dispatch | Android OS notification center | Low / Low | In-app modal alert if notification permission denied. |
| **T14** | **Security Test Matrix** | AndroidX Test, Robolectric, Instrumentation, Fault Injection | Test entitlements | CI / Real Device Runner | Test fixture isolation | High / High | Synthetic fixtures; zero live malware per Rule 06. |
| **T15** | **Performance Engine** | Zero-allocation byte slicing, streaming SHA-256, LRU clean cache | None | Native thread / Web Worker | Memory bounded to < 32 MB heap delta | High / High | Short-circuit sieve (< 0.08 ms cache hit). |
| **T16** | **Independent Audit** | Static analyzer, Lint, STRIDE matrix, Differential Privacy audit | None | Pre-release release gate | Audit reports in `docs/` | Med / Low | Fail-closed release block if any gate fails. |

---

## 4. Android API Capability Matrix (What Android Genuinely Allows vs. Blocks)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              ANDROID OS API BOUNDARY TAXONOMY                                          │
├────────────────────────────────────────┬───────────────────────────────────────────────────────────────┤
│ OS ACTION VECTOR                       │ PLATFORM FEASIBILITY & EXACT OS MECHANISM                     │
├────────────────────────────────────────┼───────────────────────────────────────────────────────────────┤
│ Inspect downloaded APK file            │ PERMITTED (Via MediaStore / SAF input stream)                 │
│ Block package installation pre-exec    │ IMPOSSIBLE for 3rd-party apps (System PackageInstaller owns UI)│
│ Observe package installation event     │ PERMITTED (ACTION_PACKAGE_ADDED broadcast receiver)           │
│ Inspect installed app binary & cert    │ PERMITTED (PackageManager.getPackageInfo, sourceDir base.apk) │
│ Uninstall malicious app silently       │ IMPOSSIBLE (Requires user confirmation via ACTION_UNINSTALL)  │
│ Intercept browser HTTP/HTTPS traffic   │ RESTRICTED (Impossible without local VpnService loopback)     │
│ Decrypt arbitrary TLS HTTPS traffic    │ PROHIBITED (Zero-Knowledge mandate; requires root/CA cert)    │
│ Filter domain lookups (DNS)            │ PERMITTED (Local VpnService UDP port 53 interception)         │
│ Read other apps' internal data         │ IMPOSSIBLE (Linux UID sandbox & SELinux strictly block)       │
│ Crawl entire SD card silently          │ PROHIBITED on API 30+ without MANAGE_EXTERNAL_STORAGE          │
│ Scoped Storage user directory scan     │ PERMITTED (Via Storage Access Framework ACTION_OPEN_DOCUMENT_ │
│                                        │ TREE with user permission grant)                              │
│ Monitor downloads in background        │ PERMITTED (ContentObserver on MediaStore.Downloads URI)       │
│ Auto-quarantine other apps' files      │ RESTRICTED (Must copy to private vault; original delete       │
│                                        │ requires MediaStore.createDeleteRequest user prompt)          │
└────────────────────────────────────────┴───────────────────────────────────────────────────────────────┘
```

---

## 5. App Installation Protection Analysis

### 5.1 The Android Package Installation Lifecycle
```
[1. APK Downloaded] ──> [2. File Stored] ──> [3. User Opens APK] ──> [4. PackageInstaller UI]
        │                      │                     │                         │
  (Public Media)         (In Downloads)       (System Intent)          (OS System Dialog)
        │                      │                     │                         │
        ▼                      ▼                     ▼                         ▼
   Private Prot.          Private Prot.        Private Prot.             Private Prot.
   CAN OBSERVE            CAN SCAN FILE       BLIND TO INTENT           CANNOT INJECT
        │                      │                     │                         │
        └──────────────────────┼─────────────────────┴─────────────────────────┘
                               │
                               ▼
                   [5. OS Package Manager Service]
                     • Verification & DEX Compile
                     • Writes to /data/app/...
                               │
                               ▼
                   [6. Installation Complete]
                     • ACTION_PACKAGE_ADDED Broadcast Fired
                     • Private Prot. Wakes in Background
                     • Reads /data/app/.../base.apk
                     • If Threat: Dispatches Instant Danger Notification
                               │
                               ▼
                   [7. User Taps Notification]
                     • Launches ACTION_UNINSTALL_PACKAGE
                     • User confirms 1-tap uninstallation
```

### 5.2 Capability Breakdown Across Scenarios
1. **Scenario A (APK Available in Storage Before Install):**
   - *Capability:* **CAN INSPECT BEFORE INSTALLATION**.
   - *Mechanism:* Detected in Downloads via `ContentObserver`. Inspects ZIP central directory, AndroidManifest binary XML, and DEX header. Posts danger warning if malicious.
2. **Scenario B & C (User Taps APK / Package Installer Begins):**
   - *Capability:* **CANNOT BLOCK OR INTERCEPT**.
   - *Truth:* OS System PackageInstaller runs in an isolated system process. No 3rd-party app can intercept or inject into this dialog.
3. **Scenario D & E (Installation Completes):**
   - *Capability:* **CAN OBSERVE & INSPECT IMMEDIATELY AFTER INSTALLATION**.
   - *Mechanism:* Manifest-registered `ACTION_PACKAGE_ADDED` receiver wakes. Reads world-readable `/data/app/.../base.apk` via `PackageInfo.applicationInfo.sourceDir`. Inspects certificates, DEX headers, permissions, and hash in volatile RAM (< 200 ms).
4. **Scenario F & G (App Update / First Launch):**
   - *Capability:* Updates trigger `ACTION_PACKAGE_REPLACED`. Scan finishes before user typically navigates to app launcher.
5. **Special Privileges:**
   - *AccessibilityService:* **PROHIBITED**. Google Play bans Accessibility for antivirus automation, creates tapjacking risks, and drains battery.
   - *Device Owner / MDM:* Impractical for consumer apps.

---

## 6. Universal File Analysis & Parser Security

| Format / Extension | Magic Bytes | Parser Implementation Strategy | Decompression & Resource Limits | Malicious Pattern Defense |
|---|---|---|---|---|
| **APK** | `50 4B 03 04` (ZIP) | Streaming ZIP central directory parser + binary XML reader | Max archive size: 100 MB; Max entries: 5,000; Ratio limit: 100:1 | Malformed DEX headers, fake SDK versions, suspicious permissions, known malware cert hashes. |
| **ZIP** | `50 4B 03 04` | `@private-protection/core` `ArchiveAnalyzer` (zero-allocation DataView) | Max depth: 2 nested levels; Max total uncompressed: 250 MB | ZIP bomb defense (aborts if ratio > 100:1), directory traversal (`../`), disguised `.apk`/`.dex` files. |
| **RAR / 7Z** | `52 61 72 21` / `37 7A BC AF` | Header triage + magic validation; pass to bounded streaming unpacker | Header-only inspect; 32 KB sliding window | Encrypted header evasion, path traversal, nested archives. |
| **PDF** | `25 50 44 46` (`%PDF`) | `@private-protection/core` `DocumentAnalyzer` dictionary parser | Bounded object dictionary scan (max 5,000 objects) | `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`, `/OpenAction` exploit streams. |
| **DOCX / XLSX / PPTX** | `50 4B 03 04` (OOXML) | OOXML ZIP container inspection + relationship table analyzer | Unpack only `[Content_Types].xml` and `word/_rels/` | Macros (`vbaProject.bin`), external template injection (`TargetMode="External"`), OLE exploits. |
| **DOC / XLS / PPT** | `D0 CF 11 E0` (OLE2) | `DocumentAnalyzer` OLE2 Compound Binary stream directory reader | Max directory sectors: 512 | Equation Editor exploit streams (`\x01CompObj`), legacy 4.0 macros, shellcode padding. |
| **JPG / PNG / GIF / WEBP** | `FF D8 FF` / `89 50 4E 47` / `47 49 46 38` / `52 49 46 46` | Header verification + trailing payload inspection | Max header scan: 64 KB; EOF trailer inspect: 32 KB | Steganographic script droppers, trailing appended APK/PE binaries, RTLO extension spoofing. |
| **MP4 / Media** | `....ftyp` (ISO BMFF) | Box atom header verification (`ftyp`, `moov`, `mdat`) | Header-only (first 16 KB) | Fake video extensions concealing executable shellcode or APK droppers. |
| **TXT / CSV** | N/A (Plaintext) | UTF-8 / ASCII lexical analyzer | Max scanned size: 2 MB | DDE formulas (`=CMD|' /C ...'`), macro command strings, phishing URLs. |
| **HTML / JS** | `<html`, `<!DOC`, or script | Lexical token stream + script heuristic analyzer | Max script length: 512 KB | Obfuscated `eval()`, document redirect loops, credential harvesting DOM structures. |
| **Generic Binary / DEX** | `64 65 78 0A` (`dex\n`) / `7F 45 4C 46` (`ELF`) | Magic byte detector + Shannon entropy scanner | 64 KB sliding window entropy calculation | High-entropy packed sections ($H > 7.5$), embedded executable ELF binaries in non-exec paths. |

---

## 7. Full Device Scan Analysis (Scoped Storage Ground Truth)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          ANDROID DEVICE STORAGE COVERAGE                               │
├──────────────────────────┬───────────────────────┬─────────────────────────────────────┤
│ STORAGE REGION           │ ACCESSIBILITY CLASS   │ TECHNICAL DETAILS & CONSTRAINTS     │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ Installed Applications   │ FULL                  │ World-readable base.apk via         │
│ (/data/app/...)          │                       │ ApplicationInfo.sourceDir           │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ MediaStore Public Files  │ FULL (with MediaStore │ Accessible via ContentResolver:     │
│ (Images, Audio, Video,   │ permissions)          │ MediaStore.Images, MediaStore.Video,│
│ MediaStore.Downloads)    │                       │ MediaStore.Downloads                │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ User Documents & Shared  │ USER-GRANTED          │ Accessible ONLY if user selects     │
│ Folders (/sdcard/...)    │ (SAF Tree URI)        │ root folder via ACTION_OPEN_        │
│                          │                       │ DOCUMENT_TREE and grants access     │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ Removable SD Card        │ USER-GRANTED          │ Accessible via DocumentFile over    │
│                          │ (SAF Tree URI)        │ user-granted SD card root URI       │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ App's Own Private Dir    │ FULL                  │ Context.getFilesDir() (Internal)    │
│ (/data/user/0/com.pp/...)│                       │                                     │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ Other Apps' Private Dirs │ INACCESSIBLE          │ Blocked by Linux UID sandbox &      │
│ (/data/user/0/<other>/)  │ (Hard Kernel Block)   │ SELinux. POSIX 0700 permissions.    │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ App Sandboxed Data       │ INACCESSIBLE          │ Blocked by Android OS on API 30+    │
│ (/sdcard/Android/data,   │ (OS Enforcement)      │ even with SAF tree permissions.     │
│  /sdcard/Android/obb)    │                       │                                     │
├──────────────────────────┼───────────────────────┼─────────────────────────────────────┤
│ System Partition         │ READ-ONLY / EXEMPT    │ Read-only dm-verity protected OS    │
│ (/system, /vendor)       │                       │ binaries. Scanning is unnecessary.  │
└──────────────────────────┴───────────────────────┴─────────────────────────────────────┘
```

---

## 8. Phishing & Web Shield Architecture Comparison

| Architecture Option | Privacy Impact | Permissions Required | Reliability | Battery Drain | HTTPS URL Path Visibility | TLS MITM Required? | Play Store Viability | Specialist Recommendation |
|---|---|---|---|---|---|---|---|---|
| **A. Browser Integration** | High privacy | None | Low | Zero | Full URL | No | High | Incomplete (limited to 1-2 browsers). |
| **B. URL Sharing / Deep Link** | 100% private | None | 100% | Zero | Full URL | No | High | Passive; requires manual user action. |
| **C. In-App WebView** | 100% private | None | 100% | Low | Full URL | No | High | Only protects within the app itself. |
| **D. Accessibility Service** | Severe privacy leak risk | `BIND_ACCESSIBILITY_SERVICE` | Fragile (UI scraping breaks across browsers) | High | Address bar text | No | **FATAL (Rejection & Banning)** | **PROHIBITED**. High security risk, banned by Google Play for AV. |
| **E. Local Loopback VpnService** | **100% Private (Local Loopback)** | `BIND_VPN_SERVICE` | **Very High (System-wide across all apps & browsers)** | Low | Domain-level (DNS UDP 53) | **NO (Zero MITM)** | **HIGH (Standard AV architecture)** | **RECOMMENDED PRIMARY ARCHITECTURE**. |
| **F. Local Private DNS (DoH/DoT)** | 100% private | Requires system Private DNS settings | High | Zero | Domain-level | No | Med (Requires complex manual setup) | Excellent secondary option. |
| **G. Browser Extension** | High privacy | Extension permissions | High | Zero | Full URL | No | Low (Only Firefox/Kiwi support mobile extensions) | Platform-specific complement. |
| **H. Notification Listener** | Medium privacy | `BIND_NOTIFICATION_LISTENER_SERVICE` | High | Low | Message text | No | Med (Requires high-trust justification) | Excellent complementary shield for SMS/chat. |

---

## 9. Pre-Threat Warning Feasibility (Temporal Classification)

| Threat Event Vector | Temporal Classification | Underlying Mechanism & SLA | User Action Barrier |
|---|---|---|---|
| **Malicious Website Navigation** (via Local DNS Shield) | **PRE-ACTION POSSIBLE** | DNS lookup intercepted before TCP connection established (< 1 ms). | Website fails to load; blocking notification displayed instantly. |
| **APK Download in Browser** | **PRE-ACTION POSSIBLE** | Detected in Downloads via `ContentObserver` before user taps notification or opens file. | Danger notification displayed advising user to delete download immediately. |
| **APK Sideload Installation Initiation** | **NOT GUARANTEED (OS Barrier)** | Android System PackageInstaller does not offer an external interception API to 3rd-party apps. | Cannot block system installer dialog. |
| **App Installation Completion** | **IMMEDIATE POST-ACTION** | `ACTION_PACKAGE_ADDED` receiver wakes in $< 50\text{ ms}$; scans APK in $< 200\text{ ms}$. | High-priority heads-up warning notification with 1-tap uninstall intent dispatched before user opens app. |
| **Installed Malware Launch** | **NOT GUARANTEED (OS Barrier)** | Cannot intercept arbitrary app launches without abusive Accessibility service. | Immediate post-install warning is the primary defense barrier. |
| **Malicious Document Opening** | **PRE-ACTION POSSIBLE (if scanned via SAF / Downloads)** | If file downloaded or selected via app, analyzed before user opens in viewer. | Warning modal displays file risk before passing URI to external viewer. |
| **Suspicious Chat / SMS Link** | **PRE-ACTION POSSIBLE (via Notification Listener)** | Inbound SMS/chat notification intercepted in RAM; link evaluated in $< 1\text{ ms}$. | Warning banner alerts user before tapping message link. |

---

## 10. Password Generator Subsystem Design

1. **Cryptographic Randomness:** Strictly uses `java.security.SecureRandom` (backed by Linux kernel `/dev/urandom` / `getrandom()` syscall).
2. **Character Sets & Length:** Configurable 12 to 128 characters across Upper, Lower, Numbers, Symbols, and Diceware 7,776-word passphrase list.
3. **Shannon Entropy Calculation:** Evaluates $H = L \cdot \log_2(N)$ with visual threshold ratings.
4. **Secret Memory Lifecycle:** Mutable `char[]` arrays zeroed immediately (`Arrays.fill(chars, '\0')`).
5. **Clipboard Security:** Marked `EXTRA_IS_SENSITIVE = true` on API 33+; auto-cleared from clipboard after 30 seconds.
6. **Screen Protection:** Enforces `FLAG_SECURE` against screenshots, screen recording, and task switcher caching.

---

## 11. Battery, Thermal, & Low-RAM Execution Model

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ANDROID BACKGROUND EXECUTION ASSIGNMENT                         │
├─────────────────────────┬────────────────────────────┬─────────────────────────────────┤
│ TASK TYPE               │ MECHANISM                  │ CONSTRAINTS & BEHAVIOR          │
├─────────────────────────┼────────────────────────────┼─────────────────────────────────┤
│ Phishing / DNS Shield   │ Foreground Service         │ Persistent low-priority status  │
│                         │ (FOREGROUND_SERVICE_TYPE_  │ notification; ultra-low CPU     │
│                         │  SYSTEM_EXEMPTED / SPECIAL)│ (< 0.1% idle)                   │
├─────────────────────────┼────────────────────────────┼─────────────────────────────────┤
│ Real-Time Download      │ ContentObserver +          │ Registered while app active or  │
│ Monitoring              │ Event-driven Worker        │ triggered on download event     │
├─────────────────────────┼────────────────────────────┼─────────────────────────────────┤
│ App Install Monitoring  │ BroadcastReceiver          │ Manifest-registered receiver;   │
│                         │ (ACTION_PACKAGE_ADDED)     │ wakes only upon package events  │
├─────────────────────────┼────────────────────────────┼─────────────────────────────────┤
│ Scheduled Storage Scan  │ WorkManager PeriodicWork   │ Constraints: Requires Charging, │
│                         │                            │ Battery Not Low, Device Idle    │
├─────────────────────────┼────────────────────────────┼─────────────────────────────────┤
│ Threat Intelligence OTA │ WorkManager OneTimeWork    │ Constraints: Requires Unmetered │
│ Updates                 │                            │ Network, Battery Not Low        │
├─────────────────────────┼────────────────────────────┼─────────────────────────────────┤
│ Memory Pressure Trim    │ ComponentCallbacks2        │ Evicts CleanFileCache, drops    │
│                         │ onTrimMemory(TRIM_LEVEL)   │ Bloom filters from RAM          │
└─────────────────────────┴────────────────────────────┴─────────────────────────────────┘
```

---

## 12. Android Permission Strategy (Least-Privilege Audit)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     PERMISSION AUDIT & VERDICT                                         │
├────────────────────────────────┬──────────┬──────────────┬─────────────────────────────────────────────┤
│ PERMISSION NAME                │ STATUS   │ API LEVEL    │ JUSTIFICATION / ALTERNATIVE                 │
├────────────────────────────────┼──────────┼──────────────┼─────────────────────────────────────────────┤
│ POST_NOTIFICATIONS             │ ACCEPTED │ 33+          │ MANDATORY. Instant threat warnings.         │
│ VIBRATE                        │ ACCEPTED │ All          │ MANDATORY. Haptic friction feedback.       │
│ CAMERA                         │ ACCEPTED │ All          │ OPTIONAL (User opt-in for QR scanning).     │
│ BIND_VPN_SERVICE               │ ACCEPTED │ All          │ MANDATORY for local loopback DNS shield.    │
│ RECEIVE_BOOT_COMPLETED         │ ACCEPTED │ All          │ MANDATORY to re-enable shields on boot.     │
│ FOREGROUND_SERVICE             │ ACCEPTED │ 28+          │ MANDATORY for persistent DNS shield.        │
│ FOREGROUND_SERVICE_SPECIAL_USE │ ACCEPTED │ 34+          │ Required for Android 14 FGS enforcement.    │
│ QUERY_ALL_PACKAGES             │ SCRUTINY │ 30+          │ HIGH RISK. Required to inspect all packages.│
│                                │          │              │ ALTERNATIVE: Targeted <queries> if allowed. │
│ READ_EXTERNAL_STORAGE          │ ACCEPTED │ 26–32        │ Legitimate for file scanning on legacy OS.  │
│ READ_MEDIA_*                   │ ACCEPTED │ 33+          │ Legitimate for media scanning on modern OS. │
│ MANAGE_EXTERNAL_STORAGE        │ REJECTED │ 30+          │ FORBIDDEN. High Google Play rejection risk. │
│                                │          │              │ ALTERNATIVE: SAF ACTION_OPEN_DOCUMENT_TREE. │
│ BIND_ACCESSIBILITY_SERVICE     │ REJECTED │ All          │ FORBIDDEN. Abusive, insecure, battery drain.│
│ SYSTEM_ALERT_WINDOW            │ REJECTED │ All          │ FORBIDDEN. Creates tapjacking vulnerabilities│
│ DEVICE_ADMIN / DEVICE_OWNER    │ REJECTED │ All          │ FORBIDDEN for consumer release.             │
│ READ_SMS / READ_CALL_LOG       │ REJECTED │ All          │ FORBIDDEN. Violates privacy doctrine.       │
│ ACCESS_FINE_LOCATION           │ REJECTED │ All          │ FORBIDDEN. Unrelated to cybersecurity.      │
│ RECORD_AUDIO                   │ REJECTED │ All          │ FORBIDDEN. Zero voice features.             │
└────────────────────────────────┴──────────┴──────────────┴─────────────────────────────────────────────┘
```

---

## 13. Mobile Security Threat Model (STRIDE)

- **Malicious Sideloaded APK:** `ACTION_PACKAGE_ADDED` receiver inspects `base.apk` certs and permissions; alerts user with 1-tap uninstall intent.
- **Phishing Redirects:** Local `VpnService` intercepts DNS query; matches domain against local Bloom filter; drops connection.
- **Malicious Downloaded File:** `ContentObserver` detects new download; `CoreFileAnalyzer` detects double extension and magic bytes; alerts user.
- **Archive Bomb / ZIP Bomb:** `ArchiveAnalyzer` parses central directory first; enforces max 100:1 ratio, max 250 MB uncompressed limit.
- **Malformed Parser Exploit:** Zero-allocation DataView reads with explicit bounds checks; fail-closed `WARN`.
- **Path Traversal in Archive:** `ArchiveAnalyzer` sanitizes all relative paths; flags any entry containing `..` or leading `/`.
- **Threat DB Tampering & Rollbacks:** Ed25519 signature verified on every load; monotonic anti-rollback sequence counter.
- **ANR & Battery Drain:** All scanning runs on background worker threads; debounced by 500 ms with rate limits.
- **Tier-1 PII Leakage:** ProGuard/R8 strips all `Log.*` calls; volatile RAM zeroing; zero disk logging of Tier-1 data.

---

## 14. Performance Model & Empirical Mobile Budgets

- **CleanFileCache Hit:** $< 0.10\text{ ms}$ (O(1) in-memory lookup).
- **URL / Lexical Scan:** $< 1.0\text{ ms}$ (Pure deterministic string heuristics).
- **64 KB Header Triage:** $< 2.0\text{ ms}$ (Magic bytes + Shannon entropy calculation).
- **APK / DEX Central Parse:** $< 50.0\text{ ms}$ (Central directory table parsing).
- **Post-Install Audit SLA:** $< 250.0\text{ ms}$ (Completes before launcher navigation).
- **Idle Background CPU:** $< 0.2\%$ (Pure event-driven architecture).
- **Background Service RAM:** $< 25\text{ MB}$ RSS.
- **Peak Scan Heap Delta:** $< 16\text{ MB}$ (Bounded 64 KB streaming buffers).

---

## 15. Shared Core Reuse Matrix

- **Class A (Directly Reusable):** `EngineVerdict`, `Verdict`, `RiskScorer`, `RuleEngine`, `URLAnalyzer`, `TextAnalyzer`, `ArchiveAnalyzer`, `DocumentAnalyzer`, `BloomFilter`, `CleanFileCache`.
- **Class B (Reusable with Platform Adapter):** `UpdateVerifier` (Ed25519), `AuditLogger` (HMAC-SHA256).
- **Class C (Must Be Reimplemented for Android):** `QuarantineService` (uses app-private storage + MediaStore delete request), `RealtimeMonitorService` (ContentObserver), `ScanSchedulerService` (WorkManager), `NotificationService` (NotificationCompat).
- **Class D (Must Not Be Shared):** `ProcessMonitor` / `BehaviorEngine` (Windows ETW/WMI impossible on Android), `RansomwareShield` / `ShadowVault` (Windows Canary Oplocks do not map to Android Scoped Storage).

---

## 16. Comprehensive Test Architecture

- **11-Tier Test Pyramid:** Shared Core Unit $\rightarrow$ Android Native Unit $\rightarrow$ Integration $\rightarrow$ Offline Parity $\rightarrow$ Privacy Isolation $\rightarrow$ Adversarial / Fuzz $\rightarrow$ Performance Benchmark $\rightarrow$ Battery / Doze $\rightarrow$ Thermal / Low-RAM $\rightarrow$ Instrumentation $\rightarrow$ Physical Device Soak.
- **Physical Device Mandatory:** Real StrongBox Keystore sealing, Doze mode wakeups, thermal throttling, and camera frame latency cannot be trusted on emulator.

---

## 17. Physical Device Validation Matrix

- **Tier 1 (Flagship / Reference):** Google Pixel 8 / 9 (Android 14 / 15, Tensor G3/G4).
- **Tier 2 (High-End OEM):** Samsung Galaxy S23 / S24 (Android 14, OneUI 6, Snapdragon 8 Gen 2/3).
- **Tier 3 (Mid-Range OEM):** Xiaomi Redmi Note 13 (Android 13, HyperOS, MediaTek).
- **Tier 4 (Low-End / Budget):** Motorola Moto G Play (Android 12 / 13, 3–4 GB RAM, Snapdragon 680).
- **Tier 5 (Legacy MinSdk):** Samsung Galaxy S9 / Pixel 2 (Android 8.0 Oreo, API 26).

---

## 18. Phase T Dependency Graph & Implementation Order

```
STAGE 1: FOUNDATION & NATIVE IPC (T1 -> T11)
STAGE 2: THREAT INTELLIGENCE & CACHING (T9 -> T15)
STAGE 3: PARSER & UTILITY LAYER (T3 -> T8)
STAGE 4: DETECTION SHIELDS (T2 -> T5 -> T6)
STAGE 5: USER EXPERIENCE & RESPONSE (T7 -> T10 -> T13)
STAGE 6: RESILIENCE & VERIFICATION (T12 -> T4 -> T14 -> T16)
```

---

## 19. Risk Register

- **R-01 (CRITICAL):** Google Play policy scrutiny on `QUERY_ALL_PACKAGES`. Mitigation: Document core antivirus justification video; maintain targeted `<queries>` build for F-Droid/APK distribution.
- **R-02 (CRITICAL):** OS kills background `VpnService` under extreme memory pressure. Mitigation: Bind to High-Priority Foreground Service with watchdog restart.
- **R-03 (HIGH):** User confusion over manual uninstall confirmation dialogs. Mitigation: In-app educational guidance on Android OS security model.
- **R-04 (HIGH):** OEM battery killers (Samsung OneUI, MIUI) terminating background observers. Mitigation: Guided in-app battery optimization exclusion settings.
- **R-05 (MEDIUM):** Out-of-Memory on low-end 2GB RAM phones during large archive scans. Mitigation: Strict 16 MB allocation ceiling and low-RAM single-thread throttling.

---

## 20. Open Questions for Architecture Alignment

1. **Distribution Target Policy:** Google Play Store vs. Unrestricted F-Droid / Direct APK release.
2. **VPN Coexistence:** Graceful fallback to passive URL/Extension protection when user activates an external third-party VPN.
3. **Execution Runtime Migration:** Keep pure detection math in shared `@private-protection/core` via JS/WASM while building OS daemons in native Kotlin.
4. **Quarantine Retention Model:** Immediate invocation of `MediaStore.createDeleteRequest()` upon isolating malicious downloads.

---

## 21. Final Specialist Readiness Verdict

```
═════════════════════════════════════════════════════════════════════════════════════════
                       PHASE T IMPLEMENTATION READINESS VERDICT                         
═════════════════════════════════════════════════════════════════════════════════════════

                         [ GO WITH CONDITIONS ]

═════════════════════════════════════════════════════════════════════════════════════════
```

### Mandatory Conditions:
1. **Architectural Honesty:** Frame app installation protection honestly as **Real-Time Pre-Install File Auditing + Instant Post-Install Remediation**; never claim pre-execution installation blocking.
2. **Zero Abusive Permissions:** Strict prohibition of `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `DEVICE_ADMIN`, and `READ_SMS`.
3. **Zero TLS Interception:** Web Shield must use local DNS filtering (UDP port 53) without TLS MITM or CA installation.
4. **Physical Device Validation Mandatory:** Complete physical testing across the 5-tier device matrix before sign-off.
5. **Preservation of Shared Core Parity:** All core detection rules, scoring, and Bloom filters must directly import `@private-protection/core`.
