# Mobile Permission Justification & Privacy Audit (Phase 6)

> **SYSTEM STATUS: PERMISSION MINIMIZATION VERIFIED**  
> **Audited Component:** `apps/mobile/` (Android Manifest & Runtime Permissions)  
> **Target Standard:** Android CDD / Google Play User Data Policy / AGENTS.md Constitution  
> **Status:** **APPROVED — STRICT LEAST PRIVILEGE**

---

## 1. Permission Minimization Principle

PRIVATE PROTECTION operates under a strict data minimization doctrine. The mobile client asks for **zero** permissions to launch, and prompts for platform permissions strictly just-in-time when a user explicitly initiates an action that requires them.

---

## 2. Manifest Permission Matrix

| Permission | Protection Level | Purpose | Data Accessed | User-Facing Explanation | Mandatory / Optional |
|---|---|---|---|---|---|
| `android.permission.POST_NOTIFICATIONS` | `dangerous` (Runtime prompt on Android 13+) | Deliver instant heads-up warning banners when a scanned link or message is flagged as critical/dangerous. | None. Displays local notifications. | "Private Protection uses notifications to warn you when a scanned link or message poses an immediate danger." | **Optional (User Opt-in)** |
| `android.permission.VIBRATE` | `normal` (Install-time) | Provide immediate haptic warning vibration feedback when a dangerous threat or scam is identified. | None. Hardware motor control only. | "Haptic feedback alerts you immediately if a malicious threat is detected." | **Mandatory** |
| `android.permission.INTERNET` | `normal` (Install-time) | Reserved strictly for future differential threat intelligence Bloom filter delta updates (OTA). | None during scans. 0 bytes sent during local scanning. | "Used only for downloading signed offline threat database updates if enabled." | **Normal (Air-gapped during scans)** |

---

## 3. Explicitly Forbidden Permissions (Audited & Disallowed)

The following invasive permissions are **STRICTLY FORBIDDEN** from being declared in `AndroidManifest.xml`:

| Forbidden Permission | Risk / Attack Vector | Architectural Mitigation |
|---|---|---|
| `READ_CONTACTS` / `WRITE_CONTACTS` | Address book harvesting | Users manually paste suspicious message content. Address books are never read. |
| `READ_SMS` / `RECEIVE_SMS` | Inbound SMS credential & OTP theft | Background SMS monitoring is rejected in favor of user-pasted text or the official zero-network `IdentityLookup` extension. |
| `READ_CALL_LOG` / `CALL_PHONE` | Call history profiling | No telephone functionality is required or accessed. |
| `ACCESS_FINE_LOCATION` / `COARSE_LOCATION` | Geolocation tracking | Geographic location is completely irrelevant to lexical/threat intelligence analysis. |
| `READ_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` | Broad storage sniffing | Single-file user inspection uses the Android Storage Access Framework (`ACTION_OPEN_DOCUMENT`) with scoped URI permissions. |
| `RECORD_AUDIO` | Eavesdropping / microphone recording | No voice recording is supported or needed. |
| `BIND_ACCESSIBILITY_SERVICE` | Keylogging and cross-app screen reading | Prohibited. Accessibility services are not abused to inspect third-party app UIs. |

---

## 4. Deep-Link & Intent Security Justification

The mobile application registers a custom URI scheme (`privateprotection://`) to allow users or safe shortcuts to open the scanner.

### Deep Link Invariants:
1. **No Silent State Changes**: Deep links cannot toggle protection settings, modify allowlists, or disable warning gates.
2. **Strict Parameter Validation**: Supported paths are limited strictly to:
   - `privateprotection://scan?url=<encoded_url>`
   - `privateprotection://scan-text?text=<encoded_text>`
3. **Payload Sanitization**: Any deep-link parameter exceeding 2,048 bytes (URL) or 10,000 bytes (text) is dropped immediately to prevent memory attacks.
4. **No Direct Execution**: Deep links only pre-populate the input field in the UI for the user to review before scanning.
