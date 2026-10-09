# PHASE T13 — MOBILE NOTIFICATIONS ARCHITECTURE

## 1. System Overview

Phase T13 delivers **Mobile Notifications, Notification Channels, Rate Limiting & Storm Defense** for the Private Protection Android mobile client.

Mobile threat alerting must satisfy several critical engineering and safety invariants:
1. **Never suppress critical security alerts:** Under heavy event bursts or file manipulation attacks, critical security alerts (`CRITICAL_THREAT`) must never be dropped or silently ignored.
2. **Never cause notification fatigue or system UI freezes:** High-frequency events (such as recursive directory scans or synthetic malware storms) must not spam the user's Android notification tray or crash the app with rapid intent dispatches.
3. **Strict Content Sanitization & Privacy:** Notifications appear on the Android lock screen and system tray. Untrusted filenames, URLs, or payload texts must never contain Unicode Right-To-Left Overrides (`U+202E`), control characters, unescaped multi-line text, or leaked credentials.
4. **Stable Channel Taxonomy:** Notifications are assigned to predictable, semantic Android NotificationChannels with user-customizable notification importance.

---

## 2. Notification Category & Channel Architecture

Privex defines seven canonical notification categories mapped to five stable Android `NotificationChannel` instances:

| Category | Description | Channel ID | Importance | Vibration & Priority |
|---|---|---|---|---|
| `CRITICAL_THREAT` | Confirmed malware, high-risk trojans, malicious APK payloads | `threat_alerts_channel` | `IMPORTANCE_HIGH` | High Priority / Warning Haptics |
| `APP_INSTALL_WARNING` | Newly installed application requesting excessive permissions or identified as suspicious | `threat_alerts_channel` | `IMPORTANCE_HIGH` | High Priority |
| `DOWNLOAD_BLOCKED` | Malicious file download intercepted and quarantined in `PPMVAULT1` | `downloads_protection_channel` | `IMPORTANCE_HIGH` | High Priority / Vibration Pattern |
| `PHISHING_WARNING` | Malicious domain, credential harvester, or homograph link detected by Web Shield | `web_shield_alerts` | `IMPORTANCE_HIGH` | High Priority |
| `SCAN_COMPLETE` | Result of a user-initiated or scheduled Full Device or Quick Scan | `scans_and_health_channel` | `IMPORTANCE_DEFAULT` | Default Priority |
| `PROTECTION_DEGRADED` | Permission revoked, background ContentObserver killed, or battery-saver throttled | `scans_and_health_channel` | `IMPORTANCE_DEFAULT` | Default Priority |
| `UPDATE_AVAILABLE` | New verified, Ed25519-signed `.ppdb` threat intelligence sequence available | `threat_updates_channel` | `IMPORTANCE_LOW` | Low Priority (Silent) |

---

## 3. Rate Limiting, Deduplication & Storm Defense

```
                       Inbound Notification Event
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │   Input Content Sanitizer     │
                   │ • Strip U+202E / RTLO chars   │
                   │ • Strip control chars & \r\n  │
                   │ • Max title: 100, body: 250   │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │    Permission & Channel Check │
                   │ • POST_NOTIFICATIONS (API 33+)│
                   │ • areNotificationsEnabled()   │
                   │ • NotificationChannel muted?  │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │  Category Cooldown Dedup      │
                   │  (30s per-target cooldown)    │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
        Is Category == CRITICAL_THREAT?
         ├── YES ────────► BYPASS RATE LIMITER ──► Dispatch Immediately!
         └── NO
              │
              ▼
    Token-Bucket Window Check (Max 3 / 10s)
         ├── Under Limit ────────────────────────► Dispatch Individual Alert
         └── Over Limit (Rate Limited)
              │
              ▼
         Increment Burst Counter
              ├── Burst == 5 ────────────────────► Dispatch Coalesced Summary Alert (ID: 99999)
              └── Burst != 5 ────────────────────► Suppress Alert (SUPPRESSED_RATE_LIMIT)
```

### 3.1 Token-Bucket Rolling Window
- **Limit:** Maximum 3 individual native OS notifications within any 10-second rolling window (`MAX_EVENTS_IN_WINDOW = 3`, `WINDOW_MS = 10000L`).
- **Pruning:** Expired timestamps are removed from volatile memory during each dispatch attempt.

### 3.2 Repetitive Event Coalescing
- When a burst of non-critical events exceeds the token-bucket limit, subsequent events enter a suppressed burst state.
- When the burst counter reaches 5, the dispatcher emits a single **Coalesced Summary Alert** (`ID: 99999`):
  *"Multiple Security Events Detected: N repetitive security events were detected in rapid succession. Protection remains active."*

### 3.3 Critical Threat Priority Invariant
- `CRITICAL_THREAT` notifications are never dropped, never suppressed by the token-bucket window, and never converted into silent batch summaries.
- If a burst of 200 EICAR files is detected within one second, all 200 files are quarantined; exactly 3 individual alerts and 1 summary alert fire without crashing or dropping detection logic.

---

## 4. Security & Privacy Invariants

1. **Lock-Screen Privacy:** Full file paths and raw query arguments are never formatted into lock-screen notifications.
2. **Safe Intent Boundaries:** Notification taps launch `MainActivity` with explicit `PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT`. No dynamic broadcast or arbitrary intent reflection is accepted.
3. **Zero Remote Telemetry:** All notification event counts and rate-limiter metrics are computed and held strictly in local memory.
