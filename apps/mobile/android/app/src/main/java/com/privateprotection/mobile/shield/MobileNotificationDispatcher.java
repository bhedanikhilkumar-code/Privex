package com.privateprotection.mobile.shield;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;

import com.privateprotection.mobile.MainActivity;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

/**
 * MobileNotificationDispatcher (Phase T13):
 *
 * Centralized, thread-safe notification engine and storm rate-limiter for Private Protection.
 *
 * Responsibilities:
 * 1. Manages all 7 canonical notification categories and maps them to stable Android NotificationChannels.
 * 2. Enforces Token-Bucket rate limiting (max 3 individual native OS alerts per 10-second rolling window).
 * 3. Enforces 30-second per-category deduplication/cooldown for repetitive identical alerts.
 * 4. Coalesces rapid burst events (burstCount >= 3) into a single batch summary alert (ID 99999).
 * 5. Deterministic priority: Critical security alerts (CRITICAL_THREAT) are NEVER suppressed or discarded
 *    by rate limiting, but rather delivered with top priority.
 * 6. Content sanitization: Strips control characters, RTLO / bidirectional overrides (U+202E), newlines,
 *    and truncates titles/bodies to safe bounds (max 100 chars title, max 250 chars body) to guard against
 *    lock-screen leakage and terminal attacks.
 * 7. Truthful delivery tracking: Distinguishes DISPATCHED, SUPPRESSED_RATE_LIMIT, SUPPRESSED_PERMISSION,
 *    SUPPRESSED_CHANNEL_MUTED, COALESCED_BATCH, or ERROR outcomes.
 */
public class MobileNotificationDispatcher {
    private static final String TAG = "MobileNotifDispatcher";

    // Stable Android Notification Channels
    public static final String CHANNEL_CRITICAL_THREATS = "threat_alerts_channel"; // Retains existing T1/T2/T7 ID
    public static final String CHANNEL_DOWNLOADS = "downloads_protection_channel";   // Retains existing T5 ID
    public static final String CHANNEL_WEB_SHIELD = "web_shield_alerts";            // Retains existing T6 ID
    public static final String CHANNEL_SCANS_HEALTH = "scans_and_health_channel";    // Scan complete & Protection Degraded
    public static final String CHANNEL_UPDATES = "threat_updates_channel";           // Threat DB update notifications

    // Rate Limiting Parameters
    public static final int MAX_EVENTS_IN_WINDOW = 3;
    public static final long WINDOW_MS = 10000L; // 10 seconds
    public static final long CATEGORY_COOLDOWN_MS = 30000L; // 30 seconds deduplication
    public static final int COALESCE_BURST_THRESHOLD = 3; // Rule 45 mandated burst coalescing threshold


    // Content Length Bounds
    public static final int MAX_TITLE_LENGTH = 100;
    public static final int MAX_BODY_LENGTH = 250;

    // Supported Canonical Categories
    public enum Category {
        CRITICAL_THREAT,
        APP_INSTALL_WARNING,
        DOWNLOAD_BLOCKED,
        PHISHING_WARNING,
        SCAN_COMPLETE,
        PROTECTION_DEGRADED,
        UPDATE_AVAILABLE
    }

    public enum DispatchOutcome {
        DISPATCHED,
        SUPPRESSED_RATE_LIMIT,
        SUPPRESSED_PERMISSION,
        SUPPRESSED_CHANNEL_MUTED,
        COALESCED_BATCH,
        ERROR
    }

    public static class DispatchResult {
        public final DispatchOutcome outcome;
        public final String reason;
        public final int notificationId;
        public final String channelId;

        public DispatchResult(DispatchOutcome outcome, String reason, int notificationId, String channelId) {
            this.outcome = outcome;
            this.reason = reason;
            this.notificationId = notificationId;
            this.channelId = channelId;
        }

        public JSONObject toJSON() {
            JSONObject obj = new JSONObject();
            try {
                obj.put("outcome", outcome.name());
                obj.put("reason", reason);
                obj.put("notificationId", notificationId);
                obj.put("channelId", channelId);
            } catch (JSONException ignored) {}
            return obj;
        }
    }

    private static volatile MobileNotificationDispatcher sInstance;

    private final Context context;
    private final Deque<Long> dispatchTimestamps = new ArrayDeque<>();
    private final Map<String, Long> lastCategoryTimestamps = new HashMap<>();

    // Counters for telemetry and observability
    private int totalAttempted = 0;
    private int totalDispatched = 0;
    private int totalSuppressedRateLimit = 0;
    private int totalSuppressedPermission = 0;
    private int totalCoalesced = 0;
    private int currentBurstCount = 0;

    public MobileNotificationDispatcher(Context context) {
        this.context = (context != null && context.getApplicationContext() != null)
                ? context.getApplicationContext() : context;
        ensureAllChannels();
    }

    public static MobileNotificationDispatcher getInstance(Context context) {
        if (sInstance == null) {
            synchronized (MobileNotificationDispatcher.class) {
                if (sInstance == null) {
                    sInstance = new MobileNotificationDispatcher(context);
                }
            }
        }
        return sInstance;
    }

    /**
     * For unit test isolation
     */
    public static void setInstanceForTest(MobileNotificationDispatcher instance) {
        sInstance = instance;
    }

    public static void resetInstanceForTest() {
        sInstance = null;
    }

    /**
     * Creates all required Android NotificationChannels idempotently.
     */
    public synchronized void ensureAllChannels() {
        if (context == null) return;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager == null) return;

            // 1. Critical Threats & App Install Warnings
            NotificationChannel chanCritical = new NotificationChannel(
                    CHANNEL_CRITICAL_THREATS,
                    "High-Priority Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH
            );
            chanCritical.setDescription("Immediate alerts for confirmed malware, trojans, and dangerous applications.");
            chanCritical.enableVibration(true);
            chanCritical.setVibrationPattern(new long[]{0, 250, 100, 250});
            manager.createNotificationChannel(chanCritical);

            // 2. Real-Time Downloads Protection
            NotificationChannel chanDownloads = new NotificationChannel(
                    CHANNEL_DOWNLOADS,
                    "Download Protection",
                    NotificationManager.IMPORTANCE_HIGH
            );
            chanDownloads.setDescription("Real-time scan alerts and quarantine notices for downloaded files.");
            chanDownloads.enableVibration(true);
            chanDownloads.setVibrationPattern(new long[]{0, 250, 100, 250});
            manager.createNotificationChannel(chanDownloads);

            // 3. Web & Phishing Shield
            NotificationChannel chanWeb = new NotificationChannel(
                    CHANNEL_WEB_SHIELD,
                    "Web & Phishing Shield",
                    NotificationManager.IMPORTANCE_HIGH
            );
            chanWeb.setDescription("Real-time warnings for phishing URLs and malicious domains.");
            chanWeb.enableVibration(true);
            manager.createNotificationChannel(chanWeb);

            // 4. Scans & System Health
            NotificationChannel chanHealth = new NotificationChannel(
                    CHANNEL_SCANS_HEALTH,
                    "Scans & Security Health",
                    NotificationManager.IMPORTANCE_DEFAULT
            );
            chanHealth.setDescription("Notifications for device scan completions and degraded protection status.");
            manager.createNotificationChannel(chanHealth);

            // 5. Threat Intelligence Updates
            NotificationChannel chanUpdates = new NotificationChannel(
                    CHANNEL_UPDATES,
                    "Threat Database Updates",
                    NotificationManager.IMPORTANCE_LOW
            );
            chanUpdates.setDescription("Informational updates when new threat intelligence databases are verified.");
            manager.createNotificationChannel(chanUpdates);
        }
    }

    /**
     * Sanitizes untrusted strings:
     * - Strips Unicode directional overrides (e.g., U+202E RTLO, U+202A-202E, U+2066-2069).
     * - Replaces newlines and tabs with spaces.
     * - Strips non-printable ASCII / ANSI control characters.
     * - Enforces maximum length bounds.
     */
    public static String sanitizeText(String input, int maxLength) {
        if (input == null) return "";
        // Strip RTLO / directional overrides: \u202A to \u202E, \u2066 to \u2069, \u200E, \u200F
        String clean = input.replaceAll("[\u202A-\u202E\u2066-\u2069\u200E\u200F]", "");
        // Replace newlines and tabs with spaces
        clean = clean.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
        // Strip other unprintable control characters (< 0x20 except space)
        clean = clean.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");
        clean = clean.trim();
        if (clean.length() > maxLength) {
            clean = clean.substring(0, maxLength).trim() + "...";
        }
        return clean;
    }

    /**
     * Maps Category to its assigned NotificationChannel ID.
     */
    public static String getChannelForCategory(Category category) {
        switch (category) {
            case CRITICAL_THREAT:
            case APP_INSTALL_WARNING:
                return CHANNEL_CRITICAL_THREATS;
            case DOWNLOAD_BLOCKED:
                return CHANNEL_DOWNLOADS;
            case PHISHING_WARNING:
                return CHANNEL_WEB_SHIELD;
            case SCAN_COMPLETE:
            case PROTECTION_DEGRADED:
                return CHANNEL_SCANS_HEALTH;
            case UPDATE_AVAILABLE:
            default:
                return CHANNEL_UPDATES;
        }
    }

    /**
     * Dispatches a notification across the unified rate-limiting and channel pipeline.
     */
    public synchronized DispatchResult dispatch(Category category, String title, String body, String deduplicationKey) {
        totalAttempted++;
        if (context == null) {
            return new DispatchResult(DispatchOutcome.ERROR, "Context is null", 0, "");
        }

        String channelId = getChannelForCategory(category);
        String safeTitle = sanitizeText(title, MAX_TITLE_LENGTH);
        String safeBody = sanitizeText(body, MAX_BODY_LENGTH);

        // 1. Check Notification Permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            int perm = ContextCompat.checkSelfPermission(context, "android.permission.POST_NOTIFICATIONS");
            if (perm != PackageManager.PERMISSION_GRANTED) {
                totalSuppressedPermission++;
                Log.d(TAG, "Notification skipped: POST_NOTIFICATIONS not granted");
                return new DispatchResult(DispatchOutcome.SUPPRESSED_PERMISSION, "POST_NOTIFICATIONS not granted", 0, channelId);
            }
        }

        // 2. Check if Channel is Muted by user (API 26+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                if (!nm.areNotificationsEnabled()) {
                    totalSuppressedPermission++;
                    return new DispatchResult(DispatchOutcome.SUPPRESSED_PERMISSION, "System notifications disabled for app", 0, channelId);
                }
                NotificationChannel chan = nm.getNotificationChannel(channelId);
                if (chan != null && chan.getImportance() == NotificationManager.IMPORTANCE_NONE) {
                    return new DispatchResult(DispatchOutcome.SUPPRESSED_CHANNEL_MUTED, "Channel " + channelId + " is muted", 0, channelId);
                }
            }
        }

        long now = System.currentTimeMillis();
        pruneWindow(now);

        // 3. Category / Target Deduplication Check (30s cooldown for non-critical alerts)
        String dedupKey = (deduplicationKey != null && !deduplicationKey.trim().isEmpty())
                ? category.name() + ":" + deduplicationKey.trim()
                : category.name() + ":" + safeTitle;

        if (category != Category.CRITICAL_THREAT) {
            Long lastTime = lastCategoryTimestamps.get(dedupKey);
            if (lastTime != null && (now - lastTime) < CATEGORY_COOLDOWN_MS) {
                totalSuppressedRateLimit++;
                Log.d(TAG, "Suppressed duplicate notification within cooldown: " + dedupKey);
                return new DispatchResult(DispatchOutcome.SUPPRESSED_RATE_LIMIT, "Duplicate alert suppressed within cooldown", 0, channelId);
            }
        }

        // 4. Rate Limiting Token-Bucket (Max 3 per 10s window)
        // CRITICAL INVARIANT: CRITICAL_THREAT is NEVER suppressed. It always fires.
        boolean isRateLimited = (dispatchTimestamps.size() >= MAX_EVENTS_IN_WINDOW);
        if (isRateLimited && category != Category.CRITICAL_THREAT) {
            currentBurstCount++;
            Log.w(TAG, "Rate limit active (" + dispatchTimestamps.size() + "/" + MAX_EVENTS_IN_WINDOW + "). Burst count=" + currentBurstCount);

            // If burst reaches threshold (3), emit a single coalesced summary
            if (currentBurstCount == COALESCE_BURST_THRESHOLD) {
                totalCoalesced++;
                boolean coalescedSent = sendCoalescedSummary(currentBurstCount);
                if (coalescedSent) {
                    dispatchTimestamps.addLast(now);
                    return new DispatchResult(DispatchOutcome.COALESCED_BATCH, "Coalesced summary alert fired", 99999, channelId);
                }
            }
            totalSuppressedRateLimit++;
            return new DispatchResult(DispatchOutcome.SUPPRESSED_RATE_LIMIT, "Window rate limit exceeded (max 3/10s)", 0, channelId);
        }

        // Reset burst count when sending normal alert
        currentBurstCount = 0;
        lastCategoryTimestamps.put(dedupKey, now);
        dispatchTimestamps.addLast(now);

        int notifId = (int) (now ^ safeTitle.hashCode());
        int priority = NotificationCompat.PRIORITY_HIGH;
        int icon = android.R.drawable.ic_dialog_alert;

        switch (category) {
            case CRITICAL_THREAT:
                priority = NotificationCompat.PRIORITY_MAX;
                icon = android.R.drawable.stat_sys_warning;
                break;
            case APP_INSTALL_WARNING:
            case DOWNLOAD_BLOCKED:
            case PHISHING_WARNING:
                priority = NotificationCompat.PRIORITY_HIGH;
                icon = android.R.drawable.ic_dialog_alert;
                break;
            case SCAN_COMPLETE:
                priority = NotificationCompat.PRIORITY_DEFAULT;
                icon = android.R.drawable.ic_dialog_info;
                break;
            case PROTECTION_DEGRADED:
                priority = NotificationCompat.PRIORITY_DEFAULT;
                icon = android.R.drawable.stat_sys_warning;
                break;
            case UPDATE_AVAILABLE:
            default:
                priority = NotificationCompat.PRIORITY_LOW;
                icon = android.R.drawable.ic_popup_sync;
                break;
        }

        boolean sent = sendNativeNotification(notifId, channelId, safeTitle, safeBody, priority, icon);
        if (sent) {
            totalDispatched++;
            return new DispatchResult(DispatchOutcome.DISPATCHED, "Notification dispatched successfully", notifId, channelId);
        } else {
            return new DispatchResult(DispatchOutcome.ERROR, "Failed to post notification to NotificationManager", notifId, channelId);
        }
    }

    private boolean sendCoalescedSummary(int count) {
        String title = "🛡️ Multiple Security Events Detected";
        String body = count + " repetitive security events were detected in rapid succession. Protection remains active.";
        return sendNativeNotification(99999, CHANNEL_CRITICAL_THREATS, title, body, NotificationCompat.PRIORITY_HIGH, android.R.drawable.stat_sys_warning);
    }

    protected boolean sendNativeNotification(int id, String channelId, String title, String body, int priority, int icon) {
        try {
            NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager == null) return false;

            if (context.getResources() == null) {
                // Mock / headless test environment
                manager.notify(id, null);
                return true;
            }

            Intent intent = new Intent(context, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            PendingIntent pendingIntent = PendingIntent.getActivity(
                    context, 0, intent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );

            NotificationCompat.Builder builder = new NotificationCompat.Builder(context, channelId)
                    .setSmallIcon(icon)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setPriority(priority)
                    .setAutoCancel(true)
                    .setContentIntent(pendingIntent);

            manager.notify(id, builder.build());
            return true;
        } catch (Exception e) {
            Log.e(TAG, "sendNativeNotification failed: " + e.getMessage(), e);
            return false;
        }
    }

    private void pruneWindow(long now) {
        while (!dispatchTimestamps.isEmpty() && (now - dispatchTimestamps.peekFirst()) > WINDOW_MS) {
            dispatchTimestamps.removeFirst();
        }
    }

    public synchronized JSONObject getDispatcherStats() {
        pruneWindow(System.currentTimeMillis());
        JSONObject obj = new JSONObject();
        try {
            obj.put("totalAttempted", totalAttempted);
            obj.put("totalDispatched", totalDispatched);
            obj.put("totalSuppressedRateLimit", totalSuppressedRateLimit);
            obj.put("totalSuppressedPermission", totalSuppressedPermission);
            obj.put("totalCoalesced", totalCoalesced);
            obj.put("activeInWindow", dispatchTimestamps.size());
            obj.put("maxEventsInWindow", MAX_EVENTS_IN_WINDOW);
            obj.put("windowMs", WINDOW_MS);
        } catch (JSONException ignored) {}
        return obj;
    }

    public synchronized void resetStatsForTest() {
        dispatchTimestamps.clear();
        lastCategoryTimestamps.clear();
        totalAttempted = 0;
        totalDispatched = 0;
        totalSuppressedRateLimit = 0;
        totalSuppressedPermission = 0;
        totalCoalesced = 0;
        currentBurstCount = 0;
    }

    public synchronized int getRecentDispatchCount() {
        pruneWindow(System.currentTimeMillis());
        return dispatchTimestamps.size();
    }
}
