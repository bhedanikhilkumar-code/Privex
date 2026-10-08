package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * RealtimeDownloadProtectionService (Phase T5):
 *
 * Core coordinator for real-time mobile download safety:
 * 1. Coordinates MediaStore.Downloads observer and file ingress events.
 * 2. Enforces stabilization & IS_PENDING gating before deep analysis.
 * 3. Deduplicates rapid OEM/filesystem events via DownloadEventDeduplicator.
 * 4. Defends against race conditions (file modification/deletion during analysis).
 * 5. Reuses UniversalFileShieldService (T3) for 100% of detection & quarantine.
 * 6. Dispatches rate-limited native notifications.
 * 7. Truthfully performs catch-up reconciliation on app launch/resume.
 */
public class RealtimeDownloadProtectionService {
    private static final String TAG = "RealtimeDownloadShield";

    private static volatile RealtimeDownloadProtectionService instance;

    private final Context context;
    private final DownloadStabilizer stabilizer;
    private final DownloadEventDeduplicator deduplicator;
    private final DownloadNotificationHelper notificationHelper;
    private final UniversalFileShieldService fileShieldService;
    private final MobileCleanFileCache cleanFileCache;

    private final AtomicBoolean isMonitoringActive = new AtomicBoolean(false);
    private final AtomicLong lastEventTimestamp = new AtomicLong(0L);
    private final AtomicLong lastReconciliationTimestamp = new AtomicLong(0L);
    private final AtomicInteger eventsProcessed = new AtomicInteger(0);
    private final AtomicInteger threatsDetected = new AtomicInteger(0);

    private DownloadContentObserver contentObserver;

    public static synchronized RealtimeDownloadProtectionService getInstance(Context context) {
        if (instance == null) {
            instance = new RealtimeDownloadProtectionService(context);
        }
        return instance;
    }

    public RealtimeDownloadProtectionService(Context context) {
        this.context = (context != null && context.getApplicationContext() != null)
                ? context.getApplicationContext() : context;
        this.stabilizer = new DownloadStabilizer(this.context);
        this.deduplicator = new DownloadEventDeduplicator();
        this.notificationHelper = new DownloadNotificationHelper(this.context);
        this.fileShieldService = new UniversalFileShieldService(this.context);
        this.cleanFileCache = MobileCleanFileCache.getInstance(this.context);
    }

    /**
     * Starts active observation of MediaStore.Downloads.
     */
    public synchronized boolean startMonitoring() {
        if (isMonitoringActive.get()) {
            return true;
        }

        if (context == null) return false;

        try {
            ContentResolver resolver = context.getContentResolver();
            if (resolver == null) return false;

            if (contentObserver == null) {
                contentObserver = new DownloadContentObserver(context, new Handler(Looper.getMainLooper()));
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                resolver.registerContentObserver(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                        true,
                        contentObserver
                );
            } else {
                resolver.registerContentObserver(
                        MediaStore.Files.getContentUri("external"),
                        true,
                        contentObserver
                );
            }

            isMonitoringActive.set(true);
            Log.i(TAG, "Real-time download protection observer registered successfully");

            // Perform initial catch-up reconciliation
            reconcileCatchUp();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to start real-time download observer", e);
            notificationHelper.notify(
                    DownloadNotificationHelper.NotificationCategory.PROTECTION_DEGRADED,
                    "Download Monitor",
                    "Could not register background download observer: " + e.getMessage()
            );
            return false;
        }
    }

    /**
     * Stops active observation.
     */
    public synchronized boolean stopMonitoring() {
        if (!isMonitoringActive.get()) {
            return true;
        }

        if (context != null && contentObserver != null) {
            try {
                ContentResolver resolver = context.getContentResolver();
                if (resolver != null) {
                    resolver.unregisterContentObserver(contentObserver);
                }
            } catch (Exception e) {
                Log.w(TAG, "Error unregistering content observer", e);
            }
        }

        isMonitoringActive.set(false);
        Log.i(TAG, "Real-time download protection observer stopped");
        return true;
    }

    /**
     * Processes an incoming download URI through the stabilization, deduplication,
     * and inspection pipeline.
     */
    public JSONObject handleIncomingDownloadUri(Uri uri, String declaredName) {
        lastEventTimestamp.set(System.currentTimeMillis());
        eventsProcessed.incrementAndGet();

        JSONObject result = new JSONObject();
        try {
            if (uri == null) {
                result.put("status", "INACCESSIBLE");
                result.put("error", "NULL_URI");
                return result;
            }

            String uriStr = uri.toString();
            result.put("uri", uriStr);

            // 1. Stabilization check (IS_PENDING, partial extensions, 0-byte writes)
            DownloadStabilizer.StabilizationResult stab = stabilizer.checkUriStabilization(uri);
            result.put("stabilization", stab.toJSON());

            if (!stab.isReady()) {
                result.put("status", stab.state.name());
                result.put("reason", stab.reason);
                // Do NOT mark as SAFE; file is pending or incomplete
                return result;
            }

            // 2. Pre-scan metadata & Deduplication check
            long preSize = stab.size;
            long preMtime = stab.dateModified;

            DownloadEventDeduplicator.DedupDecision dedup = deduplicator.evaluateEvent(uriStr, preSize, preMtime, null);
            if (dedup == DownloadEventDeduplicator.DedupDecision.DUPLICATE) {
                DownloadEventDeduplicator.CachedEventEntry cached = deduplicator.get(uriStr);
                result.put("status", "SUPPRESSED_DUPLICATE");
                result.put("verdict", cached != null ? cached.lastVerdict : "ALLOW");
                result.put("cached", true);
                return result;
            }

            // 3. Clean File Cache check (Sub-millisecond fast-path)
            if (cleanFileCache.isClean(uriStr, preSize, preMtime)) {
                result.put("status", "CLEAN_CACHE_HIT");
                result.put("verdict", "ALLOW");
                result.put("score", 0);
                result.put("cached", true);
                deduplicator.recordResult(uriStr, preSize, preMtime, "", "ALLOW");
                return result;
            }

            // 4. Delegate to UniversalFileShieldService (T3 detection authority)
            JSONObject inspection = fileShieldService.inspectUri(uri, declaredName);
            if (inspection == null) {
                result.put("status", "FAILED");
                result.put("error", "INSPECTION_RETURNED_NULL");
                return result;
            }

            // 5. Race Condition Check: verify file did not change during analysis
            DownloadStabilizer.StabilizationResult postStab = stabilizer.checkUriStabilization(uri);
            if (postStab.state == DownloadStabilizer.StabilizationState.READY_TO_SCAN
                    && (postStab.size != preSize || postStab.dateModified != preMtime)) {
                Log.w(TAG, "File content changed during scanning: " + uri + ". Invalidating result and re-evaluating.");
                deduplicator.invalidate(uriStr);
                cleanFileCache.invalidate(uriStr, preSize, preMtime);
                // Rescan immediately on current content
                return handleIncomingDownloadUri(uri, declaredName);
            }

            String verdict = inspection.optString("verdict", "ALLOW");
            String severity = inspection.optString("severity", "NONE");
            int score = inspection.optInt("score", 0);
            String sha256 = inspection.optString("sha256", "");
            String fileName = inspection.optString("fileName", declaredName != null ? declaredName : "Download");

            result.put("status", "COMPLETED");
            result.put("verdict", verdict);
            result.put("severity", severity);
            result.put("score", score);
            result.put("inspection", inspection);

            // 6. Threat response & Notification dispatch
            if ("DANGEROUS".equals(verdict) || "CRITICAL".equals(severity) || score >= 85) {
                threatsDetected.incrementAndGet();
                deduplicator.recordResult(uriStr, preSize, preMtime, sha256, verdict);

                // Dispatch notification
                notificationHelper.notify(
                        DownloadNotificationHelper.NotificationCategory.MALWARE_DETECTED,
                        fileName,
                        "High-risk threat identified (" + verdict + ")"
                );
            } else if ("SUSPICIOUS".equals(verdict) || "HIGH".equals(severity) || score >= 50) {
                threatsDetected.incrementAndGet();
                deduplicator.recordResult(uriStr, preSize, preMtime, sha256, verdict);

                notificationHelper.notify(
                        DownloadNotificationHelper.NotificationCategory.DOWNLOAD_WARNING,
                        fileName,
                        "Potential scam, dropper, or suspicious payload"
                );
            } else {
                // Clean file: update deduplicator and clean cache
                deduplicator.recordResult(uriStr, preSize, preMtime, sha256, "ALLOW");
                cleanFileCache.putClean(uriStr, preSize, preMtime, sha256);
            }

            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error handling incoming download URI " + uri, e);
            try {
                result.put("status", "FAILED");
                result.put("error", e.getMessage());
            } catch (JSONException ignored) {}
            return result;
        }
    }

    /**
     * Processes an incoming direct File.
     */
    public JSONObject handleIncomingFile(File file) {
        lastEventTimestamp.set(System.currentTimeMillis());
        eventsProcessed.incrementAndGet();

        JSONObject result = new JSONObject();
        try {
            if (file == null || !file.exists()) {
                result.put("status", "INACCESSIBLE");
                result.put("error", "FILE_NOT_FOUND");
                return result;
            }

            String path = file.getAbsolutePath();
            result.put("path", path);

            // 1. Stabilization
            DownloadStabilizer.StabilizationResult stab = stabilizer.checkFileStabilization(file);
            result.put("stabilization", stab.toJSON());

            if (!stab.isReady()) {
                result.put("status", stab.state.name());
                result.put("reason", stab.reason);
                return result;
            }

            long preSize = file.length();
            long preMtime = file.lastModified();

            // 2. Deduplication
            DownloadEventDeduplicator.DedupDecision dedup = deduplicator.evaluateEvent(path, preSize, preMtime, null);
            if (dedup == DownloadEventDeduplicator.DedupDecision.DUPLICATE) {
                DownloadEventDeduplicator.CachedEventEntry cached = deduplicator.get(path);
                result.put("status", "SUPPRESSED_DUPLICATE");
                result.put("verdict", cached != null ? cached.lastVerdict : "ALLOW");
                result.put("cached", true);
                return result;
            }

            // 3. Clean Cache Fast-Path
            if (cleanFileCache.isClean(path, preSize, preMtime)) {
                result.put("status", "CLEAN_CACHE_HIT");
                result.put("verdict", "ALLOW");
                result.put("score", 0);
                result.put("cached", true);
                deduplicator.recordResult(path, preSize, preMtime, "", "ALLOW");
                return result;
            }

            // 4. Delegate to UniversalFileShieldService
            JSONObject inspection = fileShieldService.inspectFile(file);
            if (inspection == null) {
                result.put("status", "FAILED");
                result.put("error", "INSPECTION_FAILED");
                return result;
            }

            // 5. Race Condition Check
            if (file.exists() && (file.length() != preSize || file.lastModified() != preMtime)) {
                Log.w(TAG, "Direct file modified during analysis: " + path + ". Retrying.");
                deduplicator.invalidate(path);
                cleanFileCache.invalidate(path, preSize, preMtime);
                return handleIncomingFile(file);
            }

            String verdict = inspection.optString("verdict", "ALLOW");
            String severity = inspection.optString("severity", "NONE");
            int score = inspection.optInt("score", 0);
            String sha256 = inspection.optString("sha256", "");
            String fileName = file.getName();

            result.put("status", "COMPLETED");
            result.put("verdict", verdict);
            result.put("severity", severity);
            result.put("score", score);
            result.put("inspection", inspection);

            // 6. Threat Response
            if ("DANGEROUS".equals(verdict) || "CRITICAL".equals(severity) || score >= 85) {
                threatsDetected.incrementAndGet();
                deduplicator.recordResult(path, preSize, preMtime, sha256, verdict);

                // Attempt quarantine
                JSONObject qResult = fileShieldService.quarantineFile(file);
                boolean quarantined = qResult != null && "QUARANTINED".equals(qResult.optString("status"));
                result.put("quarantine", qResult);

                if (quarantined) {
                    notificationHelper.notify(
                            DownloadNotificationHelper.NotificationCategory.DOWNLOAD_QUARANTINED,
                            fileName,
                            "Isolated in vault: " + qResult.optString("quarantinePath", "")
                    );
                } else {
                    notificationHelper.notify(
                            DownloadNotificationHelper.NotificationCategory.MALWARE_DETECTED,
                            fileName,
                            "Dangerous malware detected"
                    );
                }
            } else if ("SUSPICIOUS".equals(verdict) || "HIGH".equals(severity) || score >= 50) {
                threatsDetected.incrementAndGet();
                deduplicator.recordResult(path, preSize, preMtime, sha256, verdict);

                notificationHelper.notify(
                        DownloadNotificationHelper.NotificationCategory.DOWNLOAD_WARNING,
                        fileName,
                        "Suspicious download detected"
                );
            } else {
                deduplicator.recordResult(path, preSize, preMtime, sha256, "ALLOW");
                cleanFileCache.putClean(path, preSize, preMtime, sha256);
            }

            return result;
        } catch (Exception e) {
            Log.e(TAG, "Error handling incoming direct file " + file, e);
            try {
                result.put("status", "FAILED");
                result.put("error", e.getMessage());
            } catch (JSONException ignored) {}
            return result;
        }
    }

    /**
     * Performs catch-up reconciliation:
     * Diffs recently modified items in MediaStore.Downloads against deduplicator and cache.
     */
    public JSONObject reconcileCatchUp() {
        JSONObject report = new JSONObject();
        int discovered = 0;
        int rescanned = 0;
        int skipped = 0;
        int threatsFound = 0;

        long startTime = System.currentTimeMillis();
        try {
            if (context == null) {
                report.put("error", "CONTEXT_NULL");
                return report;
            }

            ContentResolver resolver = context.getContentResolver();
            if (resolver == null) {
                report.put("error", "RESOLVER_NULL");
                return report;
            }

            Uri downloadsUri = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                    ? MediaStore.Downloads.EXTERNAL_CONTENT_URI
                    : MediaStore.Files.getContentUri("external");

            // Look back over the last 48 hours or since last reconciliation
            long lookbackSeconds = (System.currentTimeMillis() - 48 * 3600 * 1000L) / 1000L;
            if (lastReconciliationTimestamp.get() > 0) {
                lookbackSeconds = Math.max(lookbackSeconds, lastReconciliationTimestamp.get() / 1000L);
            }

            String selection = MediaStore.MediaColumns.DATE_MODIFIED + " > ?";
            String[] selectionArgs = new String[]{String.valueOf(lookbackSeconds)};
            String[] projection = new String[]{
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.DATE_MODIFIED
            };

            Cursor cursor = null;
            try {
                cursor = resolver.query(downloadsUri, projection, selection, selectionArgs,
                        MediaStore.MediaColumns.DATE_MODIFIED + " DESC");

                if (cursor != null) {
                    int idCol = cursor.getColumnIndex(MediaStore.MediaColumns._ID);
                    int nameCol = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME);
                    int sizeCol = cursor.getColumnIndex(MediaStore.MediaColumns.SIZE);
                    int modCol = cursor.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED);

                    int count = 0;
                    // Cap reconciliation batch at 100 items to avoid battery/ANR spikes
                    while (cursor.moveToNext() && count < 100) {
                        count++;
                        discovered++;

                        long id = idCol != -1 ? cursor.getLong(idCol) : -1;
                        String name = nameCol != -1 ? cursor.getString(nameCol) : "download";
                        long size = sizeCol != -1 ? cursor.getLong(sizeCol) : 0;
                        long mod = modCol != -1 ? cursor.getLong(modCol) : 0;

                        Uri itemUri = Uri.withAppendedPath(downloadsUri, String.valueOf(id));
                        String key = itemUri.toString();

                        // Check deduplication
                        DownloadEventDeduplicator.DedupDecision dedup = deduplicator.evaluateEvent(key, size, mod, null);
                        if (dedup == DownloadEventDeduplicator.DedupDecision.DUPLICATE) {
                            skipped++;
                            continue;
                        }

                        // Inspect newly discovered or modified download
                        JSONObject scanRes = handleIncomingDownloadUri(itemUri, name);
                        rescanned++;
                        if ("DANGEROUS".equals(scanRes.optString("verdict")) || "SUSPICIOUS".equals(scanRes.optString("verdict"))) {
                            threatsFound++;
                        }
                    }
                }
            } finally {
                if (cursor != null) {
                    try {
                        cursor.close();
                    } catch (Exception ignored) {}
                }
            }

            lastReconciliationTimestamp.set(System.currentTimeMillis());

            report.put("discovered", discovered);
            report.put("rescanned", rescanned);
            report.put("skipped", skipped);
            report.put("threatsFound", threatsFound);
            report.put("durationMs", System.currentTimeMillis() - startTime);
            report.put("timestamp", lastReconciliationTimestamp.get());
        } catch (Exception e) {
            Log.e(TAG, "Error during catch-up reconciliation", e);
            try {
                report.put("error", e.getMessage());
            } catch (JSONException ignored) {}
        }
        return report;
    }

    /**
     * Returns comprehensive, truthful runtime status.
     */
    public JSONObject getProtectionStatus() {
        JSONObject status = new JSONObject();
        try {
            status.put("isMonitoringActive", isMonitoringActive.get());
            status.put("lastEventTimestamp", lastEventTimestamp.get());
            status.put("lastReconciliationTimestamp", lastReconciliationTimestamp.get());
            status.put("eventsProcessed", eventsProcessed.get());
            status.put("threatsDetected", threatsDetected.get());
            status.put("deduplicatorStats", deduplicator.toStatsJSON());
            status.put("cleanCacheCount", cleanFileCache.size());

            // Truthful Android platform capability disclosure
            status.put("isPreOpenInterceptionSupported", false);
            status.put("platformLimitationNotice",
                    "Private Protection scans supported downloads as soon as Android makes the file available for inspection. System-wide pre-open interception is not supported by Android for third-party applications.");
        } catch (JSONException ignored) {}
        return status;
    }

    // Accessible getters for unit testing
    public DownloadStabilizer getStabilizer() {
        return stabilizer;
    }

    public DownloadEventDeduplicator getDeduplicator() {
        return deduplicator;
    }

    public DownloadNotificationHelper getNotificationHelper() {
        return notificationHelper;
    }
}
