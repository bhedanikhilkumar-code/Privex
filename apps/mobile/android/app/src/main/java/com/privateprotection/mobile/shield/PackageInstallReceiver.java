package com.privateprotection.mobile.shield;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import org.json.JSONObject;

import com.privateprotection.mobile.MainActivity;
import com.privateprotection.mobile.core.JobType;
import com.privateprotection.mobile.core.MobileSecurityCoordinator;
import com.privateprotection.mobile.core.SecurityJob;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PackageInstallReceiver (Phase T2):
 * Listens for package installation and update lifecycle broadcasts (ACTION_PACKAGE_ADDED, ACTION_PACKAGE_REPLACED).
 *
 * Truthful Android Behavior:
 * - This broadcast fires immediately AFTER package installation completes.
 * - Standard 3rd-party Android apps CANNOT intercept or block installation beforehand.
 * - Executes bounded, asynchronous audit via MobileSecurityCoordinator.
 * - De-duplicates redundant broadcast triggers within a debounce window.
 * - Dispatches high-priority notifications with direct ACTION_DELETE uninstall friction remediation.
 */
public class PackageInstallReceiver extends BroadcastReceiver {
    private static final String TAG = "PackageInstallReceiver";

    // Debounce map to prevent duplicate rapid audits for the same package
    private static final Map<String, Long> lastAuditedTimestamps = new ConcurrentHashMap<>();
    private static final long DEBOUNCE_WINDOW_MS = 5000L; // 5 seconds

    @Override
    public void onReceive(Context context, Intent intent) {
        if (context == null || intent == null) return;

        String action = intent.getAction();
        if (action == null) return;

        if (!Intent.ACTION_PACKAGE_ADDED.equals(action) &&
            !Intent.ACTION_PACKAGE_REPLACED.equals(action) &&
            !Intent.ACTION_PACKAGE_REMOVED.equals(action)) {
            return;
        }

        Uri data = intent.getData();
        if (data == null) return;

        String packageName = data.getSchemeSpecificPart();
        if (packageName == null || packageName.trim().isEmpty()) {
            return;
        }

        // Ignore our own package
        if (context.getPackageName().equals(packageName)) {
            return;
        }

        // Handle package removal: purge debounce entry and cancel any active/queued audits
        if (Intent.ACTION_PACKAGE_REMOVED.equals(action)) {
            boolean isReplacingRemove = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
            if (!isReplacingRemove) {
                lastAuditedTimestamps.remove(packageName);
                Log.i(TAG, "Package uninstalled/removed: " + packageName + ", cleared audit cache.");
                // Dismiss any outstanding threat notification for this uninstalled app
                try {
                    NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
                    if (nm != null) {
                        nm.cancel(packageName.hashCode());
                    }
                } catch (Exception ignored) {}
            }
            return;
        }

        // Check if this is an app update rather than new install
        boolean isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
        if (Intent.ACTION_PACKAGE_ADDED.equals(action) && isReplacing) {
            // An update is in progress; wait for ACTION_PACKAGE_REPLACED to avoid double-scanning
            return;
        }

        long now = System.currentTimeMillis();
        Long lastAudit = lastAuditedTimestamps.get(packageName);
        if (lastAudit != null && (now - lastAudit) < DEBOUNCE_WINDOW_MS) {
            Log.d(TAG, "Debounced duplicate install event for " + packageName);
            return;
        }
        lastAuditedTimestamps.put(packageName, now);

        Log.i(TAG, "Detected package installation event: " + action + " for " + packageName);

        // Submit PACKAGE_AUDIT job asynchronously through MobileSecurityCoordinator
        try {
            MobileSecurityCoordinator coordinator = MobileSecurityCoordinator.getInstance(context);
            JSONObject metadata = new JSONObject();
            metadata.put("packageName", packageName);
            metadata.put("eventAction", action);
            metadata.put("timestamp", now);

            coordinator.submitJob(JobType.PACKAGE_AUDIT, metadata, (job, ctrl) -> {
                ctrl.updateProgress(0.1f);
                PackageAuditService auditService = new PackageAuditService(context);
                ctrl.checkCancellation();

                ctrl.updateProgress(0.5f);
                JSONObject report = auditService.auditInstalledPackage(packageName);
                ctrl.updateProgress(0.9f);

                // Check verdict for immediate alert dispatch
                String verdict = report.optString("verdict", "ALLOW");
                int score = report.optInt("score", 0);
                String appLabel = report.optString("appLabel", packageName);

                if ("DANGEROUS".equals(verdict) || "SUSPICIOUS".equals(verdict) || score >= 45) {
                    dispatchHighRiskNotification(context, packageName, appLabel, verdict, score);
                }

                ctrl.updateProgress(1.0f);
                return report;
            });
        } catch (Exception e) {
            Log.e(TAG, "Failed to submit PACKAGE_AUDIT job for " + packageName, e);
        }
    }

    /**
     * Dispatches an instant warning notification with an immediate uninstall friction action.
     * Routes through MobileNotificationDispatcher for consolidated rate limiting, channel mapping and storm defense.
     */
    private void dispatchHighRiskNotification(Context context, String packageName, String appLabel, String verdict, int score) {
        try {
            MobileNotificationDispatcher dispatcher = MobileNotificationDispatcher.getInstance(context);
            String title = "⚠️ Dangerous App Detected: " + appLabel;
            String text = "Risk Score: " + score + "/100 (" + verdict + "). Sideloaded or requests excessive permissions.";

            MobileNotificationDispatcher.Category cat = "DANGEROUS".equals(verdict)
                    ? MobileNotificationDispatcher.Category.CRITICAL_THREAT
                    : MobileNotificationDispatcher.Category.APP_INSTALL_WARNING;

            MobileNotificationDispatcher.DispatchResult result = dispatcher.dispatch(cat, title, text, packageName);
            Log.w(TAG, "Notification result for " + packageName + ": " + result.outcome);
        } catch (Exception e) {
            Log.e(TAG, "Failed to dispatch notification for high-risk package " + packageName, e);
        }
    }
}
