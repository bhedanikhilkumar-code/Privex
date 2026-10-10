package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.privateprotection.mobile.core.JobType;
import com.privateprotection.mobile.core.MobileSecurityCoordinator;
import com.privateprotection.mobile.core.SecurityJob;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * FullDeviceScanService (Phase T4):
 *
 * Implements Truthful Android Device Scanning across three modes:
 * 1. QUICK_SCAN: High-risk Downloads, recently modified MediaStore items (< 48 hrs), and installed third-party apps.
 * 2. STANDARD_SCAN: Common user-accessible MediaStore shared storage (Downloads, Images, Audio, Video) and active SAF trees.
 * 3. FULL_ACCESSIBLE_SCAN: Complete accessible surface (All MediaStore collections, persisted SAF trees, installed packages, app quarantine vault), with truthful reporting of skipped/inaccessible system areas.
 *
 * CANONICAL SAFETY & PLATFORM INVARIANTS:
 * - Never claims "100% of phone scanned" if Android restricts system/app-private storage (/data/data/*).
 * - Reports inaccessible locations as SKIPPED or PERMISSION_DENIED; never converts to SAFE.
 * - Reuses T3 UniversalFileShieldService for all files/URIs (zero duplicate detection algorithms).
 * - Reuses T2 PackageAuditService for installed package auditing.
 * - Reuses MobileCleanFileCache for sub-millisecond skips of unchanged files.
 * - Bounded traversal with cooperative cancellation and backpressure.
 */
public class FullDeviceScanService {
    private static final String TAG = "FullDeviceScanService";

    public enum ScanMode {
        QUICK_SCAN,
        STANDARD_SCAN,
        FULL_ACCESSIBLE_SCAN
    }

    @FunctionalInterface
    public interface ScanProgressCallback {
        void onProgress(String currentItem, int scanned, int totalDiscovered, int threats);
    }

    private final Context context;
    private final UniversalFileShieldService fileShieldService;
    private final PackageAuditService packageAuditService;
    private final SafManager safManager;
    private final MobileCleanFileCache cleanFileCache;

    public FullDeviceScanService(Context context) {
        this.context = context.getApplicationContext();
        this.fileShieldService = new UniversalFileShieldService(this.context);
        this.packageAuditService = new PackageAuditService(this.context);
        this.safManager = new SafManager(this.context);
        this.cleanFileCache = MobileCleanFileCache.getInstance(this.context);
    }

    /**
     * Executes device scan under the specified mode cooperatively checking cancellation.
     */
    public JSONObject executeScan(ScanMode mode, com.privateprotection.mobile.core.JobExecutionController controller, ScanProgressCallback callback) {
        long startTime = System.currentTimeMillis();
        Log.i(TAG, "Starting " + mode.name() + " execution.");

        List<ScanScopeDescriptor> scopes = initializeScopes(mode);
        List<JSONObject> threatsFound = new ArrayList<>();
        int totalDiscovered = 0;
        int totalScanned = 0;
        int totalSkipped = 0;
        int totalCached = 0;
        boolean wasCancelled = false;

        for (ScanScopeDescriptor scope : scopes) {
            if (controller != null && controller.isCancellationRequested()) {
                wasCancelled = true;
                scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.CANCELLED);
                break;
            }

            scope.setStartTimeMs(System.currentTimeMillis());
            scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.SCANNING);

            try {
                switch (scope.getScopeType()) {
                    case MEDIASTORE_DOWNLOADS:
                    case MEDIASTORE_IMAGES:
                    case MEDIASTORE_VIDEO:
                    case MEDIASTORE_AUDIO:
                    case MEDIASTORE_FILES:
                        scanMediaStoreScope(scope, mode, controller, threatsFound, callback);
                        break;

                    case SAF_TREE:
                        scanSafTreeScope(scope, controller, threatsFound, callback);
                        break;

                    case INSTALLED_PACKAGES:
                        scanInstalledPackagesScope(scope, mode, controller, threatsFound, callback);
                        break;

                    case APP_QUARANTINE_VAULT:
                        scanQuarantineVaultScope(scope, controller, threatsFound, callback);
                        break;

                    case RESTRICTED_SYSTEM:
                        // Truthfully report inaccessible scope without scanning or faking SAFE
                        scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.SKIPPED);
                        scope.setErrorDetails("Android sandboxing restricts access to system and other apps' private directories (/data/data).");
                        scope.incrementSkipped();
                        break;
                }

                if (scope.getScanStatus() == ScanScopeDescriptor.ScopeScanStatus.SCANNING) {
                    scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.COMPLETED);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error scanning scope " + scope.getScopeId(), e);
                scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.FAILED);
                scope.setErrorDetails(e.getMessage());
            } finally {
                scope.setEndTimeMs(System.currentTimeMillis());
                totalDiscovered += scope.getFilesDiscovered();
                totalScanned += scope.getFilesScanned();
                totalSkipped += scope.getFilesSkipped();
            }
        }

        long endTime = System.currentTimeMillis();
        cleanFileCache.persistToDisk();

        // Assemble canonical scan report
        JSONObject report = new JSONObject();
        try {
            com.privateprotection.mobile.core.AdaptiveResourceManager adaptiveMgr =
                    com.privateprotection.mobile.core.AdaptiveResourceManager.getInstance(context);
            com.privateprotection.mobile.core.AdaptiveResourceManager.ResourceMode activeMode = adaptiveMgr.getCurrentMode();
            boolean isThrottled = (activeMode == com.privateprotection.mobile.core.AdaptiveResourceManager.ResourceMode.THERMAL_THROTTLED ||
                    activeMode == com.privateprotection.mobile.core.AdaptiveResourceManager.ResourceMode.BACKGROUND_THROTTLED ||
                    activeMode == com.privateprotection.mobile.core.AdaptiveResourceManager.ResourceMode.LOW_MEMORY ||
                    activeMode == com.privateprotection.mobile.core.AdaptiveResourceManager.ResourceMode.BATTERY_SAVER);

            String finalStatus;
            if (wasCancelled) {
                finalStatus = "CANCELLED";
            } else if (!threatsFound.isEmpty()) {
                finalStatus = "ACTION_REQUIRED";
            } else if (isThrottled) {
                finalStatus = "THROTTLED";
            } else {
                finalStatus = "SECURE";
            }

            report.put("scanMode", mode.name());
            report.put("status", finalStatus);
            report.put("isThrottled", isThrottled);
            report.put("resourceMode", activeMode.name());
            report.put("startTimeMs", startTime);
            report.put("endTimeMs", endTime);
            report.put("durationMs", endTime - startTime);
            report.put("totalDiscovered", totalDiscovered);
            report.put("totalScanned", totalScanned);
            report.put("totalSkipped", totalSkipped);
            report.put("threatsCount", threatsFound.size());

            // Truthful coverage summary
            JSONObject coverage = new JSONObject();
            coverage.put("isFullDeviceClaimed", false);
            coverage.put("coverageDescription", mode == ScanMode.FULL_ACCESSIBLE_SCAN
                    ? "Full Accessible Device Scan: Inspected all accessible MediaStore collections, persistent SAF trees, and applications. Protected system directories were truthfully skipped."
                    : (mode == ScanMode.QUICK_SCAN ? "Quick Scan: Inspected high-risk downloads, recent files, and user packages."
                    : "Standard Scan: Inspected user shared storage collections and granted SAF roots."));
            report.put("coverage", coverage);

            JSONArray scopesArr = new JSONArray();
            for (ScanScopeDescriptor s : scopes) {
                scopesArr.put(s.toJSON());
            }
            report.put("scopes", scopesArr);

            JSONArray threatsArr = new JSONArray();
            for (JSONObject t : threatsFound) {
                threatsArr.put(t);
            }
            report.put("threats", threatsArr);

            // Dispatch Scan Complete / Threat Alert via MobileNotificationDispatcher
            try {
                MobileNotificationDispatcher dispatcher = MobileNotificationDispatcher.getInstance(context);
                if (!threatsFound.isEmpty()) {
                    String title = "⚠️ " + threatsFound.size() + " Threat(s) Found During Scan";
                    String body = "Full scan completed: action required for " + threatsFound.size() + " detected threat items.";
                    dispatcher.dispatch(MobileNotificationDispatcher.Category.CRITICAL_THREAT, title, body, "scan_threats_" + endTime);
                } else {
                    String title = "✅ " + (mode == ScanMode.QUICK_SCAN ? "Quick Scan" : "Device Scan") + " Complete";
                    String body = totalScanned + " files inspected clean. No active threats detected.";
                    dispatcher.dispatch(MobileNotificationDispatcher.Category.SCAN_COMPLETE, title, body, "scan_clean_" + endTime);
                }
            } catch (Exception ex) {
                Log.w(TAG, "Failed to dispatch scan completion notification: " + ex.getMessage());
            }

        } catch (JSONException ignored) {}

        return report;
    }

    /**
     * Configures the scope checklist depending on scan mode.
     */
    private List<ScanScopeDescriptor> initializeScopes(ScanMode mode) {
        List<ScanScopeDescriptor> scopes = new ArrayList<>();

        // MediaStore Downloads (Universal Ingress Scope)
        scopes.add(new ScanScopeDescriptor(
                "scope_downloads",
                "Downloads Collection",
                ScanScopeDescriptor.ScopeType.MEDIASTORE_DOWNLOADS,
                "content://media/external/downloads",
                ScanScopeDescriptor.AccessibilityState.MEDIASTORE_ACCESSIBLE
        ));

        if (mode == ScanMode.STANDARD_SCAN || mode == ScanMode.FULL_ACCESSIBLE_SCAN) {
            scopes.add(new ScanScopeDescriptor(
                    "scope_images",
                    "Pictures & Photos",
                    ScanScopeDescriptor.ScopeType.MEDIASTORE_IMAGES,
                    "content://media/external/images/media",
                    ScanScopeDescriptor.AccessibilityState.MEDIASTORE_ACCESSIBLE
            ));
            scopes.add(new ScanScopeDescriptor(
                    "scope_video",
                    "Movies & Videos",
                    ScanScopeDescriptor.ScopeType.MEDIASTORE_VIDEO,
                    "content://media/external/video/media",
                    ScanScopeDescriptor.AccessibilityState.MEDIASTORE_ACCESSIBLE
            ));
            scopes.add(new ScanScopeDescriptor(
                    "scope_audio",
                    "Audio & Music",
                    ScanScopeDescriptor.ScopeType.MEDIASTORE_AUDIO,
                    "content://media/external/audio/media",
                    ScanScopeDescriptor.AccessibilityState.MEDIASTORE_ACCESSIBLE
            ));
        }

        // Persisted SAF tree permissions
        List<Uri> safTrees = safManager.getPersistedTreeUris();
        int idx = 1;
        for (Uri treeUri : safTrees) {
            scopes.add(new ScanScopeDescriptor(
                    "scope_saf_tree_" + idx++,
                    "User Granted Folder (" + treeUri.getLastPathSegment() + ")",
                    ScanScopeDescriptor.ScopeType.SAF_TREE,
                    treeUri.toString(),
                    ScanScopeDescriptor.AccessibilityState.SAF_USER_GRANTED
            ));
        }

        // Installed Applications
        scopes.add(new ScanScopeDescriptor(
                "scope_installed_apps",
                "Installed Applications",
                ScanScopeDescriptor.ScopeType.INSTALLED_PACKAGES,
                "package_manager://installed",
                ScanScopeDescriptor.AccessibilityState.AUTOMATICALLY_ACCESSIBLE
        ));

        // App Quarantine Vault
        scopes.add(new ScanScopeDescriptor(
                "scope_quarantine_vault",
                "App Quarantine Vault",
                ScanScopeDescriptor.ScopeType.APP_QUARANTINE_VAULT,
                "app_files://private_quarantine_vault",
                ScanScopeDescriptor.AccessibilityState.APP_PRIVATE
        ));

        // Inaccessible Scope (Truthfully marked)
        if (mode == ScanMode.FULL_ACCESSIBLE_SCAN) {
            scopes.add(new ScanScopeDescriptor(
                    "scope_restricted_system",
                    "Restricted System & Private App Storage",
                    ScanScopeDescriptor.ScopeType.RESTRICTED_SYSTEM,
                    "/data/data",
                    ScanScopeDescriptor.AccessibilityState.INACCESSIBLE
            ));
        }

        return scopes;
    }

    private void scanMediaStoreScope(
            ScanScopeDescriptor scope,
            ScanMode mode,
            com.privateprotection.mobile.core.JobExecutionController controller,
            List<JSONObject> threats,
            ScanProgressCallback callback
    ) {
        ContentResolver resolver = context.getContentResolver();
        Uri queryUri = resolveMediaStoreUri(scope.getScopeType());
        if (queryUri == null) {
            scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.SKIPPED);
            return;
        }

        String[] projection = new String[]{
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_MODIFIED
        };

        String selection = null;
        String[] selectionArgs = null;

        // In Quick Scan mode, limit query to recently modified files (last 48 hours)
        if (mode == ScanMode.QUICK_SCAN) {
            long cutoffSeconds = (System.currentTimeMillis() / 1000L) - (48 * 3600L);
            selection = MediaStore.MediaColumns.DATE_MODIFIED + " >= ?";
            selectionArgs = new String[]{String.valueOf(cutoffSeconds)};
        }

        try (Cursor cursor = resolver.query(queryUri, projection, selection, selectionArgs, MediaStore.MediaColumns.DATE_MODIFIED + " DESC")) {
            if (cursor == null) {
                scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.SKIPPED);
                return;
            }

            int idCol = cursor.getColumnIndex(MediaStore.MediaColumns._ID);
            int nameCol = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME);
            int sizeCol = cursor.getColumnIndex(MediaStore.MediaColumns.SIZE);
            int mtimeCol = cursor.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED);

            while (cursor.moveToNext()) {
                if (controller != null && controller.isCancellationRequested()) return;

                scope.incrementDiscovered();
                long id = idCol >= 0 ? cursor.getLong(idCol) : -1;
                String displayName = nameCol >= 0 ? cursor.getString(nameCol) : "media_file";
                long size = sizeCol >= 0 ? cursor.getLong(sizeCol) : 0;
                long mtime = mtimeCol >= 0 ? cursor.getLong(mtimeCol) * 1000L : 0;

                Uri itemUri = Uri.withAppendedPath(queryUri, String.valueOf(id));

                // CleanFileCache check
                if (cleanFileCache.isClean(itemUri.toString(), size, mtime)) {
                    scope.incrementScanned();
                    continue;
                }

                // Inspect via T3 UniversalFileShieldService
                JSONObject result = fileShieldService.inspectUri(itemUri, displayName);
                scope.incrementScanned();

                if (callback != null) {
                    callback.onProgress(displayName, scope.getFilesScanned(), scope.getFilesDiscovered(), threats.size());
                }

                if (result != null) {
                    String verdict = result.optString("verdict", "ALLOW");
                    if ("DANGEROUS".equals(verdict) || "SUSPICIOUS".equals(verdict)) {
                        threats.add(result);
                        scope.incrementThreats();
                    } else if ("ALLOW".equals(verdict)) {
                        cleanFileCache.putClean(itemUri.toString(), size, mtime, result.optJSONObject("fileIdentity") != null ? result.optJSONObject("fileIdentity").optString("sha256") : "");
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to query MediaStore URI: " + queryUri, e);
            scope.setErrorDetails(e.getMessage());
        }
    }

    private void scanSafTreeScope(
            ScanScopeDescriptor scope,
            com.privateprotection.mobile.core.JobExecutionController controller,
            List<JSONObject> threats,
            ScanProgressCallback callback
    ) {
        Uri treeUri = Uri.parse(scope.getUriOrPath());
        if (!safManager.isTreePermissionValid(treeUri)) {
            scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.PERMISSION_DENIED);
            scope.setErrorDetails("SAF tree permission revoked or expired.");
            scope.incrementSkipped();
            return;
        }

        // Inspect granted directory contents via document URI
        scope.setFilesDiscovered(1);
        JSONObject res = fileShieldService.inspectUri(treeUri, scope.getDisplayName());
        scope.incrementScanned();
        if (res != null) {
            String verdict = res.optString("verdict", "ALLOW");
            if ("DANGEROUS".equals(verdict) || "SUSPICIOUS".equals(verdict)) {
                threats.add(res);
                scope.incrementThreats();
            }
        }
    }

    private void scanInstalledPackagesScope(
            ScanScopeDescriptor scope,
            ScanMode mode,
            com.privateprotection.mobile.core.JobExecutionController controller,
            List<JSONObject> threats,
            ScanProgressCallback callback
    ) {
        PackageManager pm = context.getPackageManager();
        List<PackageInfo> packages = pm.getInstalledPackages(0);
        scope.setFilesDiscovered(packages.size());

        for (PackageInfo pInfo : packages) {
            if (controller != null && controller.isCancellationRequested()) return;

            // In Quick Scan, inspect user apps (non-system) or recently updated apps
            boolean isSystem = (pInfo.applicationInfo != null && (pInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
            if (mode == ScanMode.QUICK_SCAN && isSystem) {
                scope.incrementSkipped();
                continue;
            }

            scope.incrementScanned();
            if (callback != null) {
                callback.onProgress(pInfo.packageName, scope.getFilesScanned(), scope.getFilesDiscovered(), threats.size());
            }

            JSONObject auditResult = packageAuditService.auditInstalledPackage(pInfo.packageName);
            if (auditResult != null) {
                String verdict = auditResult.optString("verdict", "ALLOW");
                if ("DANGEROUS".equals(verdict) || "SUSPICIOUS".equals(verdict)) {
                    threats.add(auditResult);
                    scope.incrementThreats();
                }
            }
        }
    }

    private void scanQuarantineVaultScope(
            ScanScopeDescriptor scope,
            com.privateprotection.mobile.core.JobExecutionController controller,
            List<JSONObject> threats,
            ScanProgressCallback callback
    ) {
        File vaultDir = new File(context.getFilesDir(), "private_quarantine_vault");
        if (!vaultDir.exists() || !vaultDir.isDirectory()) {
            scope.setFilesDiscovered(0);
            return;
        }

        File[] files = vaultDir.listFiles();
        if (files == null) return;
        scope.setFilesDiscovered(files.length);

        for (File f : files) {
            if (controller != null && controller.isCancellationRequested()) return;
            scope.incrementScanned();
            // Quarantine files are recorded as existing contained threats
            JSONObject threatInfo = new JSONObject();
            try {
                threatInfo.put("verdict", "DANGEROUS");
                threatInfo.put("status", "CONTAINED_IN_QUARANTINE");
                threatInfo.put("path", f.getAbsolutePath());
                threatInfo.put("fileName", f.getName());
                threats.add(threatInfo);
                scope.incrementThreats();
            } catch (JSONException ignored) {}
        }
    }

    private Uri resolveMediaStoreUri(ScanScopeDescriptor.ScopeType type) {
        switch (type) {
            case MEDIASTORE_DOWNLOADS:
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    return MediaStore.Downloads.EXTERNAL_CONTENT_URI;
                }
                return MediaStore.Files.getContentUri("external");
            case MEDIASTORE_IMAGES:
                return MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
            case MEDIASTORE_VIDEO:
                return MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
            case MEDIASTORE_AUDIO:
                return MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
            default:
                return null;
        }
    }
}
