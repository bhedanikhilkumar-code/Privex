package com.privateprotection.mobile.shield;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * PackageAuditService: Evaluates risk for an installed package or APK file.
 *
 * Adheres to Canonical Principles:
 * - Deterministic, rule-based risk evaluation using canonical taxonomy
 * - Produces canonical Evidence records
 * - Never dynamically executes untrusted code
 * - Maps to canonical Verdicts (SAFE, INFORM, WARN, BLOCK/DANGEROUS)
 */
public class PackageAuditService {
    private static final String TAG = "PackageAuditService";

    // Known dangerous/sensitive Android permissions
    private static final Set<String> HIGH_RISK_PERMISSIONS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.MANAGE_EXTERNAL_STORAGE"
    )));

    // Trusted official installers (lower suspicion baseline)
    private static final Set<String> KNOWN_APP_STORES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "com.android.vending", // Google Play
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "org.fdroid.fdroid", // F-Droid
            "com.sec.android.app.samsungapps", // Samsung Galaxy Store
            "com.amazon.venezia" // Amazon Appstore
    )));

    private final Context context;

    public PackageAuditService(Context context) {
        this.context = context.getApplicationContext();
    }

    /**
     * Resolves package metadata for an installed application.
     */
    public PackageMetadata resolveInstalledPackage(String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) {
            return null;
        }

        try {
            PackageManager pm = context.getPackageManager();
            int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_ACTIVITIES |
                    PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                flags |= PackageManager.GET_SIGNING_CERTIFICATES;
            } else {
                flags |= PackageManager.GET_SIGNATURES;
            }

            PackageInfo pInfo = pm.getPackageInfo(packageName, flags);
            ApplicationInfo appInfo = pInfo.applicationInfo;

            String label = pm.getApplicationLabel(appInfo).toString();
            String versionName = pInfo.versionName != null ? pInfo.versionName : "";
            long versionCode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                    ? pInfo.getLongVersionCode() : pInfo.versionCode;

            long firstInstallTime = pInfo.firstInstallTime;
            long lastUpdateTime = pInfo.lastUpdateTime;

            String installer = "";
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    android.content.pm.InstallSourceInfo info = pm.getInstallSourceInfo(packageName);
                    installer = info != null && info.getInstallingPackageName() != null ? info.getInstallingPackageName() : "";
                } else {
                    installer = pm.getInstallerPackageName(packageName);
                }
            } catch (Exception ignored) {}

            String sourceDir = appInfo.sourceDir != null ? appInfo.sourceDir : "";
            boolean isSystemApp = (appInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;

            List<String> requestedPerms = new ArrayList<>();
            List<String> dangerousPerms = new ArrayList<>();
            if (pInfo.requestedPermissions != null) {
                for (String perm : pInfo.requestedPermissions) {
                    requestedPerms.add(perm);
                    if (HIGH_RISK_PERMISSIONS.contains(perm)) {
                        dangerousPerms.add(perm);
                    }
                }
            }

            List<String> exportedComponents = new ArrayList<>();
            if (pInfo.activities != null) {
                for (ActivityInfo a : pInfo.activities) {
                    if (a.exported) exportedComponents.add("activity:" + a.name);
                }
            }
            if (pInfo.services != null) {
                for (ServiceInfo s : pInfo.services) {
                    if (s.exported) exportedComponents.add("service:" + s.name);
                }
            }
            if (pInfo.receivers != null) {
                for (ActivityInfo r : pInfo.receivers) {
                    if (r.exported) exportedComponents.add("receiver:" + r.name);
                }
            }
            if (pInfo.providers != null) {
                for (ProviderInfo pr : pInfo.providers) {
                    if (pr.exported) exportedComponents.add("provider:" + pr.name);
                }
            }

            List<String> certDigests = extractCertificateDigests(pInfo);

            return new PackageMetadata(
                    packageName,
                    label,
                    versionName,
                    versionCode,
                    firstInstallTime,
                    lastUpdateTime,
                    installer,
                    sourceDir,
                    isSystemApp,
                    requestedPerms,
                    dangerousPerms,
                    exportedComponents,
                    certDigests
            );
        } catch (PackageManager.NameNotFoundException e) {
            Log.w(TAG, "Package not found: " + packageName);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Failed to resolve package info for " + packageName, e);
            return null;
        }
    }

    /**
     * Performs a deterministic security audit on an installed package.
     */
    public JSONObject auditInstalledPackage(String packageName) {
        PackageMetadata meta = resolveInstalledPackage(packageName);
        if (meta == null) {
            JSONObject err = new JSONObject();
            try {
                err.put("error", "PACKAGE_NOT_FOUND");
                err.put("packageName", packageName);
            } catch (JSONException ignored) {}
            return err;
        }

        ApkStaticAnalyzer.InspectionResult apkInspection = null;
        if (meta.getSourceDir() != null && !meta.getSourceDir().isEmpty()) {
            File apkFile = new File(meta.getSourceDir());
            if (apkFile.exists() && apkFile.canRead()) {
                apkInspection = ApkStaticAnalyzer.inspectApkFile(apkFile);
            }
        }

        return evaluateRisk(meta, apkInspection);
    }

    /**
     * Performs a deterministic security audit on an uninstalled APK file (Pre-install).
     */
    public JSONObject auditApkFile(String apkFilePath) {
        if (apkFilePath == null || apkFilePath.trim().isEmpty()) {
            JSONObject err = new JSONObject();
            try {
                err.put("error", "INVALID_FILE_PATH");
            } catch (JSONException ignored) {}
            return err;
        }

        File apkFile = new File(apkFilePath);
        if (!apkFile.exists() || !apkFile.isFile()) {
            JSONObject err = new JSONObject();
            try {
                err.put("error", "FILE_NOT_FOUND");
                err.put("path", apkFilePath);
            } catch (JSONException ignored) {}
            return err;
        }

        PackageManager pm = context.getPackageManager();
        PackageInfo pInfo = pm.getPackageArchiveInfo(apkFilePath,
                PackageManager.GET_PERMISSIONS | PackageManager.GET_ACTIVITIES |
                PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS);

        String pkgName = pInfo != null && pInfo.packageName != null ? pInfo.packageName : apkFile.getName();
        String label = (pInfo != null && pInfo.applicationInfo != null)
                ? String.valueOf(pm.getApplicationLabel(pInfo.applicationInfo)) : apkFile.getName();
        String vName = pInfo != null && pInfo.versionName != null ? pInfo.versionName : "1.0";
        long vCode = pInfo != null ? (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ? pInfo.getLongVersionCode() : pInfo.versionCode) : 1;

        List<String> requestedPerms = new ArrayList<>();
        List<String> dangerousPerms = new ArrayList<>();
        if (pInfo != null && pInfo.requestedPermissions != null) {
            for (String perm : pInfo.requestedPermissions) {
                requestedPerms.add(perm);
                if (HIGH_RISK_PERMISSIONS.contains(perm)) {
                    dangerousPerms.add(perm);
                }
            }
        }

        List<String> exportedComponents = new ArrayList<>();
        if (pInfo != null) {
            if (pInfo.activities != null) {
                for (ActivityInfo a : pInfo.activities) if (a.exported) exportedComponents.add("activity:" + a.name);
            }
            if (pInfo.services != null) {
                for (ServiceInfo s : pInfo.services) if (s.exported) exportedComponents.add("service:" + s.name);
            }
            if (pInfo.receivers != null) {
                for (ActivityInfo r : pInfo.receivers) if (r.exported) exportedComponents.add("receiver:" + r.name);
            }
            if (pInfo.providers != null) {
                for (ProviderInfo pr : pInfo.providers) if (pr.exported) exportedComponents.add("provider:" + pr.name);
            }
        }

        ApkStaticAnalyzer.InspectionResult apkInspection = ApkStaticAnalyzer.inspectApkFile(apkFile);

        PackageMetadata meta = new PackageMetadata(
                pkgName,
                label,
                vName,
                vCode,
                System.currentTimeMillis(),
                System.currentTimeMillis(),
                "file_system",
                apkFilePath,
                false,
                requestedPerms,
                dangerousPerms,
                exportedComponents,
                apkInspection.certEntries
        );

        return evaluateRisk(meta, apkInspection);
    }

    /**
     * Deterministic risk evaluation producing canonical evidence & verdicts.
     */
    public JSONObject evaluateRisk(PackageMetadata meta, ApkStaticAnalyzer.InspectionResult apkInspection) {
        JSONObject report = new JSONObject();
        try {
            int score = 0;
            JSONArray evidenceList = new JSONArray();

            // 1. Sideloaded / Unknown Installer Check
            boolean isSideloaded = !meta.isSystemApp() && (meta.getInstallerPackageName().isEmpty() ||
                    !KNOWN_APP_STORES.contains(meta.getInstallerPackageName()));
            if (isSideloaded) {
                score += 15;
                addEvidence(evidenceList, "INSTALLER_SOURCE", "MEDIUM", 15,
                        "Application was sideloaded or installed from an untrusted source: " +
                        (meta.getInstallerPackageName().isEmpty() ? "Unknown / Sideload" : meta.getInstallerPackageName()));
            }

            // 2. High-Risk / Excessive Dangerous Permissions
            List<String> dangPerms = meta.getDangerousPermissions();
            if (!dangPerms.isEmpty()) {
                int permWeight = Math.min(dangPerms.size() * 12, 48);
                score += permWeight;
                addEvidence(evidenceList, "HIGH_RISK_PERMISSIONS", dangPerms.size() >= 3 ? "HIGH" : "MEDIUM", permWeight,
                        "Requests " + dangPerms.size() + " highly sensitive permissions: " + dangPerms.toString());

                // Check for critical exfiltration combinations (e.g. SMS + INTERNET or ACCESSIBILITY)
                if (meta.getRequestedPermissions().contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                    score += 35;
                    addEvidence(evidenceList, "ACCESSIBILITY_SERVICE_BINDING", "CRITICAL", 35,
                            "Requests Accessibility Service binding, frequently abused by Android banking trojans & overlay malware.");
                }
                if (meta.getRequestedPermissions().contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
                    score += 25;
                    addEvidence(evidenceList, "PACKAGE_INSTALLER_PRIVILEGE", "HIGH", 25,
                            "Requests permission to silently trigger installation of other arbitrary packages.");
                }
            }

            // 3. Exported Attack Surface
            List<String> exported = meta.getExportedComponents();
            if (exported.size() > 5 && !meta.isSystemApp()) {
                score += 15;
                addEvidence(evidenceList, "WIDE_EXPORTED_ATTACK_SURFACE", "LOW", 15,
                        "Exposes " + exported.size() + " exported components accessible to any other app on the device.");
            }

            // 4. Static APK Analysis Findings
            if (apkInspection != null) {
                if (!apkInspection.isValidZip) {
                    score += 60;
                    addEvidence(evidenceList, "INVALID_OR_CORRUPT_ARCHIVE", "CRITICAL", 60,
                            "APK archive is corrupted, malformed, or violates ZIP boundaries.");
                }
                if (apkInspection.hasSuspiciousPayloads) {
                    score += 50;
                    addEvidence(evidenceList, "SUSPICIOUS_PAYLOAD_DETECTED", "CRITICAL", 50,
                            "Found suspicious embedded executable or dropper payloads: " + apkInspection.suspiciousEntries.toString());
                }
                if (!apkInspection.hasDex) {
                    score += 25;
                    addEvidence(evidenceList, "MISSING_DEX_FILE", "MEDIUM", 25,
                            "APK archive contains no compiled Android DEX executable code.");
                }
            } else if (!meta.isSystemApp()) {
                // Inaccessible or deleted APK archive on filesystem
                addEvidence(evidenceList, "APK_ARCHIVE_INACCESSIBLE", "LOW", 5,
                        "Base APK binary file could not be read directly from filesystem; static bytecode scan unavailable.");
            }

            // System apps are inherently safe unless heavily tampered
            if (meta.isSystemApp()) {
                score = Math.min(score, 10);
            }

            // Clamp score between 0 and 100
            score = Math.max(0, Math.min(score, 100));

            // Map score to canonical Verdict & Severity
            String verdict;
            String severity;
            String recommendation;

            if (score >= 70) {
                verdict = "DANGEROUS";
                severity = "CRITICAL";
                recommendation = "IMMEDIATELY_UNINSTALL";
            } else if (score >= 45) {
                verdict = "SUSPICIOUS";
                severity = "HIGH";
                recommendation = "REVIEW_PERMISSIONS_OR_UNINSTALL";
            } else if (score >= 20) {
                verdict = "CAUTION";
                severity = "MEDIUM";
                recommendation = "EXAMINE_APP_PERMISSIONS";
            } else {
                verdict = "ALLOW";
                severity = "NONE";
                recommendation = "SAFE_TO_RUN";
            }

            report.put("packageName", meta.getPackageName());
            report.put("appLabel", meta.getAppLabel());
            report.put("score", score);
            report.put("verdict", verdict);
            report.put("severity", severity);
            report.put("recommendation", recommendation);
            report.put("isSideloaded", isSideloaded);
            report.put("isSystemApp", meta.isSystemApp());
            report.put("metadata", meta.toJSON());
            report.put("evidence", evidenceList);
            if (apkInspection != null) {
                report.put("apkInspection", apkInspection.toJSON());
            }
            report.put("timestamp", System.currentTimeMillis());

        } catch (JSONException e) {
            Log.e(TAG, "Error assembling risk report", e);
        }
        return report;
    }

    private void addEvidence(JSONArray list, String code, String severity, int weight, String description) {
        try {
            JSONObject ev = new JSONObject();
            ev.put("code", code);
            ev.put("severity", severity);
            ev.put("weight", weight);
            ev.put("description", description);
            list.put(ev);
        } catch (JSONException ignored) {}
    }

    private List<String> extractCertificateDigests(PackageInfo pInfo) {
        List<String> certs = new ArrayList<>();
        try {
            Signature[] signatures = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                SigningInfo signingInfo = pInfo.signingInfo;
                if (signingInfo != null) {
                    signatures = signingInfo.hasMultipleSigners()
                            ? signingInfo.getApkContentsSigners()
                            : signingInfo.getSigningCertificateHistory();
                }
            } else {
                signatures = pInfo.signatures;
            }

            if (signatures != null) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                for (Signature sig : signatures) {
                    byte[] digest = md.digest(sig.toByteArray());
                    StringBuilder sb = new StringBuilder();
                    for (byte b : digest) sb.append(String.format("%02x", b));
                    certs.add(sb.toString());
                }
            }
        } catch (Exception ignored) {}
        return certs;
    }

    /**
     * Creates an explicit Android Intent to request user uninstallation of an application.
     */
    public Intent createUninstallIntent(String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) {
            return null;
        }
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + packageName));
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        return intent;
    }
}
