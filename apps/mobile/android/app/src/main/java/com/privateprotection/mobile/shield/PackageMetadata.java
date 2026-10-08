package com.privateprotection.mobile.shield;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Immutable metadata model for an audited Android application or APK.
 * Captured statically via PackageManager or APK header inspection.
 */
public class PackageMetadata {
    private final String packageName;
    private final String appLabel;
    private final String versionName;
    private final long versionCode;
    private final long firstInstallTimeMs;
    private final long lastUpdateTimeMs;
    private final String installerPackageName;
    private final String sourceDir;
    private final boolean isSystemApp;
    private final List<String> requestedPermissions;
    private final List<String> dangerousPermissions;
    private final List<String> exportedComponents;
    private final List<String> signingCertSha256s;

    public PackageMetadata(
            String packageName,
            String appLabel,
            String versionName,
            long versionCode,
            long firstInstallTimeMs,
            long lastUpdateTimeMs,
            String installerPackageName,
            String sourceDir,
            boolean isSystemApp,
            List<String> requestedPermissions,
            List<String> dangerousPermissions,
            List<String> exportedComponents,
            List<String> signingCertSha256s
    ) {
        this.packageName = packageName != null ? packageName : "";
        this.appLabel = appLabel != null ? appLabel : "";
        this.versionName = versionName != null ? versionName : "";
        this.versionCode = versionCode;
        this.firstInstallTimeMs = firstInstallTimeMs;
        this.lastUpdateTimeMs = lastUpdateTimeMs;
        this.installerPackageName = installerPackageName != null ? installerPackageName : "";
        this.sourceDir = sourceDir != null ? sourceDir : "";
        this.isSystemApp = isSystemApp;
        this.requestedPermissions = requestedPermissions != null
                ? Collections.unmodifiableList(new ArrayList<>(requestedPermissions))
                : Collections.emptyList();
        this.dangerousPermissions = dangerousPermissions != null
                ? Collections.unmodifiableList(new ArrayList<>(dangerousPermissions))
                : Collections.emptyList();
        this.exportedComponents = exportedComponents != null
                ? Collections.unmodifiableList(new ArrayList<>(exportedComponents))
                : Collections.emptyList();
        this.signingCertSha256s = signingCertSha256s != null
                ? Collections.unmodifiableList(new ArrayList<>(signingCertSha256s))
                : Collections.emptyList();
    }

    public String getPackageName() {
        return packageName;
    }

    public String getAppLabel() {
        return appLabel;
    }

    public String getVersionName() {
        return versionName;
    }

    public long getVersionCode() {
        return versionCode;
    }

    public long getFirstInstallTimeMs() {
        return firstInstallTimeMs;
    }

    public long getLastUpdateTimeMs() {
        return lastUpdateTimeMs;
    }

    public String getInstallerPackageName() {
        return installerPackageName;
    }

    public String getSourceDir() {
        return sourceDir;
    }

    public boolean isSystemApp() {
        return isSystemApp;
    }

    public List<String> getRequestedPermissions() {
        return requestedPermissions;
    }

    public List<String> getDangerousPermissions() {
        return dangerousPermissions;
    }

    public List<String> getExportedComponents() {
        return exportedComponents;
    }

    public List<String> getSigningCertSha256s() {
        return signingCertSha256s;
    }

    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("packageName", packageName);
            obj.put("appLabel", appLabel);
            obj.put("versionName", versionName);
            obj.put("versionCode", versionCode);
            obj.put("firstInstallTimeMs", firstInstallTimeMs);
            obj.put("lastUpdateTimeMs", lastUpdateTimeMs);
            obj.put("installerPackageName", installerPackageName);
            obj.put("sourceDir", sourceDir);
            obj.put("isSystemApp", isSystemApp);

            JSONArray reqPerms = new JSONArray();
            for (String p : requestedPermissions) reqPerms.put(p);
            obj.put("requestedPermissions", reqPerms);

            JSONArray dangPerms = new JSONArray();
            for (String p : dangerousPermissions) dangPerms.put(p);
            obj.put("dangerousPermissions", dangPerms);

            JSONArray comps = new JSONArray();
            for (String c : exportedComponents) comps.put(c);
            obj.put("exportedComponents", comps);

            JSONArray certs = new JSONArray();
            for (String c : signingCertSha256s) certs.put(c);
            obj.put("signingCertSha256s", certs);
        } catch (JSONException ignored) {
        }
        return obj;
    }

    public static PackageMetadata fromJSON(JSONObject obj) {
        if (obj == null) {
            return new PackageMetadata("", "", "", 0, 0, 0, "", "", false, null, null, null, null);
        }
        String pkg = obj.optString("packageName", "");
        String label = obj.optString("appLabel", "");
        String vName = obj.optString("versionName", "");
        long vCode = obj.optLong("versionCode", 0);
        long fit = obj.optLong("firstInstallTimeMs", 0);
        long lut = obj.optLong("lastUpdateTimeMs", 0);
        String installer = obj.optString("installerPackageName", "");
        String src = obj.optString("sourceDir", "");
        boolean sys = obj.optBoolean("isSystemApp", false);

        List<String> req = jsonArrayToList(obj.optJSONArray("requestedPermissions"));
        List<String> dang = jsonArrayToList(obj.optJSONArray("dangerousPermissions"));
        List<String> comps = jsonArrayToList(obj.optJSONArray("exportedComponents"));
        List<String> certs = jsonArrayToList(obj.optJSONArray("signingCertSha256s"));

        return new PackageMetadata(pkg, label, vName, vCode, fit, lut, installer, src, sys, req, dang, comps, certs);
    }

    private static List<String> jsonArrayToList(JSONArray arr) {
        if (arr == null) return Collections.emptyList();
        List<String> list = new ArrayList<>(arr.length());
        for (int i = 0; i < arr.length(); i++) {
            list.add(arr.optString(i));
        }
        return list;
    }
}
