package com.privateprotection.mobile.shield;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Static inspection utility for Android APK archives (Phase T2).
 *
 * SAFETY INVARIANT:
 * Zero dynamic code execution. Does NOT invoke DexClassLoader, Dalvik/ART runtime,
 * or execute binaries. Safely inspects headers, entries, certificates, and structural markers.
 */
public class ApkStaticAnalyzer {

    public static class InspectionResult {
        public final boolean isValidZip;
        public final boolean hasDex;
        public final boolean hasAndroidManifest;
        public final boolean hasNativeLibraries;
        public final boolean hasSuspiciousPayloads;
        public final long uncompressedSizeBytes;
        public final int fileCount;
        public final List<String> suspiciousEntries;
        public final List<String> certEntries;
        public final String fileSha256;

        public InspectionResult(
                boolean isValidZip,
                boolean hasDex,
                boolean hasAndroidManifest,
                boolean hasNativeLibraries,
                boolean hasSuspiciousPayloads,
                long uncompressedSizeBytes,
                int fileCount,
                List<String> suspiciousEntries,
                List<String> certEntries,
                String fileSha256
        ) {
            this.isValidZip = isValidZip;
            this.hasDex = hasDex;
            this.hasAndroidManifest = hasAndroidManifest;
            this.hasNativeLibraries = hasNativeLibraries;
            this.hasSuspiciousPayloads = hasSuspiciousPayloads;
            this.uncompressedSizeBytes = uncompressedSizeBytes;
            this.fileCount = fileCount;
            this.suspiciousEntries = suspiciousEntries != null ? Collections.unmodifiableList(suspiciousEntries) : Collections.emptyList();
            this.certEntries = certEntries != null ? Collections.unmodifiableList(certEntries) : Collections.emptyList();
            this.fileSha256 = fileSha256 != null ? fileSha256 : "";
        }

        public JSONObject toJSON() {
            JSONObject obj = new JSONObject();
            try {
                obj.put("isValidZip", isValidZip);
                obj.put("hasDex", hasDex);
                obj.put("hasAndroidManifest", hasAndroidManifest);
                obj.put("hasNativeLibraries", hasNativeLibraries);
                obj.put("hasSuspiciousPayloads", hasSuspiciousPayloads);
                obj.put("uncompressedSizeBytes", uncompressedSizeBytes);
                obj.put("fileCount", fileCount);
                obj.put("fileSha256", fileSha256);

                JSONArray susp = new JSONArray();
                for (String s : suspiciousEntries) susp.put(s);
                obj.put("suspiciousEntries", susp);

                JSONArray certs = new JSONArray();
                for (String c : certEntries) certs.put(c);
                obj.put("certEntries", certs);
            } catch (JSONException ignored) {}
            return obj;
        }
    }

    /**
     * Statically inspects an APK archive file on the local filesystem.
     * Enforces safety bounds against Zip Bombs and nested malicious archives.
     */
    public static InspectionResult inspectApkFile(File apkFile) {
        if (apkFile == null || !apkFile.exists() || !apkFile.isFile() || apkFile.length() == 0) {
            return new InspectionResult(false, false, false, false, false, 0, 0, null, null, "");
        }

        // Limit maximum inspected size to prevent memory exhaustion
        if (apkFile.length() > 500 * 1024 * 1024L) { // 500MB safety limit
            List<String> susp = new ArrayList<>();
            susp.add("APK_FILE_OVERSIZED");
            return new InspectionResult(false, false, false, false, true, apkFile.length(), 0, susp, null, "");
        }

        String fileSha256 = computeFileSha256(apkFile);

        boolean hasDex = false;
        boolean hasManifest = false;
        boolean hasNativeLibs = false;
        boolean hasSuspiciousPayloads = false;
        long totalUncompressedSize = 0;
        int fileCount = 0;
        List<String> suspiciousEntries = new ArrayList<>();
        List<String> certEntries = new ArrayList<>();

        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(apkFile);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                fileCount++;
                String name = entry.getName();
                long size = entry.getSize();
                if (size > 0) {
                    totalUncompressedSize += size;
                }

                // Check zip bomb ratio (> 100:1 ratio with > 10MB uncompressed)
                if (apkFile.length() > 0 && totalUncompressedSize > (apkFile.length() * 100) && totalUncompressedSize > 10 * 1024 * 1024) {
                    suspiciousEntries.add("ZIP_BOMB_DETECTED: excessive compression ratio");
                    hasSuspiciousPayloads = true;
                    break;
                }

                // Check standard APK elements
                if (name.equals("AndroidManifest.xml")) {
                    hasManifest = true;
                } else if (name.endsWith(".dex")) {
                    hasDex = true;
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                    hasNativeLibs = true;
                } else if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC") || name.endsWith(".SF"))) {
                    certEntries.add(name);
                }

                // Check for suspicious payloads packed inside APK
                String lower = name.toLowerCase();
                if (lower.endsWith(".exe") || lower.endsWith(".bat") || lower.endsWith(".sh") ||
                    lower.endsWith(".ps1") || lower.endsWith(".vbs") || lower.endsWith(".payload")) {
                    suspiciousEntries.add("SUSPICIOUS_PAYLOAD: " + name);
                    hasSuspiciousPayloads = true;
                } else if (name.startsWith("assets/") && (lower.endsWith(".apk") || lower.endsWith(".dex"))) {
                    // Secondary APK or DEX packed inside assets (dropper pattern)
                    suspiciousEntries.add("SUSPICIOUS_DROPPER_PAYLOAD: " + name);
                    hasSuspiciousPayloads = true;
                }
            }

            return new InspectionResult(
                    true,
                    hasDex,
                    hasManifest,
                    hasNativeLibs,
                    hasSuspiciousPayloads,
                    totalUncompressedSize,
                    fileCount,
                    suspiciousEntries,
                    certEntries,
                    fileSha256
            );
        } catch (Exception e) {
            List<String> susp = new ArrayList<>();
            susp.add("ARCHIVE_PARSE_ERROR: " + e.getMessage());
            return new InspectionResult(false, false, false, false, true, 0, 0, susp, null, fileSha256);
        } finally {
            if (zipFile != null) {
                try {
                    zipFile.close();
                } catch (Exception ignored) {}
            }
        }
    }

    private static String computeFileSha256(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream is = new java.io.FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            byte[] hash = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
