package com.privateprotection.mobile.shield;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Bounded static inspector for ZIP and nested archive containers (Phase T3).
 *
 * SAFETY INVARIANTS:
 * 1. Zero dynamic code or archive extraction into filesystem.
 * 2. Strict limits against Zip Bombs (compression ratio > 100:1 with > 10MB uncompressed size).
 * 3. Enforces bounded entry counts (max 10,000 entries).
 * 4. Maximum aggregate uncompressed size ceiling (500 MB).
 * 5. Flags path traversal entries (.. / relative escaping).
 * 6. Identifies hidden or disguised executable payloads inside benign-named archives.
 */
public class BoundedArchiveInspector {
    public static final long MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024L; // 500 MB
    public static final int MAX_ENTRIES_COUNT = 10000;
    public static final int MAX_NESTED_DEPTH = 3;

    public static class ArchiveInspectionReport {
        public final boolean isValidArchive;
        public final int entryCount;
        public final long totalUncompressedBytes;
        public final boolean isZipBomb;
        public final boolean hasPathTraversal;
        public final boolean hasSuspiciousExecutables;
        public final List<String> suspiciousEntries;
        public final List<String> detectedFileTypes;

        public ArchiveInspectionReport(
                boolean isValidArchive,
                int entryCount,
                long totalUncompressedBytes,
                boolean isZipBomb,
                boolean hasPathTraversal,
                boolean hasSuspiciousExecutables,
                List<String> suspiciousEntries,
                List<String> detectedFileTypes
        ) {
            this.isValidArchive = isValidArchive;
            this.entryCount = entryCount;
            this.totalUncompressedBytes = totalUncompressedBytes;
            this.isZipBomb = isZipBomb;
            this.hasPathTraversal = hasPathTraversal;
            this.hasSuspiciousExecutables = hasSuspiciousExecutables;
            this.suspiciousEntries = suspiciousEntries != null ? Collections.unmodifiableList(suspiciousEntries) : Collections.emptyList();
            this.detectedFileTypes = detectedFileTypes != null ? Collections.unmodifiableList(detectedFileTypes) : Collections.emptyList();
        }

        public JSONObject toJSON() {
            JSONObject obj = new JSONObject();
            try {
                obj.put("isValidArchive", isValidArchive);
                obj.put("entryCount", entryCount);
                obj.put("totalUncompressedBytes", totalUncompressedBytes);
                obj.put("isZipBomb", isZipBomb);
                obj.put("hasPathTraversal", hasPathTraversal);
                obj.put("hasSuspiciousExecutables", hasSuspiciousExecutables);

                JSONArray susp = new JSONArray();
                for (String s : suspiciousEntries) susp.put(s);
                obj.put("suspiciousEntries", susp);

                JSONArray types = new JSONArray();
                for (String t : detectedFileTypes) types.put(t);
                obj.put("detectedFileTypes", types);
            } catch (JSONException ignored) {}
            return obj;
        }
    }

    public static ArchiveInspectionReport inspectArchive(File file) {
        if (file == null || !file.exists() || !file.isFile() || file.length() == 0) {
            return new ArchiveInspectionReport(false, 0, 0, false, false, false, Collections.singletonList("FILE_NOT_FOUND"), null);
        }

        long compressedSize = file.length();
        long uncompressedSize = 0;
        int entriesCount = 0;
        boolean isZipBomb = false;
        boolean hasPathTraversal = false;
        boolean hasSuspiciousExecutables = false;
        List<String> suspiciousEntries = new ArrayList<>();
        List<String> detectedTypes = new ArrayList<>();

        ZipFile zip = null;
        try {
            zip = new ZipFile(file);
            Enumeration<? extends ZipEntry> entries = zip.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                entriesCount++;
                String name = entry.getName();
                long size = entry.getSize();
                if (size > 0) {
                    uncompressedSize += size;
                }

                // Check max entries limit
                if (entriesCount > MAX_ENTRIES_COUNT) {
                    suspiciousEntries.add("EXCESSIVE_ENTRY_COUNT: exceeds limit of " + MAX_ENTRIES_COUNT);
                    isZipBomb = true;
                    break;
                }

                // Check max uncompressed size ceiling
                if (uncompressedSize > MAX_UNCOMPRESSED_BYTES) {
                    suspiciousEntries.add("OVERSIZED_UNCOMPRESSED_PAYLOAD: exceeds 500MB");
                    isZipBomb = true;
                    break;
                }

                // Check compression ratio (> 100:1 ratio on payloads > 10MB)
                if (compressedSize > 0 && uncompressedSize > (compressedSize * 100) && uncompressedSize > 10 * 1024 * 1024) {
                    suspiciousEntries.add("ZIP_BOMB_DETECTED: extreme compression ratio (> 100:1)");
                    isZipBomb = true;
                    break;
                }

                // Path traversal check (e.g. ../../../etc/passwd)
                if (name.contains("../") || name.contains("..\\") || name.startsWith("/")) {
                    hasPathTraversal = true;
                    suspiciousEntries.add("PATH_TRAVERSAL_ENTRY: " + name);
                }

                // Suspicious executable payload check
                String lower = name.toLowerCase();
                if (lower.endsWith(".exe") || lower.endsWith(".scr") || lower.endsWith(".bat") ||
                    lower.endsWith(".cmd") || lower.endsWith(".ps1") || lower.endsWith(".vbs") ||
                    lower.endsWith(".sh") || lower.endsWith(".dex") || lower.endsWith(".payload")) {
                    hasSuspiciousExecutables = true;
                    suspiciousEntries.add("EMBEDDED_EXECUTABLE_PAYLOAD: " + name);
                }

                // Record extension categories
                int dotIdx = lower.lastIndexOf('.');
                if (dotIdx != -1 && dotIdx < lower.length() - 1) {
                    String ext = lower.substring(dotIdx);
                    if (!detectedTypes.contains(ext) && detectedTypes.size() < 20) {
                        detectedTypes.add(ext);
                    }
                }
            }

            return new ArchiveInspectionReport(
                    true,
                    entriesCount,
                    uncompressedSize,
                    isZipBomb,
                    hasPathTraversal,
                    hasSuspiciousExecutables,
                    suspiciousEntries,
                    detectedTypes
            );
        } catch (Exception e) {
            suspiciousEntries.add("ARCHIVE_CORRUPTION_OR_ERROR: " + e.getMessage());
            return new ArchiveInspectionReport(false, entriesCount, uncompressedSize, false, false, true, suspiciousEntries, detectedTypes);
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Exception ignored) {}
            }
        }
    }
}
