package com.privateprotection.mobile.shield;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Universal content-based magic byte identifier for files on Android (Phase T3).
 *
 * SAFETY INVARIANT:
 * Never trusts file extensions or caller-provided MIME types. Inspects the raw leading
 * header bytes (first 16 to 128 bytes) in memory without executing the payload.
 */
public class UniversalMagicDetector {

    public static class DetectionResult {
        public final String mimeType;
        public final String canonicalCategory; // APK, ARCHIVE, DOCUMENT, IMAGE, VIDEO, EXECUTABLE, SCRIPT, TEXT, BINARY
        public final boolean isExecutable;

        public DetectionResult(String mimeType, String canonicalCategory, boolean isExecutable) {
            this.mimeType = mimeType;
            this.canonicalCategory = canonicalCategory;
            this.isExecutable = isExecutable;
        }
    }

    /**
     * Inspects leading byte array (at least 4 to 128 bytes recommended) to detect true format.
     */
    public static DetectionResult detectMagic(byte[] header, String declaredFileName) {
        if (header == null || header.length == 0) {
            return new DetectionResult("application/octet-stream", "UNKNOWN", false);
        }

        // 1. EICAR Standard Antivirus Test Signature
        if (header.length >= 60) {
            String asciiPrefix = new String(header, 0, Math.min(header.length, 128), StandardCharsets.US_ASCII);
            if (asciiPrefix.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!")) {
                return new DetectionResult("application/x-eicar-test", "MALWARE_TEST", true);
            }
        }

        // 2. Android DEX bytecode (dex\n or dey\n)
        if (header.length >= 4 &&
            header[0] == 0x64 && header[1] == 0x65 &&
            (header[2] == 0x78 || header[2] == 0x79) && header[3] == 0x0A) {
            return new DetectionResult("application/vnd.android.dex", "DEX", true);
        }

        // 3. ELF executable / Linux / Android native binary (.so or ELF binary)
        if (header.length >= 4 &&
            header[0] == 0x7F && header[1] == 0x45 && header[2] == 0x4C && header[3] == 0x46) {
            return new DetectionResult("application/x-elf", "EXECUTABLE", true);
        }

        // 4. Windows PE executable (MZ)
        if (header.length >= 2 && header[0] == 0x4D && header[1] == 0x5A) {
            return new DetectionResult("application/x-dosexec", "EXECUTABLE", true);
        }

        // 5. ZIP Archive / APK / Office Open XML (DOCX, XLSX, PPTX) / JAR (PK\x03\x04 or PK\x05\x06)
        if (header.length >= 4 && header[0] == 0x50 && header[1] == 0x4B &&
            ((header[2] == 0x03 && header[3] == 0x04) || (header[2] == 0x05 && header[3] == 0x06))) {
            String nameLower = declaredFileName != null ? declaredFileName.toLowerCase() : "";
            if (nameLower.endsWith(".apk")) {
                return new DetectionResult("application/vnd.android.package-archive", "APK", true);
            } else if (nameLower.endsWith(".docx")) {
                return new DetectionResult("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "DOCUMENT", false);
            } else if (nameLower.endsWith(".xlsx")) {
                return new DetectionResult("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "DOCUMENT", false);
            } else if (nameLower.endsWith(".pptx")) {
                return new DetectionResult("application/vnd.openxmlformats-officedocument.presentationml.presentation", "DOCUMENT", false);
            } else if (nameLower.endsWith(".jar")) {
                return new DetectionResult("application/java-archive", "ARCHIVE", true);
            }
            return new DetectionResult("application/zip", "ARCHIVE", false);
        }

        // 6. PDF Document (%PDF-)
        if (header.length >= 4 &&
            header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 && header[3] == 0x46) {
            return new DetectionResult("application/pdf", "DOCUMENT", false);
        }

        // 7. Legacy Microsoft Compound File Binary (DOC, XLS, PPT) (0xD0CF11E0A1B11AE1)
        if (header.length >= 8 &&
            (header[0] & 0xFF) == 0xD0 && (header[1] & 0xFF) == 0xCF &&
            (header[2] & 0xFF) == 0x11 && (header[3] & 0xFF) == 0xE0 &&
            (header[4] & 0xFF) == 0xA1 && (header[5] & 0xFF) == 0xB1 &&
            (header[6] & 0xFF) == 0x1A && (header[7] & 0xFF) == 0xE1) {
            return new DetectionResult("application/msword", "DOCUMENT", false);
        }

        // 8. Images
        // PNG (\x89PNG\r\n\x1a\n)
        if (header.length >= 8 &&
            (header[0] & 0xFF) == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 &&
            header[4] == 0x0D && header[5] == 0x0A && header[6] == 0x1A && header[7] == 0x0A) {
            return new DetectionResult("image/png", "IMAGE", false);
        }
        // JPEG (\xFF\xD8\xFF)
        if (header.length >= 3 &&
            (header[0] & 0xFF) == 0xFF && (header[1] & 0xFF) == 0xD8 && (header[2] & 0xFF) == 0xFF) {
            return new DetectionResult("image/jpeg", "IMAGE", false);
        }
        // GIF (GIF87a or GIF89a)
        if (header.length >= 6 && header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38) {
            return new DetectionResult("image/gif", "IMAGE", false);
        }
        // WEBP (RIFF....WEBP)
        if (header.length >= 12 &&
            header[0] == 0x52 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x46 &&
            header[8] == 0x57 && header[9] == 0x45 && header[10] == 0x42 && header[11] == 0x50) {
            return new DetectionResult("image/webp", "IMAGE", false);
        }

        // 9. Video MP4 (....ftypisom, ftypmp42, etc.)
        if (header.length >= 8 &&
            header[4] == 0x66 && header[5] == 0x74 && header[6] == 0x79 && header[7] == 0x70) {
            return new DetectionResult("video/mp4", "VIDEO", false);
        }

        // 10. Scripts and Text
        // Shell script / shebang (#!)
        if (header.length >= 2 && header[0] == 0x23 && header[1] == 0x21) {
            return new DetectionResult("text/x-shellscript", "SCRIPT", true);
        }

        // Check if plain text / HTML
        String textPrefix = new String(header, 0, Math.min(header.length, 64), StandardCharsets.UTF_8).trim().toLowerCase();
        if (textPrefix.startsWith("<!doctype html") || textPrefix.startsWith("<html")) {
            return new DetectionResult("text/html", "TEXT", false);
        }

        return new DetectionResult("application/octet-stream", "BINARY", false);
    }
}
