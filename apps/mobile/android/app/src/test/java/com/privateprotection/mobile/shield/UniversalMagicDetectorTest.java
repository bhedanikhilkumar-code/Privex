package com.privateprotection.mobile.shield;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class UniversalMagicDetectorTest {

    @Test
    public void testEicarTestSignatureDetection() {
        String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        byte[] bytes = eicar.getBytes(StandardCharsets.US_ASCII);

        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(bytes, "sample.txt");
        assertEquals("application/x-eicar-test", res.mimeType);
        assertEquals("MALWARE_TEST", res.canonicalCategory);
        assertTrue(res.isExecutable);
    }

    @Test
    public void testDexHeaderDetection() {
        byte[] dexBytes = new byte[] {0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x39, 0x00};
        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(dexBytes, "classes.dex");
        assertEquals("application/vnd.android.dex", res.mimeType);
        assertEquals("DEX", res.canonicalCategory);
        assertTrue(res.isExecutable);
    }

    @Test
    public void testElfHeaderDetection() {
        byte[] elfBytes = new byte[] {0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00};
        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(elfBytes, "libnative.so");
        assertEquals("application/x-elf", res.mimeType);
        assertEquals("EXECUTABLE", res.canonicalCategory);
        assertTrue(res.isExecutable);
    }

    @Test
    public void testPeDosHeaderDetection() {
        byte[] peBytes = new byte[] {0x4D, 0x5A, (byte) 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(peBytes, "setup.exe");
        assertEquals("application/x-dosexec", res.mimeType);
        assertEquals("EXECUTABLE", res.canonicalCategory);
        assertTrue(res.isExecutable);
    }

    @Test
    public void testZipAndApkDetection() {
        byte[] zipBytes = new byte[] {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00};

        UniversalMagicDetector.DetectionResult zipRes = UniversalMagicDetector.detectMagic(zipBytes, "archive.zip");
        assertEquals("application/zip", zipRes.mimeType);
        assertEquals("ARCHIVE", zipRes.canonicalCategory);
        assertFalse(zipRes.isExecutable);

        UniversalMagicDetector.DetectionResult apkRes = UniversalMagicDetector.detectMagic(zipBytes, "app.apk");
        assertEquals("application/vnd.android.package-archive", apkRes.mimeType);
        assertEquals("APK", apkRes.canonicalCategory);
        assertTrue(apkRes.isExecutable);
    }

    @Test
    public void testPdfHeaderDetection() {
        byte[] pdfBytes = "%PDF-1.7\r\n...".getBytes(StandardCharsets.US_ASCII);
        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(pdfBytes, "invoice.pdf");
        assertEquals("application/pdf", res.mimeType);
        assertEquals("DOCUMENT", res.canonicalCategory);
        assertFalse(res.isExecutable);
    }

    @Test
    public void testImageHeadersDetection() {
        // PNG
        byte[] pngBytes = new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        UniversalMagicDetector.DetectionResult pngRes = UniversalMagicDetector.detectMagic(pngBytes, "image.png");
        assertEquals("image/png", pngRes.mimeType);
        assertEquals("IMAGE", pngRes.canonicalCategory);

        // JPEG
        byte[] jpegBytes = new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0};
        UniversalMagicDetector.DetectionResult jpegRes = UniversalMagicDetector.detectMagic(jpegBytes, "photo.jpg");
        assertEquals("image/jpeg", jpegRes.mimeType);
        assertEquals("IMAGE", jpegRes.canonicalCategory);
    }

    @Test
    public void testShellScriptDetection() {
        byte[] shBytes = "#!/bin/bash\necho dangerous\n".getBytes(StandardCharsets.US_ASCII);
        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(shBytes, "script.sh");
        assertEquals("text/x-shellscript", res.mimeType);
        assertEquals("SCRIPT", res.canonicalCategory);
        assertTrue(res.isExecutable);
    }

    @Test
    public void testNullAndEmptyHeaderSafety() {
        UniversalMagicDetector.DetectionResult res1 = UniversalMagicDetector.detectMagic(null, "none");
        assertEquals("application/octet-stream", res1.mimeType);
        assertEquals("UNKNOWN", res1.canonicalCategory);

        UniversalMagicDetector.DetectionResult res2 = UniversalMagicDetector.detectMagic(new byte[0], "none");
        assertEquals("application/octet-stream", res2.mimeType);
        assertEquals("UNKNOWN", res2.canonicalCategory);
    }
}
