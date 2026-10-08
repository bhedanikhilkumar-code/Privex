package com.privateprotection.mobile.shield;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for ApkStaticAnalyzer:
 * Tests ZIP entry traversal, detection of Android components (DEX, manifest, native libs),
 * detection of embedded malicious payloads/droppers, and invalid ZIP handling.
 */
public class ApkStaticAnalyzerTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void testCleanApkArchive() throws IOException {
        File apk = tempFolder.newFile("clean_app.apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk))) {
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            zos.write("<manifest/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("classes.dex"));
            zos.write(new byte[]{0x64, 0x65, 0x78, 0x0a}); // DEX magic
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("lib/arm64-v8a/libnative.so"));
            zos.write(new byte[]{0x7f, 0x45, 0x4c, 0x46}); // ELF magic
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("META-INF/CERT.RSA"));
            zos.write(new byte[]{0x30, (byte) 0x82});
            zos.closeEntry();
        }

        ApkStaticAnalyzer.InspectionResult result = ApkStaticAnalyzer.inspectApkFile(apk);
        assertTrue(result.isValidZip);
        assertTrue(result.hasDex);
        assertTrue(result.hasAndroidManifest);
        assertTrue(result.hasNativeLibraries);
        assertFalse(result.hasSuspiciousPayloads);
        assertEquals(4, result.fileCount);
        assertEquals(1, result.certEntries.size());
        assertFalse(result.fileSha256.isEmpty());
    }

    @Test
    public void testSuspiciousPayloadDetection() throws IOException {
        File apk = tempFolder.newFile("malicious_dropper.apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk))) {
            zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
            zos.write("<manifest/>".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Embedded secondary APK dropper in assets
            zos.putNextEntry(new ZipEntry("assets/payload.apk"));
            zos.write(new byte[]{0x50, 0x4b, 0x03, 0x04});
            zos.closeEntry();

            // Embedded executable payload
            zos.putNextEntry(new ZipEntry("res/raw/backdoor.exe"));
            zos.write(new byte[]{'M', 'Z'});
            zos.closeEntry();
        }

        ApkStaticAnalyzer.InspectionResult result = ApkStaticAnalyzer.inspectApkFile(apk);
        assertTrue(result.isValidZip);
        assertTrue(result.hasSuspiciousPayloads);
        assertTrue(result.suspiciousEntries.size() >= 2);
    }

    @Test
    public void testInvalidOrMissingApk() {
        ApkStaticAnalyzer.InspectionResult nonExistent = ApkStaticAnalyzer.inspectApkFile(new File("non_existent.apk"));
        assertFalse(nonExistent.isValidZip);

        ApkStaticAnalyzer.InspectionResult nullResult = ApkStaticAnalyzer.inspectApkFile(null);
        assertFalse(nullResult.isValidZip);
    }

    @Test
    public void testCorruptZipFile() throws IOException {
        File corrupt = tempFolder.newFile("corrupt.apk");
        try (FileOutputStream fos = new FileOutputStream(corrupt)) {
            fos.write("THIS_IS_NOT_A_VALID_ZIP_FILE_AT_ALL".getBytes(StandardCharsets.UTF_8));
        }

        ApkStaticAnalyzer.InspectionResult result = ApkStaticAnalyzer.inspectApkFile(corrupt);
        assertFalse(result.isValidZip);
        assertTrue(result.hasSuspiciousPayloads);
    }
}
