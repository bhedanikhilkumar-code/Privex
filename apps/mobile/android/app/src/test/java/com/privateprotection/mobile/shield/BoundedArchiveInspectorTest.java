package com.privateprotection.mobile.shield;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

public class BoundedArchiveInspectorTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void testCleanZipArchiveInspection() throws Exception {
        File zipFile = tempFolder.newFile("clean.zip");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile))) {
            ZipEntry entry1 = new ZipEntry("document.txt");
            zos.putNextEntry(entry1);
            zos.write("Hello safe world".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            ZipEntry entry2 = new ZipEntry("data.json");
            zos.putNextEntry(entry2);
            zos.write("{\"key\":\"value\"}".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        BoundedArchiveInspector.ArchiveInspectionReport report = BoundedArchiveInspector.inspectArchive(zipFile);
        assertTrue(report.isValidArchive);
        assertEquals(2, report.entryCount);
        assertFalse(report.isZipBomb);
        assertFalse(report.hasPathTraversal);
        assertFalse(report.hasSuspiciousExecutables);
        assertTrue(report.suspiciousEntries.isEmpty());
        assertTrue(report.detectedFileTypes.contains(".txt"));
        assertTrue(report.detectedFileTypes.contains(".json"));
    }

    @Test
    public void testPathTraversalDetection() throws Exception {
        File zipFile = tempFolder.newFile("traversal.zip");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile))) {
            ZipEntry badEntry = new ZipEntry("../../etc/passwd");
            zos.putNextEntry(badEntry);
            zos.write("root:x:0:0".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        BoundedArchiveInspector.ArchiveInspectionReport report = BoundedArchiveInspector.inspectArchive(zipFile);
        assertTrue(report.isValidArchive);
        assertTrue(report.hasPathTraversal);
        assertTrue(report.suspiciousEntries.stream().anyMatch(s -> s.contains("PATH_TRAVERSAL_ENTRY")));
    }

    @Test
    public void testSuspiciousExecutableInArchive() throws Exception {
        File zipFile = tempFolder.newFile("stealth.zip");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile))) {
            ZipEntry exeEntry = new ZipEntry("setup.exe");
            zos.putNextEntry(exeEntry);
            zos.write("binary_stub".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }

        BoundedArchiveInspector.ArchiveInspectionReport report = BoundedArchiveInspector.inspectArchive(zipFile);
        assertTrue(report.isValidArchive);
        assertTrue(report.hasSuspiciousExecutables);
        assertTrue(report.suspiciousEntries.stream().anyMatch(s -> s.contains("EMBEDDED_EXECUTABLE_PAYLOAD")));
    }

    @Test
    public void testNonExistentOrCorruptFile() {
        File missing = new File(tempFolder.getRoot(), "missing.zip");
        BoundedArchiveInspector.ArchiveInspectionReport report = BoundedArchiveInspector.inspectArchive(missing);
        assertFalse(report.isValidArchive);
        assertEquals(0, report.entryCount);
    }
}
