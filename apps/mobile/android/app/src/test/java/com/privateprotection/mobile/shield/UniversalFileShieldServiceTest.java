package com.privateprotection.mobile.shield;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class UniversalFileShieldServiceTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private UniversalFileShieldService shieldService;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        File dummyFilesDir = tempFolder.getRoot();
        when(mockContext.getFilesDir()).thenReturn(dummyFilesDir);
        shieldService = new UniversalFileShieldService(mockContext);
    }

    @Test
    public void testCleanTextFileInspection() throws Exception {
        File txtFile = tempFolder.newFile("notes.txt");
        try (FileOutputStream fos = new FileOutputStream(txtFile)) {
            fos.write("Hello world, this is a clean text note.".getBytes(StandardCharsets.UTF_8));
        }

        JSONObject result = shieldService.inspectFile(txtFile);
        assertNotNull(result);
        assertEquals("ALLOW", result.getString("verdict"));
        assertEquals("NONE", result.getString("severity"));
        assertTrue(result.getInt("score") <= 10);
        assertTrue(result.getString("recommendation").contains("SAFE_TO_OPEN"));
    }

    @Test
    public void testEicarMalwareDetection() throws Exception {
        String eicarSignature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        byte[] eicarBytes = eicarSignature.getBytes(StandardCharsets.US_ASCII);

        // Directly test UniversalMagicDetector on EICAR bytes
        UniversalMagicDetector.DetectionResult res = UniversalMagicDetector.detectMagic(eicarBytes, "sample.txt");
        assertEquals("application/x-eicar-test", res.mimeType);
        assertEquals("MALWARE_TEST", res.canonicalCategory);
        assertTrue(res.isExecutable);

        // Test mock Uri inspection with stream to avoid OS-level host AV interception on disk
        android.content.ContentResolver mockResolver = Mockito.mock(android.content.ContentResolver.class);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);
        android.net.Uri mockUri = Mockito.mock(android.net.Uri.class);
        when(mockUri.toString()).thenReturn("content://downloads/eicar.com");
        when(mockResolver.openInputStream(mockUri)).thenAnswer(inv -> new java.io.ByteArrayInputStream(eicarBytes));

        JSONObject result = shieldService.inspectUri(mockUri, "eicar.com");
        assertNotNull(result);
        assertEquals("DANGEROUS", result.getString("verdict"));
        assertEquals("CRITICAL", result.getString("severity"));
        assertEquals(100, result.getInt("score"));

        JSONArray evidence = result.getJSONArray("evidence");
        boolean hasEicar = false;
        for (int i = 0; i < evidence.length(); i++) {
            if ("EICAR_TEST_PAYLOAD".equals(evidence.getJSONObject(i).getString("code"))) {
                hasEicar = true;
                break;
            }
        }
        assertTrue("Evidence should contain EICAR_TEST_PAYLOAD", hasEicar);
    }

    @Test
    public void testDeceptiveDoubleExtensionDetection() throws Exception {
        File doubleExtFile = tempFolder.newFile("invoice.pdf.exe");
        try (FileOutputStream fos = new FileOutputStream(doubleExtFile)) {
            // Write standard PE header
            fos.write(new byte[]{0x4D, 0x5A, 0x00, 0x00});
        }

        JSONObject result = shieldService.inspectFile(doubleExtFile);
        assertNotNull(result);
        assertEquals("DANGEROUS", result.getString("verdict"));
        assertTrue(result.getInt("score") >= 85);

        JSONArray evidence = result.getJSONArray("evidence");
        boolean hasDoubleExt = false;
        for (int i = 0; i < evidence.length(); i++) {
            if ("DECEPTIVE_DOUBLE_EXTENSION".equals(evidence.getJSONObject(i).getString("code"))) {
                hasDoubleExt = true;
                break;
            }
        }
        assertTrue("Evidence should detect deceptive double extension", hasDoubleExt);
    }

    @Test
    public void testArchiveWithEmbeddedExecutable() throws Exception {
        File zipFile = tempFolder.newFile("archive_with_exe.zip");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile))) {
            ZipEntry entry = new ZipEntry("payload.exe");
            zos.putNextEntry(entry);
            zos.write(new byte[]{0x4D, 0x5A});
            zos.closeEntry();
        }

        JSONObject result = shieldService.inspectFile(zipFile);
        assertNotNull(result);
        assertTrue(result.getInt("score") >= 70);
        assertNotNull(result.optJSONObject("archiveInspection"));
        assertTrue(result.getJSONObject("archiveInspection").getBoolean("hasSuspiciousExecutables"));
    }

    @Test
    public void testQuarantineVaultIsolation() throws Exception {
        File maliciousFile = tempFolder.newFile("sample_threat.bin");
        try (FileOutputStream fos = new FileOutputStream(maliciousFile)) {
            fos.write("malicious payload bytes".getBytes(StandardCharsets.UTF_8));
        }

        JSONObject qResult = shieldService.quarantineFile(maliciousFile);
        assertNotNull(qResult);
        assertEquals("QUARANTINED", qResult.getString("status"));
        assertTrue(qResult.has("quarantinePath"));

        String qPath = qResult.getString("quarantinePath");
        File qFile = new File(qPath);
        assertTrue("Quarantined file must exist in vault", qFile.exists());
    }

    @Test
    public void testHasDeceptiveDoubleExtensionStaticHelper() {
        assertTrue(UniversalFileShieldService.hasDeceptiveDoubleExtension("contract.pdf.exe"));
        assertTrue(UniversalFileShieldService.hasDeceptiveDoubleExtension("photo.jpg.scr"));
        assertTrue(UniversalFileShieldService.hasDeceptiveDoubleExtension("table.xlsx.bat"));
        assertFalse(UniversalFileShieldService.hasDeceptiveDoubleExtension("normal.pdf"));
        assertFalse(UniversalFileShieldService.hasDeceptiveDoubleExtension("normal.exe"));
        assertFalse(UniversalFileShieldService.hasDeceptiveDoubleExtension("archive.tar.gz"));
    }
}
