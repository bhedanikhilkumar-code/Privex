package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class RealtimeDownloadProtectionServiceTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private ContentResolver mockResolver;
    private RealtimeDownloadProtectionService service;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        mockResolver = Mockito.mock(ContentResolver.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);
        when(mockContext.getFilesDir()).thenReturn(tempFolder.getRoot());

        service = new RealtimeDownloadProtectionService(mockContext);
    }

    @Test
    public void testHandleMissingFileReturnsInaccessible() {
        File missing = new File(tempFolder.getRoot(), "ghost.apk");
        JSONObject res = service.handleIncomingFile(missing);
        assertNotNull(res);
        assertEquals("INACCESSIBLE", res.optString("status"));
    }

    @Test
    public void testHandlePartialDownloadDeferred() throws Exception {
        File partial = tempFolder.newFile("sample.pdf.crdownload");
        JSONObject res = service.handleIncomingFile(partial);
        assertNotNull(res);
        assertEquals("DEFERRED", res.optString("status"));
        assertNotEquals("ALLOW", res.optString("verdict"));
    }

    @Test
    public void testHandleCleanFileAndDeduplication() throws Exception {
        File clean = tempFolder.newFile("receipt.txt");
        try (FileOutputStream fos = new FileOutputStream(clean)) {
            fos.write("Official payment receipt #12345".getBytes(StandardCharsets.UTF_8));
        }

        JSONObject res1 = service.handleIncomingFile(clean);
        assertNotNull(res1);
        assertEquals("COMPLETED", res1.optString("status"));
        assertEquals("ALLOW", res1.optString("verdict"));

        // Second call without changing file should be suppressed duplicate or clean cache hit
        JSONObject res2 = service.handleIncomingFile(clean);
        assertNotNull(res2);
        assertTrue(res2.optBoolean("cached"));
        assertEquals("ALLOW", res2.optString("verdict"));
    }

    @Test
    public void testFileModificationTriggersFreshRescan() throws Exception {
        File doc = tempFolder.newFile("notes.txt");
        try (FileOutputStream fos = new FileOutputStream(doc)) {
            fos.write("Clean document".getBytes(StandardCharsets.UTF_8));
        }

        JSONObject res1 = service.handleIncomingFile(doc);
        assertEquals("COMPLETED", res1.optString("status"));
        assertEquals("ALLOW", res1.optString("verdict"));

        // Append bytes and change file size/mtime
        Thread.sleep(50);
        try (FileOutputStream fos = new FileOutputStream(doc, true)) {
            fos.write(" - updated text content".getBytes(StandardCharsets.UTF_8));
        }

        JSONObject res2 = service.handleIncomingFile(doc);
        assertEquals("COMPLETED", res2.optString("status"));
        assertFalse(res2.optBoolean("cached"));
    }

    @Test
    public void testMaliciousDoubleExtensionDetection() throws Exception {
        File malware = tempFolder.newFile("invoice.pdf.exe");
        try (FileOutputStream fos = new FileOutputStream(malware)) {
            // Write PE header bytes
            fos.write(new byte[]{0x4D, 0x5A, 0x00, 0x00});
        }

        JSONObject res = service.handleIncomingFile(malware);
        assertNotNull(res);
        assertEquals("COMPLETED", res.optString("status"));
        assertEquals("DANGEROUS", res.optString("verdict"));
        assertTrue(res.optInt("score") >= 85);
    }

    @Test
    public void testNullUriHandling() {
        JSONObject res = service.handleIncomingDownloadUri(null, "unknown.bin");
        assertNotNull(res);
        assertEquals("INACCESSIBLE", res.optString("status"));
    }

    @Test
    public void testTruthfulPlatformLimitationDisclosure() {
        JSONObject status = service.getProtectionStatus();
        assertNotNull(status);
        assertFalse("Third-party Android apps cannot claim pre-open interception",
                status.optBoolean("isPreOpenInterceptionSupported"));
        assertTrue(status.optString("platformLimitationNotice").contains("System-wide pre-open interception is not supported"));
    }

    @Test
    public void testCatchUpReconciliationStructure() {
        JSONObject catchUp = service.reconcileCatchUp();
        assertNotNull(catchUp);
        assertTrue(catchUp.has("discovered"));
        assertTrue(catchUp.has("rescanned"));
        assertTrue(catchUp.has("skipped"));
        assertTrue(catchUp.has("threatsFound"));
    }
}
