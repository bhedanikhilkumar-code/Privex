package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.MediaStore;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileOutputStream;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class DownloadStabilizerTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private ContentResolver mockResolver;
    private DownloadStabilizer stabilizer;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        mockResolver = Mockito.mock(ContentResolver.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);
        stabilizer = new DownloadStabilizer(mockContext);
    }

    @Test
    public void testPartialDownloadNameDetection() {
        assertTrue(DownloadStabilizer.isPartialDownloadName("document.pdf.crdownload"));
        assertTrue(DownloadStabilizer.isPartialDownloadName("payload.zip.part"));
        assertTrue(DownloadStabilizer.isPartialDownloadName("movie.mp4.download"));
        assertTrue(DownloadStabilizer.isPartialDownloadName("app.apk.tmp"));
        assertFalse(DownloadStabilizer.isPartialDownloadName("document.pdf"));
        assertFalse(DownloadStabilizer.isPartialDownloadName("app.apk"));
        assertFalse(DownloadStabilizer.isPartialDownloadName("archive.zip"));
        assertFalse(DownloadStabilizer.isPartialDownloadName(null));
    }

    @Test
    public void testFileStabilizationMissingFile() {
        File missing = new File(tempFolder.getRoot(), "missing.bin");
        DownloadStabilizer.StabilizationResult res = stabilizer.checkFileStabilization(missing);
        assertEquals(DownloadStabilizer.StabilizationState.INACCESSIBLE, res.state);
        assertFalse(res.isReady());
    }

    @Test
    public void testFileStabilizationPartialExtensionDeferred() throws Exception {
        File partial = tempFolder.newFile("sample.apk.crdownload");
        DownloadStabilizer.StabilizationResult res = stabilizer.checkFileStabilization(partial);
        assertEquals(DownloadStabilizer.StabilizationState.DEFERRED, res.state);
        assertFalse(res.isReady());
    }

    @Test
    public void testFileStabilizationZeroBytesStabilizing() throws Exception {
        File zeroByte = tempFolder.newFile("empty.pdf");
        DownloadStabilizer.StabilizationResult res = stabilizer.checkFileStabilization(zeroByte);
        assertEquals(DownloadStabilizer.StabilizationState.STABILIZING, res.state);
        assertFalse(res.isReady());
    }

    @Test
    public void testFileStabilizationValidFileReady() throws Exception {
        File valid = tempFolder.newFile("valid.pdf");
        try (FileOutputStream fos = new FileOutputStream(valid)) {
            fos.write("Sample PDF content".getBytes());
        }
        DownloadStabilizer.StabilizationResult res = stabilizer.checkFileStabilization(valid);
        assertEquals(DownloadStabilizer.StabilizationState.READY_TO_SCAN, res.state);
        assertTrue(res.isReady());
        assertEquals(valid.length(), res.size);
    }

    @Test
    public void testUriStabilizationNullUri() {
        DownloadStabilizer.StabilizationResult res = stabilizer.checkUriStabilization(null);
        assertEquals(DownloadStabilizer.StabilizationState.INACCESSIBLE, res.state);
        assertFalse(res.isReady());
    }

    @Test
    public void testUriStabilizationPartialNameInUriDeferred() {
        Uri mockUri = Mockito.mock(Uri.class);
        when(mockUri.toString()).thenReturn("content://downloads/file.zip.crdownload");
        DownloadStabilizer.StabilizationResult res = stabilizer.checkUriStabilization(mockUri);
        assertEquals(DownloadStabilizer.StabilizationState.DEFERRED, res.state);
        assertFalse(res.isReady());
    }

    @Test
    public void testUriStabilizationCursorReady() {
        Uri mockUri = Mockito.mock(Uri.class);
        when(mockUri.toString()).thenReturn("content://downloads/101");

        Cursor mockCursor = Mockito.mock(Cursor.class);
        when(mockResolver.query(eq(mockUri), any(), any(), any(), any())).thenReturn(mockCursor);
        when(mockCursor.moveToFirst()).thenReturn(true);
        when(mockCursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)).thenReturn(0);
        when(mockCursor.getString(0)).thenReturn("invoice.pdf");
        when(mockCursor.getColumnIndex(MediaStore.MediaColumns.SIZE)).thenReturn(1);
        when(mockCursor.getLong(1)).thenReturn(4096L);
        when(mockCursor.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED)).thenReturn(2);
        when(mockCursor.getLong(2)).thenReturn(123456789L);
        when(mockCursor.getColumnIndex(MediaStore.MediaColumns.MIME_TYPE)).thenReturn(3);
        when(mockCursor.getString(3)).thenReturn("application/pdf");

        DownloadStabilizer.StabilizationResult res = stabilizer.checkUriStabilization(mockUri);
        assertEquals(DownloadStabilizer.StabilizationState.READY_TO_SCAN, res.state);
        assertTrue(res.isReady());
        assertEquals(4096L, res.size);
    }
}
