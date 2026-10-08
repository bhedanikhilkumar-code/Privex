package com.privateprotection.mobile.shield;

import android.content.Context;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class MobileCleanFileCacheTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private MobileCleanFileCache cache;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getFilesDir()).thenReturn(tempFolder.getRoot());
        cache = new MobileCleanFileCache(mockContext);
        cache.clear();
    }

    @Test
    public void testPutAndGetCleanFile() {
        String path = "/storage/emulated/0/Download/safe_document.pdf";
        long size = 2048L;
        long mtime = 1700000000000L;
        String sha256 = "abcdef1234567890";

        assertFalse(cache.isClean(path, size, mtime));

        cache.putClean(path, size, mtime, sha256);
        assertTrue(cache.isClean(path, size, mtime));
        assertEquals(1, cache.size());
    }

    @Test
    public void testCacheInvalidationOnSizeOrMtimeChange() {
        String path = "/storage/emulated/0/Download/modified_file.txt";
        long originalSize = 100L;
        long originalMtime = 1700000000000L;

        cache.putClean(path, originalSize, originalMtime, "hash1");
        assertTrue(cache.isClean(path, originalSize, originalMtime));

        // File modified (mtime updated)
        assertFalse(cache.isClean(path, originalSize, originalMtime + 5000L));

        // File size changed
        assertFalse(cache.isClean(path, originalSize + 50L, originalMtime));
    }

    @Test
    public void testExplicitInvalidateAndClear() {
        String path = "/storage/emulated/0/Download/file.bin";
        cache.putClean(path, 500L, 1000L, "hash");
        assertTrue(cache.isClean(path, 500L, 1000L));

        cache.invalidate(path, 500L, 1000L);
        assertFalse(cache.isClean(path, 500L, 1000L));

        cache.putClean(path, 500L, 1000L, "hash");
        cache.clear();
        assertEquals(0, cache.size());
    }

    @Test
    public void testDiskPersistence() {
        String path = "/storage/emulated/0/Download/persisted.pdf";
        cache.putClean(path, 1024L, 2000L, "hash");
        cache.persistToDisk();

        // Create new cache instance from same folder to verify recovery from disk
        MobileCleanFileCache newCache = new MobileCleanFileCache(mockContext);
        assertTrue(newCache.isClean(path, 1024L, 2000L));
    }
}
