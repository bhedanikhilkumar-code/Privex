package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.content.UriPermission;
import android.net.Uri;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SafManagerTest {

    private Context mockContext;
    private ContentResolver mockResolver;
    private SafManager safManager;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        mockResolver = Mockito.mock(ContentResolver.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);
        safManager = new SafManager(mockContext);
    }

    @Test
    public void testPersistTreePermissionSuccess() {
        Uri treeUri = Mockito.mock(Uri.class);
        when(treeUri.toString()).thenReturn("content://com.android.externalstorage.documents/tree/primary%3ADocuments");
        boolean result = safManager.persistTreePermission(treeUri);
        assertTrue("Expected persistTreePermission to return true", result);
        verify(mockResolver, atLeastOnce()).takePersistableUriPermission(eq(treeUri), anyInt());
    }

    @Test
    public void testReleaseTreePermissionSuccess() {
        Uri treeUri = Mockito.mock(Uri.class);
        when(treeUri.toString()).thenReturn("content://com.android.externalstorage.documents/tree/primary%3ADocuments");
        boolean result = safManager.releaseTreePermission(treeUri);
        assertTrue(result);
        verify(mockResolver, atLeastOnce()).releasePersistableUriPermission(eq(treeUri), anyInt());
    }

    @Test
    public void testGetPersistedTreesAndValidation() throws Exception {
        Uri treeUri = Mockito.mock(Uri.class);
        when(treeUri.toString()).thenReturn("content://com.android.externalstorage.documents/tree/primary%3ADocuments");
        UriPermission perm = Mockito.mock(UriPermission.class);
        when(perm.getUri()).thenReturn(treeUri);
        when(perm.isReadPermission()).thenReturn(true);
        when(mockResolver.getPersistedUriPermissions()).thenReturn(Collections.singletonList(perm));

        assertTrue(safManager.isTreePermissionValid(treeUri));
        assertEquals(1, safManager.getPersistedTreeUris().size());

        JSONArray json = safManager.getPersistedTreesJSON();
        assertEquals(1, json.length());
        assertTrue(json.getJSONObject(0).optBoolean("isValid"));
    }

    @Test
    public void testRevokedTreePermissionIsInvalid() {
        Uri treeUri = Mockito.mock(Uri.class);
        when(treeUri.toString()).thenReturn("content://com.android.externalstorage.documents/tree/primary%3ADocuments");
        when(mockResolver.getPersistedUriPermissions()).thenReturn(Collections.emptyList());

        assertFalse(safManager.isTreePermissionValid(treeUri));
    }
}
