package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import com.privateprotection.mobile.core.SecurityJob;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class FullDeviceScanServiceTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private ContentResolver mockResolver;
    private PackageManager mockPackageManager;
    private FullDeviceScanService scanService;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        mockResolver = Mockito.mock(ContentResolver.class);
        mockPackageManager = Mockito.mock(PackageManager.class);

        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);
        when(mockContext.getPackageManager()).thenReturn(mockPackageManager);
        when(mockContext.getFilesDir()).thenReturn(tempFolder.getRoot());

        // Setup mock empty packages
        PackageInfo sampleApp = new PackageInfo();
        sampleApp.packageName = "com.sample.app";
        sampleApp.applicationInfo = new ApplicationInfo();
        sampleApp.applicationInfo.flags = 0; // user app
        when(mockPackageManager.getInstalledPackages(anyInt())).thenReturn(Collections.singletonList(sampleApp));

        scanService = new FullDeviceScanService(mockContext);
    }

    @Test
    public void testQuickScanExecution() {
        JSONObject result = scanService.executeScan(FullDeviceScanService.ScanMode.QUICK_SCAN, null, null);
        assertNotNull(result);
        assertEquals("QUICK_SCAN", result.optString("scanMode"));
        assertTrue(result.has("status"));
        assertTrue(result.has("totalDiscovered"));
        assertTrue(result.has("scopes"));

        JSONObject coverage = result.optJSONObject("coverage");
        assertNotNull(coverage);
        assertFalse(coverage.optBoolean("isFullDeviceClaimed"));
        assertTrue(coverage.optString("coverageDescription").contains("Quick Scan"));
    }

    @Test
    public void testStandardScanExecution() {
        JSONObject result = scanService.executeScan(FullDeviceScanService.ScanMode.STANDARD_SCAN, null, null);
        assertNotNull(result);
        assertEquals("STANDARD_SCAN", result.optString("scanMode"));
        assertTrue(result.has("scopes"));

        JSONArray scopes = result.optJSONArray("scopes");
        assertNotNull(scopes);
        assertTrue(scopes.length() >= 4); // Downloads, Images, Video, Audio, Apps, Vault
    }

    @Test
    public void testFullAccessibleDeviceScanTruthfulness() {
        JSONObject result = scanService.executeScan(FullDeviceScanService.ScanMode.FULL_ACCESSIBLE_SCAN, null, null);
        assertNotNull(result);
        assertEquals("FULL_ACCESSIBLE_SCAN", result.optString("scanMode"));

        JSONObject coverage = result.optJSONObject("coverage");
        assertNotNull(coverage);
        assertFalse("Must never falsely claim 100% full device scanned", coverage.optBoolean("isFullDeviceClaimed"));
        assertTrue(coverage.optString("coverageDescription").contains("Protected system directories were truthfully skipped"));

        JSONArray scopes = result.optJSONArray("scopes");
        boolean hasRestrictedScope = false;
        for (int i = 0; i < scopes.length(); i++) {
            JSONObject s = scopes.optJSONObject(i);
            if ("scope_restricted_system".equals(s.optString("scopeId"))) {
                hasRestrictedScope = true;
                assertEquals("INACCESSIBLE", s.optString("accessibilityState"));
                assertEquals("SKIPPED", s.optString("scanStatus"));
                break;
            }
        }
        assertTrue("Full Accessible scan must include and truthfully report restricted system scope", hasRestrictedScope);
    }

    @Test
    public void testCooperativeScanCancellation() {
        com.privateprotection.mobile.core.JobExecutionController mockCtrl =
                Mockito.mock(com.privateprotection.mobile.core.JobExecutionController.class);
        when(mockCtrl.isCancellationRequested()).thenReturn(true);

        JSONObject result = scanService.executeScan(FullDeviceScanService.ScanMode.QUICK_SCAN, mockCtrl, null);
        assertNotNull(result);
        assertEquals("CANCELLED", result.optString("status"));
    }
}
