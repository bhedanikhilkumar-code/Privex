package com.privateprotection.mobile.shield;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.*;

public class ScanScopeDescriptorTest {

    @Test
    public void testScanScopeDescriptorLifecycle() {
        ScanScopeDescriptor scope = new ScanScopeDescriptor(
                "scope_downloads",
                "Downloads Collection",
                ScanScopeDescriptor.ScopeType.MEDIASTORE_DOWNLOADS,
                "content://media/external/downloads",
                ScanScopeDescriptor.AccessibilityState.MEDIASTORE_ACCESSIBLE
        );

        assertEquals("scope_downloads", scope.getScopeId());
        assertEquals("Downloads Collection", scope.getDisplayName());
        assertEquals(ScanScopeDescriptor.ScopeType.MEDIASTORE_DOWNLOADS, scope.getScopeType());
        assertEquals(ScanScopeDescriptor.AccessibilityState.MEDIASTORE_ACCESSIBLE, scope.getAccessibilityState());
        assertEquals(ScanScopeDescriptor.ScopeScanStatus.PENDING, scope.getScanStatus());

        scope.incrementDiscovered();
        scope.incrementDiscovered();
        assertEquals(2, scope.getFilesDiscovered());

        scope.incrementScanned();
        assertEquals(1, scope.getFilesScanned());

        scope.incrementSkipped();
        assertEquals(1, scope.getFilesSkipped());

        scope.incrementThreats();
        assertEquals(1, scope.getThreatsFound());

        scope.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.COMPLETED);
        assertEquals(ScanScopeDescriptor.ScopeScanStatus.COMPLETED, scope.getScanStatus());

        JSONObject json = scope.toJSON();
        assertNotNull(json);
        assertEquals("scope_downloads", json.optString("scopeId"));
        assertEquals("COMPLETED", json.optString("scanStatus"));
        assertEquals(2, json.optInt("filesDiscovered"));
        assertEquals(1, json.optInt("filesScanned"));
        assertEquals(1, json.optInt("filesSkipped"));
        assertEquals(1, json.optInt("threatsFound"));
    }

    @Test
    public void testRestrictedSystemScopeTruthfulness() {
        ScanScopeDescriptor restricted = new ScanScopeDescriptor(
                "scope_restricted_system",
                "Restricted System Storage",
                ScanScopeDescriptor.ScopeType.RESTRICTED_SYSTEM,
                "/data/data",
                ScanScopeDescriptor.AccessibilityState.INACCESSIBLE
        );

        assertEquals(ScanScopeDescriptor.AccessibilityState.INACCESSIBLE, restricted.getAccessibilityState());
        restricted.setScanStatus(ScanScopeDescriptor.ScopeScanStatus.SKIPPED);
        restricted.setErrorDetails("Android sandbox restriction prevents third-party scanning");

        JSONObject json = restricted.toJSON();
        assertEquals("INACCESSIBLE", json.optString("accessibilityState"));
        assertEquals("SKIPPED", json.optString("scanStatus"));
        assertTrue(json.optString("errorDetails").contains("sandbox"));
    }
}
