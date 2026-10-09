package com.privateprotection.mobile.shield;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Unit tests for PackageAuditService risk evaluation algorithms.
 */
public class PackageAuditServiceTest {

    private PackageAuditService auditService;
    private Context mockContext;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        auditService = new PackageAuditService(mockContext);
    }

    @Test
    public void testCleanAppEvaluatesToAllow() {
        PackageMetadata cleanMeta = new PackageMetadata(
                "com.trusted.calculator",
                "Clean Calculator",
                "1.0.0",
                1L,
                1000L,
                1000L,
                "com.android.vending", // Google Play
                "/data/app/clean.apk",
                false,
                Collections.singletonList("android.permission.VIBRATE"),
                Collections.emptyList(), // No dangerous permissions
                Collections.singletonList("activity:MainActivity"),
                Collections.singletonList("cert_hash")
        );

        ApkStaticAnalyzer.InspectionResult cleanApk = new ApkStaticAnalyzer.InspectionResult(
                true, true, true, false, false, 1024, 10, Collections.emptyList(), Collections.singletonList("META-INF/CERT.RSA"), "hash"
        );

        JSONObject report = auditService.evaluateRisk(cleanMeta, cleanApk);
        assertNotNull(report);
        assertEquals("ALLOW", report.optString("verdict"));
        assertEquals("NONE", report.optString("severity"));
        assertTrue(report.optInt("score") < 20);
        assertFalse(report.optBoolean("isSideloaded"));
    }

    @Test
    public void testMaliciousTrojanWithAccessibilityAndSideload() {
        PackageMetadata trojanMeta = new PackageMetadata(
                "com.fake.bank.trojan",
                "System Update",
                "1.0.0",
                1L,
                1000L,
                1000L,
                "", // Sideloaded / Unknown installer
                "/data/app/trojan.apk",
                false,
                Arrays.asList(
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS",
                        "android.permission.REQUEST_INSTALL_PACKAGES"
                ),
                Arrays.asList(
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS",
                        "android.permission.REQUEST_INSTALL_PACKAGES"
                ),
                Arrays.asList("activity:A1", "activity:A2", "service:S1", "receiver:R1", "receiver:R2", "receiver:R3"),
                Collections.singletonList("cert_hash")
        );

        ApkStaticAnalyzer.InspectionResult dropperApk = new ApkStaticAnalyzer.InspectionResult(
                true, true, true, false, true, 2048, 15,
                Collections.singletonList("SUSPICIOUS_DROPPER_PAYLOAD: assets/payload.apk"),
                Collections.singletonList("META-INF/CERT.RSA"),
                "hash"
        );

        JSONObject report = auditService.evaluateRisk(trojanMeta, dropperApk);
        assertNotNull(report);
        assertEquals("DANGEROUS", report.optString("verdict"));
        assertEquals("CRITICAL", report.optString("severity"));
        assertEquals("IMMEDIATELY_UNINSTALL", report.optString("recommendation"));
        assertTrue(report.optInt("score") >= 70);
        assertTrue(report.optBoolean("isSideloaded"));

        JSONArray evidence = report.optJSONArray("evidence");
        assertNotNull(evidence);
        assertTrue(evidence.length() >= 4);
    }

    @Test
    public void testInaccessibleApkDoesNotMarkAsClean() {
        PackageMetadata meta = new PackageMetadata(
                "com.sideload.app",
                "Sideload App",
                "1.0.0",
                1L,
                1000L,
                1000L,
                "", // Sideloaded
                "/data/app/deleted.apk",
                false,
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList()
        );

        // Null apkInspection simulates inaccessible/deleted file on disk
        JSONObject report = auditService.evaluateRisk(meta, null);
        assertNotNull(report);
        JSONArray evidence = report.optJSONArray("evidence");
        assertNotNull(evidence);

        boolean foundInaccessibleSignal = false;
        for (int i = 0; i < evidence.length(); i++) {
            JSONObject ev = evidence.optJSONObject(i);
            if (ev != null && "APK_ARCHIVE_INACCESSIBLE".equals(ev.optString("code"))) {
                foundInaccessibleSignal = true;
                break;
            }
        }
        assertTrue("Inaccessible APK must generate APK_ARCHIVE_INACCESSIBLE evidence", foundInaccessibleSignal);
    }

    @Test
    public void testCreateUninstallIntent() {
        Intent intent = auditService.createUninstallIntent("com.malicious.app");
        assertNotNull(intent);

        Intent nullIntent = auditService.createUninstallIntent(null);
        org.junit.Assert.assertNull(nullIntent);

        Intent emptyIntent = auditService.createUninstallIntent("   ");
        org.junit.Assert.assertNull(emptyIntent);
    }

    @Test
    public void testCriticalSystemPackageSafeguards() {
        assertTrue(PackageAuditService.isCriticalSystemPackage("android"));
        assertTrue(PackageAuditService.isCriticalSystemPackage("com.android.systemui"));
        assertTrue(PackageAuditService.isCriticalSystemPackage("com.google.android.packageinstaller"));
        assertFalse(PackageAuditService.isCriticalSystemPackage("com.thirdparty.game"));

        // Critical system packages MUST NOT produce an uninstall intent
        Intent intent = auditService.createUninstallIntent("android");
        org.junit.Assert.assertNull("Uninstall intent must be refused for critical system package", intent);
    }

    @Test
    public void testEvaluateRemediationNonInstalledPackage() {
        JSONObject res = auditService.evaluateRemediation("com.nonexistent.app");
        assertNotNull(res);
        assertEquals("NOT_INSTALLED", res.optString("status"));
        assertFalse(res.optBoolean("canUninstall"));
        assertEquals("NO_ACTION_REQUIRED", res.optString("recommendedAction"));
    }

    @Test
    public void testCreateAppDetailsIntent() {
        Intent intent = auditService.createAppDetailsIntent("com.sample.app");
        assertNotNull(intent);
        org.junit.Assert.assertNull(auditService.createAppDetailsIntent(null));
        org.junit.Assert.assertNull(auditService.createAppDetailsIntent("   "));
    }
}
