package com.privateprotection.mobile.shield;

import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for PackageMetadata model and serialization.
 */
public class PackageMetadataTest {

    @Test
    public void testPackageMetadataConstructionAndGetters() {
        PackageMetadata meta = new PackageMetadata(
                "com.example.malicious",
                "Malicious Sample",
                "1.2.3",
                42L,
                1000L,
                2000L,
                "com.android.vending",
                "/data/app/com.example.malicious/base.apk",
                false,
                Arrays.asList("android.permission.INTERNET", "android.permission.READ_SMS"),
                Collections.singletonList("android.permission.READ_SMS"),
                Collections.singletonList("activity:com.example.malicious.MainActivity"),
                Collections.singletonList("abcdef1234567890")
        );

        assertEquals("com.example.malicious", meta.getPackageName());
        assertEquals("Malicious Sample", meta.getAppLabel());
        assertEquals("1.2.3", meta.getVersionName());
        assertEquals(42L, meta.getVersionCode());
        assertEquals(1000L, meta.getFirstInstallTimeMs());
        assertEquals(2000L, meta.getLastUpdateTimeMs());
        assertEquals("com.android.vending", meta.getInstallerPackageName());
        assertEquals("/data/app/com.example.malicious/base.apk", meta.getSourceDir());
        assertFalse(meta.isSystemApp());
        assertEquals(2, meta.getRequestedPermissions().size());
        assertEquals(1, meta.getDangerousPermissions().size());
        assertEquals(1, meta.getExportedComponents().size());
        assertEquals(1, meta.getSigningCertSha256s().size());
    }

    @Test
    public void testJSONSerializationRoundTrip() {
        PackageMetadata original = new PackageMetadata(
                "com.test.app",
                "Test App",
                "2.0.0",
                100L,
                5000L,
                6000L,
                "org.fdroid.fdroid",
                "/data/app/test.apk",
                true,
                Collections.singletonList("android.permission.CAMERA"),
                Collections.singletonList("android.permission.CAMERA"),
                Collections.emptyList(),
                Collections.singletonList("sha256_mock_cert")
        );

        JSONObject json = original.toJSON();
        assertNotNull(json);

        PackageMetadata restored = PackageMetadata.fromJSON(json);
        assertEquals(original.getPackageName(), restored.getPackageName());
        assertEquals(original.getAppLabel(), restored.getAppLabel());
        assertEquals(original.getVersionName(), restored.getVersionName());
        assertEquals(original.getVersionCode(), restored.getVersionCode());
        assertEquals(original.getFirstInstallTimeMs(), restored.getFirstInstallTimeMs());
        assertEquals(original.getLastUpdateTimeMs(), restored.getLastUpdateTimeMs());
        assertEquals(original.getInstallerPackageName(), restored.getInstallerPackageName());
        assertEquals(original.getSourceDir(), restored.getSourceDir());
        assertTrue(restored.isSystemApp());
        assertEquals(1, restored.getRequestedPermissions().size());
        assertEquals(1, restored.getDangerousPermissions().size());
        assertEquals(0, restored.getExportedComponents().size());
        assertEquals(1, restored.getSigningCertSha256s().size());
    }

    @Test
    public void testNullSafetyInModel() {
        PackageMetadata nullMeta = new PackageMetadata(null, null, null, 0, 0, 0, null, null, false, null, null, null, null);
        assertEquals("", nullMeta.getPackageName());
        assertEquals("", nullMeta.getAppLabel());
        assertEquals("", nullMeta.getVersionName());
        assertEquals("", nullMeta.getInstallerPackageName());
        assertEquals("", nullMeta.getSourceDir());
        assertTrue(nullMeta.getRequestedPermissions().isEmpty());
        assertTrue(nullMeta.getDangerousPermissions().isEmpty());
        assertTrue(nullMeta.getExportedComponents().isEmpty());
        assertTrue(nullMeta.getSigningCertSha256s().isEmpty());

        JSONObject json = nullMeta.toJSON();
        assertNotNull(json);

        PackageMetadata fromNull = PackageMetadata.fromJSON(null);
        assertNotNull(fromNull);
        assertEquals("", fromNull.getPackageName());
    }
}
