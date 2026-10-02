package com.privateprotection.mobile;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * Android Instrumentation Tests: Runs on real Android Runtime (Emulator / Device).
 * Verifies real Android Keystore, EncryptedSharedPreferences, Storage Forensics, and Native Bridge.
 */
@RunWith(AndroidJUnit4.class)
public class AndroidSecurityBridgeInstrumentationTest {

    private Context context;
    private SecureStorageManager storageManager;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
        storageManager = new SecureStorageManager(context);
        storageManager.clear();
    }

    @After
    public void tearDown() {
        if (storageManager != null) {
            storageManager.clear();
        }
    }

    @Test
    public void testHardwareEncryptedStorageLifecycleAndForensics() throws Exception {
        assertTrue("Storage must be hardware-backed encrypted", storageManager.isHardwareEncrypted());

        String testKey = "user_secret_token";
        String testSecret = "TEST_SECRET_123";

        // 1. Write secret
        boolean written = storageManager.putString(testKey, testSecret);
        assertTrue("Put string should succeed", written);

        // 2. Read back
        String recovered = storageManager.getString(testKey, null);
        assertEquals("Recovered secret must match original value", testSecret, recovered);

        // 3. Storage Forensics: Inspect physical file on disk
        File prefsDir = new File(context.getApplicationInfo().dataDir, "shared_prefs");
        File prefXml = new File(prefsDir, SecureStorageManager.PREF_FILE_NAME + ".xml");
        assertTrue("Encrypted SharedPreferences XML file must exist on disk", prefXml.exists());

        byte[] bytes = new byte[(int) prefXml.length()];
        try (FileInputStream fis = new FileInputStream(prefXml)) {
            fis.read(bytes);
        }
        String xmlContent = new String(bytes, StandardCharsets.UTF_8);

        // FORENSIC ASSERTION: Plaintext secret MUST NOT appear anywhere in the XML!
        assertFalse("CRITICAL SECURITY FAILURE: Plaintext secret found in SharedPreferences XML!",
                xmlContent.contains("TEST_SECRET_123"));
        assertFalse("CRITICAL SECURITY FAILURE: Plaintext key found in SharedPreferences XML!",
                xmlContent.contains("user_secret_token"));

        // Must contain encrypted ciphertext entries and Keystore-backed keysets
        assertTrue("XML must contain encrypted keyset entries",
                xmlContent.contains("__androidx_security_crypto_encrypted_prefs_key_keyset__"));

        // 4. Crypto-shredding: Clear removes entries
        boolean cleared = storageManager.clear();
        assertTrue("Clear should succeed", cleared);
        assertNull("Key must be absent after clear", storageManager.getString(testKey, null));
    }

    @Test
    public void testQrCodeFrameDecodingOnAndroidRuntime() throws Exception {
        String testUrl = "https://privateprotection.org/threat-check";
        QRCodeWriter writer = new QRCodeWriter();
        int size = 200;
        BitMatrix matrix = writer.encode(testUrl, BarcodeFormat.QR_CODE, size, size);

        int[] pixels = new int[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                pixels[y * size + x] = matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
            }
        }

        String decoded = QrCodeDecoder.decodeRgbPixels(pixels, size, size);
        assertEquals("Decoded URL should match", testUrl, decoded);
    }
}
