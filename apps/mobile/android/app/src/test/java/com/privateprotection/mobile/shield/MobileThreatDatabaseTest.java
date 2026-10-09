package com.privateprotection.mobile.shield;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Locale;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class MobileThreatDatabaseTest {

    private Context mockContext;
    private File tempDbDir;
    private MobileThreatDatabase threatDatabase;

    // Ephemeral KeyPair for testing valid Ed25519 signatures
    private KeyPair testKeyPair;
    private String testPublicKeyHex;

    @Before
    public void setUp() throws Exception {
        MobileThreatDatabase.resetInstanceForTesting();
        tempDbDir = new File(System.getProperty("java.io.tmpdir"), "ppdb_test_" + System.currentTimeMillis());
        tempDbDir.mkdirs();

        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getDatabasePath(Mockito.anyString())).thenAnswer(invocation ->
                new File(tempDbDir, (String) invocation.getArgument(0)));

        threatDatabase = MobileThreatDatabase.getInstance(mockContext);
        MobileThreatDatabase.setAllowTestKeysForTesting(true);

        // Generate test Ed25519 keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        testKeyPair = kpg.generateKeyPair();

        // Extract raw 32-byte public key from DER SPKI
        byte[] encoded = testKeyPair.getPublic().getEncoded();
        // SPKI for Ed25519 is 44 bytes total; raw key is last 32 bytes
        byte[] rawPubKey = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, rawPubKey, 0, 32);
        testPublicKeyHex = bytesToHex(rawPubKey);
    }

    @After
    public void tearDown() {
        if (threatDatabase != null) {
            threatDatabase.close();
        }
        MobileThreatDatabase.resetInstanceForTesting();
        deleteRecursive(tempDbDir);
        MobileThreatDatabase.setAllowTestKeysForTesting(false);
    }

    private void deleteRecursive(File f) {
        if (f.isDirectory()) {
            for (File c : f.listFiles()) deleteRecursive(c);
        }
        f.delete();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String signMessage(String message, java.security.PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(signer.sign());
    }

    private String computeSha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(data));
    }

    @Test
    public void testFactorySeedIntegrity() {
        // EICAR hash must exist and be CRITICAL MALWARE
        String eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        MobileThreatDatabase.ThreatRecord rec = threatDatabase.lookupFileHash(eicar);
        assertNotNull("EICAR test hash must be present in factory seed", rec);
        assertEquals("MALWARE", rec.category);
        assertEquals("CRITICAL", rec.severity);
        assertTrue(rec.isCritical);

        // Synthetic malware hash
        String synthetic = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b801";
        MobileThreatDatabase.ThreatRecord synRec = threatDatabase.lookupFileHash(synthetic);
        assertNotNull("Synthetic trojan hash must be present", synRec);

        // Known seed domains
        assertTrue("eicar.org must be recognized as bad domain", threatDatabase.isDomainMalicious("eicar.org"));
        assertTrue("Subdomain of seed must be recognized", threatDatabase.isDomainMalicious("login.phishing-bank-login.com"));
        assertFalse("Legitimate domain must be safe", threatDatabase.isDomainMalicious("google.com"));

        // Metadata check
        JSONObject meta = threatDatabase.getActiveMetadata();
        assertTrue("Must be marked factory seed", "true".equals(meta.optString("is_factory_seed")));
        assertEquals(100, threatDatabase.getVersionSequence());
    }

    @Test
    public void testRejectUnconfiguredOrPlaceholderZeroTrustKey() {
        String updatePayload = "{\"addRecords\":[],\"removeIndicators\":[]}";
        JSONObject manifest = new JSONObject();
        try {
            manifest.put("targetSequence", 105);
            manifest.put("targetVersion", "1.0.5");
            manifest.put("formatVersion", "PPDB_V1");
            manifest.put("recordsCount", 0);
            manifest.put("sha256", computeSha256(updatePayload.getBytes(StandardCharsets.UTF_8)));
            manifest.put("ed25519Signature", "deadbeef");

            JSONObject bundle = new JSONObject();
            bundle.put("manifest", manifest);
            bundle.put("payload", new JSONObject(updatePayload));

            // Explicitly pass placeholder zero key
            MobileThreatDatabase.UpdateResult res = threatDatabase.applySignedUpdateBundle(
                    bundle.toString(),
                    MobileThreatDatabase.PLACEHOLDER_ZERO_KEY
            );

            assertFalse("All-zero placeholder trust key must be rejected", res.success);
            assertEquals("UNCONFIGURED_TRUST_KEY", res.code);
        } catch (Exception e) {
            fail("Exception thrown: " + e.getMessage());
        }
    }

    @Test
    public void testRejectTestKeyWhenTestModeDisabled() throws Exception {
        MobileThreatDatabase.setAllowTestKeysForTesting(false);

        String updatePayload = "{\"addRecords\":[],\"removeIndicators\":[]}";
        String payloadDigest = computeSha256(updatePayload.getBytes(StandardCharsets.UTF_8));
        String canonicalMsg = "105:PPDB_V1:" + payloadDigest;
        String sig = signMessage(canonicalMsg, testKeyPair.getPrivate());

        JSONObject manifest = new JSONObject();
        manifest.put("targetSequence", 105);
        manifest.put("targetVersion", "1.0.5");
        manifest.put("formatVersion", "PPDB_V1");
        manifest.put("recordsCount", 0);
        manifest.put("sha256", payloadDigest);
        manifest.put("ed25519Signature", sig);

        JSONObject bundle = new JSONObject();
        bundle.put("manifest", manifest);
        bundle.put("payload", new JSONObject(updatePayload));

        // Use a known test key hex
        String knownTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        MobileThreatDatabase.UpdateResult res = threatDatabase.applySignedUpdateBundle(
                bundle.toString(),
                knownTestKeyHex
        );

        assertFalse("Test key must be rejected in production mode", res.success);
        assertEquals("TEST_KEY_REJECTED", res.code);
    }

    @Test
    public void testStrictMonotonicAntiDowngrade() throws Exception {
        String updatePayload = "{\"addRecords\":[],\"removeIndicators\":[]}";
        String payloadDigest = computeSha256(updatePayload.getBytes(StandardCharsets.UTF_8));

        // Sequence <= currentSequence (100)
        int downgradeSeq = 99;
        String canonicalMsg = downgradeSeq + ":PPDB_V1:" + payloadDigest;
        String sig = signMessage(canonicalMsg, testKeyPair.getPrivate());

        JSONObject manifest = new JSONObject();
        manifest.put("targetSequence", downgradeSeq);
        manifest.put("targetVersion", "0.9.9");
        manifest.put("formatVersion", "PPDB_V1");
        manifest.put("recordsCount", 0);
        manifest.put("sha256", payloadDigest);
        manifest.put("ed25519Signature", sig);

        JSONObject bundle = new JSONObject();
        bundle.put("manifest", manifest);
        bundle.put("payload", new JSONObject(updatePayload));

        MobileThreatDatabase.UpdateResult res = threatDatabase.applySignedUpdateBundle(
                bundle.toString(),
                testPublicKeyHex
        );

        assertFalse("Downgrade sequence must be rejected", res.success);
        assertEquals("DOWNGRADE_OR_REPLAY_REJECTED", res.code);
    }

    @Test
    public void testRejectInvalidSignature() throws Exception {
        String updatePayload = "{\"addRecords\":[],\"removeIndicators\":[]}";
        String payloadDigest = computeSha256(updatePayload.getBytes(StandardCharsets.UTF_8));

        // Sign with a completely different ephemeral key
        KeyPair rogueKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String canonicalMsg = "105:PPDB_V1:" + payloadDigest;
        String rogueSig = signMessage(canonicalMsg, rogueKeyPair.getPrivate());

        JSONObject manifest = new JSONObject();
        manifest.put("targetSequence", 105);
        manifest.put("targetVersion", "1.0.5");
        manifest.put("formatVersion", "PPDB_V1");
        manifest.put("recordsCount", 0);
        manifest.put("sha256", payloadDigest);
        manifest.put("ed25519Signature", rogueSig);

        JSONObject bundle = new JSONObject();
        bundle.put("manifest", manifest);
        bundle.put("payload", new JSONObject(updatePayload));

        MobileThreatDatabase.UpdateResult res = threatDatabase.applySignedUpdateBundle(
                bundle.toString(),
                testPublicKeyHex
        );

        assertFalse("Invalid signature must fail verification", res.success);
        assertEquals("SIGNATURE_VERIFICATION_FAILED", res.code);
    }

    @Test
    public void testRejectPayloadDigestMismatch() throws Exception {
        String originalPayload = "{\"addRecords\":[],\"removeIndicators\":[]}";
        String payloadDigest = computeSha256(originalPayload.getBytes(StandardCharsets.UTF_8));
        String canonicalMsg = "105:PPDB_V1:" + payloadDigest;
        String sig = signMessage(canonicalMsg, testKeyPair.getPrivate());

        // Tamper with payload after signing
        String tamperedPayload = "{\"addRecords\":[{\"indicator\":\"attacker.com\",\"type\":\"DOMAIN\"}],\"removeIndicators\":[]}";

        JSONObject manifest = new JSONObject();
        manifest.put("targetSequence", 105);
        manifest.put("targetVersion", "1.0.5");
        manifest.put("formatVersion", "PPDB_V1");
        manifest.put("recordsCount", 0);
        manifest.put("sha256", payloadDigest);
        manifest.put("ed25519Signature", sig);

        JSONObject bundle = new JSONObject();
        bundle.put("manifest", manifest);
        bundle.put("payload", new JSONObject(tamperedPayload));

        MobileThreatDatabase.UpdateResult res = threatDatabase.applySignedUpdateBundle(
                bundle.toString(),
                testPublicKeyHex
        );

        assertFalse("Tampered payload must trigger digest mismatch", res.success);
        assertEquals("PAYLOAD_DIGEST_MISMATCH", res.code);
    }

    @Test
    public void testApplyValidSignedUpdateAndVerifyDetection() throws Exception {
        String testBadHash = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";
        String testBadDomain = "zero-day-phish-portal.cc";

        JSONObject addRecordHash = new JSONObject();
        addRecordHash.put("indicator", testBadHash);
        addRecordHash.put("type", "FILE_HASH");
        addRecordHash.put("threatName", "OTA_ZERO_DAY_TROJAN");
        addRecordHash.put("category", "MALWARE");
        addRecordHash.put("severity", "CRITICAL");
        addRecordHash.put("isCritical", true);

        JSONObject addRecordDomain = new JSONObject();
        addRecordDomain.put("indicator", testBadDomain);
        addRecordDomain.put("type", "DOMAIN");
        addRecordDomain.put("threatName", "OTA_ZERO_DAY_PHISH");
        addRecordDomain.put("category", "PHISHING");
        addRecordDomain.put("severity", "HIGH");
        addRecordDomain.put("isCritical", false);

        JSONArray addRecords = new JSONArray();
        addRecords.put(addRecordHash);
        addRecords.put(addRecordDomain);

        JSONObject payload = new JSONObject();
        payload.put("addRecords", addRecords);
        payload.put("removeIndicators", new JSONArray());

        String payloadStr = payload.toString();
        String payloadDigest = computeSha256(payloadStr.getBytes(StandardCharsets.UTF_8));
        int targetSeq = 110;
        String canonicalMsg = targetSeq + ":PPDB_V1:" + payloadDigest;
        String sig = signMessage(canonicalMsg, testKeyPair.getPrivate());

        JSONObject manifest = new JSONObject();
        manifest.put("targetSequence", targetSeq);
        manifest.put("targetVersion", "1.1.0-ota");
        manifest.put("formatVersion", "PPDB_V1");
        manifest.put("recordsCount", 2);
        manifest.put("sha256", payloadDigest);
        manifest.put("ed25519Signature", sig);
        manifest.put("sourceFeed", "OTA_THREAT_FEED");

        JSONObject bundle = new JSONObject();
        bundle.put("manifest", manifest);
        bundle.put("payload", payload);

        // Before update: indicators do not exist
        assertNull(threatDatabase.lookupFileHash(testBadHash));
        assertFalse(threatDatabase.isDomainMalicious(testBadDomain));

        // Apply update
        MobileThreatDatabase.UpdateResult res = threatDatabase.applySignedUpdateBundle(
                bundle.toString(),
                testPublicKeyHex
        );

        assertTrue("Valid update must succeed: " + res.message, res.success);
        assertEquals(targetSeq, threatDatabase.getVersionSequence());

        // Indicators now immediately resolved in-memory
        MobileThreatDatabase.ThreatRecord foundHash = threatDatabase.lookupFileHash(testBadHash);
        assertNotNull("Newly installed malicious hash must be detected", foundHash);
        assertEquals("OTA_ZERO_DAY_TROJAN", foundHash.threatName);
        assertTrue(threatDatabase.isDomainMalicious(testBadDomain));
        assertTrue(threatDatabase.isDomainMalicious("sub." + testBadDomain));

        // Rollback restores factory seed and removes newly added indicators
        boolean rollbackOk = threatDatabase.rollbackToFactorySeed();
        assertTrue("Rollback must succeed", rollbackOk);
        assertEquals(100, threatDatabase.getVersionSequence());
        assertNull("Rolled back hash must no longer be present", threatDatabase.lookupFileHash(testBadHash));
        assertFalse("Rolled back domain must no longer be present", threatDatabase.isDomainMalicious(testBadDomain));

        // Factory seed indicators still present after rollback
        String eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assertNotNull("EICAR remains present after rollback", threatDatabase.lookupFileHash(eicar));
    }
}
