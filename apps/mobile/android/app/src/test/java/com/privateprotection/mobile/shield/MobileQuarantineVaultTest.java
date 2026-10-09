package com.privateprotection.mobile.shield;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/**
 * MobileQuarantineVaultTest (Phase T10):
 *
 * Comprehensive unit and security tests for the mobile encrypted quarantine vault,
 * authenticated streaming (PPMVAULT1), state machine truthfulness, crash consistency,
 * restore integrity, and tamper resistance.
 */
public class MobileQuarantineVaultTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private File vaultDir;
    private MobileQuarantineVault vault;

    @Before
    public void setUp() throws Exception {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        File dummyFilesDir = tempFolder.newFolder("app_files");
        when(mockContext.getFilesDir()).thenReturn(dummyFilesDir);

        vaultDir = new File(dummyFilesDir, MobileQuarantineVault.VAULT_DIR_NAME);
        vault = new MobileQuarantineVault(mockContext, vaultDir);
    }

    @After
    public void tearDown() {
        if (vault != null) {
            vault.clearVaultForTesting();
        }
    }

    private String calculateSha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Test
    public void testSuccessfulEncryptedQuarantineAndIntegrityVerification() throws Exception {
        byte[] payload = "EICAR-STANDARD-ANTIVIRUS-TEST-PAYLOAD-FOR-VAULT-UNIT-TEST".getBytes(StandardCharsets.UTF_8);
        String expectedSha = calculateSha256(payload);

        File threatFile = tempFolder.newFile("eicar.com");
        try (FileOutputStream fos = new FileOutputStream(threatFile)) {
            fos.write(payload);
        }

        JSONObject result = vault.quarantineFile(threatFile, "DANGEROUS", "CRITICAL", "Eicar test string");
        assertNotNull(result);
        assertEquals(MobileQuarantineVault.STATE_ISOLATED, result.getString("status"));
        assertTrue(result.getBoolean("originalDeleted"));
        assertEquals(expectedSha, result.getString("sha256"));
        assertFalse("Original file must be removed", threatFile.exists());

        String itemId = result.getString("itemId");
        JSONObject record = vault.getItem(itemId);
        assertNotNull(record);
        assertEquals(MobileQuarantineVault.STATE_ISOLATED, record.getString("state"));
        assertEquals("eicar.com", record.getString("fileName"));

        File vaultBlob = new File(vaultDir, record.getString("vaultFileName"));
        assertTrue("Vault encrypted blob must exist on disk", vaultBlob.exists());

        // Verify blob header is encrypted container PPMVAULT
        byte[] headerMagic = new byte[8];
        try (FileInputStream fis = new FileInputStream(vaultBlob)) {
            fis.read(headerMagic);
        }
        assertArrayEquals(MobileQuarantineVault.CONTAINER_MAGIC, headerMagic);

        // Verify blob does NOT contain plaintext payload
        byte[] blobBytes = new byte[(int) vaultBlob.length()];
        try (FileInputStream fis = new FileInputStream(vaultBlob)) {
            fis.read(blobBytes);
        }
        String blobContent = new String(blobBytes, StandardCharsets.ISO_8859_1);
        assertFalse("Quarantine vault file must not contain raw plaintext",
                blobContent.contains("EICAR-STANDARD-ANTIVIRUS-TEST-PAYLOAD"));
    }

    @Test
    public void testMultiChunkStreamingAndBoundedMemory() throws Exception {
        // Create 150 KB payload to exercise multi-chunk (64 KB + 64 KB + 22 KB) streaming
        byte[] largePayload = new byte[150 * 1024];
        for (int i = 0; i < largePayload.length; i++) {
            largePayload[i] = (byte) ((i % 127) + 1);
        }
        String expectedSha = calculateSha256(largePayload);

        File largeThreat = tempFolder.newFile("large_dropper.bin");
        try (FileOutputStream fos = new FileOutputStream(largeThreat)) {
            fos.write(largePayload);
        }

        JSONObject result = vault.quarantineFile(largeThreat, "DANGEROUS", "CRITICAL", "Large binary threat");
        assertNotNull(result);
        assertEquals(MobileQuarantineVault.STATE_ISOLATED, result.getString("status"));
        assertEquals(expectedSha, result.getString("sha256"));

        String itemId = result.getString("itemId");
        JSONObject record = vault.getItem(itemId);
        assertEquals(150 * 1024, record.getLong("fileSizeBytes"));

        // Restore and verify roundtrip bytes match exactly
        File restored = new File(tempFolder.getRoot(), "restored_large.bin");
        JSONObject restoreRes = vault.restoreItem(itemId, restored.getAbsolutePath(), false, false);
        assertEquals("RESTORED", restoreRes.getString("status"));
        assertTrue(restored.exists());
        assertEquals(150 * 1024, restored.length());

        byte[] restoredBytes = new byte[(int) restored.length()];
        try (FileInputStream fis = new FileInputStream(restored)) {
            fis.read(restoredBytes);
        }
        assertArrayEquals("Restored bytes must match original payload", largePayload, restoredBytes);
    }

    @Test
    public void testTamperedCiphertextIsRejected() throws Exception {
        byte[] payload = "Suspicious script payload for tamper test".getBytes(StandardCharsets.UTF_8);
        File threat = tempFolder.newFile("script.js");
        try (FileOutputStream fos = new FileOutputStream(threat)) {
            fos.write(payload);
        }

        JSONObject qRes = vault.quarantineFile(threat, "SUSPICIOUS", "MEDIUM", "JS heuristic");
        String itemId = qRes.getString("itemId");
        JSONObject item = vault.getItem(itemId);
        File vaultFile = new File(vaultDir, item.getString("vaultFileName"));
        assertTrue(vaultFile.exists());

        // Tamper with ciphertext byte past header
        try (RandomAccessFile raf = new RandomAccessFile(vaultFile, "rw")) {
            raf.seek(MobileQuarantineVault.HEADER_SIZE + 10);
            byte current = raf.readByte();
            raf.seek(MobileQuarantineVault.HEADER_SIZE + 10);
            raf.writeByte(current ^ 0xFF); // flip bits
        }

        // Attempt restore; authenticated decryption MUST fail
        File target = new File(tempFolder.getRoot(), "tampered_restored.js");
        JSONObject restoreRes = vault.restoreItem(itemId, target.getAbsolutePath(), false, false);
        assertEquals("FAILED", restoreRes.getString("status"));
        assertEquals("RESTORE_VERIFICATION_FAILED", restoreRes.getString("error"));
        assertFalse("Tampered file must not be written to destination", target.exists());

        // Vault blob must remain intact on failure
        assertTrue("Vault blob must not be destroyed on failed restore", vaultFile.exists());
    }

    @Test
    public void testTruncatedVaultRecordIsRejected() throws Exception {
        byte[] payload = "Test payload for truncation".getBytes(StandardCharsets.UTF_8);
        File threat = tempFolder.newFile("sample.bin");
        try (FileOutputStream fos = new FileOutputStream(threat)) {
            fos.write(payload);
        }

        JSONObject qRes = vault.quarantineFile(threat, "DANGEROUS", "HIGH", "Sample threat");
        String itemId = qRes.getString("itemId");
        JSONObject item = vault.getItem(itemId);
        File vaultFile = new File(vaultDir, item.getString("vaultFileName"));

        // Truncate file to only 30 bytes (corrupt header)
        try (RandomAccessFile raf = new RandomAccessFile(vaultFile, "rw")) {
            raf.setLength(30);
        }

        File target = new File(tempFolder.getRoot(), "target.bin");
        JSONObject restoreRes = vault.restoreItem(itemId, target.getAbsolutePath(), false, false);
        assertEquals("FAILED", restoreRes.getString("status"));
        assertFalse(target.exists());
    }

    @Test
    public void testTruthfulStateWhenOriginalDeletionFails() throws Exception {
        byte[] payload = "Threat that cannot be deleted".getBytes(StandardCharsets.UTF_8);
        File nonDeletable = tempFolder.newFile("locked_threat.bin");
        try (FileOutputStream fos = new FileOutputStream(nonDeletable)) {
            fos.write(payload);
        }

        // Spy or create file that returns false on delete()
        File spiedFile = Mockito.spy(nonDeletable);
        Mockito.doReturn(false).when(spiedFile).delete();

        JSONObject res = vault.quarantineFile(spiedFile, "DANGEROUS", "CRITICAL", "Locked file");
        assertNotNull(res);

        // MUST be SOURCE_REMAINS, NOT ISOLATED!
        assertEquals(MobileQuarantineVault.STATE_SOURCE_REMAINS, res.getString("status"));
        assertFalse(res.getBoolean("originalDeleted"));
        assertTrue(res.has("warning"));

        String itemId = res.getString("itemId");
        JSONObject record = vault.getItem(itemId);
        assertEquals(MobileQuarantineVault.STATE_SOURCE_REMAINS, record.getString("state"));
        assertFalse(record.getBoolean("originalDeleted"));

        // Vault copy STILL exists safely
        File vaultBlob = new File(vaultDir, record.getString("vaultFileName"));
        assertTrue(vaultBlob.exists());
    }

    @Test
    public void testManifestCrashConsistencyAndBackupRecovery() throws Exception {
        byte[] payload = "Threat record for manifest recovery test".getBytes(StandardCharsets.UTF_8);
        File threat = tempFolder.newFile("payload1.exe");
        try (FileOutputStream fos = new FileOutputStream(threat)) {
            fos.write(payload);
        }

        JSONObject res = vault.quarantineFile(threat, "DANGEROUS", "CRITICAL", "EXE test");
        String itemId = res.getString("itemId");

        // Force a manifest backup by quarantining a second file
        File threat2 = tempFolder.newFile("payload2.exe");
        try (FileOutputStream fos = new FileOutputStream(threat2)) {
            fos.write("second payload".getBytes(StandardCharsets.UTF_8));
        }
        vault.quarantineFile(threat2, "DANGEROUS", "HIGH", "EXE test 2");

        File manifest = new File(vaultDir, MobileQuarantineVault.MANIFEST_FILE_NAME);
        File backup = new File(vaultDir, MobileQuarantineVault.MANIFEST_BACKUP_NAME);
        assertTrue(manifest.exists());
        assertTrue(backup.exists());

        // Corrupt main manifest file
        try (FileOutputStream fos = new FileOutputStream(manifest)) {
            fos.write("CORRUPTED_JSON_NOT_VALID_SYNTAX".getBytes(StandardCharsets.UTF_8));
        }

        // Initialize fresh vault instance pointing to same directory
        MobileQuarantineVault recoveredVault = new MobileQuarantineVault(mockContext, vaultDir);
        JSONArray items = recoveredVault.getAllItems();
        assertTrue("Must recover records from backup manifest", items.length() >= 1);
        assertNotNull("Must find first item from recovered backup", recoveredVault.getItem(itemId));
    }

    @Test
    public void testRestoreSafeDestinationValidation() throws Exception {
        byte[] payload = "Traversal test".getBytes(StandardCharsets.UTF_8);
        File threat = tempFolder.newFile("traversal.bin");
        try (FileOutputStream fos = new FileOutputStream(threat)) {
            fos.write(payload);
        }

        JSONObject qRes = vault.quarantineFile(threat, "DANGEROUS", "HIGH", "Test");
        String itemId = qRes.getString("itemId");

        // 1. Directory traversal rejected
        JSONObject travRes = vault.restoreItem(itemId, tempFolder.getRoot().getAbsolutePath() + "/../escaped.bin", false, false);
        assertEquals("FAILED", travRes.getString("status"));
        assertEquals("PATH_TRAVERSAL_DETECTED", travRes.getString("error"));

        // 2. Restricted system directory rejected
        JSONObject sysRes = vault.restoreItem(itemId, "/system/bin/malware", false, false);
        assertEquals("FAILED", sysRes.getString("status"));
        assertEquals("RESTRICTED_SYSTEM_PATH", sysRes.getString("error"));

        // 3. Existing destination fails safely when overwrite=false
        File existing = tempFolder.newFile("already_exists.bin");
        JSONObject existRes = vault.restoreItem(itemId, existing.getAbsolutePath(), false, false);
        assertEquals("FAILED", existRes.getString("status"));
        assertEquals("DESTINATION_EXISTS", existRes.getString("error"));

        // 4. Existing destination succeeds when overwrite=true
        JSONObject overwriteRes = vault.restoreItem(itemId, existing.getAbsolutePath(), true, false);
        assertEquals("RESTORED", overwriteRes.getString("status"));
    }

    @Test
    public void testPurgeItemRemovesBlobAndManifestEntry() throws Exception {
        byte[] payload = "Purge test payload".getBytes(StandardCharsets.UTF_8);
        File threat = tempFolder.newFile("purge.bin");
        try (FileOutputStream fos = new FileOutputStream(threat)) {
            fos.write(payload);
        }

        JSONObject qRes = vault.quarantineFile(threat, "DANGEROUS", "HIGH", "Test");
        String itemId = qRes.getString("itemId");
        JSONObject item = vault.getItem(itemId);
        File blob = new File(vaultDir, item.getString("vaultFileName"));
        assertTrue(blob.exists());

        boolean deleted = vault.deleteItem(itemId);
        assertTrue(deleted);
        assertNull(vault.getItem(itemId));
        assertFalse("Blob file must be purged from disk", blob.exists());
    }

    @Test
    public void testVaultStatsAggregatesCorrectly() throws Exception {
        File f1 = tempFolder.newFile("f1.bin");
        try (FileOutputStream fos = new FileOutputStream(f1)) { fos.write(new byte[100]); }
        File f2 = tempFolder.newFile("f2.bin");
        try (FileOutputStream fos = new FileOutputStream(f2)) { fos.write(new byte[200]); }

        vault.quarantineFile(f1, "DANGEROUS", "CRITICAL", "T1");
        vault.quarantineFile(f2, "DANGEROUS", "HIGH", "T2");

        JSONObject stats = vault.getVaultStats();
        assertEquals(2, stats.getInt("totalItems"));
        assertEquals(2, stats.getInt("isolatedCount"));
        assertEquals(0, stats.getInt("sourceRemainsCount"));
        assertEquals(300, stats.getLong("totalProtectedBytes"));
    }
}
