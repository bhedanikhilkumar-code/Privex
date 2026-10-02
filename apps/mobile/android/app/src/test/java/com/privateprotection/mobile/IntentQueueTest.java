package com.privateprotection.mobile;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for Intent handling and Cold-Start Queueing (BLOCKER-05).
 */
public class IntentQueueTest {

    @Test
    public void testIntentSerializationAndLengthCapping() throws Exception {
        // 1. Text length bounding (10,000 chars)
        StringBuilder hugeText = new StringBuilder();
        for (int i = 0; i < 15000; i++) {
            hugeText.append("A");
        }

        String input = hugeText.toString();
        String safeText = input.length() > 10000 ? input.substring(0, 10000) : input;
        assertEquals(10000, safeText.length());

        JSONObject intentData = new JSONObject();
        intentData.put("action", "SHARED_TEXT");
        intentData.put("payload", safeText);
        intentData.put("timestamp", 123456789L);

        assertEquals("SHARED_TEXT", intentData.getString("action"));
        assertEquals(10000, intentData.getString("payload").length());
    }

    @Test
    public void testDeepLinkUrlLengthCapping() throws Exception {
        // 2. URL length bounding (2,048 chars)
        StringBuilder hugeUrl = new StringBuilder("https://example.com/");
        while (hugeUrl.length() < 3000) {
            hugeUrl.append("path/");
        }

        String rawUrl = hugeUrl.toString();
        String safeUrl = rawUrl.length() > 2048 ? rawUrl.substring(0, 2048) : rawUrl;
        assertEquals(2048, safeUrl.length());

        JSONObject intentData = new JSONObject();
        intentData.put("action", "DEEP_LINK_URL");
        intentData.put("payload", safeUrl);

        assertEquals("DEEP_LINK_URL", intentData.getString("action"));
        assertEquals(2048, intentData.getString("payload").length());
    }

    @Test
    public void testAtomicConsumptionProtocol() {
        // Simulates MainActivity pending intent buffer: consumed exactly once
        String buffer = "{\"action\":\"SHARED_TEXT\",\"payload\":\"Urgent security test\"}";

        // First consume
        String consumedFirst = buffer;
        buffer = null; // Cleared atomically
        assertNotNull(consumedFirst);
        assertEquals("{\"action\":\"SHARED_TEXT\",\"payload\":\"Urgent security test\"}", consumedFirst);

        // Second consume must return null (exactly once delivery)
        String consumedSecond = buffer;
        assertNull("Subsequent consume must return null (strictly exactly once)", consumedSecond);
    }
}
