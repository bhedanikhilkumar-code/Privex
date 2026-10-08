package com.privateprotection.mobile.shield;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class DownloadEventDeduplicatorTest {

    private DownloadEventDeduplicator deduplicator;

    @Before
    public void setUp() {
        deduplicator = new DownloadEventDeduplicator(10);
    }

    @Test
    public void testNewEventDetection() {
        DownloadEventDeduplicator.DedupDecision decision =
                deduplicator.evaluateEvent("content://downloads/1", 1024L, 5000L, null);
        assertEquals(DownloadEventDeduplicator.DedupDecision.NEW_EVENT, decision);
    }

    @Test
    public void testDuplicateEventSuppression() {
        String key = "content://downloads/1";
        deduplicator.recordResult(key, 1024L, 5000L, "hash123", "ALLOW");

        DownloadEventDeduplicator.DedupDecision decision =
                deduplicator.evaluateEvent(key, 1024L, 5000L, "hash123");
        assertEquals(DownloadEventDeduplicator.DedupDecision.DUPLICATE, decision);
    }

    @Test
    public void testSizeChangeTriggersRescan() {
        String key = "content://downloads/2";
        deduplicator.recordResult(key, 1024L, 5000L, "hash123", "ALLOW");

        DownloadEventDeduplicator.DedupDecision decision =
                deduplicator.evaluateEvent(key, 2048L, 5000L, "hash123");
        assertEquals(DownloadEventDeduplicator.DedupDecision.RESCAN_SIZE_CHANGED, decision);
    }

    @Test
    public void testMtimeChangeTriggersRescan() {
        String key = "content://downloads/3";
        deduplicator.recordResult(key, 1024L, 5000L, "hash123", "ALLOW");

        DownloadEventDeduplicator.DedupDecision decision =
                deduplicator.evaluateEvent(key, 1024L, 6000L, "hash123");
        assertEquals(DownloadEventDeduplicator.DedupDecision.RESCAN_MTIME_CHANGED, decision);
    }

    @Test
    public void testHashChangeTriggersRescan() {
        String key = "content://downloads/4";
        deduplicator.recordResult(key, 1024L, 5000L, "hash_old", "ALLOW");

        DownloadEventDeduplicator.DedupDecision decision =
                deduplicator.evaluateEvent(key, 1024L, 5000L, "hash_new");
        assertEquals(DownloadEventDeduplicator.DedupDecision.RESCAN_HASH_CHANGED, decision);
    }

    @Test
    public void testInvalidateKeyRemovesRecord() {
        String key = "content://downloads/5";
        deduplicator.recordResult(key, 1024L, 5000L, "hash123", "ALLOW");
        assertEquals(1, deduplicator.size());

        deduplicator.invalidate(key);
        assertEquals(0, deduplicator.size());

        DownloadEventDeduplicator.DedupDecision decision =
                deduplicator.evaluateEvent(key, 1024L, 5000L, "hash123");
        assertEquals(DownloadEventDeduplicator.DedupDecision.NEW_EVENT, decision);
    }

    @Test
    public void testBoundedLruEviction() {
        DownloadEventDeduplicator smallDedup = new DownloadEventDeduplicator(3);
        smallDedup.recordResult("key1", 10, 10, "h1", "ALLOW");
        smallDedup.recordResult("key2", 20, 20, "h2", "ALLOW");
        smallDedup.recordResult("key3", 30, 30, "h3", "ALLOW");
        assertEquals(3, smallDedup.size());

        // Adding 4th should evict key1
        smallDedup.recordResult("key4", 40, 40, "h4", "ALLOW");
        assertEquals(3, smallDedup.size());
        assertEquals(DownloadEventDeduplicator.DedupDecision.NEW_EVENT,
                smallDedup.evaluateEvent("key1", 10, 10, "h1"));
        assertEquals(DownloadEventDeduplicator.DedupDecision.DUPLICATE,
                smallDedup.evaluateEvent("key4", 40, 40, "h4"));
    }
}
