package com.privateprotection.mobile.shield;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DownloadEventDeduplicator (Phase T5):
 *
 * Deterministic event deduplication across rapid Android MediaStore & OEM notifications.
 *
 * Invariant:
 * - If URI/path has identical size + mtime -> DUPLICATE (suppressed).
 * - If size changed -> RESCAN_SIZE_CHANGED.
 * - If mtime changed -> RESCAN_MTIME_CHANGED.
 * - If content hash changed -> RESCAN_HASH_CHANGED.
 * - Never suppresses a rescan if content changed.
 */
public class DownloadEventDeduplicator {
    private static final int MAX_ENTRIES = 5000;

    public enum DedupDecision {
        NEW_EVENT,
        DUPLICATE,
        RESCAN_SIZE_CHANGED,
        RESCAN_MTIME_CHANGED,
        RESCAN_HASH_CHANGED
    }

    public static class CachedEventEntry {
        public final String key;
        public final long size;
        public final long mtime;
        public final String contentHash;
        public final String lastVerdict;
        public final long timestamp;

        public CachedEventEntry(String key, long size, long mtime, String contentHash, String lastVerdict, long timestamp) {
            this.key = key;
            this.size = size;
            this.mtime = mtime;
            this.contentHash = contentHash != null ? contentHash : "";
            this.lastVerdict = lastVerdict != null ? lastVerdict : "";
            this.timestamp = timestamp;
        }
    }

    private final LinkedHashMap<String, CachedEventEntry> cache;

    public DownloadEventDeduplicator() {
        this(MAX_ENTRIES);
    }

    public DownloadEventDeduplicator(final int maxCapacity) {
        this.cache = new LinkedHashMap<String, CachedEventEntry>(maxCapacity, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CachedEventEntry> eldest) {
                return size() > maxCapacity;
            }
        };
    }

    /**
     * Evaluates whether an incoming event is a duplicate or requires a fresh scan.
     */
    public synchronized DedupDecision evaluateEvent(String identityKey, long size, long mtime, String contentHash) {
        if (identityKey == null || identityKey.trim().isEmpty()) {
            return DedupDecision.NEW_EVENT;
        }

        CachedEventEntry existing = cache.get(identityKey);
        if (existing == null) {
            return DedupDecision.NEW_EVENT;
        }

        if (existing.size != size) {
            return DedupDecision.RESCAN_SIZE_CHANGED;
        }

        if (existing.mtime != mtime) {
            return DedupDecision.RESCAN_MTIME_CHANGED;
        }

        if (contentHash != null && !contentHash.isEmpty()
                && !existing.contentHash.isEmpty()
                && !contentHash.equalsIgnoreCase(existing.contentHash)) {
            return DedupDecision.RESCAN_HASH_CHANGED;
        }

        return DedupDecision.DUPLICATE;
    }

    /**
     * Stores or updates the outcome of a completed file scan.
     */
    public synchronized void recordResult(String identityKey, long size, long mtime, String contentHash, String verdict) {
        if (identityKey == null || identityKey.trim().isEmpty()) return;
        CachedEventEntry entry = new CachedEventEntry(
                identityKey,
                size,
                mtime,
                contentHash,
                verdict,
                System.currentTimeMillis()
        );
        cache.put(identityKey, entry);
    }

    /**
     * Returns the cached entry for a given key, or null if absent.
     */
    public synchronized CachedEventEntry get(String identityKey) {
        if (identityKey == null) return null;
        return cache.get(identityKey);
    }

    /**
     * Invalidates an entry when a file changes during analysis or is deleted.
     */
    public synchronized void invalidate(String identityKey) {
        if (identityKey != null) {
            cache.remove(identityKey);
        }
    }

    /**
     * Clears all deduplication records.
     */
    public synchronized void clear() {
        cache.clear();
    }

    public synchronized int size() {
        return cache.size();
    }

    public synchronized JSONObject toStatsJSON() {
        JSONObject obj = new JSONObject();
        try {
            obj.put("cachedEntries", cache.size());
            obj.put("maxCapacity", MAX_ENTRIES);
        } catch (JSONException ignored) {}
        return obj;
    }
}
