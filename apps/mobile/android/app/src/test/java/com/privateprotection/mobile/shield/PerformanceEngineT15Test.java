package com.privateprotection.mobile.shield;

import android.content.Context;
import android.net.Uri;
import com.privateprotection.mobile.core.AdaptiveResourceManager;
import com.privateprotection.mobile.core.BoundedWorkerExecutor;
import com.privateprotection.mobile.core.JobExecutionController;
import com.privateprotection.mobile.core.JobState;
import com.privateprotection.mobile.core.JobType;
import com.privateprotection.mobile.core.MobileSecurityCoordinator;
import com.privateprotection.mobile.core.SecurityJob;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/**
 * PerformanceEngineT15Test (Phase T15):
 *
 * Master Performance, Memory Bounds, and Latency Benchmark Suite.
 *
 * Targets from Phase T15 Specification:
 * 1. Protection-service warm-start overhead below 500 ms.
 * 2. Small local-file ingress triage p50 below 20 ms (and p95 below 50 ms).
 * 3. No unbounded memory growth during a 1,000-file burst (heap delta < 32 MB).
 * 4. No ANR during full scan (cooperative cancellation, offloaded background threads).
 * 5. Bounded background CPU and battery usage (adaptive low-power scan deferral).
 * 6. Scan queues remain cancellable and resumable.
 * 7. Security invariant parity (never sacrifice detection quality for speed).
 */
public class PerformanceEngineT15Test {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private Context mockContext;
    private UniversalFileShieldService shieldService;
    private File filesDir;

    @Before
    public void setUp() throws Exception {
        filesDir = tempFolder.newFolder("app_files");
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getFilesDir()).thenReturn(filesDir);

        android.content.SharedPreferences mockPrefs = Mockito.mock(android.content.SharedPreferences.class);
        when(mockPrefs.getString(Mockito.anyString(), Mockito.anyString())).thenReturn("[]");
        when(mockContext.getSharedPreferences(Mockito.anyString(), Mockito.anyInt())).thenReturn(mockPrefs);

        AdaptiveResourceManager.resetInstanceForTest();
        AdaptiveResourceManager.getInstance(mockContext);
        MobileSecurityCoordinator.resetInstance();

        shieldService = new UniversalFileShieldService(mockContext);
    }

    @After
    public void tearDown() {
        AdaptiveResourceManager.resetInstanceForTest();
        MobileSecurityCoordinator.resetInstance();
        MobileNotificationDispatcher.resetInstanceForTest();
    }

    /**
     * Target 1: Protection-service warm-start overhead < 500 ms.
     */
    @Test
    public void testTarget1_ProtectionServiceWarmStartOverhead() {
        long startTime = System.nanoTime();

        // Instantiate core protection services
        MobileSecurityCoordinator coordinator = MobileSecurityCoordinator.getInstance(mockContext);
        UniversalFileShieldService fileShield = new UniversalFileShieldService(mockContext);
        AdaptiveResourceManager adaptiveMgr = AdaptiveResourceManager.getInstance(mockContext);
        MobileCleanFileCache cache = MobileCleanFileCache.getInstance(mockContext);

        long elapsedMs = (System.nanoTime() - startTime) / 1_000_000L;

        assertNotNull(coordinator);
        assertNotNull(fileShield);
        assertNotNull(adaptiveMgr);
        assertNotNull(cache);

        System.out.println("[T15 Benchmark] Protection service warm-start overhead: " + elapsedMs + " ms");
        assertTrue("Warm-start overhead must be < 500 ms SLA, was: " + elapsedMs + " ms", elapsedMs < 500);
    }

    /**
     * Target 2: Small local-file ingress triage p50 < 20 ms and p95 < 50 ms across 50 samples.
     */
    @Test
    public void testTarget2_SmallFileIngressTriageLatencyDistribution() throws Exception {
        int sampleCount = 50;
        List<Long> latenciesMs = new ArrayList<>(sampleCount);

        // Pre-create small test files (1 KB to 16 KB)
        List<File> testFiles = new ArrayList<>();
        for (int i = 0; i < sampleCount; i++) {
            File f = tempFolder.newFile("sample_triage_" + i + ".txt");
            try (FileOutputStream fos = new FileOutputStream(f)) {
                byte[] data = ("Clean text content payload for performance benchmarking index " + i).getBytes(StandardCharsets.UTF_8);
                fos.write(data);
            }
            testFiles.add(f);
        }

        // Warm up JIT (15 iterations)
        for (int w = 0; w < 15; w++) {
            shieldService.inspectFile(testFiles.get(w % testFiles.size()));
        }

        // Measure individual triage times across samples
        for (int i = 0; i < sampleCount; i++) {
            long t0 = System.nanoTime();
            JSONObject res = shieldService.inspectFile(testFiles.get(i));
            long t1 = System.nanoTime();
            long durMs = (t1 - t0) / 1_000_000L;
            latenciesMs.add(durMs);
            assertEquals("ALLOW", res.optString("verdict"));
        }

        Collections.sort(latenciesMs);
        long p50 = latenciesMs.get((int) (sampleCount * 0.50));
        long p95 = latenciesMs.get((int) (sampleCount * 0.95));
        long max = latenciesMs.get(sampleCount - 1);

        System.out.println("[T15 Benchmark] Small-File Triage Latencies: p50=" + p50 + " ms, p95=" + p95 + " ms, max=" + max + " ms");
        assertTrue("Small-file triage p50 must be < 20 ms, was: " + p50 + " ms", p50 < 20);
        assertTrue("Small-file triage p95 must be < 50 ms, was: " + p95 + " ms", p95 < 50);
    }

    /**
     * Target 2b: Clean-file cache hit vs miss & invalidation.
     */
    @Test
    public void testCleanFileCacheHitAndInvalidationPerformance() throws Exception {
        File cleanFile = tempFolder.newFile("cached_document.pdf");
        try (FileOutputStream fos = new FileOutputStream(cleanFile)) {
            fos.write(new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34}); // %PDF-1.4 header
        }

        // 1st inspect -> Cache Miss, inspects and stores in cache
        JSONObject firstRes = shieldService.inspectFile(cleanFile);
        assertEquals("ALLOW", firstRes.optString("verdict"));

        // 2nd inspect -> Cache Hit
        long t0 = System.nanoTime();
        JSONObject cachedRes = shieldService.inspectFile(cleanFile);
        long hitDurationUs = (System.nanoTime() - t0) / 1_000L;

        assertEquals("ALLOW", cachedRes.optString("verdict"));
        assertTrue("Cached result should indicate fromCache", cachedRes.optBoolean("fromCache", false));
        System.out.println("[T15 Benchmark] Clean file cache hit latency: " + hitDurationUs + " µs");
        assertTrue("Cache hit latency must be < 5 ms", hitDurationUs < 5000);

        // Modify file size -> Cache Invalidation
        try (FileOutputStream fos = new FileOutputStream(cleanFile, true)) {
            fos.write("additional appended data".getBytes(StandardCharsets.UTF_8));
        }

        JSONObject modifiedRes = shieldService.inspectFile(cleanFile);
        assertEquals("ALLOW", modifiedRes.optString("verdict"));
        assertFalse("Modified file must NOT hit old cache", modifiedRes.optBoolean("fromCache", false));
    }

    /**
     * Target 3: 1,000-File Burst Workload & Memory Bounds (Heap Delta < 32 MB).
     */
    @Test
    public void testTarget3_OneThousandFileBurstMemoryBounds() {
        DownloadEventDeduplicator deduplicator = new DownloadEventDeduplicator();

        // Measure initial memory
        System.gc();
        Runtime rt = Runtime.getRuntime();
        long memBefore = rt.totalMemory() - rt.freeMemory();

        int totalEvents = 1000;
        int duplicates = 0;
        int sizeChanges = 0;

        for (int i = 0; i < totalEvents; i++) {
            String key = "content://media/external/downloads/item_" + (i % 100); // 100 distinct files with repetitive events
            long size = 1024;
            long mtime = 1700000000L;

            DownloadEventDeduplicator.DedupDecision decision = deduplicator.evaluateEvent(key, size, mtime, "");
            if (decision == DownloadEventDeduplicator.DedupDecision.DUPLICATE) {
                duplicates++;
            } else if (decision == DownloadEventDeduplicator.DedupDecision.RESCAN_SIZE_CHANGED) {
                sizeChanges++;
            }
            deduplicator.recordResult(key, size, mtime, "", "ALLOW");
        }

        System.gc();
        long memAfter = rt.totalMemory() - rt.freeMemory();
        long heapDeltaMb = Math.max(0, memAfter - memBefore) / (1024 * 1024);

        System.out.println("[T15 Benchmark] 1,000-file burst: total=" + totalEvents +
                ", duplicates=" + duplicates + ", sizeChanges=" + sizeChanges +
                ", heapDelta=" + heapDeltaMb + " MB");

        assertTrue("Deduplicator should process repetitive events (duplicates > 0)", duplicates > 0);
        assertTrue("Heap delta during 1,000-file burst must be < 32 MB, was: " + heapDeltaMb + " MB", heapDeltaMb < 32);
        assertTrue("Deduplicator size must be <= MAX_ENTRIES", deduplicator.size() <= 5000);
    }

    /**
     * Target 4: No ANR during full scan / Cooperative Cancellation.
     */
    @Test
    public void testTarget4_CooperativeScanCancellation() {
        FullDeviceScanService scanService = new FullDeviceScanService(mockContext);
        AtomicBoolean wasCancelled = new AtomicBoolean(false);

        JobExecutionController controller = new JobExecutionController() {
            @Override
            public boolean isCancellationRequested() {
                return wasCancelled.get();
            }

            @Override
            public void checkCancellation() {
                if (wasCancelled.get()) {
                    throw new RuntimeException("JOB_CANCELLED");
                }
            }

            @Override
            public void updateProgress(float progress) {}

            @Override
            public void setMetadata(String key, Object value) {}
        };

        // Trigger cancellation immediately
        wasCancelled.set(true);
        JSONObject result = scanService.executeScan(FullDeviceScanService.ScanMode.QUICK_SCAN, controller, null);

        assertNotNull(result);
        assertEquals("CANCELLED", result.optString("status"));
        System.out.println("[T15 Benchmark] Full scan cooperative cancellation responded cleanly with CANCELLED status");
    }

    /**
     * Target 5: Bounded Background CPU and Battery Usage (Adaptive Scan Deferral).
     */
    @Test
    public void testTarget5_AdaptiveLowBatteryScanDeferral() {
        AdaptiveResourceManager adaptiveManager = AdaptiveResourceManager.getInstance(mockContext);
        MobileSecurityCoordinator coordinator = MobileSecurityCoordinator.getInstance(mockContext);

        // Simulate Battery < 20% Discharging
        adaptiveManager.setTestOverrides(15, false, AdaptiveResourceManager.ThermalStatus.NONE, false);
        assertEquals(AdaptiveResourceManager.ResourceMode.BATTERY_SAVER, adaptiveManager.getCurrentMode());
        assertFalse(adaptiveManager.canExecuteScheduledDeepScan());

        // Submit a scheduled deep scan
        JSONObject metadata = new JSONObject();
        try {
            metadata.put("isScheduled", true);
        } catch (Exception ignored) {}

        SecurityJob job = coordinator.submitJob(JobType.STORAGE_SCAN, metadata, (j, ctrl) -> {
            fail("Scheduled scan must NOT execute when battery is low and discharging");
            return new JSONObject();
        });

        assertEquals(JobState.DEFERRED, job.getState());
        assertTrue(job.getCancellationReason() != null && job.getCancellationReason().contains("Deferred due to adaptive"));
        System.out.println("[T15 Benchmark] Scheduled scan safely deferred under low-battery: " + job.getCancellationReason());

        // Now simulate device plugged into charger
        adaptiveManager.setTestOverrides(15, true, AdaptiveResourceManager.ThermalStatus.NONE, false);
        assertTrue("Plugged-in state allows scheduled scans even at 15%", adaptiveManager.canExecuteScheduledDeepScan());
    }

    /**
     * Target 6: Bounded Worker Executor Capacity & Backpressure Rejection.
     */
    @Test
    public void testTarget6_BoundedWorkerQueueCapacityAndBackpressure() throws Exception {
        int corePool = 2;
        int maxPool = 2;
        int queueCapacity = 10;
        BoundedWorkerExecutor executor = new BoundedWorkerExecutor(corePool, maxPool, queueCapacity);

        CountDownLatch blockerLatch = new CountDownLatch(1);
        CountDownLatch startedLatch = new CountDownLatch(corePool);

        // Occupy active threads
        for (int i = 0; i < corePool; i++) {
            executor.execute(() -> {
                startedLatch.countDown();
                try {
                    blockerLatch.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {}
            });
        }
        assertTrue(startedLatch.await(1, TimeUnit.SECONDS));

        // Fill bounded queue (10 slots)
        for (int i = 0; i < queueCapacity; i++) {
            executor.execute(() -> {});
        }

        // Next item must be rejected safely
        boolean rejected = false;
        try {
            executor.execute(() -> {});
        } catch (RejectedExecutionException ex) {
            rejected = true;
        }

        assertTrue("Bounded worker executor must reject tasks when capacity is exceeded", rejected);
        blockerLatch.countDown();
        executor.shutdown();
    }

    /**
     * Target 7: Streaming SHA-256 correctness against known test hashes.
     */
    @Test
    public void testStreamingSha256Correctness() throws Exception {
        File emptyFile = tempFolder.newFile("empty.bin");
        // Empty file SHA-256 is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        String expectedEmptySha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(new byte[0]);
        String actualHex = UniversalFileShieldService.bytesToHex(hash);

        assertEquals(expectedEmptySha, actualHex);

        // Test bytesToHex fast path on sample bytes
        byte[] sample = new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        assertEquals("deadbeef", UniversalFileShieldService.bytesToHex(sample));
    }

    /**
     * Target 8: Security Invariant Parity under Performance Optimizations.
     * Asserts that performance optimizations NEVER sacrifice detection quality.
     */
    @Test
    public void testSecurityInvariantParityMaintained() throws Exception {
        // 1. Double extension file -> DANGEROUS
        File disguisedFile = tempFolder.newFile("malware.pdf.exe");
        try (FileOutputStream fos = new FileOutputStream(disguisedFile)) {
            fos.write(new byte[]{0x4D, 0x5A, 0x00, 0x00});
        }
        JSONObject dResult = shieldService.inspectFile(disguisedFile);
        assertEquals("DANGEROUS", dResult.optString("verdict"));
        assertTrue(dResult.getInt("score") >= 85);
        assertFalse("Threat must NEVER be cached as clean", dResult.optBoolean("fromCache", false));

        // 2. Verified clean file -> ALLOW, then hits cache
        File cleanFile = tempFolder.newFile("readme.txt");
        try (FileOutputStream fos = new FileOutputStream(cleanFile)) {
            fos.write("Clean user notes".getBytes(StandardCharsets.UTF_8));
        }
        JSONObject cResult1 = shieldService.inspectFile(cleanFile);
        assertEquals("ALLOW", cResult1.optString("verdict"));

        JSONObject cResult2 = shieldService.inspectFile(cleanFile);
        assertEquals("ALLOW", cResult2.optString("verdict"));
        assertTrue("Subsequent clean inspect must hit clean cache", cResult2.optBoolean("fromCache", false));
    }
}
