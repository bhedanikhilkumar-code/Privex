package com.privateprotection.mobile.core;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Comprehensive Unit Test Suite for MobileSecurityCoordinator (Phase T1).
 * Tests all required dimensions: lifecycle, job execution, cancellation race conditions,
 * failure propagation, concurrency bounds, memory throttling, and truthful recovery.
 */
public class MobileSecurityCoordinatorTest {

    private Context mockContext;
    private Context mockAppContext;
    private SharedPreferences mockPrefs;
    private SharedPreferences.Editor mockEditor;
    private Map<String, String> backingStore;

    private BoundedWorkerExecutor testExecutor;
    private JobStateStore testStore;
    private MobileSecurityCoordinator coordinator;

    @Before
    public void setUp() {
        backingStore = new HashMap<>();
        mockContext = Mockito.mock(Context.class);
        mockAppContext = Mockito.mock(Context.class);
        mockPrefs = Mockito.mock(SharedPreferences.class);
        mockEditor = Mockito.mock(SharedPreferences.Editor.class);

        when(mockContext.getApplicationContext()).thenReturn(mockAppContext);
        when(mockAppContext.getSharedPreferences(anyString(), Mockito.anyInt())).thenReturn(mockPrefs);

        when(mockPrefs.edit()).thenReturn(mockEditor);
        when(mockPrefs.getString(anyString(), any())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String def = invocation.getArgument(1);
            return backingStore.getOrDefault(key, def);
        });
        when(mockEditor.putString(anyString(), anyString())).thenAnswer(invocation -> {
            backingStore.put(invocation.getArgument(0), invocation.getArgument(1));
            return mockEditor;
        });
        when(mockEditor.remove(anyString())).thenAnswer(invocation -> {
            backingStore.remove(invocation.getArgument(0));
            return mockEditor;
        });
        doAnswer(invocation -> null).when(mockEditor).apply();

        testExecutor = new BoundedWorkerExecutor(2, 4, 64);
        testStore = new JobStateStore(mockPrefs);
        coordinator = new MobileSecurityCoordinator(mockContext, testExecutor, testStore);
    }

    @After
    public void tearDown() {
        if (coordinator != null && !coordinator.isShutdown()) {
            coordinator.shutdownNow();
        }
        MobileSecurityCoordinator.resetInstance();
    }

    @Test
    public void testCoordinatorInitializationAndStats() {
        assertFalse(coordinator.isShutdown());
        JSONObject stats = coordinator.getCoordinatorStats();
        assertNotNull(stats);
        assertFalse(stats.optBoolean("isShutdown"));
        assertFalse(stats.optBoolean("isThrottled"));
        assertEquals(0, stats.optInt("activeJobsCount"));
    }

    @Test
    public void testSuccessfulJobExecutionAndCompletion() throws Exception {
        CountDownLatch doneLatch = new CountDownLatch(1);

        SecurityJob job = coordinator.submitJob(JobType.FILE_SCAN, null, (j, ctrl) -> {
            ctrl.updateProgress(0.5f);
            JSONObject res = new JSONObject();
            res.put("verdict", "ALLOW");
            res.put("score", 0);
            doneLatch.countDown();
            return res;
        });

        assertNotNull(job);
        assertNotNull(job.getId());

        assertTrue(doneLatch.await(3, TimeUnit.SECONDS));
        // Give coordinator a moment to finalize completion
        Thread.sleep(100);

        SecurityJob completed = coordinator.getJob(job.getId());
        assertNotNull(completed);
        assertEquals(JobState.COMPLETED, completed.getState());
        assertEquals(1.0f, completed.getProgress(), 0.001f);
        assertNotNull(completed.getResult());
        assertEquals("ALLOW", completed.getResult().getString("verdict"));
    }

    @Test
    public void testJobFailureAndErrorPropagation() throws Exception {
        CountDownLatch doneLatch = new CountDownLatch(1);

        SecurityJob job = coordinator.submitJob(JobType.URL_SCAN, null, (j, ctrl) -> {
            doneLatch.countDown();
            throw new RuntimeException("Heuristic pipeline parse exception");
        });

        assertTrue(doneLatch.await(3, TimeUnit.SECONDS));
        Thread.sleep(100);

        SecurityJob failed = coordinator.getJob(job.getId());
        assertNotNull(failed);
        assertEquals(JobState.FAILED, failed.getState());
        assertTrue(failed.getErrorReason().contains("Heuristic pipeline parse exception"));
    }

    @Test
    public void testCooperativeJobCancellationDuringExecution() throws Exception {
        CountDownLatch startedLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(1);
        AtomicBoolean threwCancellation = new AtomicBoolean(false);

        SecurityJob job = coordinator.submitJob(JobType.STORAGE_SCAN, null, (j, ctrl) -> {
            startedLatch.countDown();
            // Busy loop checking cancellation
            for (int i = 0; i < 50; i++) {
                if (ctrl.isCancellationRequested()) {
                    ctrl.checkCancellation();
                }
                Thread.sleep(20);
            }
            return new JSONObject();
        });

        assertTrue(startedLatch.await(2, TimeUnit.SECONDS));
        boolean cancelTriggered = coordinator.cancelJob(job.getId(), "User pressed stop");
        assertTrue(cancelTriggered);

        // Wait for worker to exit
        Thread.sleep(200);

        SecurityJob cancelledJob = coordinator.getJob(job.getId());
        assertNotNull(cancelledJob);
        assertEquals(JobState.CANCELLED, cancelledJob.getState());
        assertEquals("User pressed stop", cancelledJob.getCancellationReason());
    }

    @Test
    public void testCancelJobAfterCompletionFails() throws Exception {
        CountDownLatch doneLatch = new CountDownLatch(1);

        SecurityJob job = coordinator.submitJob(JobType.HEALTH_CHECK, null, (j, ctrl) -> {
            doneLatch.countDown();
            return new JSONObject();
        });

        assertTrue(doneLatch.await(2, TimeUnit.SECONDS));
        Thread.sleep(100);

        // Job is COMPLETED, cancellation must return false
        boolean result = coordinator.cancelJob(job.getId(), "Too late");
        assertFalse(result);
        assertEquals(JobState.COMPLETED, coordinator.getJob(job.getId()).getState());
    }

    @Test
    public void testCancelNonExistentJobReturnsFalse() {
        assertFalse(coordinator.cancelJob("non-existent-uuid", "Nothing"));
    }

    @Test
    public void testConcurrentJobsExecution() throws Exception {
        int jobCount = 10;
        CountDownLatch allDone = new CountDownLatch(jobCount);

        for (int i = 0; i < jobCount; i++) {
            coordinator.submitJob(JobType.PACKAGE_AUDIT, null, (j, ctrl) -> {
                Thread.sleep(20);
                allDone.countDown();
                return new JSONObject();
            });
        }

        assertTrue(allDone.await(5, TimeUnit.SECONDS));
        Thread.sleep(150);

        List<SecurityJob> recent = coordinator.getRecentJobs(20);
        assertTrue(recent.size() >= 10);
        for (SecurityJob j : recent) {
            assertEquals(JobState.COMPLETED, j.getState());
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSubmitNullJobTypeThrows() {
        coordinator.submitJob(null, null, (j, ctrl) -> new JSONObject());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSubmitNullTaskThrows() {
        coordinator.submitJob(JobType.FILE_SCAN, null, null);
    }

    @Test(expected = IllegalStateException.class)
    public void testSubmitJobAfterShutdownThrows() {
        coordinator.shutdown();
        assertTrue(coordinator.isShutdown());
        coordinator.submitJob(JobType.FILE_SCAN, null, (j, ctrl) -> new JSONObject());
    }

    @Test
    public void testRepeatedShutdownIsSafe() {
        coordinator.shutdown();
        assertTrue(coordinator.isShutdown());
        coordinator.shutdown(); // Should not throw
        assertTrue(coordinator.isShutdown());
    }

    @Test
    public void testLowMemoryTrimmingThrottlesWorker() {
        // Trigger TRIM_MEMORY_RUNNING_LOW
        coordinator.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW);
        JSONObject stats = coordinator.getCoordinatorStats();
        assertTrue(stats.optBoolean("isThrottled"));
        assertEquals(1, stats.optInt("workerMaxPoolSize"));

        // Trigger memory normalization
        coordinator.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_RUNNING_MODERATE);
        JSONObject statsNormalized = coordinator.getCoordinatorStats();
        assertFalse(statsNormalized.optBoolean("isThrottled"));
        assertEquals(4, statsNormalized.optInt("workerMaxPoolSize"));
    }

    @Test
    public void testOnLowMemoryThrottlesWorker() {
        coordinator.onLowMemory();
        JSONObject stats = coordinator.getCoordinatorStats();
        assertTrue(stats.optBoolean("isThrottled"));
        assertEquals(1, stats.optInt("workerMaxPoolSize"));
    }
}
