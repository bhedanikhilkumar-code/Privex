package com.privateprotection.mobile.core;

import android.content.SharedPreferences;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Tests for JobStateStore persistence, history limits, and crash recovery protocol.
 */
public class JobStateStoreTest {

    private SharedPreferences mockPrefs;
    private SharedPreferences.Editor mockEditor;
    private Map<String, String> backingStore;

    @Before
    public void setUp() {
        backingStore = new HashMap<>();
        mockPrefs = Mockito.mock(SharedPreferences.class);
        mockEditor = Mockito.mock(SharedPreferences.Editor.class);

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
    }

    @Test
    public void testPersistAndRetrieveJob() {
        JobStateStore store = new JobStateStore(mockPrefs);

        SecurityJob job = new SecurityJob("test-1", JobType.FILE_SCAN, 1000L, null);
        job.transitionTo(JobState.RUNNING, null);
        job.setProgress(0.5f);

        store.persistJob(job);

        SecurityJob retrieved = store.getJob("test-1");
        assertNotNull(retrieved);
        assertEquals("test-1", retrieved.getId());
        assertEquals(JobState.RUNNING, retrieved.getState());
        assertEquals(0.5f, retrieved.getProgress(), 0.001f);
    }

    @Test
    public void testTruthfulProcessCrashRecovery() {
        // Step 1: Pre-crash session creates and starts a job
        JobStateStore preCrashStore = new JobStateStore(mockPrefs);
        SecurityJob runningJob = new SecurityJob("crash-job-1", JobType.STORAGE_SCAN, 2000L, null);
        runningJob.transitionTo(JobState.RUNNING, null);
        preCrashStore.persistJob(runningJob);

        SecurityJob completedJob = new SecurityJob("good-job-2", JobType.URL_SCAN, 1500L, null);
        completedJob.transitionTo(JobState.RUNNING, null);
        completedJob.transitionTo(JobState.COMPLETED, null);
        preCrashStore.persistJob(completedJob);

        // Step 2: App process terminates abruptly and restarts -> new JobStateStore loads from disk
        JobStateStore postCrashStore = new JobStateStore(mockPrefs);

        // Step 3: Run recovery protocol
        List<SecurityJob> recovered = postCrashStore.recoverOrphanedJobs();

        assertEquals(1, recovered.size());
        SecurityJob recoveredJob = recovered.get(0);
        assertEquals("crash-job-1", recoveredJob.getId());
        assertEquals(JobState.FAILED, recoveredJob.getState());
        assertEquals("PROCESS_TERMINATED_ABRUPTLY", recoveredJob.getErrorReason());
        assertTrue(recoveredJob.getCompletedAtMs() > 0L);

        // The already COMPLETED job must NOT be marked as failed
        SecurityJob untouched = postCrashStore.getJob("good-job-2");
        assertNotNull(untouched);
        assertEquals(JobState.COMPLETED, untouched.getState());
    }

    @Test
    public void testMaxHistoryPruning() {
        JobStateStore store = new JobStateStore(mockPrefs);

        // Persist 60 jobs (limit is 50)
        for (int i = 0; i < 60; i++) {
            SecurityJob job = new SecurityJob("job-" + i, JobType.HEALTH_CHECK, 1000L + i, null);
            job.transitionTo(JobState.RUNNING, null);
            job.transitionTo(JobState.COMPLETED, null);
            store.persistJob(job);
        }

        List<SecurityJob> all = store.getAllJobs();
        assertTrue(all.size() <= 50);
        // The first 10 oldest jobs should be evicted
        assertFalse(store.getAllJobs().stream().anyMatch(j -> j.getId().equals("job-0")));
        // The newest jobs must be present
        assertTrue(store.getAllJobs().stream().anyMatch(j -> j.getId().equals("job-59")));
    }

    @Test
    public void testCorruptedIndividualRecordHandling() {
        // Populate backingStore with one valid job, one malformed JSON job, and one valid job
        backingStore.put("job_valid_1", "{\"id\":\"valid_1\",\"type\":\"FILE_SCAN\",\"state\":\"COMPLETED\",\"progress\":1.0,\"createdAtMs\":1000}");
        backingStore.put("job_corrupted", "{this is malformed json!@#$}");
        backingStore.put("job_valid_2", "{\"id\":\"valid_2\",\"type\":\"URL_SCAN\",\"state\":\"FAILED\",\"progress\":0.0,\"createdAtMs\":2000}");
        backingStore.put("job_ids_index", "[\"valid_1\",\"corrupted\",\"valid_2\"]");

        JobStateStore store = new JobStateStore(mockPrefs);
        List<SecurityJob> loaded = store.getAllJobs();

        // The store must skip the corrupted record and load the two valid ones
        assertEquals(2, loaded.size());
        assertNotNull(store.getJob("valid_1"));
        assertNotNull(store.getJob("valid_2"));
        assertEquals(JobState.COMPLETED, store.getJob("valid_1").getState());
        assertEquals(JobState.FAILED, store.getJob("valid_2").getState());
    }
}
