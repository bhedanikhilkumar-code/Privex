package com.privateprotection.mobile.core;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for SecurityJob model, state transitions, progress clamping, and JSON serialization.
 */
public class SecurityJobTest {

    @Test
    public void testJobCreationDefaults() {
        SecurityJob job = new SecurityJob(JobType.FILE_SCAN, null);

        assertNotNull(job.getId());
        assertEquals(JobType.FILE_SCAN, job.getType());
        assertEquals(JobState.QUEUED, job.getState());
        assertEquals(0.0f, job.getProgress(), 0.001f);
        assertTrue(job.getCreatedAtMs() > 0L);
        assertEquals(0L, job.getStartedAtMs());
        assertEquals(0L, job.getCompletedAtMs());
        assertFalse(job.isTerminal());
        assertFalse(job.isCancelled());
    }

    @Test
    public void testProgressClamping() {
        SecurityJob job = new SecurityJob(JobType.URL_SCAN, null);

        job.setProgress(0.5f);
        assertEquals(0.5f, job.getProgress(), 0.001f);

        job.setProgress(-0.2f);
        assertEquals(0.0f, job.getProgress(), 0.001f);

        job.setProgress(1.5f);
        assertEquals(1.0f, job.getProgress(), 0.001f);
    }

    @Test
    public void testAtomicStateTransitions() {
        SecurityJob job = new SecurityJob(JobType.PACKAGE_AUDIT, null);

        // Transition from QUEUED to RUNNING
        assertTrue(job.transitionTo(JobState.RUNNING, null));
        assertEquals(JobState.RUNNING, job.getState());
        assertTrue(job.getStartedAtMs() > 0L);

        // Invalid transition: RUNNING to QUEUED
        assertFalse(job.transitionTo(JobState.QUEUED, null));
        assertEquals(JobState.RUNNING, job.getState());

        // Valid transition: RUNNING to COMPLETED
        assertTrue(job.transitionTo(JobState.COMPLETED, null));
        assertEquals(JobState.COMPLETED, job.getState());
        assertTrue(job.getCompletedAtMs() > 0L);
        assertTrue(job.isTerminal());

        // Invalid transition from terminal state
        assertFalse(job.transitionTo(JobState.RUNNING, null));
        assertFalse(job.transitionTo(JobState.FAILED, "error"));
        assertEquals(JobState.COMPLETED, job.getState());
    }

    @Test
    public void testCancellationTransitions() {
        SecurityJob job = new SecurityJob(JobType.DOWNLOAD_INSPECT, null);

        assertTrue(job.transitionTo(JobState.CANCELLING, "User requested cancel"));
        assertTrue(job.isCancelled());
        assertEquals("User requested cancel", job.getCancellationReason());

        assertTrue(job.transitionTo(JobState.CANCELLED, null));
        assertTrue(job.isTerminal());
        assertTrue(job.isCancelled());
        assertEquals(JobState.CANCELLED, job.getState());
    }

    @Test
    public void testFailureTransition() {
        SecurityJob job = new SecurityJob(JobType.STORAGE_SCAN, null);

        assertTrue(job.transitionTo(JobState.RUNNING, null));
        assertTrue(job.transitionTo(JobState.FAILED, "I/O error during scan"));
        assertTrue(job.isTerminal());
        assertEquals("I/O error during scan", job.getErrorReason());
    }

    @Test
    public void testJsonRoundTripSerialization() throws Exception {
        JSONObject meta = new JSONObject();
        meta.put("targetPath", "/sdcard/Downloads/sample.apk");
        meta.put("fileSize", 1024L);

        SecurityJob original = new SecurityJob("job-1234", JobType.FILE_SCAN, 1600000000000L, meta);
        original.transitionTo(JobState.RUNNING, null);
        original.setProgress(0.75f);
        JSONObject result = new JSONObject();
        result.put("verdict", "ALLOW");
        result.put("riskScore", 0);
        original.setResult(result);
        original.transitionTo(JobState.COMPLETED, null);

        JSONObject serialized = original.toJSON();
        assertNotNull(serialized);
        assertEquals("job-1234", serialized.getString("id"));
        assertEquals("FILE_SCAN", serialized.getString("type"));
        assertEquals("COMPLETED", serialized.getString("state"));
        assertEquals(0.75, serialized.getDouble("progress"), 0.001);

        SecurityJob reconstructed = SecurityJob.fromJSON(serialized);
        assertNotNull(reconstructed);
        assertEquals(original.getId(), reconstructed.getId());
        assertEquals(original.getType(), reconstructed.getType());
        assertEquals(original.getState(), reconstructed.getState());
        assertEquals(original.getProgress(), reconstructed.getProgress(), 0.001f);
        assertEquals("/sdcard/Downloads/sample.apk", reconstructed.getMetadata().getString("targetPath"));
        assertEquals("ALLOW", reconstructed.getResult().getString("verdict"));
    }
}
