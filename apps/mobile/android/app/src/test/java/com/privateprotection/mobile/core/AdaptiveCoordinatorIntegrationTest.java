package com.privateprotection.mobile.core;

import android.content.Context;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.*;

/**
 * Tests coordinator integration with AdaptiveResourceManager:
 * Verifies scheduled deep scan deferral, backpressure, and priority handling.
 */
public class AdaptiveCoordinatorIntegrationTest {

    private MobileSecurityCoordinator coordinator;
    private AdaptiveResourceManager adaptiveManager;

    @Before
    public void setUp() {
        Context mockContext = Mockito.mock(Context.class);
        Mockito.when(mockContext.getApplicationContext()).thenReturn(mockContext);
        Mockito.when(mockContext.getSharedPreferences(Mockito.anyString(), Mockito.anyInt()))
                .thenReturn(Mockito.mock(android.content.SharedPreferences.class));

        AdaptiveResourceManager.resetInstanceForTest();
        adaptiveManager = new AdaptiveResourceManager(null);
        adaptiveManager.clearTestOverrides();
        AdaptiveResourceManager.setInstanceForTest(adaptiveManager);

        BoundedWorkerExecutor executor = new BoundedWorkerExecutor(2, 4, 16);
        JobStateStore store = new JobStateStore(mockContext);

        coordinator = new MobileSecurityCoordinator(mockContext, executor, store);
    }

    @After
    public void tearDown() {
        if (coordinator != null) {
            coordinator.shutdown();
        }
        if (adaptiveManager != null) {
            adaptiveManager.clearTestOverrides();
        }
        AdaptiveResourceManager.resetInstanceForTest();
    }

    @Test
    public void testScheduledDeepScanDeferredWhenBatteryLowDischarging() {
        // Battery < 20% discharging
        adaptiveManager.setTestOverrides(10, false, AdaptiveResourceManager.ThermalStatus.NONE, false);

        JSONObject meta = new JSONObject();
        try {
            meta.put("isScheduled", true);
            meta.put("scanMode", "FULL_ACCESSIBLE_SCAN");
        } catch (Exception ignored) {}

        SecurityJob job = coordinator.submitJob(JobType.STORAGE_SCAN, meta, (j, ctrl) -> new JSONObject());

        assertEquals("Scheduled scan must transition to DEFERRED under low battery",
                JobState.DEFERRED, job.getState());
        assertTrue("Deferred scan must include explanation reason",
                job.getCancellationReason() != null && job.getCancellationReason().contains("Deferred due to adaptive"));
    }

    @Test
    public void testManualScanProceedsEvenWhenBatteryLow() {
        // Battery < 20% discharging
        adaptiveManager.setTestOverrides(10, false, AdaptiveResourceManager.ThermalStatus.NONE, false);

        JSONObject meta = new JSONObject();
        try {
            meta.put("isScheduled", false); // Manual scan requested by user
            meta.put("scanMode", "FULL_ACCESSIBLE_SCAN");
        } catch (Exception ignored) {}

        SecurityJob job = coordinator.submitJob(JobType.STORAGE_SCAN, meta, (j, ctrl) -> {
            JSONObject res = new JSONObject();
            res.put("status", "SUCCESS");
            return res;
        });

        assertNotEquals("Manual scan must NOT be automatically deferred", JobState.DEFERRED, job.getState());
    }

    @Test
    public void testCriticalThreatOutranksBackgroundWorkAndIsNotDeferred() {
        // Low battery and moderate thermal
        adaptiveManager.setTestOverrides(15, false, AdaptiveResourceManager.ThermalStatus.MODERATE, false);

        // Active threat event triage
        JSONObject meta = new JSONObject();
        try {
            meta.put("isScheduled", false);
            meta.put("fileTarget", "eicar.com");
        } catch (Exception ignored) {}

        SecurityJob job = coordinator.submitJob(JobType.FILE_SCAN, meta, (j, ctrl) -> {
            JSONObject res = new JSONObject();
            res.put("verdict", "DANGEROUS");
            return res;
        });

        assertNotEquals(JobState.DEFERRED, job.getState());
        assertEquals(JobType.FILE_SCAN, job.getType());
    }

    @Test
    public void testCoordinatorStatsIncludesAdaptiveMetrics() {
        adaptiveManager.setTestOverrides(85, true, AdaptiveResourceManager.ThermalStatus.LIGHT, false);

        JSONObject stats = coordinator.getCoordinatorStats();
        assertTrue("Stats must contain adaptiveStatus", stats.has("adaptiveStatus"));
        JSONObject adaptive = stats.optJSONObject("adaptiveStatus");
        assertNotNull(adaptive);
        assertEquals("LIGHT", adaptive.optString("thermalStatus"));
        assertTrue(adaptive.optBoolean("isCharging"));
    }
}
