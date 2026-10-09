package com.privateprotection.mobile.core;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;

/**
 * Unit tests for AdaptiveResourceManager (Phase T12).
 * Verifies all 20 required behaviors for battery, thermal, and low-RAM adaptation.
 */
public class AdaptiveResourceManagerTest {

    private AdaptiveResourceManager resourceManager;

    @Before
    public void setUp() {
        AdaptiveResourceManager.resetInstanceForTest();
        resourceManager = new AdaptiveResourceManager(null);
    }

    @After
    public void tearDown() {
        if (resourceManager != null) {
            resourceManager.clearTestOverrides();
        }
        AdaptiveResourceManager.resetInstanceForTest();
    }

    @Test
    public void testBatteryBelow20DischargingDefersScheduledDeepScan() {
        // Battery < 20% discharging
        resourceManager.setTestOverrides(15, false, AdaptiveResourceManager.ThermalStatus.NONE, false);

        assertEquals(AdaptiveResourceManager.ResourceMode.BATTERY_SAVER, resourceManager.getCurrentMode());
        assertFalse("Scheduled deep scan must be deferred when battery < 20% and discharging",
                resourceManager.canExecuteScheduledDeepScan());
        assertTrue(resourceManager.getTransitionReason().contains("deferring non-critical deep work"));
    }

    @Test
    public void testBatteryBelow20WhileChargingAllowsScan() {
        // Battery < 20% but charging
        resourceManager.setTestOverrides(15, true, AdaptiveResourceManager.ThermalStatus.NONE, false);

        assertEquals(AdaptiveResourceManager.ResourceMode.NORMAL, resourceManager.getCurrentMode());
        assertTrue("Scheduled deep scan should be eligible when charging even if battery is low",
                resourceManager.canExecuteScheduledDeepScan());
    }

    @Test
    public void testBatteryRecoveryResumesEligibility() {
        // First low
        resourceManager.setTestOverrides(10, false, AdaptiveResourceManager.ThermalStatus.NONE, false);
        assertFalse(resourceManager.canExecuteScheduledDeepScan());

        // Recovered
        resourceManager.setTestOverrides(65, false, AdaptiveResourceManager.ThermalStatus.NONE, false);
        assertEquals(AdaptiveResourceManager.ResourceMode.NORMAL, resourceManager.getCurrentMode());
        assertTrue("Scheduled deep scan should be eligible when battery recovers",
                resourceManager.canExecuteScheduledDeepScan());
    }

    @Test
    public void testThermalPressureReducesConcurrency() {
        // Moderate thermal
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.MODERATE, false);
        assertEquals(AdaptiveResourceManager.ResourceMode.THERMAL_THROTTLED, resourceManager.getCurrentMode());
        int concurrency = resourceManager.getRecommendedWorkerConcurrency(4);
        assertEquals(2, concurrency);

        // Severe thermal
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.SEVERE, false);
        assertEquals(AdaptiveResourceManager.ResourceMode.THERMAL_THROTTLED, resourceManager.getCurrentMode());
        assertFalse("Severe thermal must defer scheduled deep scan",
                resourceManager.canExecuteScheduledDeepScan());
    }

    @Test
    public void testThermalRecoveryRestoresConcurrencySafely() {
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.CRITICAL, false);
        assertEquals(AdaptiveResourceManager.ResourceMode.THERMAL_THROTTLED, resourceManager.getCurrentMode());
        assertFalse(resourceManager.canExecuteScheduledDeepScan());

        // Thermal normalizes
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.NONE, false);
        assertEquals(AdaptiveResourceManager.ResourceMode.NORMAL, resourceManager.getCurrentMode());
        assertTrue(resourceManager.canExecuteScheduledDeepScan());
        assertEquals(4, resourceManager.getRecommendedWorkerConcurrency(4));
    }

    @Test
    public void testUnsupportedThermalAPIHandledTruthfully() {
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.UNAVAILABLE, false);
        JSONObject json = resourceManager.getAdaptiveStatusJSON();
        assertEquals("UNAVAILABLE", json.optString("thermalStatus"));
        assertFalse(json.optBoolean("isThermalSupported"));
    }

    @Test
    public void testLowMemoryModeEnforcesBoundedBuffersAndSingleWorker() {
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.NONE, true);

        assertEquals(AdaptiveResourceManager.ResourceMode.LOW_MEMORY, resourceManager.getCurrentMode());
        assertEquals(16 * 1024, resourceManager.getStreamingBufferSize()); // 16 KB bounded buffer
        assertEquals(1, resourceManager.getRecommendedWorkerConcurrency(4)); // Single thread
        assertFalse("Low RAM must defer bulk scheduled deep scans", resourceManager.canExecuteScheduledDeepScan());
    }

    @Test
    public void testForegroundWorkloadThrottlesBackgroundActivity() {
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.NONE, false);
        resourceManager.setForegroundHeavy(true);

        assertEquals(AdaptiveResourceManager.ResourceMode.BACKGROUND_THROTTLED, resourceManager.getCurrentMode());
        assertEquals(1, resourceManager.getRecommendedWorkerConcurrency(4));

        resourceManager.setForegroundHeavy(false);
        assertEquals(AdaptiveResourceManager.ResourceMode.NORMAL, resourceManager.getCurrentMode());
    }

    @Test
    public void testCombinedLowMemoryAndSevereThermalTransitionsToDegradedCritical() {
        resourceManager.setTestOverrides(80, false, AdaptiveResourceManager.ThermalStatus.SEVERE, true);

        assertEquals(AdaptiveResourceManager.ResourceMode.DEGRADED_CRITICAL, resourceManager.getCurrentMode());
        assertEquals(16 * 1024, resourceManager.getStreamingBufferSize());
        assertEquals(1, resourceManager.getRecommendedWorkerConcurrency(4));
        assertFalse(resourceManager.canExecuteScheduledDeepScan());
    }

    @Test
    public void testListenerNotificationOnModeChange() {
        AtomicBoolean notified = new AtomicBoolean(false);
        resourceManager.addListener((newMode, reason) -> {
            if (newMode == AdaptiveResourceManager.ResourceMode.BATTERY_SAVER) {
                notified.set(true);
            }
        });

        resourceManager.setTestOverrides(12, false, AdaptiveResourceManager.ThermalStatus.NONE, false);
        assertTrue("Listener should be notified of mode change", notified.get());
    }
}
