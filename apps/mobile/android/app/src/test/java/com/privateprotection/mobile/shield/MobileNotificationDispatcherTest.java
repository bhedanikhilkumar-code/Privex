package com.privateprotection.mobile.shield;

import android.app.NotificationManager;
import android.content.Context;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class MobileNotificationDispatcherTest {

    private Context mockContext;
    private NotificationManager mockNotificationManager;
    private MobileNotificationDispatcher dispatcher;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        mockNotificationManager = Mockito.mock(NotificationManager.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getSystemService(Context.NOTIFICATION_SERVICE)).thenReturn(mockNotificationManager);

        dispatcher = new MobileNotificationDispatcher(mockContext);
        MobileNotificationDispatcher.setInstanceForTest(dispatcher);
        dispatcher.resetStatsForTest();
    }

    @After
    public void tearDown() {
        MobileNotificationDispatcher.resetInstanceForTest();
    }

    @Test
    public void testAllSevenCategoriesMapToChannels() {
        assertEquals(MobileNotificationDispatcher.CHANNEL_CRITICAL_THREATS,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.CRITICAL_THREAT));
        assertEquals(MobileNotificationDispatcher.CHANNEL_CRITICAL_THREATS,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.APP_INSTALL_WARNING));
        assertEquals(MobileNotificationDispatcher.CHANNEL_DOWNLOADS,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED));
        assertEquals(MobileNotificationDispatcher.CHANNEL_WEB_SHIELD,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.PHISHING_WARNING));
        assertEquals(MobileNotificationDispatcher.CHANNEL_SCANS_HEALTH,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.SCAN_COMPLETE));
        assertEquals(MobileNotificationDispatcher.CHANNEL_SCANS_HEALTH,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.PROTECTION_DEGRADED));
        assertEquals(MobileNotificationDispatcher.CHANNEL_UPDATES,
                MobileNotificationDispatcher.getChannelForCategory(MobileNotificationDispatcher.Category.UPDATE_AVAILABLE));
    }

    @Test
    public void testSanitizeTextStripsRtloAndControls() {
        // Test U+202E Right-To-Left Override
        String evil = "invoice_\u202Eexe.pdf";
        String clean = MobileNotificationDispatcher.sanitizeText(evil, 100);
        assertEquals("invoice_exe.pdf", clean);

        // Test newlines and carriage returns replaced
        String multiLine = "Line 1\r\nLine 2\tTab";
        String cleanLines = MobileNotificationDispatcher.sanitizeText(multiLine, 100);
        assertEquals("Line 1  Line 2 Tab", cleanLines);

        // Test length truncation
        String longTitle = "A".repeat(150);
        String truncated = MobileNotificationDispatcher.sanitizeText(longTitle, 50);
        assertEquals(53, truncated.length()); // 50 chars + "..."
        assertTrue(truncated.endsWith("..."));
    }

    @Test
    public void testRateLimitingTokenBucketMaxThreePerWindow() {
        // Dispatch 3 valid alerts
        MobileNotificationDispatcher.DispatchResult r1 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "File 1", "Threat 1", "f1");
        MobileNotificationDispatcher.DispatchResult r2 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.PHISHING_WARNING, "Link 2", "Threat 2", "f2");
        MobileNotificationDispatcher.DispatchResult r3 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.SCAN_COMPLETE, "Scan 3", "Threat 3", "f3");

        assertEquals(MobileNotificationDispatcher.DispatchOutcome.DISPATCHED, r1.outcome);
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.DISPATCHED, r2.outcome);
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.DISPATCHED, r3.outcome);
        assertEquals(3, dispatcher.getRecentDispatchCount());

        // 4th alert in rolling window must be rate-limited
        MobileNotificationDispatcher.DispatchResult r4 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "File 4", "Threat 4", "f4");
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.SUPPRESSED_RATE_LIMIT, r4.outcome);
    }

    @Test
    public void testCriticalThreatPriorityBypassesRateLimiting() {
        // Fill window with 3 events
        dispatcher.dispatch(MobileNotificationDispatcher.Category.SCAN_COMPLETE, "A", "A", "k1");
        dispatcher.dispatch(MobileNotificationDispatcher.Category.SCAN_COMPLETE, "B", "B", "k2");
        dispatcher.dispatch(MobileNotificationDispatcher.Category.SCAN_COMPLETE, "C", "C", "k3");
        assertEquals(3, dispatcher.getRecentDispatchCount());

        // A CRITICAL_THREAT alert MUST NOT be suppressed
        MobileNotificationDispatcher.DispatchResult critical = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.CRITICAL_THREAT, "Trojan Detected", "BankBot APK", "trojan");

        assertEquals(MobileNotificationDispatcher.DispatchOutcome.DISPATCHED, critical.outcome);
    }

    @Test
    public void testCooldownDeduplicationForIdenticalNonCriticalAlerts() {
        MobileNotificationDispatcher.DispatchResult r1 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.PHISHING_WARNING, "Phish Link", "Domain blocked", "bad.com");
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.DISPATCHED, r1.outcome);

        // Immediate duplicate for same domain
        MobileNotificationDispatcher.DispatchResult r2 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.PHISHING_WARNING, "Phish Link", "Domain blocked", "bad.com");
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.SUPPRESSED_RATE_LIMIT, r2.outcome);
        assertTrue(r2.reason.contains("Duplicate alert suppressed"));
    }

    @Test
    public void testBurstCoalescingAfterThreshold() {
        // Dispatch 3 initial alerts
        dispatcher.dispatch(MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "D1", "D1", "d1");
        dispatcher.dispatch(MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "D2", "D2", "d2");
        dispatcher.dispatch(MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "D3", "D3", "d3");

        // Suppressed 1, 2 (burstCount = 1, 2)
        for (int i = 4; i <= 5; i++) {
            MobileNotificationDispatcher.DispatchResult r = dispatcher.dispatch(
                    MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "D" + i, "D" + i, "d" + i);
            assertEquals(MobileNotificationDispatcher.DispatchOutcome.SUPPRESSED_RATE_LIMIT, r.outcome);
        }

        // 3rd suppressed event in burst (burstCount = 3 == COALESCE_BURST_THRESHOLD) triggers COALESCED_BATCH
        MobileNotificationDispatcher.DispatchResult coalesced = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "D6", "D6", "d6");

        assertEquals(MobileNotificationDispatcher.DispatchOutcome.COALESCED_BATCH, coalesced.outcome);
        assertEquals(99999, coalesced.notificationId);

        // 4th burst event is suppressed again
        MobileNotificationDispatcher.DispatchResult r7 = dispatcher.dispatch(
                MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED, "D7", "D7", "d7");
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.SUPPRESSED_RATE_LIMIT, r7.outcome);
    }

    @Test
    public void testRule45CoalescingThresholdRegression() {
        assertEquals("Rule 45 requires COALESCE_BURST_THRESHOLD to equal 3", 3, MobileNotificationDispatcher.COALESCE_BURST_THRESHOLD);
    }

    @Test
    public void testMandatoryStormScenario200SyntheticDetections() {
        int dispatched = 0;
        int rateLimited = 0;
        int coalesced = 0;

        for (int i = 1; i <= 200; i++) {
            // EICAR detections under storm
            MobileNotificationDispatcher.DispatchResult res = dispatcher.dispatch(
                    MobileNotificationDispatcher.Category.DOWNLOAD_BLOCKED,
                    "EICAR Standard AV Test #" + i,
                    "Synthetic test fixture quarantined",
                    "eicar_" + i
            );

            if (res.outcome == MobileNotificationDispatcher.DispatchOutcome.DISPATCHED) {
                dispatched++;
            } else if (res.outcome == MobileNotificationDispatcher.DispatchOutcome.SUPPRESSED_RATE_LIMIT) {
                rateLimited++;
            } else if (res.outcome == MobileNotificationDispatcher.DispatchOutcome.COALESCED_BATCH) {
                coalesced++;
            }
        }

        // Invariants:
        // - Exactly 3 individual native alerts dispatched
        // - Exactly 1 coalesced summary alert fired at burst threshold
        // - 196 events safely rate-limited
        assertEquals("Max 3 individual alerts permitted in 10s window", 3, dispatched);
        assertEquals("Exactly 1 coalesced summary alert must fire during rapid burst", 1, coalesced);
        assertEquals(196, rateLimited);
        assertEquals(200, dispatched + rateLimited + coalesced);

        JSONObject stats = dispatcher.getDispatcherStats();
        assertEquals(200, stats.optInt("totalAttempted"));
        assertEquals(3, stats.optInt("totalDispatched"));
        assertEquals(1, stats.optInt("totalCoalesced"));
        assertEquals(196, stats.optInt("totalSuppressedRateLimit"));
    }

    @Test
    public void testNullContextSafety() {
        MobileNotificationDispatcher nullDispatcher = new MobileNotificationDispatcher(null);
        MobileNotificationDispatcher.DispatchResult res = nullDispatcher.dispatch(
                MobileNotificationDispatcher.Category.CRITICAL_THREAT, "Title", "Body", "key");
        assertEquals(MobileNotificationDispatcher.DispatchOutcome.ERROR, res.outcome);
    }
}
