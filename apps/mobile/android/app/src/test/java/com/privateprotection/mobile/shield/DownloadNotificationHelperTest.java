package com.privateprotection.mobile.shield;

import android.app.NotificationManager;
import android.content.Context;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class DownloadNotificationHelperTest {

    private Context mockContext;
    private NotificationManager mockNotificationManager;
    private DownloadNotificationHelper helper;

    @Before
    public void setUp() {
        MobileNotificationDispatcher.resetInstanceForTest();
        mockContext = Mockito.mock(Context.class);
        mockNotificationManager = Mockito.mock(NotificationManager.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getSystemService(Context.NOTIFICATION_SERVICE)).thenReturn(mockNotificationManager);
        helper = new DownloadNotificationHelper(mockContext);
    }

    @Test
    public void testNotificationCategories() {
        // Dispatches within limit
        boolean r1 = helper.notify(DownloadNotificationHelper.NotificationCategory.DOWNLOAD_SCANNED, "notes.txt", "Clean file");
        boolean r2 = helper.notify(DownloadNotificationHelper.NotificationCategory.DOWNLOAD_WARNING, "dropper.zip", "Suspicious archive");
        boolean r3 = helper.notify(DownloadNotificationHelper.NotificationCategory.MALWARE_DETECTED, "trojan.apk", "Malicious DEX payload");

        assertTrue("First notification should dispatch", r1);
        assertTrue("Second notification should dispatch", r2);
        assertTrue("Third notification should dispatch", r3);

        assertEquals(3, helper.getRecentDispatchCount());

        // 4th notification in window must be rate-limited
        boolean r4 = helper.notify(DownloadNotificationHelper.NotificationCategory.DOWNLOAD_QUARANTINED, "eicar.com", "Quarantined");
        assertFalse("Fourth notification in 10s window must be rate-limited", r4);
    }

    @Test
    public void testNullContextSafety() {
        DownloadNotificationHelper nullHelper = new DownloadNotificationHelper(null);
        assertFalse(nullHelper.notify(DownloadNotificationHelper.NotificationCategory.MALWARE_DETECTED, "threat.exe", "Error"));
    }
}
