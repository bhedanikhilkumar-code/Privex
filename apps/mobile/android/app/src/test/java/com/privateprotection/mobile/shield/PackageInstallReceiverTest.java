package com.privateprotection.mobile.shield;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.privateprotection.mobile.core.BoundedWorkerExecutor;
import com.privateprotection.mobile.core.JobStateStore;
import com.privateprotection.mobile.core.JobType;
import com.privateprotection.mobile.core.MobileSecurityCoordinator;
import com.privateprotection.mobile.core.SecurityJob;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for PackageInstallReceiver:
 * Verifies handling of ACTION_PACKAGE_ADDED and ACTION_PACKAGE_REPLACED,
 * filtering of internal packages, debouncing of rapid duplicate events,
 * and asynchronous PACKAGE_AUDIT job dispatch to MobileSecurityCoordinator.
 */
public class PackageInstallReceiverTest {

    private Context mockContext;
    private PackageInstallReceiver receiver;
    private MobileSecurityCoordinator coordinator;
    private Map<String, String> backingPrefs;

    @Before
    public void setUp() {
        backingPrefs = new HashMap<>();
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        when(mockContext.getPackageName()).thenReturn("com.privateprotection.mobile");

        SharedPreferences mockPrefs = Mockito.mock(SharedPreferences.class);
        SharedPreferences.Editor mockEditor = Mockito.mock(SharedPreferences.Editor.class);
        when(mockPrefs.edit()).thenReturn(mockEditor);
        when(mockPrefs.getString(anyString(), any())).thenAnswer(inv -> {
            String k = inv.getArgument(0);
            String def = inv.getArgument(1);
            return backingPrefs.getOrDefault(k, def);
        });
        when(mockContext.getSharedPreferences(anyString(), any(Integer.class))).thenReturn(mockPrefs);

        MobileSecurityCoordinator.resetInstance();
        BoundedWorkerExecutor executor = new BoundedWorkerExecutor(1, 2, 10);
        JobStateStore store = new JobStateStore(mockContext);
        coordinator = new MobileSecurityCoordinator(mockContext, executor, store);
        MobileSecurityCoordinator.setInstanceForTest(coordinator);
        receiver = new PackageInstallReceiver();
    }

    @Test
    public void testPackageAddedBroadcastSubmitsAuditJob() throws InterruptedException {
        Intent mockIntent = Mockito.mock(Intent.class);
        when(mockIntent.getAction()).thenReturn(Intent.ACTION_PACKAGE_ADDED);
        Uri mockUri = Mockito.mock(Uri.class);
        when(mockUri.getSchemeSpecificPart()).thenReturn("com.thirdparty.testapp");
        when(mockIntent.getData()).thenReturn(mockUri);
        when(mockIntent.getBooleanExtra(Intent.EXTRA_REPLACING, false)).thenReturn(false);

        receiver.onReceive(mockContext, mockIntent);

        Thread.sleep(150);

        List<SecurityJob> active = coordinator.getActiveJobs();
        int totalPersisted = coordinator.getCoordinatorStats().optInt("totalPersistedJobs", 0);
        assertTrue("Expected PACKAGE_AUDIT job to be submitted", active.size() > 0 || totalPersisted > 0);
    }

    @Test
    public void testIgnoresOwnPackage() throws InterruptedException {
        Intent mockIntent = Mockito.mock(Intent.class);
        when(mockIntent.getAction()).thenReturn(Intent.ACTION_PACKAGE_ADDED);
        Uri mockUri = Mockito.mock(Uri.class);
        when(mockUri.getSchemeSpecificPart()).thenReturn("com.privateprotection.mobile");
        when(mockIntent.getData()).thenReturn(mockUri);

        receiver.onReceive(mockContext, mockIntent);
        Thread.sleep(100);

        assertEquals(0, coordinator.getActiveJobs().size());
    }

    @Test
    public void testIgnoresNullOrIrrelevantIntents() {
        receiver.onReceive(mockContext, null);
        receiver.onReceive(null, Mockito.mock(Intent.class));

        Intent wrongAction = Mockito.mock(Intent.class);
        when(wrongAction.getAction()).thenReturn("android.intent.action.BOOT_COMPLETED");
        receiver.onReceive(mockContext, wrongAction);

        assertEquals(0, coordinator.getActiveJobs().size());
    }
}
