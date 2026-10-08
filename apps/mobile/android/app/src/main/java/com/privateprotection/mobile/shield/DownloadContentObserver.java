package com.privateprotection.mobile.shield;

import android.content.Context;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.util.Log;

import org.json.JSONObject;

import com.privateprotection.mobile.core.JobType;
import com.privateprotection.mobile.core.MobileSecurityCoordinator;
import com.privateprotection.mobile.core.SecurityJob;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DownloadContentObserver (Phase T3):
 *
 * Observes public download events via Android MediaStore (MediaStore.Downloads.EXTERNAL_CONTENT_URI).
 *
 * TRUTHFUL ANDROID BEHAVIOR:
 * - Fires when a file entry is inserted or updated in MediaStore Downloads.
 * - Standard 3rd-party Android applications CANNOT intercept pre-open or replace system download managers.
 * - Debounces rapid multi-stage download writes (e.g., chunk flushes).
 * - Enqueues background security inspection jobs through MobileSecurityCoordinator.
 */
public class DownloadContentObserver extends ContentObserver {
    private static final String TAG = "DownloadContentObserver";

    private static final Map<String, Long> lastObservedTimestamps = new ConcurrentHashMap<>();
    private static final long DEBOUNCE_WINDOW_MS = 3000L; // 3 seconds debounce per URI

    private final Context context;

    public DownloadContentObserver(Context context, Handler handler) {
        super(handler != null ? handler : new Handler(Looper.getMainLooper()));
        this.context = context.getApplicationContext();
    }

    @Override
    public void onChange(boolean selfChange, Uri uri) {
        super.onChange(selfChange, uri);
        if (uri == null) return;

        String uriKey = uri.toString();
        long now = System.currentTimeMillis();
        Long lastSeen = lastObservedTimestamps.get(uriKey);
        if (lastSeen != null && (now - lastSeen) < DEBOUNCE_WINDOW_MS) {
            return;
        }
        lastObservedTimestamps.put(uriKey, now);

        Log.i(TAG, "Observed file event in MediaStore: " + uri);

        try {
            JSONObject meta = new JSONObject();
            meta.put("uri", uri.toString());
            meta.put("eventSource", "MEDIASTORE_DOWNLOADS");
            meta.put("observedTimestamp", now);

            MobileSecurityCoordinator coordinator = MobileSecurityCoordinator.getInstance(context);
            coordinator.submitJob(JobType.DOWNLOAD_INSPECT, meta, (job, ctrl) -> {
                RealtimeDownloadProtectionService service = RealtimeDownloadProtectionService.getInstance(context);
                return service.handleIncomingDownloadUri(uri, null);
            });
        } catch (Exception e) {
            Log.e(TAG, "Failed to submit download inspection job for " + uri, e);
        }
    }
}
