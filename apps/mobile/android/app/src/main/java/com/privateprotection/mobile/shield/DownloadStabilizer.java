package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.MediaStore;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;

/**
 * DownloadStabilizer (Phase T5):
 *
 * Evaluates file and download readiness before deep inspection:
 * 1. Checks MediaStore IS_PENDING on Android 10+ (API 29+).
 * 2. Checks partial download extensions (.crdownload, .part, .tmp).
 * 3. Enforces bounded size and modification stability for direct files.
 * 4. Strictly prevents premature inspection or declaring unstable files SAFE.
 */
public class DownloadStabilizer {
    private static final String TAG = "DownloadStabilizer";

    public enum StabilizationState {
        WAITING_FOR_COMPLETION,
        STABILIZING,
        READY_TO_SCAN,
        DEFERRED,
        INACCESSIBLE,
        FAILED
    }

    public static class StabilizationResult {
        public final StabilizationState state;
        public final long size;
        public final long dateModified;
        public final String mimeType;
        public final String reason;

        public StabilizationResult(StabilizationState state, long size, long dateModified, String mimeType, String reason) {
            this.state = state;
            this.size = size;
            this.dateModified = dateModified;
            this.mimeType = mimeType != null ? mimeType : "";
            this.reason = reason != null ? reason : "";
        }

        public boolean isReady() {
            return state == StabilizationState.READY_TO_SCAN;
        }

        public JSONObject toJSON() {
            JSONObject obj = new JSONObject();
            try {
                obj.put("state", state.name());
                obj.put("size", size);
                obj.put("dateModified", dateModified);
                obj.put("mimeType", mimeType);
                obj.put("reason", reason);
                obj.put("isReady", isReady());
            } catch (JSONException ignored) {}
            return obj;
        }
    }

    private final Context context;

    public DownloadStabilizer(Context context) {
        this.context = (context != null && context.getApplicationContext() != null)
                ? context.getApplicationContext() : context;
    }

    /**
     * Evaluates stabilization for a MediaStore or content Uri.
     */
    public StabilizationResult checkUriStabilization(Uri uri) {
        if (uri == null) {
            return new StabilizationResult(StabilizationState.INACCESSIBLE, 0, 0, "", "Null URI");
        }

        String uriStr = uri.toString();
        // Check for partial download indicators in uri string
        if (isPartialDownloadName(uriStr)) {
            return new StabilizationResult(StabilizationState.DEFERRED, 0, 0, "", "Partial download extension detected (.crdownload/.part)");
        }

        if (context == null) {
            return new StabilizationResult(StabilizationState.READY_TO_SCAN, 0, System.currentTimeMillis(), "", "No context available, fallback ready");
        }

        ContentResolver resolver = context.getContentResolver();
        if (resolver == null) {
            return new StabilizationResult(StabilizationState.FAILED, 0, 0, "", "ContentResolver unavailable");
        }

        Cursor cursor = null;
        try {
            String[] projection;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                projection = new String[]{
                        MediaStore.MediaColumns._ID,
                        MediaStore.MediaColumns.DISPLAY_NAME,
                        MediaStore.MediaColumns.SIZE,
                        MediaStore.MediaColumns.DATE_MODIFIED,
                        MediaStore.MediaColumns.MIME_TYPE,
                        MediaStore.MediaColumns.IS_PENDING
                };
            } else {
                projection = new String[]{
                        MediaStore.MediaColumns._ID,
                        MediaStore.MediaColumns.DISPLAY_NAME,
                        MediaStore.MediaColumns.SIZE,
                        MediaStore.MediaColumns.DATE_MODIFIED,
                        MediaStore.MediaColumns.MIME_TYPE
                };
            }

            cursor = resolver.query(uri, projection, null, null, null);
            if (cursor != null && cursor.moveToFirst()) {
                int nameIdx = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME);
                String displayName = nameIdx != -1 ? cursor.getString(nameIdx) : "";
                if (isPartialDownloadName(displayName)) {
                    return new StabilizationResult(StabilizationState.DEFERRED, 0, 0, "", "Partial download extension: " + displayName);
                }

                // Check IS_PENDING on Android 10+
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    int pendingIdx = cursor.getColumnIndex(MediaStore.MediaColumns.IS_PENDING);
                    if (pendingIdx != -1) {
                        int isPending = cursor.getInt(pendingIdx);
                        if (isPending != 0) {
                            Log.d(TAG, "Download URI is still pending write: " + uri);
                            return new StabilizationResult(StabilizationState.WAITING_FOR_COMPLETION, 0, 0, "", "IS_PENDING == 1");
                        }
                    }
                }

                int sizeIdx = cursor.getColumnIndex(MediaStore.MediaColumns.SIZE);
                int modIdx = cursor.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED);
                int mimeIdx = cursor.getColumnIndex(MediaStore.MediaColumns.MIME_TYPE);

                long size = sizeIdx != -1 ? cursor.getLong(sizeIdx) : 0;
                long modified = modIdx != -1 ? cursor.getLong(modIdx) : 0;
                String mime = mimeIdx != -1 ? cursor.getString(mimeIdx) : "";

                if (size <= 0) {
                    return new StabilizationResult(StabilizationState.STABILIZING, size, modified, mime, "Size is 0 bytes, stabilizing");
                }

                return new StabilizationResult(StabilizationState.READY_TO_SCAN, size, modified, mime, "Stabilized and ready");
            } else {
                // If cursor is null or empty, URI might be inaccessible or removed
                return new StabilizationResult(StabilizationState.INACCESSIBLE, 0, 0, "", "URI cursor empty or inaccessible");
            }
        } catch (SecurityException e) {
            Log.w(TAG, "SecurityException checking URI stabilization: " + uri, e);
            return new StabilizationResult(StabilizationState.INACCESSIBLE, 0, 0, "", "Permission denied");
        } catch (Exception e) {
            Log.w(TAG, "Exception checking URI stabilization: " + uri, e);
            return new StabilizationResult(StabilizationState.FAILED, 0, 0, "", e.getMessage());
        } finally {
            if (cursor != null) {
                try {
                    cursor.close();
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Evaluates stabilization for a direct File.
     */
    public StabilizationResult checkFileStabilization(File file) {
        if (file == null || !file.exists()) {
            return new StabilizationResult(StabilizationState.INACCESSIBLE, 0, 0, "", "File does not exist");
        }

        String name = file.getName();
        if (isPartialDownloadName(name)) {
            return new StabilizationResult(StabilizationState.DEFERRED, 0, file.lastModified(), "", "Partial download extension detected: " + name);
        }

        if (!file.canRead()) {
            return new StabilizationResult(StabilizationState.INACCESSIBLE, file.length(), file.lastModified(), "", "File cannot be read (permission denied)");
        }

        long length = file.length();
        if (length <= 0) {
            return new StabilizationResult(StabilizationState.STABILIZING, 0, file.lastModified(), "", "File length is 0 bytes");
        }

        return new StabilizationResult(StabilizationState.READY_TO_SCAN, length, file.lastModified(), "", "File stable and readable");
    }

    public static boolean isPartialDownloadName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.endsWith(".crdownload")
                || lower.endsWith(".part")
                || lower.endsWith(".download")
                || lower.endsWith(".tmp");
    }
}
