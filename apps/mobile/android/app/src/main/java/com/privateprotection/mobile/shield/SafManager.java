package com.privateprotection.mobile.shield;

import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.UriPermission;
import android.net.Uri;
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * SafManager: Manages persistent Storage Access Framework (SAF) tree permissions (Phase T4).
 *
 * Responsibilities:
 * - Persisting Uri permissions via ContentResolver.takePersistableUriPermission
 * - Querying currently active persisted tree permissions
 * - Releasing permissions gracefully when revoked by user
 * - Validating tree readability before initiating directory traversal
 */
public class SafManager {
    private static final String TAG = "SafManager";

    private final Context context;

    public SafManager(Context context) {
        this.context = (context != null && context.getApplicationContext() != null)
                ? context.getApplicationContext() : context;
    }

    /**
     * Persists a newly granted tree Uri permission from ACTION_OPEN_DOCUMENT_TREE.
     */
    public boolean persistTreePermission(Uri treeUri) {
        if (treeUri == null) return false;
        try {
            int takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
            context.getContentResolver().takePersistableUriPermission(treeUri, takeFlags);
            Log.i(TAG, "Persisted SAF tree permission: " + treeUri);
            return true;
        } catch (SecurityException e) {
            Log.w(TAG, "Failed to take persistable URI permission for: " + treeUri, e);
            try {
                // Fallback to read-only grant if write permission was not given
                context.getContentResolver().takePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                return true;
            } catch (Exception ex) {
                System.err.println("SafManager SecurityException: " + ex);
                ex.printStackTrace();
                return false;
            }
        } catch (Exception e) {
            System.err.println("SafManager Exception: " + e);
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Releases a previously persisted tree Uri permission.
     */
    public boolean releaseTreePermission(Uri treeUri) {
        if (treeUri == null) return false;
        try {
            int flags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
            context.getContentResolver().releasePersistableUriPermission(treeUri, flags);
            Log.i(TAG, "Released SAF tree permission: " + treeUri);
            return true;
        } catch (Exception e) {
            System.err.println("SafManager release Exception: " + e);
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Returns all active persisted Uri permissions granted to this app.
     */
    public List<Uri> getPersistedTreeUris() {
        List<Uri> results = new ArrayList<>();
        try {
            List<UriPermission> perms = context.getContentResolver().getPersistedUriPermissions();
            for (UriPermission p : perms) {
                if (p.isReadPermission()) {
                    results.add(p.getUri());
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to list persisted URI permissions", e);
        }
        return Collections.unmodifiableList(results);
    }

    /**
     * Validates whether a tree Uri is still valid, readable, and not revoked.
     */
    public boolean isTreePermissionValid(Uri treeUri) {
        if (treeUri == null) return false;
        try {
            List<UriPermission> perms = context.getContentResolver().getPersistedUriPermissions();
            for (UriPermission p : perms) {
                if (p.getUri().equals(treeUri) && p.isReadPermission()) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public JSONArray getPersistedTreesJSON() {
        JSONArray arr = new JSONArray();
        List<Uri> trees = getPersistedTreeUris();
        for (Uri u : trees) {
            JSONObject obj = new JSONObject();
            try {
                obj.put("uri", u.toString());
                obj.put("isValid", isTreePermissionValid(u));
            } catch (JSONException ignored) {}
            arr.put(obj);
        }
        return arr;
    }
}
